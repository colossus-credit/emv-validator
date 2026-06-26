// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {P256} from "solady/utils/P256.sol";
import {IValidator, ISigner, IPolicy} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {PassFlag, PermissionId, PolicyData} from "kernel/src/types/Types.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_SIGNER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/src/types/Constants.sol";
import {ValidatorLib} from "kernel/src/utils/ValidationTypeLib.sol";
import {EMVCallData} from "./util/EMVCallData.sol";

struct EMVTransactionData {
    bytes iccDN; // 9F4C - ICC Dynamic Number (3 bytes) - REQUIRED for DDA
    bytes arqc; // 9F26 - Application Cryptogram (8 bytes)
    bytes unpredictableNumber; // 9F37 - 4 bytes from terminal
    bytes atc; // 9F36 - 2-byte Application Transaction Counter
    bytes amount; // 9F02 - 6-byte BCD amount
    bytes currency; // 5F2A - 2-byte ISO currency code (big-endian)
    bytes date; // 9A - YYMMDD (3 bytes BCD)
    bytes txnType; // 9C - 1 byte transaction type
    bytes tvr; // 95 - 5 bytes Terminal Verification Results
    bytes cvmResults; // 9F34 - 3 bytes CVM Results
    bytes terminalId; // 9F1C - Terminal ID (8 bytes)
    bytes merchantId; // 9F16 - Merchant ID (15 bytes)
    bytes acquirerId; // 9F01 - Acquirer ID (6 bytes)
    bytes signature; // P-256 signature envelope: keyHash || pubkeyX || pubkeyY || r || s
}

interface IKernelPermissionConfig {
    struct PermissionConfig {
        PassFlag permissionFlag;
        ISigner signer;
        PolicyData[] policyData;
    }

    function permissionConfig(PermissionId permission) external view returns (PermissionConfig memory config);
}

/**
 * @title EMVSigner
 * @dev ERC-7579 signer module for raw EMV P-256 signature validation.
 * @notice Mutable card controls such as replay protection and freezing are enforced by policy modules.
 */
contract EMVSigner is IValidator, ISigner {
    uint256 private constant EMV_FIELDS_LENGTH = 52;

    mapping(address account => mapping(bytes32 permission => bytes32 keyHash)) private authorizedKeyHashes;

    error StandaloneValidatorDisabled();
    error InvalidConfig();
    error InvalidRequiredPolicy();
    error RequiredPolicyMissing(address policy);
    error InvalidSignatureLength(uint256 actualSize);
    error PublicKeyNotRegistered();
    error InvalidPublicKeySize();
    error InvalidPublicKey();
    error InvalidSender();

    event EMVSignerInstalled(
        address indexed account, bytes32 indexed permission, bytes32 indexed keyHash, bytes32 pubkeyX, bytes32 pubkeyY
    );

    /**
     * @dev Install permission-scoped signer key configuration: permission || abi.encode(atc, x, y).
     */
    function onInstall(bytes calldata _data) external payable override {
        (bytes32 permission, bytes calldata signerData) = _signerInstallData(_data);
        (, bytes32 pubkeyX, bytes32 pubkeyY, address callPolicy, address cardPolicy, address limitPolicy) =
            abi.decode(signerData, (uint16, bytes32, bytes32, address, address, address));

        if (pubkeyX == bytes32(0) || pubkeyY == bytes32(0)) {
            revert InvalidPublicKeySize();
        }
        _validateRequiredPolicies(permission, callPolicy, cardPolicy, limitPolicy);

        bytes32 keyHash = computeKeyHash(pubkeyX, pubkeyY);
        authorizedKeyHashes[msg.sender][permission] = keyHash;

        emit EMVSignerInstalled(msg.sender, permission, keyHash, pubkeyX, pubkeyY);
    }

    function onUninstall(bytes calldata _data) external payable override {
        if (_data.length < 32) {
            revert InvalidConfig();
        }
        bytes32 permission = bytes32(_data[0:32]);
        delete authorizedKeyHashes[msg.sender][permission];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_SIGNER;
    }

    /**
     * @dev Satisfy the ERC-7579 module interface without account-level initialization reads.
     */
    function isInitialized(address) external pure override returns (bool) {
        return true;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /* userOpHash */
    )
        external
        payable
        override
        returns (uint256)
    {
        userOp;
        revert StandaloneValidatorDisabled();
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32)
        external
        payable
        override
        returns (uint256)
    {
        return _validateEMVUserOp(id, msg.sender, userOp.callData, userOp.signature);
    }

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        sender;
        hash;
        sig;
        revert StandaloneValidatorDisabled();
    }

    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        return _checkSignature(id, sender, hash, sig);
    }

    function computeKeyHash(bytes32 pubkeyX, bytes32 pubkeyY) public pure returns (bytes32) {
        return keccak256(abi.encode(pubkeyX, pubkeyY));
    }

    function getAuthorizedKeyHash(address account, bytes32 permission) external view returns (bytes32) {
        return authorizedKeyHashes[account][permission];
    }

    function isPublicKeyRegistered(address account, bytes32 permission, bytes32 keyHash) external view returns (bool) {
        return authorizedKeyHashes[account][permission] == keyHash;
    }

    function _validateEMVUserOp(bytes32 permission, address account, bytes calldata callData, bytes calldata signature)
        internal
        view
        returns (uint256)
    {
        bytes calldata emvFields = EMVCallData.extractEMVFields(callData);
        if (emvFields.length != EMV_FIELDS_LENGTH) {
            revert InvalidSignatureLength(emvFields.length);
        }

        (bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s) = _decodeEMVSignature(signature);
        if (!_isValidPublicKeyHash(keyHash, pubkeyX, pubkeyY)) {
            revert InvalidPublicKey();
        }

        if (authorizedKeyHashes[account][permission] != keyHash) {
            revert PublicKeyNotRegistered();
        }

        return _verifyEMVSignature(emvFields, pubkeyX, pubkeyY, r, s)
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    function _checkSignature(bytes32 permission, address sender, bytes32 hash, bytes calldata sig)
        internal
        view
        returns (bytes4)
    {
        if (sender == address(0)) {
            revert InvalidSender();
        }

        if (sig.length != 160) {
            return ERC1271_INVALID;
        }

        (bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s) = _decodeEMVSignature(sig);
        if (!_isValidPublicKeyHash(keyHash, pubkeyX, pubkeyY)) {
            return ERC1271_INVALID;
        }

        if (authorizedKeyHashes[sender][permission] != keyHash) {
            revert PublicKeyNotRegistered();
        }

        return P256.verifySignature(hash, r, s, pubkeyX, pubkeyY) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function _verifyEMVSignature(bytes calldata emvFields, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s)
        internal
        view
        returns (bool)
    {
        return P256.verifySignature(sha256(emvFields), r, s, pubkeyX, pubkeyY);
    }

    function _decodeEMVSignature(bytes calldata signature)
        internal
        pure
        returns (bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s)
    {
        if (signature.length != 160) {
            revert InvalidSignatureLength(signature.length);
        }

        assembly {
            keyHash := calldataload(signature.offset)
            pubkeyX := calldataload(add(signature.offset, 32))
            pubkeyY := calldataload(add(signature.offset, 64))
            r := calldataload(add(signature.offset, 96))
            s := calldataload(add(signature.offset, 128))
        }
    }

    function _signerInstallData(bytes calldata data)
        internal
        pure
        returns (bytes32 permission, bytes calldata signerData)
    {
        if (data.length == 96) {
            revert StandaloneValidatorDisabled();
        }
        if (data.length == 224) return (bytes32(data[0:32]), data[32:]);
        revert InvalidConfig();
    }

    function _isValidPublicKeyHash(bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY) internal pure returns (bool) {
        return computeKeyHash(pubkeyX, pubkeyY) == keyHash;
    }

    function _validateRequiredPolicies(bytes32 permission, address callPolicy, address cardPolicy, address limitPolicy)
        internal
        view
    {
        if (callPolicy == address(0) || cardPolicy == address(0) || limitPolicy == address(0)) {
            revert InvalidRequiredPolicy();
        }

        IKernelPermissionConfig.PermissionConfig memory config =
            IKernelPermissionConfig(msg.sender).permissionConfig(PermissionId.wrap(bytes4(permission)));
        if (address(config.signer) != address(this)) {
            revert InvalidRequiredPolicy();
        }

        _requirePolicy(config.policyData, callPolicy);
        _requirePolicy(config.policyData, cardPolicy);
        _requirePolicy(config.policyData, limitPolicy);
    }

    function _requirePolicy(PolicyData[] memory policyData, address requiredPolicy) internal pure {
        for (uint256 i = 0; i < policyData.length; i++) {
            (, IPolicy policy) = ValidatorLib.decodePolicyData(policyData[i]);
            if (address(policy) == requiredPolicy) {
                return;
            }
        }

        revert RequiredPolicyMissing(requiredPolicy);
    }
}
