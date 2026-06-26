// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {P256} from "solady/utils/P256.sol";
import {IValidator, ISigner} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_SIGNER,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/src/types/Constants.sol";
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

/**
 * @title EMVSigner
 * @dev ERC-7579 signer/validator module for raw EMV P-256 signature validation.
 * @notice Mutable card controls such as replay protection and freezing are enforced by policy modules.
 */
contract EMVSigner is IValidator, ISigner {
    uint256 private constant EMV_FIELDS_LENGTH = 52;
    bytes32 private constant DIRECT_VALIDATOR_KEY = bytes32(0);

    mapping(address account => mapping(bytes32 permission => bytes32 keyHash)) private authorizedKeyHashes;

    error InvalidConfig();
    error InvalidSignatureLength(uint256 actualSize);
    error PublicKeyNotRegistered();
    error InvalidPublicKeySize();
    error InvalidPublicKey();
    error InvalidSender();

    event EMVSignerInstalled(
        address indexed account, bytes32 indexed permission, bytes32 indexed keyHash, bytes32 pubkeyX, bytes32 pubkeyY
    );

    /**
     * @dev Install signer key configuration. Direct validator installs pass abi.encode(atc, x, y);
     *      permission signer installs pass permission || abi.encode(atc, x, y).
     */
    function onInstall(bytes calldata _data) external payable override {
        (bytes32 permission, bytes calldata signerData) = _signerInstallData(_data);
        (, bytes32 pubkeyX, bytes32 pubkeyY) = abi.decode(signerData, (uint16, bytes32, bytes32));

        if (pubkeyX == bytes32(0) || pubkeyY == bytes32(0)) {
            revert InvalidPublicKeySize();
        }

        bytes32 keyHash = computeKeyHash(pubkeyX, pubkeyY);
        authorizedKeyHashes[msg.sender][permission] = keyHash;

        emit EMVSignerInstalled(msg.sender, permission, keyHash, pubkeyX, pubkeyY);
    }

    function onUninstall(bytes calldata _data) external payable override {
        bytes32 permission = _data.length >= 32 ? bytes32(_data[0:32]) : DIRECT_VALIDATOR_KEY;
        delete authorizedKeyHashes[msg.sender][permission];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_SIGNER;
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
        return _validateEMVUserOp(DIRECT_VALIDATOR_KEY, msg.sender, userOp.callData, userOp.signature);
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
        return _checkSignature(DIRECT_VALIDATOR_KEY, sender, hash, sig);
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
            return (DIRECT_VALIDATOR_KEY, data);
        }
        if (data.length == 128) {
            return (bytes32(data[0:32]), data[32:]);
        }
        revert InvalidConfig();
    }

    function _isValidPublicKeyHash(bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY) internal pure returns (bool) {
        return computeKeyHash(pubkeyX, pubkeyY) == keyHash;
    }
}
