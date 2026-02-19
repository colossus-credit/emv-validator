// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {P256} from "./P256Compat.sol";
import {IValidator, IExecutor, IHook} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "kernel/src/types/Constants.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {ExecMode, CallType} from "kernel/src/types/Types.sol";

struct EMVTransactionData {
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
    bytes signature; // ECDSA signature: 64 bytes raw r||s (from 9F10+9F7C or DER-decoded 9F4B)
    // Note: P-256 public key (x, y coordinates) registered during onInstall, not included per-transaction
}

/**
 * @title EMVValidator
 * @dev Complete ERC-7579 module for EMV CDA validation and ERC20 execution
 * @notice Validates EMV CDA signatures and executes ERC20 transfers with merchant registry integration
 */
contract EMVValidator is IValidator {
    // ========== EVENTS ==========

    event ReplayProtectionUpdated(address indexed kernel, bytes4 unpredictableNumber, uint16 newATC);

    // ========== STORAGE ==========

    struct EMVValidatorStorage {
        mapping(uint32 => bool) usedUnpredictableNumbers; // Track used unpredictable numbers (4 bytes)
        uint16 expectedATC; // Next expected ATC value for this kernel instance
        bytes32 pubkeyX; // P-256 public key x coordinate (32 bytes)
        bytes32 pubkeyY; // P-256 public key y coordinate (32 bytes)
    }

    mapping(address => EMVValidatorStorage) public emvValidatorStorage;
    address public immutable target; // Expected target address for validation
    bytes4 public immutable selector; // Expected function selector for validation

    // ========== ERRORS ==========
    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidCurrencyCode(uint16 currency);
    error InvalidConfig();
    error InvalidTarget(address expected, address actual);
    error InvalidFunctionSelector(bytes4 expected, bytes4 actual);
    error InvalidSignatureLength(uint256 actualSize);
    error PublicKeyNotRegistered();
    error InvalidPublicKeySize();
    error InvalidSender();
    error InvalidSignature();

    event EMVValidatorInstalled(address indexed account, uint16 atc, bytes32 pubkeyX, bytes32 pubkeyY);

    // ========== CONSTRUCTOR ==========

    /**
     * @dev Constructor to initialize immutable values
     * @param _target The target address for validation
     * @param _selector The function selector for validation
     */
    constructor(address _target, bytes4 _selector) {
        if (_target == address(0) || _selector == bytes4(0)) {
            revert InvalidConfig();
        }
        target = _target;
        selector = _selector;
    }

    // ========== MODULE LIFECYCLE ==========

    /**
     * @dev Install the module with ATC configuration and P-256 public key registration
     * @param _data Encoded configuration: abi.encode(atc, pubkeyX, pubkeyY)
     *        - atc: uint16 - Initial ATC value
     *        - pubkeyX: bytes32 - P-256 public key x coordinate (32 bytes)
     *        - pubkeyY: bytes32 - P-256 public key y coordinate (32 bytes)
     */
    function onInstall(bytes calldata _data) external payable override {
        if (_data.length == 0) {
            revert InvalidConfig();
        }

        (uint16 atc, bytes32 pubkeyX, bytes32 pubkeyY) = abi.decode(_data, (uint16, bytes32, bytes32));

        // Validate P-256 public key (not zero)
        if (pubkeyX == bytes32(0) || pubkeyY == bytes32(0)) {
            revert InvalidPublicKeySize();
        }

        emvValidatorStorage[msg.sender].expectedATC = atc;
        emvValidatorStorage[msg.sender].pubkeyX = pubkeyX;
        emvValidatorStorage[msg.sender].pubkeyY = pubkeyY;

        emit EMVValidatorInstalled(msg.sender, atc, pubkeyX, pubkeyY);
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        // Reset ATC counter for this account
        emvValidatorStorage[msg.sender].expectedATC = 0;

        // Clear registered P-256 public key
        delete emvValidatorStorage[msg.sender].pubkeyX;
        delete emvValidatorStorage[msg.sender].pubkeyY;

        // Note: usedUnpredictableNumbers entries remain for security
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR;
    }

    /**
     * @dev Check if module is initialized for the smart account
     */
    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        // Module is considered initialized if the account has been configured with a P-256 public key
        return emvValidatorStorage[smartAccount].pubkeyX != bytes32(0)
            && emvValidatorStorage[smartAccount].pubkeyY != bytes32(0);
    }

    // ========== VALIDATOR FUNCTIONS ==========

    /**
     * @dev Validate EMV CDA signature for ERC-4337 user operation
     * @param userOp The user operation with EMV fields in callData and RSA signature in signature field
     * @return SIG_VALIDATION_SUCCESS_UINT if valid, SIG_VALIDATION_FAILED_UINT otherwise
     * @notice The userOpHash parameter is unused as we use SHA-256 hash of the EMV dynamic data
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /* userOpHash */
    )
        external
        payable
        override
        returns (uint256)
    {
        // Note: userOp.callData should contain the kernel.execute() call with EMV fields
        // We need to extract the EMV fields from within the execute call
        bytes calldata emvFields = _extractEMVFieldsFromCallData(userOp.callData);

        // Validate that this EMV signature is being used for the correct target and function
        _validateTargetAndSelector(userOp.callData);

        // Gas-optimized validation using calldata extraction instead of full memory expansion
        // Validate currency code from EMV fields
        _validateCurrencyCode(emvFields);

        // Validate replay protection and update state
        _validateReplayProtectionAndUpdateState(emvFields);

        // Verify P-256 ECDSA signature (userOp.signature should be 64 bytes: r||s)
        return (_verifyEMVSignature(userOp.signature, emvFields, msg.sender))
            ? SIG_VALIDATION_SUCCESS_UINT
            : SIG_VALIDATION_FAILED_UINT;
    }

    /**
     * @dev Validate EMV signature for ERC-1271 (view-only, no state changes)
     * @param sender The account address to validate signature for
     * @param hash The SHA-256 hash of the EMV dynamic data to validate
     * @param sig The ECDSA P-256 signature bytes (64 bytes: r||s)
     * @return ERC1271_MAGICVALUE if valid, ERC1271_INVALID otherwise
     */
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        if (sender == address(0)) {
            revert InvalidSender();
        }

        if (!_isInitialized(sender)) {
            revert PublicKeyNotRegistered();
        }

        // Validate signature length (must be 64 bytes: r||s)
        if (sig.length != 64) {
            return ERC1271_INVALID;
        }

        // Get registered P-256 public key
        bytes32 pubkeyX = emvValidatorStorage[sender].pubkeyX;
        bytes32 pubkeyY = emvValidatorStorage[sender].pubkeyY;

        // Extract signature components: r (32 bytes) || s (32 bytes)
        uint256 r;
        uint256 s;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
        }

        // Verify ECDSA signature using P256 library
        bool isValid = P256.verifySignature(hash, r, s, uint256(pubkeyX), uint256(pubkeyY));

        return isValid ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    /**
     * @dev Get the configured target and selector
     * @return targetAddress The target address for validation
     * @return functionSelector The function selector for validation
     */
    function getValidationConfig() external view returns (address targetAddress, bytes4 functionSelector) {
        return (target, selector);
    }

    /**
     * @dev Get the EMV storage for a specific account
     * @param account The smart account address
     * @return expectedATC The next expected ATC value
     */
    function getEMVStorage(address account) external view returns (uint16 expectedATC) {
        return emvValidatorStorage[account].expectedATC;
    }

    /**
     * @dev Get the registered public key for a specific account
     * @param account The smart account address
     * @return pubkeyX The P-256 public key x coordinate
     * @return pubkeyY The P-256 public key y coordinate
     */
    function getRegisteredPublicKey(address account)
        external
        view
        returns (bytes32 pubkeyX, bytes32 pubkeyY)
    {
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[account];
        return (accountStorage.pubkeyX, accountStorage.pubkeyY);
    }

    /**
     * @dev Check if an unpredictable number has been used for a specific account
     * @param account The smart account address
     * @param unpredictableNumber The unpredictable number to check
     * @return used True if the unpredictable number has been used
     */
    function isUnpredictableNumberUsed(address account, bytes4 unpredictableNumber) external view returns (bool used) {
        return emvValidatorStorage[account].usedUnpredictableNumbers[uint32(unpredictableNumber)];
    }

    // ========== INTERNAL VALIDATION FUNCTIONS ==========

    /**
     * @dev Extract EMV fields from the nested callData structure
     * @param callData The callData from PackedUserOperation containing kernel.execute(...)
     * @return emvFields The 63-byte EMV transaction fields
     */
    function _extractEMVFieldsFromCallData(bytes calldata callData) internal pure returns (bytes calldata emvFields) {
        // Parse execute(ExecMode, bytes) call data structure:
        // selector(4) + execMode(32) + offset(32) + length(32) + executionCalldata(variable)

        // Get offset to executionCalldata (should be 0x40 = 64)
        uint256 executionDataOffset = uint256(bytes32(callData[36:68]));

        // ExecutionCalldata starts at: 4 + offset + 32 (skip length field)
        uint256 executionDataStart = 4 + executionDataOffset + 32;

        // For DELEGATECALL: decodeDelegate format (abi.encodePacked): target(20) + inner_calldata(variable)
        // Skip target(20) bytes to get to inner calldata
        uint256 innerCalldataStart = executionDataStart + 20;

        // Inner calldata structure (ABI encoded): selector(4) + offset(32) + length(32) + emvFields(63)
        // Skip selector(4) + offset(32) + length(32) = 68 bytes
        uint256 emvDataStart = innerCalldataStart + 68;

        // EMV fields are always 63 bytes
        return callData[emvDataStart:emvDataStart + 63];
    }

    /**
     * @dev Validate that the callData is calling the expected target and function
     * @param callData The callData from the PackedUserOperation
     */
    function _validateTargetAndSelector(bytes calldata callData) internal view {
        bytes4 actualSelector = bytes4(callData[0:4]);
        if (actualSelector != selector) {
            revert InvalidFunctionSelector(selector, actualSelector);
        }

        // Parse execute(ExecMode, bytes) call data structure:
        // selector(4) + execMode(32) + offset(32) + length(32) + executionCalldata(variable)

        // Get offset to executionCalldata (should be 0x40 = 64)
        uint256 executionDataOffset = uint256(bytes32(callData[36:68]));

        // ExecutionCalldata starts at: 4 + offset + 32 (skip length field)
        uint256 executionDataStart = 4 + executionDataOffset + 32;

        // Extract target address from the beginning of executionCalldata (encodeSingle format)
        // encodeSingle format: target(20) + value(32) + calldata(variable)
        if (callData.length >= executionDataStart + 20) {
            address actualTarget = address(bytes20(callData[executionDataStart:executionDataStart + 20]));
            if (actualTarget != target) {
                revert InvalidTarget(target, actualTarget);
            }
        } else {
            revert InvalidTarget(target, address(0));
        }
    }

    // ========== GAS-OPTIMIZED CALLDATA EXTRACTION ==========

    /**
     * @dev Extract unpredictable number (4 bytes) from packed EMV fields - Assembly optimized
     */
    function _extractUnpredictableNumber(bytes calldata emvFields) internal pure returns (bytes4 result) {
        assembly {
            result := calldataload(add(emvFields.offset, 8))
        }
    }

    /**
     * @dev Extract ATC (2 bytes) from packed EMV fields - Assembly optimized
     */
    function _extractATC(bytes calldata emvFields) internal pure returns (bytes2 result) {
        assembly {
            result := calldataload(add(emvFields.offset, 12))
        }
    }

    /**
     * @dev Extract currency (2 bytes) from packed EMV fields - Assembly optimized
     */
    function _extractCurrency(bytes calldata emvFields) internal pure returns (bytes2 result) {
        assembly {
            result := calldataload(add(emvFields.offset, 20))
        }
    }

    /**
     * @dev Validate currency code (must be 840 USD or 997 USN)
     * @param emvFields The EMV fields calldata to extract currency from
     */
    function _validateCurrencyCode(bytes calldata emvFields) internal pure {
        // Currency is stored as 2 bytes in BCD format (n3 per EMV spec)
        // 840 USD = 0x0840, 997 USN = 0x0997
        bytes2 currencyBytes = _extractCurrency(emvFields);
        uint16 currency = uint16(currencyBytes);
        if (currency != 0x0840 && currency != 0x0997) {
            revert InvalidCurrencyCode(currency);
        }
    }

    /**
     * @dev Validate replay protection and update transaction state in one operation - Storage optimized
     * @param emvFields The EMV fields calldata to extract data from
     */
    function _validateReplayProtectionAndUpdateState(bytes calldata emvFields) internal {
        // Extract values using assembly for efficiency
        bytes4 unpredictableNumberBytes;
        bytes2 atcBytes;
        assembly {
            unpredictableNumberBytes := calldataload(add(emvFields.offset, 8))
            atcBytes := calldataload(add(emvFields.offset, 12))
        }

        uint32 unpredictableNumber = uint32(unpredictableNumberBytes);
        uint16 receivedATC = uint16(atcBytes);

        // Load storage once and cache the slot
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[msg.sender];
        uint16 currentATC = accountStorage.expectedATC;

        // Validate replay protection
        if (accountStorage.usedUnpredictableNumbers[unpredictableNumber]) {
            revert UnpredictableNumberAlreadyUsed(unpredictableNumberBytes);
        }

        if (receivedATC != currentATC) {
            revert InvalidATCSequence(currentATC, receivedATC);
        }

        // Update state after validation passes (batch storage writes)
        accountStorage.usedUnpredictableNumbers[unpredictableNumber] = true;
        accountStorage.expectedATC = currentATC + 1;

        // Emit combined event
        emit ReplayProtectionUpdated(msg.sender, unpredictableNumberBytes, currentATC + 1);
    }

    /**
     * @dev Assemble EMV dynamic data directly from EMV fields
     * @param emvFields The 63-byte EMV transaction fields
     * @return dynamicData The assembled dynamic data for signature verification
     */
    /**
     * @dev Verify EMV P-256 ECDSA signature
     * @param signature The ECDSA signature bytes (must be 64 bytes: r||s)
     * @param emvFields The packed EMV fields from calldata
     * @param account The account address to validate signature for
     * @return true if signature is valid, false otherwise
     */
    function _verifyEMVSignature(bytes calldata signature, bytes calldata emvFields, address account)
        internal
        view
        returns (bool)
    {
        // Validate signature length (must be 64 bytes: r||s)
        if (signature.length != 64) {
            revert InvalidSignatureLength(signature.length);
        }

        // Get registered P-256 public key
        bytes32 pubkeyX = emvValidatorStorage[account].pubkeyX;
        bytes32 pubkeyY = emvValidatorStorage[account].pubkeyY;

        if (pubkeyX == bytes32(0) || pubkeyY == bytes32(0)) {
            revert PublicKeyNotRegistered();
        }

        // Extract signature components: r (32 bytes) || s (32 bytes)
        uint256 r;
        uint256 s;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
        }

        // Build signed data from emvFields: UN(4) || Amount(6) || Currency(2) || ATC(2) = 14 bytes
        // emvFields layout: ARQC(8) + UN(4) + ATC(2) + Amount(6) + Currency(2) + ... = 63 bytes
        bytes memory signedData = new bytes(14);
        for (uint256 i = 0; i < 4; i++) signedData[i] = emvFields[8 + i]; // UN at offset 8
        for (uint256 i = 0; i < 6; i++) signedData[4 + i] = emvFields[12 + i]; // Amount at offset 12
        for (uint256 i = 0; i < 2; i++) signedData[10 + i] = emvFields[18 + i]; // Currency at offset 18
        for (uint256 i = 0; i < 2; i++) signedData[12 + i] = emvFields[20 + i]; // ATC at offset 20

        // Compute SHA-256 hash
        bytes32 messageHash = sha256(signedData);

        // Verify ECDSA signature using P256 library
        return P256.verifySignature(messageHash, r, s, uint256(pubkeyX), uint256(pubkeyY));
    }
}
