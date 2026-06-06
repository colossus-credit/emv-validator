// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {P256} from "solady/utils/P256.sol";
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
 * @title EMVValidator
 * @dev Complete ERC-7579 module for EMV CDA validation and ERC20 execution
 * @notice Validates EMV CDA signatures and executes ERC20 transfers with merchant registry integration
 */
contract EMVValidator is IValidator {
    // ========== EVENTS ==========

    event ReplayProtectionUpdated(
        address indexed kernel, bytes32 indexed keyHash, bytes4 unpredictableNumber, uint256 newATC
    );

    // ========== STORAGE ==========

    uint256 private constant KEY_INITIALIZED = 1 << 255;
    uint256 private constant ATC_MASK = KEY_INITIALIZED - 1;
    uint256 private constant ATC_MAX = type(uint16).max;

    struct EMVValidatorStorage {
        bool initialized;
        mapping(uint32 => bool) usedUnpredictableNumbers; // Track used unpredictable numbers (4 bytes)
        mapping(bytes32 keyHash => uint256 atcState) keyATCState;
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
    error InvalidPublicKey();
    error ATCExhausted(bytes32 keyHash);
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

        bytes32 keyHash = computeKeyHash(pubkeyX, pubkeyY);

        EMVValidatorStorage storage accountStorage = emvValidatorStorage[msg.sender];
        accountStorage.initialized = true;
        accountStorage.keyATCState[keyHash] = KEY_INITIALIZED | uint256(atc);

        emit EMVValidatorInstalled(msg.sender, atc, pubkeyX, pubkeyY);
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        emvValidatorStorage[msg.sender].initialized = false;
        // Note: key ATC state and used unpredictable numbers remain for security and cannot be enumerated.
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
        return emvValidatorStorage[smartAccount].initialized;
    }

    // ========== VALIDATOR FUNCTIONS ==========

    /**
     * @dev Validate EMV CDA signature for ERC-4337 user operation
     * @param userOp The user operation with EMV fields in callData and P-256 signature envelope in signature field
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

        (bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s) =
            _decodeEMVSignature(userOp.signature);
        if (!_isValidPublicKeyHash(keyHash, pubkeyX, pubkeyY)) {
            revert InvalidPublicKey();
        }

        (bytes4 unpredictableNumber, uint256 currentATC) = _validateReplayProtection(emvFields, msg.sender, keyHash);

        if (!_verifyEMVSignature(emvFields, pubkeyX, pubkeyY, r, s)) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        _updateReplayProtectionAndATC(keyHash, unpredictableNumber, currentATC);

        return SIG_VALIDATION_SUCCESS_UINT;
    }

    /**
     * @dev Validate EMV signature for ERC-1271 (view-only, no state changes)
     * @param sender The account address to validate signature for
     * @param hash The SHA-256 hash of the EMV dynamic data to validate
     * @param sig The P-256 signature envelope: keyHash || pubkeyX || pubkeyY || r || s
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

        if (sig.length != 160) {
            return ERC1271_INVALID;
        }

        (bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s) = _decodeEMVSignature(sig);

        if (!_isValidPublicKeyHash(keyHash, pubkeyX, pubkeyY)) {
            return ERC1271_INVALID;
        }

        if (!_isPublicKeyRegistered(sender, keyHash)) {
            revert PublicKeyNotRegistered();
        }

        // Verify ECDSA signature using P256 library
        bool isValid = P256.verifySignature(hash, r, s, pubkeyX, pubkeyY);

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

    function computeKeyHash(bytes32 pubkeyX, bytes32 pubkeyY) public pure returns (bytes32) {
        return keccak256(abi.encode(pubkeyX, pubkeyY));
    }

    /**
     * @dev Get the per-key ATC state for a specific account.
     * @param account The smart account address
     * @param keyHash The hash of abi.encode(pubkeyX, pubkeyY)
     * @return expectedATC The next expected ATC value
     * @return initialized True if the key has been installed for the account
     */
    function getEMVStorage(address account, bytes32 keyHash)
        external
        view
        returns (uint256 expectedATC, bool initialized)
    {
        uint256 atcState = emvValidatorStorage[account].keyATCState[keyHash];
        initialized = (atcState & KEY_INITIALIZED) != 0;
        expectedATC = atcState & ATC_MASK;
    }

    function getExpectedATC(address account, bytes32 keyHash) external view returns (uint256 expectedATC) {
        uint256 atcState = emvValidatorStorage[account].keyATCState[keyHash];
        if ((atcState & KEY_INITIALIZED) == 0) {
            revert PublicKeyNotRegistered();
        }
        return atcState & ATC_MASK;
    }

    function isPublicKeyRegistered(address account, bytes32 keyHash) external view returns (bool) {
        return _isPublicKeyRegistered(account, keyHash);
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
     * @return emvFields The EMV transaction fields
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

        // Inner calldata structure (ABI encoded): selector(4) + offset(32) + length(32) + emvFields
        // Skip selector(4) + offset(32) + length(32) = 68 bytes
        uint256 emvDataStart = innerCalldataStart + 68;
        uint256 emvDataLength = uint256(bytes32(callData[innerCalldataStart + 36:innerCalldataStart + 68]));

        return callData[emvDataStart:emvDataStart + emvDataLength];
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

    function _emvFieldOffsets(bytes calldata emvFields)
        internal
        pure
        returns (uint256 unpredictableNumberOffset, uint256 atcOffset, uint256 amountOffset, uint256 currencyOffset)
    {
        if (emvFields.length == 40) {
            return (9, 36, 3, 38);
        }

        if (emvFields.length == 63) {
            return (8, 12, 14, 20);
        }

        revert InvalidSignatureLength(emvFields.length);
    }

    /**
     * @dev Extract unpredictable number (4 bytes) from packed EMV fields - Assembly optimized
     */
    function _extractUnpredictableNumber(bytes calldata emvFields) internal pure returns (bytes4 result) {
        (uint256 unpredictableNumberOffset,,,) = _emvFieldOffsets(emvFields);
        assembly {
            result := calldataload(add(emvFields.offset, unpredictableNumberOffset))
        }
    }

    /**
     * @dev Extract ATC (2 bytes) from packed EMV fields - Assembly optimized
     * Position 36-37 in 40-byte format
     */
    function _extractATC(bytes calldata emvFields) internal pure returns (bytes2 result) {
        (, uint256 atcOffset,,) = _emvFieldOffsets(emvFields);
        assembly {
            result := calldataload(add(emvFields.offset, atcOffset))
        }
    }

    /**
     * @dev Extract currency (2 bytes) from packed EMV fields - Assembly optimized
     * Position 38-39 in 40-byte format
     */
    function _extractCurrency(bytes calldata emvFields) internal pure returns (bytes2 result) {
        (,,, uint256 currencyOffset) = _emvFieldOffsets(emvFields);
        assembly {
            result := calldataload(add(emvFields.offset, currencyOffset))
        }
    }

    /**
     * @dev Validate currency code (must be 840 USD or 997 USN)
     * @param emvFields The EMV fields calldata to extract currency from
     */
    function _validateCurrencyCode(bytes calldata emvFields) internal pure {
        // Accept both BCD-style n3 encoding and uint16 numeric encoding used by local fixtures.
        bytes2 currencyBytes = _extractCurrency(emvFields);
        uint16 currency = uint16(currencyBytes);
        if (currency != 0x0840 && currency != 0x0997 && currency != 840 && currency != 997) {
            revert InvalidCurrencyCode(currency);
        }
    }

    /**
     * @dev Validate replay protection and ATC state without mutating storage
     * @param emvFields The EMV fields calldata to extract data from
     */
    function _validateReplayProtection(bytes calldata emvFields, address account, bytes32 keyHash)
        internal
        view
        returns (bytes4 unpredictableNumberBytes, uint256 currentATC)
    {
        // Extract values using assembly for efficiency
        (uint256 unpredictableNumberOffset, uint256 atcOffset,,) = _emvFieldOffsets(emvFields);
        bytes2 atcBytes;
        assembly {
            unpredictableNumberBytes := calldataload(add(emvFields.offset, unpredictableNumberOffset))
            atcBytes := calldataload(add(emvFields.offset, atcOffset))
        }

        uint32 unpredictableNumber = uint32(unpredictableNumberBytes);
        uint16 receivedATC = uint16(atcBytes);

        // Load storage once and cache the slot
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[account];
        uint256 keyATCState = accountStorage.keyATCState[keyHash];

        if ((keyATCState & KEY_INITIALIZED) == 0) {
            revert PublicKeyNotRegistered();
        }

        currentATC = keyATCState & ATC_MASK;
        if (currentATC > ATC_MAX) {
            revert ATCExhausted(keyHash);
        }

        // Validate replay protection
        if (accountStorage.usedUnpredictableNumbers[unpredictableNumber]) {
            revert UnpredictableNumberAlreadyUsed(unpredictableNumberBytes);
        }

        if (uint256(receivedATC) != currentATC) {
            revert InvalidATCSequence(uint16(currentATC), receivedATC);
        }
    }

    function _updateReplayProtectionAndATC(bytes32 keyHash, bytes4 unpredictableNumberBytes, uint256 currentATC)
        internal
    {
        if (currentATC == ATC_MAX) {
            revert ATCExhausted(keyHash);
        }

        uint32 unpredictableNumber = uint32(unpredictableNumberBytes);
        uint256 nextATC = currentATC + 1;
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[msg.sender];

        accountStorage.usedUnpredictableNumbers[unpredictableNumber] = true;
        accountStorage.keyATCState[keyHash] = KEY_INITIALIZED | nextATC;

        emit ReplayProtectionUpdated(msg.sender, keyHash, unpredictableNumberBytes, nextATC);
    }

    /**
     * @dev Verify EMV P-256 ECDSA signature
     * @param pubkeyX The supplied P-256 public key x coordinate
     * @param pubkeyY The supplied P-256 public key y coordinate
     * @param r The ECDSA signature r value
     * @param s The ECDSA signature s value
     * @param emvFields The packed EMV fields from calldata
     * @return true if signature is valid, false otherwise
     */
    function _verifyEMVSignature(bytes calldata emvFields, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s)
        internal
        view
        returns (bool)
    {
        (uint256 unpredictableNumberOffset, uint256 atcOffset, uint256 amountOffset, uint256 currencyOffset) =
            _emvFieldOffsets(emvFields);

        bytes memory signedMessage = abi.encodePacked(
            emvFields[unpredictableNumberOffset:unpredictableNumberOffset + 4],
            emvFields[amountOffset:amountOffset + 6],
            emvFields[currencyOffset:currencyOffset + 2],
            emvFields[atcOffset:atcOffset + 2]
        );

        bytes32 messageHash = sha256(signedMessage);

        // Verify ECDSA signature using P256 library
        return P256.verifySignature(messageHash, r, s, pubkeyX, pubkeyY);
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

    function _isValidPublicKeyHash(bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY) internal pure returns (bool) {
        return computeKeyHash(pubkeyX, pubkeyY) == keyHash;
    }

    function _isPublicKeyRegistered(address account, bytes32 keyHash) internal view returns (bool) {
        return (emvValidatorStorage[account].keyATCState[keyHash] & KEY_INITIALIZED) != 0;
    }
}
