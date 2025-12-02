// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {RsaVerifyOptimized} from "lib/SolRsaVerify/src/RsaVerifyOptimized.sol";
import {IValidator, IExecutor, IHook} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "src/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "src/types/Constants.sol";
import {ExecLib} from "src/utils/ExecLib.sol";
import {ExecMode, CallType} from "src/types/Types.sol";

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
    bytes signature; // 9F4B - RSA signature (256 bytes for RSA-2048)
    // Note: Public key (exponent and modulus) are now registered during onInstall, not included in signature
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
        bytes exponent; // RSA public key exponent (3 bytes)
        bytes modulus; // RSA public key modulus (256 bytes for RSA-2048)
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
    error InvalidRSAKeySize(uint256 actualSize);
    error PublicKeyNotRegistered();
    error InvalidPublicKeySize();
    error InvalidSender();

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
     * @dev Install the module with ATC configuration and public key registration
     * @param _data Encoded configuration: abi.encode(atc, exponent, modulus)
     *        - atc: uint16 - Initial ATC value
     *        - exponent: bytes - RSA public key exponent (3 bytes)
     *        - modulus: bytes - RSA public key modulus (256 bytes for RSA-2048)
     */
    function onInstall(bytes calldata _data) external payable override {
        if (_data.length == 0) {
            revert InvalidConfig();
        }

        (uint16 atc, bytes memory exponent, bytes memory modulus) = abi.decode(_data, (uint16, bytes, bytes));
        
        // Validate RSA-2048 key size
        if (exponent.length != 3) {
            revert InvalidPublicKeySize();
        }
        if (modulus.length != 256) {
            revert InvalidPublicKeySize();
        }

        emvValidatorStorage[msg.sender].expectedATC = atc;
        emvValidatorStorage[msg.sender].exponent = exponent;
        emvValidatorStorage[msg.sender].modulus = modulus;
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        
        // Reset ATC counter for this account
        emvValidatorStorage[msg.sender].expectedATC = 0;
        
        // Clear registered public key
        delete emvValidatorStorage[msg.sender].exponent;
        delete emvValidatorStorage[msg.sender].modulus;
        
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
        // Module is considered initialized if the account has been configured with a public key
        return emvValidatorStorage[smartAccount].modulus.length == 256;
    }

    // ========== VALIDATOR FUNCTIONS ==========

    /**
     * @dev Validate EMV CDA signature for ERC-4337 user operation
     * @param userOp The user operation with EMV fields in callData and RSA signature in signature field
     * @return SIG_VALIDATION_SUCCESS_UINT if valid, SIG_VALIDATION_FAILED_UINT otherwise
     * @notice The userOpHash parameter is unused as we use SHA-256 hash of the EMV dynamic data
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 /* userOpHash */)
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

        // Assemble dynamic data and compute its SHA-256 hash
        bytes memory dynamicData = _assembleDynamicData(emvFields);
        bytes32 dataHash = sha256(dynamicData);

        // Validate replay protection and update state together (both work with same data)
        _validateReplayProtectionAndUpdateState(emvFields);
        // Verify RSA signature (userOp.signature should be 256 bytes)
        return (_verifyEMVSignature(userOp.signature, dataHash, msg.sender)) ? SIG_VALIDATION_SUCCESS_UINT : SIG_VALIDATION_FAILED_UINT;
    }

    /**
     * @dev Validate EMV signature for ERC-1271 (view-only, no state changes)
     * @param sender The account address to validate signature for
     * @param hash The SHA-256 hash of the EMV dynamic data to validate
     * @param sig The RSA signature bytes (256 bytes for RSA-2048)
     * @return ERC1271_MAGICVALUE if valid, ERC1271_INVALID otherwise
     */
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        if(sender == address(0)) {
            revert InvalidSender();
        }

        if(!_isInitialized(sender)) {
            revert PublicKeyNotRegistered();
        }

        return (_verifyEMVSignature(sig, hash, sender)) ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function verifyEMVSignature(bytes calldata signature, bytes32 hash, address account) external view returns (bool) {
        return _verifyEMVSignature(signature, hash, account);
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
     * @return exponent The RSA public key exponent
     * @return modulus The RSA public key modulus
     */
    function getRegisteredPublicKey(address account) external view returns (bytes memory exponent, bytes memory modulus) {
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[account];
        return (accountStorage.exponent, accountStorage.modulus);
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
        // Currency is stored as 2 bytes big-endian
        bytes2 currencyBytes = _extractCurrency(emvFields);
        uint16 currency = uint16(currencyBytes);
        if (currency != 840 && currency != 997) {
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
    function _assembleDynamicData(bytes calldata emvFields) internal pure returns (bytes memory dynamicData) {
        // EMV fields are packed: ARQC(8) + UnpredictableNumber(4) + ATC(2) + Amount(6) + Currency(2) + Date(3) + TxnType(1) + TVR(5) + CVMResults(3) + TerminalId(8) + MerchantId(15) + AcquirerId(6) = 63 bytes
        require(emvFields.length == 63, "Invalid EMV fields length");

        // Assemble according to EMV Book 2, Annex C.5 (Signed Data Format 3)
        return abi.encodePacked(
            bytes1(0x6A), // Header
            bytes1(0x03), // Format (Signed Data Format 3)
            emvFields, // All 12 fields as one slice (63 bytes)
            bytes1(0xBC) // Trailer
        );
    }

    /**
     * @dev Verify EMV RSA signature using PKCS#1 v1.5 with SHA-256
     * @param signature The RSA signature bytes (must be 256 bytes for RSA-2048)
     * @param hash The SHA-256 hash of the EMV dynamic data
     * @param account The account address to validate signature for
     * @return true if signature is valid, false otherwise
     */
    function _verifyEMVSignature(bytes calldata signature, bytes32 hash, address account) internal view returns (bool) {
        // Use registered public key
        bytes memory exponent = emvValidatorStorage[account].exponent;
        bytes memory modulus = emvValidatorStorage[account].modulus;
        // Validate public key size
        if (exponent.length != 3 || modulus.length != 256) {
            revert InvalidPublicKeySize();
        }
                // Validate signature length (must be 256 bytes for RSA-2048)
        if (signature.length != 256) {
            revert InvalidRSAKeySize(signature.length);
        }

        // Verify RSA signature using PKCS#1 v1.5 with pre-computed SHA-256 hash
        return RsaVerifyOptimized.pkcs1Sha256(hash, signature, exponent, modulus);
    }
}
