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
    bytes arqc;                 // 9F26 - Application Cryptogram (8 bytes)
    bytes unpredictableNumber;  // 9F37 - 4 bytes from terminal
    bytes atc;                  // 9F36 - 2-byte Application Transaction Counter
    bytes amount;               // 9F02 - 6-byte BCD amount
    bytes currency;             // 5F2A - 2-byte ISO currency code (big-endian)
    bytes date;                 // 9A - YYMMDD (3 bytes BCD)
    bytes txnType;              // 9C - 1 byte transaction type
    bytes tvr;                  // 95 - 5 bytes Terminal Verification Results
    bytes cvmResults;           // 9F34 - 3 bytes CVM Results
    bytes terminalId;           // 9F1C - Terminal ID (8 bytes)
    bytes merchantId;           // 9F16 - Merchant ID (15 bytes)
    bytes acquirerId;           // 9F01 - Acquirer ID (6 bytes)
    bytes signature;            // 9F4B - RSA signature
    bytes exponent;             // RSA public key exponent
    bytes modulus;              // RSA public key modulus
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
        mapping(uint32 => bool) usedUnpredictableNumbers;  // Track used unpredictable numbers (4 bytes)
        uint16 expectedATC;  // Next expected ATC value for this kernel instance
    }
    
    mapping(address => EMVValidatorStorage) public emvValidatorStorage;
    address public immutable target;               // Expected target address for validation
    bytes4 public immutable selector;              // Expected function selector for validation

    // ========== ERRORS ==========
    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidCurrencyCode(uint16 currency);
    error InvalidConfig();
    error InvalidTarget(address expected, address actual);
    error InvalidFunctionSelector(bytes4 expected, bytes4 actual);
    error InvalidRSAKeySize(uint256 actualSize);

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
     * @dev Install the module with ATC configuration
     * @param _data Encoded configuration: abi.encode(atc)
     */
    function onInstall(bytes calldata _data) external payable override {
        if (_data.length == 0) {
            revert InvalidConfig();
        }
        
        uint16 atc = abi.decode(_data, (uint16));
        emvValidatorStorage[msg.sender].expectedATC = atc;
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        // Reset ATC counter for this account
        emvValidatorStorage[msg.sender].expectedATC = 0;
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
        // Module is considered initialized if the account has been configured
        // Check if ATC has been set (non-zero) or if there are used unpredictable numbers
        return emvValidatorStorage[smartAccount].expectedATC > 0;
    }

    // ========== VALIDATOR FUNCTIONS ==========

    /**
     * @dev Validate EMV CDA signature for ERC-4337 user operation
     * @param userOp The user operation containing EMV transaction data in signature field
     * @param userOpHash The hash of the user operation
     * @return SIG_VALIDATION_SUCCESS_UINT if valid, SIG_VALIDATION_FAILED_UINT otherwise
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        // Validate that this EMV signature is being used for the correct target and function
        _validateTargetAndSelector(userOp.callData);
        
        // Gas-optimized validation using calldata extraction instead of full memory expansion
        // Validate currency code
        _validateCurrencyCode(userOp.signature);
        
        // Verify RSA signature using PKCS#1 v1.5 with SHA-256
        bool isValid = _verifyEMVSignature(userOp.signature);
        
        if (isValid) {
            // Validate replay protection and update state together (both work with same data)
            _validateReplayProtectionAndUpdateState(userOp.signature);
            return SIG_VALIDATION_SUCCESS_UINT;
        } else {
            return SIG_VALIDATION_FAILED_UINT;
        }
    }

    /**
     * @dev Validate EMV signature for ERC-1271 (view-only, no state changes)
     * @param hash The hash to validate
     * @param sig The signature data containing EMV transaction data
     * @return ERC1271_MAGICVALUE if valid, ERC1271_INVALID otherwise
     */
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        try this.verifyEMVSignature(sig) returns (bool success) {
            if (success) {
                return ERC1271_MAGICVALUE;
            }
        } catch {
            // Validation failed
        }
        
        return ERC1271_INVALID;
    }

    function verifyEMVSignature(bytes calldata signature) external view returns (bool) {
        return _verifyEMVSignature(signature);
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
     * @dev Extract unpredictable number (4 bytes) from packed signature - Assembly optimized
     */
    function _extractUnpredictableNumber(bytes calldata signature) internal pure returns (bytes4 result) {
        assembly {
            result := calldataload(add(signature.offset, 8))
        }
    }
    
    /**
     * @dev Extract ATC (2 bytes) from packed signature - Assembly optimized
     */
    function _extractATC(bytes calldata signature) internal pure returns (bytes2 result) {
        assembly {
            result := calldataload(add(signature.offset, 12))
        }
    }
    
    /**
     * @dev Extract currency (2 bytes) from packed signature - Assembly optimized
     */
    function _extractCurrency(bytes calldata signature) internal pure returns (bytes2 result) {
        assembly {
            result := calldataload(add(signature.offset, 20))
        }
    }
    

    /**
     * @dev Validate currency code (must be 840 USD or 997 USN)
     * @param signature The signature calldata to extract currency from
     */
    function _validateCurrencyCode(bytes calldata signature) internal pure {
        // Currency is stored as 2 bytes big-endian
        bytes2 currencyBytes = _extractCurrency(signature);
        uint16 currency = uint16(currencyBytes);
        if (currency != 840 && currency != 997) {
            revert InvalidCurrencyCode(currency);
        }
    }
    
    /**
     * @dev Validate replay protection and update transaction state in one operation - Storage optimized
     * @param signature The signature calldata to extract data from
     */
    function _validateReplayProtectionAndUpdateState(bytes calldata signature) internal {
        // Extract values using assembly for efficiency
        bytes4 unpredictableNumberBytes;
        bytes2 atcBytes;
        assembly {
            unpredictableNumberBytes := calldataload(add(signature.offset, 8))
            atcBytes := calldataload(add(signature.offset, 12))
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
     * @dev Assemble EMV dynamic data directly from calldata
     * @param signature The signature calldata to extract fields from
     * @return dynamicData The assembled dynamic data for signature verification
     */
    function _assembleDynamicData(bytes calldata signature) internal pure returns (bytes memory dynamicData) {
        // Extract all 12 EMV fields as one continuous slice from packed data
        // Fields are now packed: ARQC(8) + UnpredictableNumber(4) + ATC(2) + Amount(6) + Currency(2) + Date(3) + TxnType(1) + TVR(5) + CVMResults(3) + TerminalId(8) + MerchantId(15) + AcquirerId(6) = 63 bytes
        bytes calldata allFieldBytes = signature[0:63]; // Extract first 63 bytes which contain all EMV fields
        
        // Assemble according to EMV Book 2, Annex C.5 (Signed Data Format 3)
        return abi.encodePacked(
            bytes1(0x6A),          // Header
            bytes1(0x03),          // Format (Signed Data Format 3)
            allFieldBytes,         // All 12 fields as one slice (63 bytes)
            bytes1(0xBC)           // Trailer
        );
    }

    /**
     * @dev Verify EMV RSA signature using PKCS#1 v1.5 with SHA-256
     * @param signature The signature calldata containing all EMV transaction data
     * @return true if signature is valid, false otherwise
     */
    function _verifyEMVSignature(bytes calldata signature) internal view returns (bool) {
        // Assemble dynamic data directly from calldata
        bytes memory dynamicData = _assembleDynamicData(signature);
        
        // Extract signature and key components from packed data
        uint256 emvFieldsLength = 63; // All EMV fields
        
        // Calculate modulus length first to determine signature length
        // Total length - EMV fields - exponent(3) = signature + modulus
        uint256 sigAndModulusLength = signature.length - emvFieldsLength - 3;
        
        // For RSA-2048: signature(256) + modulus(256) = 512 bytes
        // For RSA-1024: signature(128) + modulus(128) = 256 bytes  
        uint256 modulusLength;
        uint256 sigLength;
        
        if (sigAndModulusLength == 512) {
            // RSA-2048
            sigLength = 256;
            modulusLength = 256;
        } else if (sigAndModulusLength == 256) {
            // RSA-1024 - block this
            revert InvalidRSAKeySize(128);
        } else {
            // Invalid signature format
            revert InvalidRSAKeySize(sigAndModulusLength / 2);
        }
        
        bytes calldata sigBytes = signature[emvFieldsLength:emvFieldsLength + sigLength];
        
        // Exponent starts after signature (always 3 bytes)
        uint256 expStart = emvFieldsLength + sigLength;
        bytes calldata exponent = signature[expStart:expStart + 3];
        
        // Modulus starts after exponent
        uint256 modStart = expStart + 3;
        bytes calldata modulus = signature[modStart:modStart + modulusLength];
        
        // Verify RSA signature using PKCS#1 v1.5 with SHA-256
        return RsaVerifyOptimized.pkcs1Sha256Raw(
            dynamicData,
            sigBytes,
            exponent,
            modulus
        );
    }


}
