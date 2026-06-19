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

    uint256 private constant ATC_MAX = type(uint16).max;
    // The signed message is exactly what the JavaCard applet signs at GPO:
    // ATC(2) || PDOL(50) = 52 bytes (see emv-card-sim PaymentApplication.java
    // generateEcdsaAtGpo + profiles/default.yaml canonical PDOL). The contract
    // hashes the whole message with SHA-256 and P256-verifies; replay fields are
    // read from fixed offsets within it.
    uint256 private constant EMV_FIELDS_LENGTH = 52;

    // Offsets within the 52-byte ATC(2) || PDOL(50) slice-from-front message. The P-256 signature
    // covers all 52 bytes; this records which signed fields the contracts also *enforce*, and where.
    // 9F01 (acquirer) and 9F21 (time) are NOT signed: acquirer is an EMVSettlement.execute() argument
    // (the terminal can't put a real acquirer in the GPO), and time drifts between GPO sign and host
    // reconstruction. Their removal shifts the advisory tail (Country/Date/MCC) back by 6 bytes.
    //   off  len  tag    field                          enforced by
    //   0    2    9F36   ATC (card-prefixed)            EMVValidator (replay)
    //   2    4    9F37   Unpredictable Number           EMVValidator (replay)
    //   6    1    9C     Transaction Type               EMVValidator (_validateAuxiliaryFields)
    //   7    2    5F2A   Transaction Currency Code      EMVValidator (_validateCurrencyCode)
    //   9    6    9F02   Amount, Authorised             EMVSettlement (transfer amount)
    //   15   6    9F03   Amount, Other                  EMVValidator (_validateAuxiliaryFields)
    //   21   1    5F36   Transaction Currency Exponent  EMVValidator (_validateAuxiliaryFields)
    //   22   15   9F16   Merchant Identifier            EMVSettlement (routing)
    //   37   8    9F1C   Terminal Identification        EMVSettlement (routing)
    //   45   2    9F1A   Terminal Country Code          advisory (signed only)
    //   47   3    9A     Transaction Date               advisory (signed only)
    //   50   2    9F15   Merchant Category Code         advisory (signed only)
    uint256 private constant TXN_TYPE_OFFSET = 6;
    uint256 private constant AMOUNT_OTHER_OFFSET = 15;
    uint256 private constant CURRENCY_EXP_OFFSET = 21;
    uint8 private constant SUPPORTED_TXN_TYPE = 0x00; // Purchase / goods & services
    uint8 private constant SUPPORTED_CURRENCY_EXPONENT = 2; // minor units for USD (840) / USN (997)

    struct CardState {
        uint192 atc;
        bool initialized;
        bool frozen;
    }

    struct EMVValidatorStorage {
        bool initialized;
        mapping(uint32 => bool) usedUnpredictableNumbers; // Track used unpredictable numbers (4 bytes)
        mapping(bytes32 keyHash => CardState cardState) cards;
    }

    mapping(address => EMVValidatorStorage) public emvValidatorStorage;
    address public immutable target; // Expected target address for validation
    bytes4 public immutable selector; // Expected function selector for validation

    // ========== ERRORS ==========
    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidCurrencyCode(uint16 currency);
    error UnsupportedTransactionType(uint8 txnType);
    error UnexpectedAmountOther();
    error InvalidCurrencyExponent(uint8 exponent);
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
    error CardFrozen(bytes32 keyHash);

    event EMVValidatorInstalled(address indexed account, uint16 atc, bytes32 pubkeyX, bytes32 pubkeyY);
    event EMVCardFrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardUnfrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardRevoked(address indexed account, bytes32 indexed keyHash);

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
        accountStorage.cards[keyHash] = CardState({atc: uint192(atc), initialized: true, frozen: false});

        emit EMVValidatorInstalled(msg.sender, atc, pubkeyX, pubkeyY);
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        emvValidatorStorage[msg.sender].initialized = false;
        // Note: card state and used unpredictable numbers remain for security and cannot be enumerated.
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
     * @notice The userOpHash parameter is unused as we use SHA-256 hash of the packed EMV validator payload
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
        _validateAuxiliaryFields(emvFields);

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
     * @param hash The SHA-256 hash of the packed EMV validator payload to validate
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

        CardState memory card = emvValidatorStorage[sender].cards[keyHash];
        if (!card.initialized) {
            revert PublicKeyNotRegistered();
        }
        if (card.frozen) {
            revert CardFrozen(keyHash);
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

    function freezeCard(bytes32 keyHash) external {
        CardState storage card = emvValidatorStorage[msg.sender].cards[keyHash];
        if (!card.initialized) {
            revert PublicKeyNotRegistered();
        }

        card.frozen = true;
        emit EMVCardFrozen(msg.sender, keyHash);
    }

    function unfreezeCard(bytes32 keyHash) external {
        CardState storage card = emvValidatorStorage[msg.sender].cards[keyHash];
        if (!card.initialized) {
            revert PublicKeyNotRegistered();
        }

        card.frozen = false;
        emit EMVCardUnfrozen(msg.sender, keyHash);
    }

    function revokeCard(bytes32 keyHash) external {
        CardState storage card = emvValidatorStorage[msg.sender].cards[keyHash];
        if (!card.initialized) {
            revert PublicKeyNotRegistered();
        }

        delete emvValidatorStorage[msg.sender].cards[keyHash];
        emit EMVCardRevoked(msg.sender, keyHash);
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
        CardState memory card = emvValidatorStorage[account].cards[keyHash];
        initialized = card.initialized;
        expectedATC = card.atc;
    }

    function getExpectedATC(address account, bytes32 keyHash) external view returns (uint256 expectedATC) {
        CardState memory card = emvValidatorStorage[account].cards[keyHash];
        if (!card.initialized) {
            revert PublicKeyNotRegistered();
        }
        return card.atc;
    }

    function isPublicKeyRegistered(address account, bytes32 keyHash) external view returns (bool) {
        return _isPublicKeyRegistered(account, keyHash);
    }

    function isCardFrozen(address account, bytes32 keyHash) external view returns (bool) {
        return emvValidatorStorage[account].cards[keyHash].frozen;
    }

    function getCardState(address account, bytes32 keyHash)
        external
        view
        returns (uint256 expectedATC, bool initialized, bool frozen)
    {
        CardState memory card = emvValidatorStorage[account].cards[keyHash];
        return (card.atc, card.initialized, card.frozen);
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

        // Inner = execute(bytes): selector(4) + offset(32) + length(32) + emvData. Skip 68 to emvData.
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
        // Replay/currency offsets within the 61-byte ATC(2) || PDOL(59) signed message. The full
        // signed-field map — including the type / amount-other / currency-exponent fields enforced
        // in _validateAuxiliaryFields and the merchant/terminal/acquirer fields EMVSettlement reads —
        // is tabulated at the offset constants near EMV_FIELDS_LENGTH.
        // returns (unpredictableNumberOffset, atcOffset, amountOffset, currencyOffset) = (2, 0, 9, 7)
        if (emvFields.length == EMV_FIELDS_LENGTH) {
            return (2, 0, 9, 7);
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
     * Offset 0 of the 61-byte ATC(2)||PDOL(59) message. This is the pre-increment
     * ATC the applet signs at GPO (N); replay state tracks N then advances to N+1.
     */
    function _extractATC(bytes calldata emvFields) internal pure returns (bytes2 result) {
        (, uint256 atcOffset,,) = _emvFieldOffsets(emvFields);
        assembly {
            result := calldataload(add(emvFields.offset, atcOffset))
        }
    }

    /**
     * @dev Extract currency (2 bytes) from packed EMV fields - Assembly optimized
     * 5F2A at offset 16 of the 61-byte message (PDOL offset 14).
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
     * @dev Enforce the card-signed "validated" fields the settlement does not consume:
     * 9C transaction type, 9F03 amount-other, 5F36 currency exponent. The P-256 signature already
     * binds all 61 bytes; this records which signed values the contract accepts (pilot policy:
     * purchases only, no secondary amount, USD/USN minor units). Runs before signature verification,
     * alongside the currency check, so an unsupported field fails fast with a precise error.
     * @param emvFields The 61-byte EMV fields calldata
     */
    function _validateAuxiliaryFields(bytes calldata emvFields) internal pure {
        // 9C Transaction Type @ 6 — purchase (0x00) only.
        uint8 txnType = uint8(emvFields[TXN_TYPE_OFFSET]);
        if (txnType != SUPPORTED_TXN_TYPE) {
            revert UnsupportedTransactionType(txnType);
        }
        // 9F03 Amount, Other @ 15 (6 bytes) — no secondary amount / cashback.
        if (bytes6(emvFields[AMOUNT_OTHER_OFFSET:AMOUNT_OTHER_OFFSET + 6]) != bytes6(0)) {
            revert UnexpectedAmountOther();
        }
        // 5F36 Transaction Currency Exponent @ 21 — minor-unit exponent for the supported currencies.
        uint8 currencyExponent = uint8(emvFields[CURRENCY_EXP_OFFSET]);
        if (currencyExponent != SUPPORTED_CURRENCY_EXPONENT) {
            revert InvalidCurrencyExponent(currencyExponent);
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

        // Cache read-only card state in memory; only the replay bitmap needs storage.
        EMVValidatorStorage storage accountStorage = emvValidatorStorage[account];
        CardState memory card = accountStorage.cards[keyHash];

        if (!card.initialized) {
            revert PublicKeyNotRegistered();
        }
        if (card.frozen) {
            revert CardFrozen(keyHash);
        }

        currentATC = card.atc;
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
        CardState storage card = accountStorage.cards[keyHash];
        card.atc = uint192(nextATC);
        card.initialized = true;

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
        // emvFields IS the applet's signed message: ATC(2) || PDOL(59) = 61 bytes,
        // with no TLV framing. The applet signs SHA-256(message) with ECDSA-P256
        // (ALG_ECDSA_SHA_256), emitting raw r||s. Hash the whole message and verify.
        bytes32 messageHash = sha256(emvFields);

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
        return emvValidatorStorage[account].cards[keyHash].initialized;
    }
}
