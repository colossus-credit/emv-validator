// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {P256} from "solady/utils/P256.sol";
import {IValidator, IExecutor, IHook, ISigner} from "kernel/src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_SIGNER,
    MODULE_TYPE_HOOK,
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
 * @dev ERC-7579 signer/validator module for EMV CDA validation.
 * @notice Validates card signatures and replay state. Transaction policy checks live in policy modules.
 */
contract EMVSigner is IValidator, ISigner {
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

    // Offsets within the 52-byte ATC(2) || PDOL(50) slice-from-front message.
    //   off  len  tag    field                          enforced by
    //   0    2    9F36   ATC (card-prefixed)            EMVSigner (replay)
    //   2    4    9F37   Unpredictable Number           EMVSigner (replay)
    //   6    1    9C     Transaction Type               EMVLimitPolicy
    //   7    2    5F2A   Transaction Currency Code      EMVLimitPolicy
    //   9    6    9F02   Amount, Authorised             EMVLimitPolicy / EMVSettlement
    //   15   6    9F03   Amount, Other                  EMVLimitPolicy
    //   21   1    5F36   Transaction Currency Exponent  EMVLimitPolicy
    //   22   15   9F16   Merchant Identifier            EMVSettlement (routing)
    //   37   8    9F1C   Terminal Identification        advisory (signed only)
    //   45   2    9F1A   Terminal Country Code          advisory (signed only)
    //   47   3    9A     Transaction Date               advisory (signed only)
    //   50   2    9F15   Merchant Category Code         advisory (signed only)

    struct CardData {
        // Stored one-based so zero can mean "not registered".
        uint152 atc;
        bool frozen;
        mapping(uint32 unpredictableNumber => bool used) usedUnpredictableNumbers;
    }

    mapping(address account => mapping(bytes32 keyHash => CardData card)) private cards;

    // ========== ERRORS ==========
    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidConfig();
    error InvalidSignatureLength(uint256 actualSize);
    error PublicKeyNotRegistered();
    error InvalidPublicKeySize();
    error InvalidPublicKey();
    error ATCExhausted(bytes32 keyHash);
    error InvalidSender();
    error InvalidSignature();
    error CardFrozen(bytes32 keyHash);

    event EMVSignerInstalled(address indexed account, uint16 atc, bytes32 pubkeyX, bytes32 pubkeyY);
    event EMVCardFrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardUnfrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardRevoked(address indexed account, bytes32 indexed keyHash);

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

        bytes calldata cardData = _cardInstallData(_data);
        uint16 atc;
        bytes32 pubkeyX;
        bytes32 pubkeyY;
        (atc, pubkeyX, pubkeyY) = abi.decode(cardData, (uint16, bytes32, bytes32));

        // Validate P-256 public key (not zero)
        if (pubkeyX == bytes32(0) || pubkeyY == bytes32(0)) {
            revert InvalidPublicKeySize();
        }

        bytes32 keyHash = computeKeyHash(pubkeyX, pubkeyY);

        CardData storage card = cards[msg.sender][keyHash];
        card.atc = uint152(uint256(atc) + 1);
        card.frozen = false;

        emit EMVSignerInstalled(msg.sender, atc, pubkeyX, pubkeyY);
    }

    /**
     * @dev Uninstall the module
     */
    function onUninstall(bytes calldata) external payable override {
        // Card state and used unpredictable numbers remain for security and cannot be enumerated.
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_SIGNER;
    }

    /**
     * @dev Satisfy the ERC-7579 module interface without account-level storage.
     */
    function isInitialized(address) external pure override returns (bool) {
        return true;
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
        return _validateEMVUserOp(userOp.callData, userOp.signature, msg.sender);
    }

    function checkUserOpSignature(bytes32, PackedUserOperation calldata userOp, bytes32)
        external
        payable
        override
        returns (uint256)
    {
        return _validateEMVUserOp(userOp.callData, userOp.signature, msg.sender);
    }

    function _validateEMVUserOp(bytes calldata callData, bytes calldata signature, address account)
        internal
        returns (uint256)
    {
        // Note: callData should contain the kernel.execute() call with EMV fields.
        bytes calldata emvFields = EMVCallData.extractEMVFields(callData);

        (bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s) = _decodeEMVSignature(signature);
        if (!_isValidPublicKeyHash(keyHash, pubkeyX, pubkeyY)) {
            revert InvalidPublicKey();
        }

        (bytes4 unpredictableNumber, uint256 currentATC) = _validateCardData(emvFields, account, keyHash);

        if (!_verifyEMVSignature(emvFields, pubkeyX, pubkeyY, r, s)) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        _updateCardData(keyHash, unpredictableNumber, currentATC);

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
        return _checkSignature(sender, hash, sig);
    }

    function checkSignature(bytes32, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        return _checkSignature(sender, hash, sig);
    }

    function _checkSignature(address sender, bytes32 hash, bytes calldata sig) internal view returns (bytes4) {
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

        CardData storage card = cards[sender][keyHash];
        if (!_isCardRegistered(card)) {
            revert PublicKeyNotRegistered();
        }

        if (card.frozen) {
            revert CardFrozen(keyHash);
        }

        // Verify ECDSA signature using P256 library
        bool isValid = P256.verifySignature(hash, r, s, pubkeyX, pubkeyY);

        return isValid ? ERC1271_MAGICVALUE : ERC1271_INVALID;
    }

    function computeKeyHash(bytes32 pubkeyX, bytes32 pubkeyY) public pure returns (bytes32) {
        return keccak256(abi.encode(pubkeyX, pubkeyY));
    }

    function freezeCard(bytes32 keyHash) external {
        if (!_isCardRegistered(msg.sender, keyHash)) {
            revert PublicKeyNotRegistered();
        }

        cards[msg.sender][keyHash].frozen = true;
        emit EMVCardFrozen(msg.sender, keyHash);
    }

    function unfreezeCard(bytes32 keyHash) external {
        if (!_isCardRegistered(msg.sender, keyHash)) {
            revert PublicKeyNotRegistered();
        }

        cards[msg.sender][keyHash].frozen = false;
        emit EMVCardUnfrozen(msg.sender, keyHash);
    }

    function revokeCard(bytes32 keyHash) external {
        if (!_isCardRegistered(msg.sender, keyHash)) {
            revert PublicKeyNotRegistered();
        }

        delete cards[msg.sender][keyHash];
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
        uint256 storedATC = cards[account][keyHash].atc;
        initialized = storedATC != 0;
        if (initialized) {
            expectedATC = storedATC - 1;
        }
    }

    function getExpectedATC(address account, bytes32 keyHash) external view returns (uint256 expectedATC) {
        uint256 storedATC = cards[account][keyHash].atc;
        if (storedATC == 0) {
            revert PublicKeyNotRegistered();
        }

        return storedATC - 1;
    }

    function isPublicKeyRegistered(address account, bytes32 keyHash) external view returns (bool) {
        return _isPublicKeyRegistered(account, keyHash);
    }

    function isCardFrozen(address account, bytes32 keyHash) external view returns (bool) {
        return cards[account][keyHash].frozen;
    }

    function getCardState(address account, bytes32 keyHash)
        external
        view
        returns (uint256 expectedATC, bool initialized, bool frozen)
    {
        CardData storage card = cards[account][keyHash];
        uint256 storedATC = card.atc;
        initialized = storedATC != 0;
        if (initialized) {
            expectedATC = storedATC - 1;
        }
        frozen = card.frozen;
    }

    /**
     * @dev Check if an unpredictable number has been used for a specific account
     * @param account The smart account address
     * @param unpredictableNumber The unpredictable number to check
     * @return used True if the unpredictable number has been used
     */
    function isUnpredictableNumberUsed(address account, bytes32 keyHash, bytes4 unpredictableNumber)
        external
        view
        returns (bool used)
    {
        return cards[account][keyHash].usedUnpredictableNumbers[uint32(unpredictableNumber)];
    }

    // ========== INTERNAL VALIDATION FUNCTIONS ==========

    // ========== GAS-OPTIMIZED CALLDATA EXTRACTION ==========

    function _emvFieldOffsets(bytes calldata emvFields)
        internal
        pure
        returns (uint256 unpredictableNumberOffset, uint256 atcOffset)
    {
        // Replay offsets within the 52-byte ATC(2) || PDOL(50) signed message.
        if (emvFields.length == EMV_FIELDS_LENGTH) {
            return (2, 0);
        }

        revert InvalidSignatureLength(emvFields.length);
    }

    /**
     * @dev Validate replay protection and ATC without mutating storage
     * @param emvFields The EMV fields calldata to extract data from
     */
    function _validateCardData(bytes calldata emvFields, address account, bytes32 keyHash)
        internal
        view
        returns (bytes4 unpredictableNumberBytes, uint256 currentATC)
    {
        // Extract values using assembly for efficiency
        (uint256 unpredictableNumberOffset, uint256 atcOffset) = _emvFieldOffsets(emvFields);
        bytes2 atcBytes;
        assembly {
            unpredictableNumberBytes := calldataload(add(emvFields.offset, unpredictableNumberOffset))
            atcBytes := calldataload(add(emvFields.offset, atcOffset))
        }

        uint32 unpredictableNumber = uint32(unpredictableNumberBytes);
        uint16 receivedATC = uint16(atcBytes);
        CardData storage card = cards[account][keyHash];

        uint256 storedATC = card.atc;
        if (storedATC == 0) {
            revert PublicKeyNotRegistered();
        }

        if (card.frozen) {
            revert CardFrozen(keyHash);
        }

        currentATC = storedATC - 1;
        if (currentATC > ATC_MAX) {
            revert ATCExhausted(keyHash);
        }

        // Validate replay protection
        if (card.usedUnpredictableNumbers[unpredictableNumber]) {
            revert UnpredictableNumberAlreadyUsed(unpredictableNumberBytes);
        }

        // Strictly-increasing (not equal): received >= expected; advancing past it below still blocks replay.
        if (uint256(receivedATC) < currentATC) {
            revert InvalidATCSequence(uint16(currentATC), receivedATC);
        }

        currentATC = receivedATC;
    }

    function _updateCardData(bytes32 keyHash, bytes4 unpredictableNumberBytes, uint256 currentATC) internal {
        if (currentATC == ATC_MAX) {
            revert ATCExhausted(keyHash);
        }

        uint32 unpredictableNumber = uint32(unpredictableNumberBytes);
        uint256 nextATC = currentATC + 1;
        CardData storage card = cards[msg.sender][keyHash];
        card.usedUnpredictableNumbers[unpredictableNumber] = true;
        card.atc = uint152(nextATC + 1);

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
        // emvFields IS the applet's signed message: ATC(2) || PDOL(50) = 52 bytes,
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

    function _cardInstallData(bytes calldata data) internal pure returns (bytes calldata) {
        if (data.length == 96) {
            return data;
        }
        if (data.length == 128) {
            return data[32:];
        }
        revert InvalidConfig();
    }

    function _isValidPublicKeyHash(bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY) internal pure returns (bool) {
        return computeKeyHash(pubkeyX, pubkeyY) == keyHash;
    }

    function _isCardRegistered(address account, bytes32 keyHash) internal view returns (bool) {
        return _isCardRegistered(cards[account][keyHash]);
    }

    function _isCardRegistered(CardData storage card) internal view returns (bool) {
        return card.atc != 0;
    }

    function _isPublicKeyRegistered(address account, bytes32 keyHash) internal view returns (bool) {
        return _isCardRegistered(account, keyHash);
    }
}
