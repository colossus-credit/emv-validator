// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyBase} from "kernel/src/sdk/moduleBase/PolicyBase.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_SUCCESS_UINT} from "kernel/src/types/Constants.sol";
import {EMVCallData} from "../util/EMVCallData.sol";

contract EMVCardPolicy is PolicyBase {
    uint256 private constant ATC_MAX = type(uint16).max;
    uint256 private constant EMV_FIELDS_LENGTH = 52;
    uint256 private constant UNPREDICTABLE_NUMBER_OFFSET = 2;
    uint256 private constant ATC_OFFSET = 0;

    struct CardData {
        // Stored one-based so zero means "not registered".
        uint64 atc;
        bool frozen;
        mapping(uint32 unpredictableNumber => bool used) usedUnpredictableNumbers;
    }

    mapping(address account => mapping(bytes32 keyHash => CardData card)) private cards;
    mapping(address account => mapping(bytes32 permission => bytes32 keyHash)) private permissionKeyHashes;

    error UnpredictableNumberAlreadyUsed(bytes4 unpredictableNumber);
    error InvalidATCSequence(uint16 expected, uint16 received);
    error InvalidConfig();
    error InvalidSignatureLength(uint256 actualSize);
    error PublicKeyNotRegistered();
    error InvalidPublicKeySize();
    error ATCExhausted(bytes32 keyHash);
    error CardFrozen(bytes32 keyHash);

    event ReplayProtectionUpdated(
        address indexed account, bytes32 indexed keyHash, bytes4 unpredictableNumber, uint256 newATC
    );
    event EMVCardRegistered(
        address indexed account,
        bytes32 indexed permission,
        bytes32 indexed keyHash,
        uint16 atc,
        bytes32 pubkeyX,
        bytes32 pubkeyY
    );
    event EMVCardFrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardUnfrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardRevoked(address indexed account, bytes32 indexed keyHash);

    function _policyOninstall(bytes32 permission, bytes calldata data) internal override {
        (uint16 atc, bytes32 pubkeyX, bytes32 pubkeyY) = abi.decode(data, (uint16, bytes32, bytes32));
        if (pubkeyX == bytes32(0) || pubkeyY == bytes32(0)) {
            revert InvalidPublicKeySize();
        }

        bytes32 keyHash = computeKeyHash(pubkeyX, pubkeyY);
        permissionKeyHashes[msg.sender][permission] = keyHash;

        CardData storage card = cards[msg.sender][keyHash];
        card.atc = uint64(atc) + 1;
        card.frozen = false;

        emit EMVCardRegistered(msg.sender, permission, keyHash, atc, pubkeyX, pubkeyY);
    }

    function _policyOnUninstall(bytes32 permission, bytes calldata) internal override {
        delete permissionKeyHashes[msg.sender][permission];
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        bytes32 keyHash = permissionKeyHashes[msg.sender][id];
        if (keyHash == bytes32(0)) {
            revert PublicKeyNotRegistered();
        }

        bytes calldata emvFields = EMVCallData.extractEMVFields(userOp.callData);
        _validateAndUpdateCard(msg.sender, keyHash, emvFields);
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function checkSignaturePolicy(bytes32 id, address sender, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        bytes32 keyHash = permissionKeyHashes[sender][id];
        if (keyHash == bytes32(0)) {
            revert PublicKeyNotRegistered();
        }

        CardData storage card = cards[sender][keyHash];
        if (card.atc == 0) {
            revert PublicKeyNotRegistered();
        }
        if (card.frozen) {
            revert CardFrozen(keyHash);
        }

        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function computeKeyHash(bytes32 pubkeyX, bytes32 pubkeyY) public pure returns (bytes32) {
        return keccak256(abi.encode(pubkeyX, pubkeyY));
    }

    function freezeCard(bytes32 keyHash) external {
        uint64 storedATC = cards[msg.sender][keyHash].atc;
        if (storedATC == 0) {
            revert PublicKeyNotRegistered();
        }

        cards[msg.sender][keyHash].frozen = true;
        emit EMVCardFrozen(msg.sender, keyHash);
    }

    function unfreezeCard(bytes32 keyHash) external {
        uint64 storedATC = cards[msg.sender][keyHash].atc;
        if (storedATC == 0) {
            revert PublicKeyNotRegistered();
        }

        cards[msg.sender][keyHash].frozen = false;
        emit EMVCardUnfrozen(msg.sender, keyHash);
    }

    function revokeCard(bytes32 keyHash) external {
        uint64 storedATC = cards[msg.sender][keyHash].atc;
        if (storedATC == 0) {
            revert PublicKeyNotRegistered();
        }

        delete cards[msg.sender][keyHash];
        emit EMVCardRevoked(msg.sender, keyHash);
    }

    function getPermissionKeyHash(address account, bytes32 permission) external view returns (bytes32) {
        return permissionKeyHashes[account][permission];
    }

    function getEMVStorage(address account, bytes32 keyHash)
        external
        view
        returns (uint256 expectedATC, bool initialized)
    {
        uint64 storedATC = cards[account][keyHash].atc;
        initialized = storedATC != 0;
        if (initialized) {
            expectedATC = storedATC - 1;
        }
    }

    function getExpectedATC(address account, bytes32 keyHash) external view returns (uint256 expectedATC) {
        uint64 storedATC = cards[account][keyHash].atc;
        if (storedATC == 0) {
            revert PublicKeyNotRegistered();
        }

        return storedATC - 1;
    }

    function isPublicKeyRegistered(address account, bytes32 keyHash) external view returns (bool) {
        return cards[account][keyHash].atc != 0;
    }

    function isCardFrozen(address account, bytes32 keyHash) external view returns (bool) {
        return cards[account][keyHash].frozen;
    }

    function getCardState(address account, bytes32 keyHash)
        external
        view
        returns (uint256 expectedATC, bool initialized, bool frozen)
    {
        uint64 storedATC = cards[account][keyHash].atc;
        initialized = storedATC != 0;
        if (initialized) {
            expectedATC = storedATC - 1;
        }
        frozen = cards[account][keyHash].frozen;
    }

    function isUnpredictableNumberUsed(address account, bytes32 keyHash, bytes4 unpredictableNumber)
        external
        view
        returns (bool used)
    {
        return cards[account][keyHash].usedUnpredictableNumbers[uint32(unpredictableNumber)];
    }

    function _validateAndUpdateCard(address account, bytes32 keyHash, bytes calldata emvFields) internal {
        if (emvFields.length != EMV_FIELDS_LENGTH) {
            revert InvalidSignatureLength(emvFields.length);
        }

        bytes4 unpredictableNumberBytes;
        bytes2 atcBytes;
        assembly {
            unpredictableNumberBytes := calldataload(add(emvFields.offset, UNPREDICTABLE_NUMBER_OFFSET))
            atcBytes := calldataload(add(emvFields.offset, ATC_OFFSET))
        }

        CardData storage card = cards[account][keyHash];
        uint64 storedATC = card.atc;
        if (storedATC == 0) {
            revert PublicKeyNotRegistered();
        }

        if (card.frozen) {
            revert CardFrozen(keyHash);
        }

        uint64 expectedATC = storedATC - 1;
        if (expectedATC > ATC_MAX) {
            revert ATCExhausted(keyHash);
        }

        uint32 unpredictableNumber = uint32(unpredictableNumberBytes);
        if (card.usedUnpredictableNumbers[unpredictableNumber]) {
            revert UnpredictableNumberAlreadyUsed(unpredictableNumberBytes);
        }

        uint16 receivedATC = uint16(atcBytes);
        if (uint256(receivedATC) < expectedATC) {
            revert InvalidATCSequence(uint16(expectedATC), receivedATC);
        }
        if (receivedATC == ATC_MAX) {
            revert ATCExhausted(keyHash);
        }

        uint256 nextATC = uint256(receivedATC) + 1;
        card.usedUnpredictableNumbers[unpredictableNumber] = true;
        card.atc = uint64(nextATC + 1);

        emit ReplayProtectionUpdated(account, keyHash, unpredictableNumberBytes, nextATC);
    }
}
