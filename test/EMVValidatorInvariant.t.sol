// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {EMVValidator} from "../src/EMVValidator.sol";

contract InvariantEMVValidatorHarness is EMVValidator {
    constructor(address target, bytes4 selector) EMVValidator(target, selector) {}

    function exposedValidateCardData(bytes calldata emvFields, address account, bytes32 keyHash)
        external
        view
        returns (bytes4 unpredictableNumber, uint256 currentATC, uint96 amount)
    {
        return _validateCardData(emvFields, account, keyHash);
    }

    function exposedUpdateCardData(bytes32 keyHash, bytes4 unpredictableNumber, uint256 currentATC, uint96 amount)
        external
    {
        _updateCardData(keyHash, unpredictableNumber, currentATC, amount);
    }
}

contract EMVCardStateHandler {
    bytes32 private constant TEST_PUBKEY_X = 0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83;
    bytes32 private constant TEST_PUBKEY_Y = 0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9;
    address private constant TEST_MERCHANT_ADDRESS = address(uint160(0x00000000004d45524348414E5430303132333400));

    InvariantEMVValidatorHarness public immutable validator;
    bytes32 public immutable keyHash;

    bool public registered;
    bool public frozen;
    uint256 public expectedATC;
    uint96 public cycleMax;
    uint96 public perTxnMax;
    bool public hasLastSuccessfulUnpredictableNumber;
    uint32 public lastSuccessfulUnpredictableNumber;

    constructor() {
        validator = new InvariantEMVValidatorHarness(address(0x1234), bytes4(0x01020304));
        keyHash = validator.computeKeyHash(TEST_PUBKEY_X, TEST_PUBKEY_Y);
    }

    function install(uint16 atc, uint96 newCycleMax, uint96 newPerTxnMax) external {
        validator.onInstall(abi.encode(atc, TEST_PUBKEY_X, TEST_PUBKEY_Y, newCycleMax, newPerTxnMax));

        registered = true;
        frozen = false;
        expectedATC = atc;
        cycleMax = newCycleMax;
        perTxnMax = newPerTxnMax;
    }

    function freezeCard() external {
        if (!registered) return;

        validator.freezeCard(keyHash);
        frozen = true;
    }

    function unfreezeCard() external {
        if (!registered) return;

        validator.unfreezeCard(keyHash);
        frozen = false;
    }

    function revokeCard() external {
        if (!registered) return;

        validator.revokeCard(keyHash);
        registered = false;
        frozen = false;
        expectedATC = 0;
        cycleMax = 0;
        perTxnMax = 0;
    }

    function setCycleMax(uint96 newCycleMax) external {
        if (!registered) return;

        validator.setCycleMax(keyHash, newCycleMax);
        cycleMax = newCycleMax;
    }

    function setPerTxnMax(uint96 newPerTxnMax) external {
        if (!registered) return;

        validator.setPerTxnMax(keyHash, newPerTxnMax);
        perTxnMax = newPerTxnMax;
    }

    function spend(uint16 receivedATC, uint32 unpredictableNumber, uint96 rawAmount) external {
        if (!registered || frozen) return;

        uint96 amount = uint96((uint256(rawAmount) % 999_999_999_999) + 1);
        bytes memory emvFields = _emvFields(receivedATC, unpredictableNumber, amount);

        try validator.exposedValidateCardData(emvFields, address(this), keyHash) returns (
            bytes4 unpredictableNumberBytes, uint256 currentATC, uint96 validatedAmount
        ) {
            try validator.exposedUpdateCardData(keyHash, unpredictableNumberBytes, currentATC, validatedAmount) {
                expectedATC = currentATC + 1;
                lastSuccessfulUnpredictableNumber = uint32(unpredictableNumberBytes);
                hasLastSuccessfulUnpredictableNumber = true;
            } catch {}
        } catch {}
    }

    function _emvFields(uint16 atc, uint32 unpredictableNumber, uint96 amountCents)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes2(atc),
            bytes4(unpredictableNumber),
            bytes1(0),
            bytes2(0x0840),
            _amountCentsToBCD(amountCents),
            hex"000000000000",
            bytes1(0x02),
            bytes15(uint120(uint160(TEST_MERCHANT_ADDRESS))),
            bytes8("TERM0001"),
            bytes2(0x0840),
            bytes3(0x231201),
            bytes2(0x5999)
        );
    }

    function _amountCentsToBCD(uint96 amountCents) private pure returns (bytes memory encoded) {
        encoded = new bytes(6);
        uint96 remaining = amountCents;

        for (uint256 i = 6; i > 0;) {
            unchecked {
                --i;
            }
            uint8 lowNibble = uint8(remaining % 10);
            remaining /= 10;
            uint8 highNibble = uint8(remaining % 10);
            remaining /= 10;
            encoded[i] = bytes1((highNibble << 4) | lowNibble);
        }
    }
}

contract EMVValidatorInvariantTest is StdInvariant, Test {
    EMVCardStateHandler private handler;
    InvariantEMVValidatorHarness private validator;

    function setUp() public {
        handler = new EMVCardStateHandler();
        validator = handler.validator();

        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = EMVCardStateHandler.install.selector;
        selectors[1] = EMVCardStateHandler.freezeCard.selector;
        selectors[2] = EMVCardStateHandler.unfreezeCard.selector;
        selectors[3] = EMVCardStateHandler.revokeCard.selector;
        selectors[4] = EMVCardStateHandler.setCycleMax.selector;
        selectors[5] = EMVCardStateHandler.setPerTxnMax.selector;
        selectors[6] = EMVCardStateHandler.spend.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function invariant_CardRegistrationMatchesCycleSentinel() public view {
        bytes32 keyHash = handler.keyHash();
        (uint256 storedATC, bool initialized) = validator.getEMVStorage(address(handler), keyHash);

        assertEq(initialized, handler.registered());
        assertEq(validator.isPublicKeyRegistered(address(handler), keyHash), handler.registered());

        if (handler.registered()) {
            assertEq(storedATC, handler.expectedATC());
            assertEq(validator.getExpectedATC(address(handler), keyHash), handler.expectedATC());
        } else {
            assertEq(storedATC, 0);
        }
    }

    function invariant_FrozenAndLimitStateMatchModel() public view {
        bytes32 keyHash = handler.keyHash();

        assertEq(validator.isCardFrozen(address(handler), keyHash), handler.frozen());

        (, uint96 cycleMax,, uint96 perTxnMax) = validator.getCardLimits(address(handler), keyHash);
        assertEq(cycleMax, handler.cycleMax());
        assertEq(perTxnMax, handler.perTxnMax());
    }

    function invariant_ExpectedATCNeverExceedsCardCounterSpace() public view {
        assertLe(handler.expectedATC(), type(uint16).max);
    }

    function invariant_SuccessfulUnpredictableNumbersRemainMarkedUsed() public view {
        if (!handler.hasLastSuccessfulUnpredictableNumber()) return;

        assertTrue(
            validator.isUnpredictableNumberUsed(
                address(handler), handler.keyHash(), bytes4(handler.lastSuccessfulUnpredictableNumber())
            )
        );
    }
}
