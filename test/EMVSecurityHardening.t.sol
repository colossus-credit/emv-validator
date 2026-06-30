// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import {AcquirerConfig} from "../src/AcquirerConfig.sol";
import {EMVSettlement} from "../src/EMVSettlement.sol";
import {EMVValidator} from "../src/EMVValidator.sol";
import {ANSEncoding} from "../src/util/ANSEncoding.sol";
import {BCDEncoding} from "../src/util/BCDEncoding.sol";
import {ColossusTestToken} from "./util/ColossusTestToken.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {CALLTYPE_DELEGATECALL, ERC1271_INVALID, EXECTYPE_DEFAULT} from "kernel/src/types/Constants.sol";
import {ExecModePayload, ExecModeSelector} from "kernel/src/types/Types.sol";

contract SecurityBCDEncodingHarness {
    function extractAmountCents(bytes calldata bcdAmount) external pure returns (uint96) {
        return BCDEncoding.extractAmountCents(bcdAmount);
    }

    function extractAmountFromBCD(bytes calldata bcdAmount, uint8 tokenDecimals) external pure returns (uint256) {
        return BCDEncoding.extractAmountFromBCD(bcdAmount, tokenDecimals);
    }
}

contract SecurityANSEncodingHarness {
    function encode(string calldata value) external pure returns (bytes memory) {
        return ANSEncoding.encode(value);
    }
}

contract SecurityAcquirerConfigHarness is AcquirerConfig {
    function exposedAccumulateClearAndReuse(address recipient)
        external
        returns (uint256 firstLength, uint256 accumulatedFee, uint256 secondLength, uint256 feeAfterClear)
    {
        FeeRecipient[] memory recipients = new FeeRecipient[](2);

        firstLength = _addOrAccumulateFee(recipients, 0, recipient, 100);
        firstLength = _addOrAccumulateFee(recipients, firstLength, recipient, 50);
        accumulatedFee = recipients[0].fee;

        _clearTransientStorage(recipients, firstLength);

        FeeRecipient[] memory afterClear = new FeeRecipient[](1);
        secondLength = _addOrAccumulateFee(afterClear, 0, recipient, 25);
        feeAfterClear = afterClear[0].fee;
    }
}

contract SecurityMalformedDistributionConfig {
    enum Mode {
        Empty,
        ZeroFee,
        FeeEqualsAmount,
        MerchantFee,
        ZeroFeeRecipient,
        ZeroMerchantRecipient,
        Valid
    }

    Mode public mode;
    address public immutable feeRecipient;
    address public immutable merchant;

    constructor(address feeRecipient_, address merchant_) {
        feeRecipient = feeRecipient_;
        merchant = merchant_;
    }

    function setMode(Mode mode_) external {
        mode = mode_;
    }

    function calculatePaymentDistribution(uint120, uint256 totalAmount)
        external
        view
        returns (AcquirerConfig.FeeRecipient[] memory recipients)
    {
        if (mode == Mode.Empty) {
            return new AcquirerConfig.FeeRecipient[](0);
        }

        recipients = new AcquirerConfig.FeeRecipient[](2);

        if (mode == Mode.ZeroFee) {
            recipients[0] = AcquirerConfig.FeeRecipient({fee: 0, recipient: feeRecipient});
            recipients[1] = AcquirerConfig.FeeRecipient({fee: 0, recipient: merchant});
            return recipients;
        }

        if (mode == Mode.FeeEqualsAmount) {
            recipients[0] = AcquirerConfig.FeeRecipient({fee: totalAmount, recipient: feeRecipient});
            recipients[1] = AcquirerConfig.FeeRecipient({fee: 0, recipient: merchant});
            return recipients;
        }

        if (mode == Mode.MerchantFee) {
            recipients[0] = AcquirerConfig.FeeRecipient({fee: 1 ether, recipient: feeRecipient});
            recipients[1] = AcquirerConfig.FeeRecipient({fee: 1, recipient: merchant});
            return recipients;
        }

        if (mode == Mode.ZeroFeeRecipient) {
            recipients[0] = AcquirerConfig.FeeRecipient({fee: 1 ether, recipient: address(0)});
            recipients[1] = AcquirerConfig.FeeRecipient({fee: 0, recipient: merchant});
            return recipients;
        }

        if (mode == Mode.ZeroMerchantRecipient) {
            recipients[0] = AcquirerConfig.FeeRecipient({fee: 1 ether, recipient: feeRecipient});
            recipients[1] = AcquirerConfig.FeeRecipient({fee: 0, recipient: address(0)});
            return recipients;
        }

        recipients[0] = AcquirerConfig.FeeRecipient({fee: 1 ether, recipient: feeRecipient});
        recipients[1] = AcquirerConfig.FeeRecipient({fee: 0, recipient: merchant});
    }
}

contract SecurityEMVSettlementHarness is EMVSettlement {
    constructor(address tokenAddress, address acquirerConfigAddress, uint8 tokenDecimals)
        EMVSettlement(tokenAddress, acquirerConfigAddress, tokenDecimals)
    {}

    function exposedProcessFeePayments(AcquirerConfig.FeeRecipient[] memory feeRecipients, uint256 totalAmount)
        external
    {
        _processFeePayments(feeRecipients, totalAmount);
    }

    function exposedOffsets(bytes calldata emvData)
        external
        pure
        returns (uint256 amountOffset, uint256 merchantOffset)
    {
        return _emvSettlementOffsets(emvData);
    }
}

contract SecurityEMVValidatorHarness is EMVValidator {
    constructor(address target, bytes4 selector) EMVValidator(target, selector) {}

    function exposedExtractEMVFieldsFromCallData(bytes calldata callData) external view returns (bytes memory) {
        return _extractEMVFieldsFromCallData(callData);
    }

    function exposedValidateTargetAndSelector(bytes calldata callData) external view {
        _validateTargetAndSelector(callData);
    }

    function exposedExtractUnpredictableNumber(bytes calldata emvFields) external pure returns (bytes4) {
        return _extractUnpredictableNumber(emvFields);
    }

    function exposedExtractATC(bytes calldata emvFields) external pure returns (bytes2) {
        return _extractATC(emvFields);
    }

    function exposedExtractCurrency(bytes calldata emvFields) external pure returns (bytes2) {
        return _extractCurrency(emvFields);
    }

    function exposedValidateCurrencyCode(bytes calldata emvFields) external pure {
        _validateCurrencyCode(emvFields);
    }

    function exposedValidateAuxiliaryFields(bytes calldata emvFields) external pure {
        _validateAuxiliaryFields(emvFields);
    }

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

    function exposedDecodeEMVSignature(bytes calldata signature)
        external
        pure
        returns (bytes32 keyHash, bytes32 pubkeyX, bytes32 pubkeyY, bytes32 r, bytes32 s)
    {
        return _decodeEMVSignature(signature);
    }
}

contract EMVSecurityHardeningTest is Test {
    bytes32 private constant TEST_PUBKEY_X = 0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83;
    bytes32 private constant TEST_PUBKEY_Y = 0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9;
    bytes32 private constant TEST_SIGNATURE_R = 0xe6a9a4f20d16a123252c98913b9f7cd740d20f4acdbb2d70d9edb86a70602797;
    bytes32 private constant TEST_SIGNATURE_S = 0x2502bc1502afe1072734ac5a0f16483bbf9f123c3b213699a8ddad289a3314d7;
    bytes private constant TEST_SIGNATURE = hex"e6a9a4f20d16a123252c98913b9f7cd740d20f4acdbb2d70d9edb86a70602797"
        hex"2502bc1502afe1072734ac5a0f16483bbf9f123c3b213699a8ddad289a3314d7";
    bytes4 private constant ACCOUNT_EXECUTE_SELECTOR = bytes4(keccak256("execute(bytes32,bytes)"));
    address private constant TEST_MERCHANT_ADDRESS = address(uint160(0x00000000004d45524348414E5430303132333400));

    SecurityBCDEncodingHarness private bcd;
    SecurityANSEncodingHarness private ans;
    SecurityEMVValidatorHarness private validator;
    address private settlementTarget;
    bytes32 private keyHash;

    function setUp() public {
        bcd = new SecurityBCDEncodingHarness();
        ans = new SecurityANSEncodingHarness();
        settlementTarget = makeAddr("settlementTarget");
        validator = new SecurityEMVValidatorHarness(settlementTarget, ACCOUNT_EXECUTE_SELECTOR);
        keyHash = validator.computeKeyHash(TEST_PUBKEY_X, TEST_PUBKEY_Y);
    }

    function testFuzz_BCDEncodingExtractsTwelveDigitCentAmounts(uint96 amountCents) public view {
        amountCents = uint96(bound(amountCents, 0, 999_999_999_999));
        bytes memory encoded = _amountCentsToBCD(amountCents);

        assertEq(bcd.extractAmountCents(encoded), amountCents);
    }

    function testFuzz_BCDEncodingScalesByTokenDecimals(uint96 amountCents, uint8 tokenDecimals) public view {
        amountCents = uint96(bound(amountCents, 0, 999_999_999_999));
        tokenDecimals = uint8(bound(tokenDecimals, 2, 18));

        bytes memory encoded = _amountCentsToBCD(amountCents);

        assertEq(bcd.extractAmountFromBCD(encoded, tokenDecimals), uint256(amountCents) * 10 ** (tokenDecimals - 2));
    }

    function testFuzz_BCDEncodingInvalidNibbleReturnsZero(bytes6 raw, uint8 index, bool corruptHighNibble) public view {
        bytes memory encoded = abi.encodePacked(raw);
        uint256 selectedIndex = uint256(index) % 6;
        uint8 value = uint8(encoded[selectedIndex]);

        if (corruptHighNibble) {
            value = (value & 0x0F) | 0xA0;
        } else {
            value = (value & 0xF0) | 0x0A;
        }
        encoded[selectedIndex] = bytes1(value);

        assertEq(bcd.extractAmountCents(encoded), 0);
    }

    function testFuzz_BCDEncodingRejectsWrongLength(bytes memory encoded) public {
        vm.assume(encoded.length != 6);
        vm.expectRevert(BCDEncoding.InvalidBCDLength.selector);
        bcd.extractAmountCents(encoded);
    }

    function testFuzz_ANSEncodingAcceptsPrintableBytes(bytes15 raw, uint8 rawLength) public view {
        uint256 length = uint256(rawLength) % 16;
        bytes memory value = new bytes(length);

        for (uint256 i = 0; i < length; i++) {
            value[i] = bytes1(uint8(0x20 + (uint8(raw[i]) % 0x5F)));
        }

        assertEq(ans.encode(string(value)), value);
    }

    function testFuzz_ANSEncodingRejectsNonPrintableBytes(uint8 character) public {
        vm.assume(character < 0x20 || character > 0x7E);

        bytes memory value = abi.encodePacked(bytes1(character));
        vm.expectRevert(abi.encodeWithSelector(ANSEncoding.InvalidANSCharacter.selector, bytes1(character)));
        ans.encode(string(value));
    }

    function test_AcquirerConfigInternalTransientStorageIsCleared() public {
        SecurityAcquirerConfigHarness config = new SecurityAcquirerConfigHarness();
        address recipient = makeAddr("sharedFeeRecipient");

        (uint256 firstLength, uint256 accumulatedFee, uint256 secondLength, uint256 feeAfterClear) =
            config.exposedAccumulateClearAndReuse(recipient);

        assertEq(firstLength, 1);
        assertEq(accumulatedFee, 150);
        assertEq(secondLength, 1);
        assertEq(feeAfterClear, 25);
    }

    function test_AcquirerConfigRejectsZeroAcquirerAddress() public {
        AcquirerConfig config = new AcquirerConfig();

        vm.expectRevert(AcquirerConfig.InvalidAcquirerAddress.selector);
        config.setAcquirer(uint48(bytes6("ACQ001")), address(0));
    }

    function testFuzz_AcquirerConfigOnlySelectedAcquirerCanUpdateMerchant(
        uint120 merchantId,
        address merchant,
        address attacker
    ) public {
        merchantId = uint120(bound(merchantId, 1, type(uint120).max));
        vm.assume(merchant != address(0));
        vm.assume(attacker != address(0));
        vm.assume(attacker != address(this));

        AcquirerConfig config = new AcquirerConfig();
        uint48 acquirerId = uint48(bytes6("ACQ001"));
        config.setAcquirer(acquirerId, address(this));
        config.setMerchant(merchantId, acquirerId, merchant);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(AcquirerConfig.UnauthorizedAcquirer.selector, acquirerId, attacker));
        config.setMerchant(merchantId, acquirerId, attacker);

        assertEq(config.getMerchantAddress(merchantId), merchant);
    }

    function testFuzz_AcquirerConfigDistributionMatchesConfiguredFees(
        uint120 merchantId,
        uint16 acquirerFeeRate,
        uint16 networkFeeRate,
        uint16 interchangeFeeRate,
        uint128 rawAmount,
        uint128 rawSwipeFee
    ) public {
        merchantId = uint120(bound(merchantId, 1, type(uint120).max));
        uint256 totalAmount = bound(rawAmount, 1 ether, 1_000_000 ether);
        uint256 swipeFee = bound(rawSwipeFee, 0, totalAmount / 10);
        acquirerFeeRate = uint16(bound(acquirerFeeRate, 0, 30));
        networkFeeRate = uint16(bound(networkFeeRate, 0, 15));
        interchangeFeeRate = uint16(bound(interchangeFeeRate, 0, 250));

        AcquirerConfig config = new AcquirerConfig();
        uint48 acquirerId = uint48(bytes6("ACQ001"));
        address merchant = makeAddr("distributionMerchant");
        address acquirerRecipient = makeAddr("distributionAcquirer");
        address networkRecipient = makeAddr("distributionNetwork");
        address interchangeRecipient = makeAddr("distributionInterchange");

        config.setAcquirer(acquirerId, address(this));
        config.setAcquirerFee(acquirerId, acquirerRecipient, acquirerFeeRate);
        config.setSwipeFee(acquirerId, swipeFee);
        config.setNetworkFee(networkRecipient, networkFeeRate);
        config.setInterchangeFee(interchangeRecipient, interchangeFeeRate);
        config.setMerchant(merchantId, acquirerId, merchant);

        AcquirerConfig.FeeRecipient[] memory recipients = config.calculatePaymentDistribution(merchantId, totalAmount);
        uint256 totalFees;
        for (uint256 i = 0; i < recipients.length - 1; i++) {
            assertGt(recipients[i].fee, 0);
            assertTrue(recipients[i].recipient != address(0));
            totalFees += recipients[i].fee;
        }

        assertEq(recipients[recipients.length - 1].recipient, merchant);
        assertEq(recipients[recipients.length - 1].fee, 0);

        uint256 expectedFees = (totalAmount * acquirerFeeRate) / 10_000 + swipeFee + (totalAmount * networkFeeRate)
            / 10_000 + (totalAmount * interchangeFeeRate) / 10_000;
        assertEq(totalFees, expectedFees);
    }

    function test_EMVSettlementRejectsMalformedDistributionArrays() public {
        address feeRecipient = makeAddr("feeRecipient");
        address merchant = makeAddr("merchant");
        SecurityMalformedDistributionConfig config = new SecurityMalformedDistributionConfig(feeRecipient, merchant);
        ColossusTestToken token = new ColossusTestToken(address(this), 18);
        EMVSettlement settlement = new EMVSettlement(address(token), address(config), 18);
        token.mint(address(settlement), 1_000 ether);
        bytes memory emvFields = _emvFields(10_000);

        config.setMode(SecurityMalformedDistributionConfig.Mode.Empty);
        vm.expectRevert(abi.encodeWithSelector(EMVSettlement.InvalidFee.selector, 0));
        settlement.execute(emvFields);

        config.setMode(SecurityMalformedDistributionConfig.Mode.ZeroFee);
        vm.expectRevert(abi.encodeWithSelector(EMVSettlement.InvalidFee.selector, 0));
        settlement.execute(emvFields);

        config.setMode(SecurityMalformedDistributionConfig.Mode.FeeEqualsAmount);
        vm.expectRevert(EMVSettlement.BelowTransactionMinimum.selector);
        settlement.execute(emvFields);

        config.setMode(SecurityMalformedDistributionConfig.Mode.MerchantFee);
        vm.expectRevert(EMVSettlement.InvalidMerchantFee.selector);
        settlement.execute(emvFields);

        config.setMode(SecurityMalformedDistributionConfig.Mode.ZeroFeeRecipient);
        vm.expectRevert(abi.encodeWithSelector(EMVSettlement.InvalidFee.selector, 0));
        settlement.execute(emvFields);

        config.setMode(SecurityMalformedDistributionConfig.Mode.ZeroMerchantRecipient);
        vm.expectRevert(abi.encodeWithSelector(EMVSettlement.InvalidFee.selector, 1));
        settlement.execute(emvFields);

        assertEq(token.balanceOf(feeRecipient), 0);
        assertEq(token.balanceOf(merchant), 0);
    }

    function test_EMVSettlementProcessesValidDistributionFromConfig() public {
        address feeRecipient = makeAddr("validFeeRecipient");
        address merchant = makeAddr("validMerchant");
        SecurityMalformedDistributionConfig config = new SecurityMalformedDistributionConfig(feeRecipient, merchant);
        ColossusTestToken token = new ColossusTestToken(address(this), 18);
        EMVSettlement settlement = new EMVSettlement(address(token), address(config), 18);
        token.mint(address(settlement), 1_000 ether);

        config.setMode(SecurityMalformedDistributionConfig.Mode.Valid);
        settlement.execute(_emvFields(10_000));

        assertEq(token.balanceOf(feeRecipient), 1 ether);
        assertEq(token.balanceOf(merchant), 99 ether);
    }

    function test_EMVSettlementHarnessRejectsBadProcessFeeInputs() public {
        AcquirerConfig config = new AcquirerConfig();
        ColossusTestToken token = new ColossusTestToken(address(this), 18);
        SecurityEMVSettlementHarness settlement = new SecurityEMVSettlementHarness(address(token), address(config), 18);
        token.mint(address(settlement), 1_000 ether);

        AcquirerConfig.FeeRecipient[] memory emptyRecipients = new AcquirerConfig.FeeRecipient[](0);
        vm.expectRevert(abi.encodeWithSelector(EMVSettlement.InvalidFee.selector, 0));
        settlement.exposedProcessFeePayments(emptyRecipients, 100 ether);

        AcquirerConfig.FeeRecipient[] memory zeroMerchant = new AcquirerConfig.FeeRecipient[](1);
        zeroMerchant[0] = AcquirerConfig.FeeRecipient({fee: 0, recipient: address(0)});
        vm.expectRevert(abi.encodeWithSelector(EMVSettlement.InvalidFee.selector, 0));
        settlement.exposedProcessFeePayments(zeroMerchant, 100 ether);
    }

    function test_EMVSettlementOffsetsAcceptOnlyCanonicalSignedMessageLength() public {
        AcquirerConfig config = new AcquirerConfig();
        ColossusTestToken token = new ColossusTestToken(address(this), 18);
        SecurityEMVSettlementHarness settlement = new SecurityEMVSettlementHarness(address(token), address(config), 18);

        (uint256 amountOffset, uint256 merchantOffset) = settlement.exposedOffsets(_emvFields(10_000));
        assertEq(amountOffset, 9);
        assertEq(merchantOffset, 22);

        vm.expectRevert(EMVSettlement.InvalidBCDLength.selector);
        settlement.exposedOffsets(hex"1234");
    }

    function test_EMVValidatorHarnessExtractsNestedCalldataAndFields() public view {
        bytes memory emvFields = _emvFields(10_000);
        bytes memory callData = _accountExecuteCall(settlementTarget, emvFields);

        assertEq(validator.exposedExtractEMVFieldsFromCallData(callData), emvFields);
        validator.exposedValidateTargetAndSelector(callData);
        assertEq(validator.exposedExtractUnpredictableNumber(emvFields), bytes4(0x12345678));
        assertEq(validator.exposedExtractATC(emvFields), bytes2(0));
        assertEq(validator.exposedExtractCurrency(emvFields), bytes2(0x0840));
        validator.exposedValidateCurrencyCode(emvFields);
        validator.exposedValidateAuxiliaryFields(emvFields);
    }

    function test_EMVValidatorHarnessRejectsWrongSelectorAndTarget() public {
        bytes memory emvFields = _emvFields(10_000);
        bytes4 wrongSelector = bytes4(0xdeadbeef);
        bytes memory wrongSelectorCall =
            abi.encodeWithSelector(wrongSelector, bytes32(0), abi.encodePacked(settlementTarget));

        vm.expectRevert(
            abi.encodeWithSelector(
                EMVValidator.InvalidFunctionSelector.selector, ACCOUNT_EXECUTE_SELECTOR, wrongSelector
            )
        );
        validator.exposedValidateTargetAndSelector(wrongSelectorCall);

        address wrongTarget = makeAddr("wrongTarget");
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.InvalidTarget.selector, settlementTarget, wrongTarget));
        validator.exposedValidateTargetAndSelector(_accountExecuteCall(wrongTarget, emvFields));
    }

    function test_EMVValidatorRejectsNonPaymentInnerCallWithAppendedSignedBlob() public {
        bytes memory emvFields = _emvFields(10_000);
        bytes memory nonPaymentInnerCall = bytes.concat(
            EMVSettlement.isModuleType.selector,
            abi.encode(uint256(2)),
            abi.encode(uint256(emvFields.length)),
            emvFields
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                EMVValidator.InvalidFunctionSelector.selector,
                EMVSettlement.execute.selector,
                EMVSettlement.isModuleType.selector
            )
        );
        validator.exposedExtractEMVFieldsFromCallData(
            _accountExecuteRawInnerCall(settlementTarget, nonPaymentInnerCall)
        );
    }

    function test_EMVValidatorRejectsPayloadSwapThroughNonCanonicalInnerBytesOffset() public {
        bytes memory signedFields = _emvFields(10_000);
        bytes memory attackerFields = _replaceEMVField(_emvFields(20_000), 2, hex"99887766");
        bytes memory maliciousInnerCall = bytes.concat(
            EMVSettlement.execute.selector,
            bytes32(uint256(0x80)),
            bytes32(uint256(signedFields.length)),
            signedFields,
            new bytes(12),
            bytes32(uint256(attackerFields.length)),
            attackerFields
        );

        vm.expectRevert(EMVValidator.InvalidCallData.selector);
        validator.exposedExtractEMVFieldsFromCallData(_accountExecuteRawInnerCall(settlementTarget, maliciousInnerCall));
    }

    function test_EMVValidatorHarnessDecodesSignatureEnvelope() public {
        bytes memory signature = _emvSignatureEnvelope();
        (bytes32 decodedKeyHash, bytes32 decodedX, bytes32 decodedY, bytes32 r, bytes32 s) =
            validator.exposedDecodeEMVSignature(signature);

        assertEq(decodedKeyHash, keyHash);
        assertEq(decodedX, TEST_PUBKEY_X);
        assertEq(decodedY, TEST_PUBKEY_Y);
        assertEq(r, TEST_SIGNATURE_R);
        assertEq(s, TEST_SIGNATURE_S);

        bytes memory shortSignature = new bytes(159);
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.InvalidSignatureLength.selector, 159));
        validator.exposedDecodeEMVSignature(shortSignature);
    }

    function test_EMVValidatorValidateUserOpRejectsMismatchedKeyHashEnvelope() public {
        PackedUserOperation memory op;
        op.sender = address(this);
        op.callData = _accountExecuteCall(settlementTarget, _emvFields(10_000));
        op.signature = abi.encodePacked(bytes32(uint256(1)), TEST_PUBKEY_X, TEST_PUBKEY_Y, TEST_SIGNATURE);

        vm.expectRevert(EMVValidator.InvalidPublicKey.selector);
        validator.validateUserOp(op, bytes32(0));
    }

    function test_EMVValidatorERC1271ReturnsInvalidForMismatchedKeyHashEnvelope() public {
        validator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));
        bytes memory badEnvelope = abi.encodePacked(bytes32(uint256(1)), TEST_PUBKEY_X, TEST_PUBKEY_Y, TEST_SIGNATURE);

        assertEq(
            validator.isValidSignatureWithSender(address(this), sha256(_emvFields(10_000)), badEnvelope),
            ERC1271_INVALID
        );
    }

    function test_EMVValidatorInstallUsesOneAsCycleSentinelAtTimestampZero() public {
        SecurityEMVValidatorHarness freshValidator =
            new SecurityEMVValidatorHarness(settlementTarget, ACCOUNT_EXECUTE_SELECTOR);

        vm.warp(0);
        freshValidator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        (uint64 cycle,,,) = freshValidator.getCardLimits(address(this), keyHash);
        assertEq(cycle, 1);
    }

    function test_EMVValidatorValidateCardDataRejectsCorruptATCStorageAboveMax() public {
        validator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        bytes32 cardBase = _cardDataBase(address(this), keyHash);
        uint256 packedLimitsATCAndFrozen = uint256(type(uint96).max) | ((uint256(type(uint16).max) + 1) << 96);
        vm.store(address(validator), bytes32(uint256(cardBase) + 1), bytes32(packedLimitsATCAndFrozen));

        vm.expectRevert(abi.encodeWithSelector(EMVValidator.ATCExhausted.selector, keyHash));
        validator.exposedValidateCardData(_emvFields(10_000), address(this), keyHash);
    }

    function test_EMVValidatorHarnessValidatesAndUpdatesCardData() public {
        validator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y, uint96(20_000), uint96(10_000)));
        bytes memory emvFields = _emvFields(10_000);

        (bytes4 unpredictableNumber, uint256 currentATC, uint96 amount) =
            validator.exposedValidateCardData(emvFields, address(this), keyHash);
        assertEq(unpredictableNumber, bytes4(0x12345678));
        assertEq(currentATC, 0);
        assertEq(amount, 10_000);

        validator.exposedUpdateCardData(keyHash, unpredictableNumber, currentATC, amount);

        assertEq(validator.getExpectedATC(address(this), keyHash), 1);
        assertTrue(validator.isUnpredictableNumberUsed(address(this), keyHash, unpredictableNumber));

        vm.expectRevert(
            abi.encodeWithSelector(EMVValidator.UnpredictableNumberAlreadyUsed.selector, unpredictableNumber)
        );
        validator.exposedValidateCardData(emvFields, address(this), keyHash);

        bytes memory lowAtcFreshUn = _replaceEMVField(emvFields, 2, hex"99887766");
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.InvalidATCSequence.selector, uint16(1), uint16(0)));
        validator.exposedValidateCardData(lowAtcFreshUn, address(this), keyHash);
    }

    function test_EMVValidatorHarnessCoversFrozenLimitAndAmountBranches() public {
        validator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y, uint96(9_999), uint96(9_999)));
        bytes memory emvFields = _emvFields(10_000);

        vm.expectRevert(
            abi.encodeWithSelector(
                EMVValidator.PerTransactionLimitExceeded.selector, keyHash, uint96(10_000), uint96(9_999)
            )
        );
        validator.exposedValidateCardData(emvFields, address(this), keyHash);

        validator.setPerTxnMax(keyHash, 10_000);
        vm.expectRevert(
            abi.encodeWithSelector(EMVValidator.CycleLimitExceeded.selector, keyHash, uint256(10_000), uint96(9_999))
        );
        validator.exposedValidateCardData(emvFields, address(this), keyHash);

        validator.setCycleMax(keyHash, 10_000);
        validator.freezeCard(keyHash);
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.CardFrozen.selector, keyHash));
        validator.exposedValidateCardData(emvFields, address(this), keyHash);

        validator.unfreezeCard(keyHash);
        bytes memory zeroAmountFields = _replaceEMVField(emvFields, 9, hex"000000000000");
        vm.expectRevert(EMVValidator.InvalidAmount.selector);
        validator.exposedValidateCardData(zeroAmountFields, address(this), keyHash);
    }

    function test_EMVValidatorHarnessResetsCycleTotalAfterOneDay() public {
        validator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y, uint96(15_000), type(uint96).max));

        bytes memory firstFields = _emvFields(10_000);
        (bytes4 firstUn, uint256 firstATC, uint96 firstAmount) =
            validator.exposedValidateCardData(firstFields, address(this), keyHash);
        validator.exposedUpdateCardData(keyHash, firstUn, firstATC, firstAmount);

        (,, uint96 cycleTotal,) = validator.getCardLimits(address(this), keyHash);
        assertEq(cycleTotal, 10_000);

        vm.warp(block.timestamp + 1 days);
        bytes memory secondFields = _replaceEMVField(_emvFields(10_000), 0, hex"0001");
        secondFields = _replaceEMVField(secondFields, 2, hex"87654321");

        (bytes4 secondUn, uint256 secondATC, uint96 secondAmount) =
            validator.exposedValidateCardData(secondFields, address(this), keyHash);
        validator.exposedUpdateCardData(keyHash, secondUn, secondATC, secondAmount);

        (,, cycleTotal,) = validator.getCardLimits(address(this), keyHash);
        assertEq(cycleTotal, 10_000);
    }

    function test_EMVValidatorHarnessRejectsATCExhaustionOnUpdate() public {
        validator.onInstall(abi.encode(type(uint16).max, TEST_PUBKEY_X, TEST_PUBKEY_Y));
        bytes memory emvFields = _replaceEMVField(_emvFields(10_000), 0, hex"ffff");

        (bytes4 unpredictableNumber, uint256 currentATC, uint96 amount) =
            validator.exposedValidateCardData(emvFields, address(this), keyHash);
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.ATCExhausted.selector, keyHash));
        validator.exposedUpdateCardData(keyHash, unpredictableNumber, currentATC, amount);
    }

    function testFuzz_EMVValidatorInstallRoundTripsATCAndLimits(uint16 atc, uint96 cycleMax, uint96 perTxnMax) public {
        validator.onInstall(abi.encode(atc, TEST_PUBKEY_X, TEST_PUBKEY_Y, cycleMax, perTxnMax));

        (uint256 expectedATC, bool initialized) = validator.getEMVStorage(address(this), keyHash);
        (, uint96 actualCycleMax,, uint96 actualPerTxnMax) = validator.getCardLimits(address(this), keyHash);

        assertTrue(initialized);
        assertEq(expectedATC, atc);
        assertEq(actualCycleMax, cycleMax);
        assertEq(actualPerTxnMax, perTxnMax);
    }

    function testFuzz_EMVValidatorRejectsAmountsAbovePerTxnMax(uint96 rawLimit, uint96 rawOverBy) public {
        uint96 limit = uint96(bound(rawLimit, 0, 999_999_999_998));
        uint96 overBy = uint96(bound(rawOverBy, 1, 999_999_999_999 - limit));
        uint96 amount = limit + overBy;

        validator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y, type(uint96).max, limit));

        vm.expectRevert(
            abi.encodeWithSelector(EMVValidator.PerTransactionLimitExceeded.selector, keyHash, amount, limit)
        );
        validator.exposedValidateCardData(_emvFields(amount), address(this), keyHash);
    }

    function testFuzz_EMVValidatorRejectsAmountsAboveCycleMax(uint96 rawLimit, uint96 rawOverBy) public {
        uint96 limit = uint96(bound(rawLimit, 0, 999_999_999_998));
        uint96 overBy = uint96(bound(rawOverBy, 1, 999_999_999_999 - limit));
        uint96 amount = limit + overBy;

        validator.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y, limit, type(uint96).max));

        vm.expectRevert(abi.encodeWithSelector(EMVValidator.CycleLimitExceeded.selector, keyHash, amount, limit));
        validator.exposedValidateCardData(_emvFields(amount), address(this), keyHash);
    }

    function _emvSignatureEnvelope() private view returns (bytes memory) {
        return abi.encodePacked(keyHash, TEST_PUBKEY_X, TEST_PUBKEY_Y, TEST_SIGNATURE);
    }

    function _accountExecuteCall(address target, bytes memory emvFields) private pure returns (bytes memory) {
        return _accountExecuteRawInnerCall(target, abi.encodeWithSelector(EMVSettlement.execute.selector, emvFields));
    }

    function _accountExecuteRawInnerCall(address target, bytes memory innerCallData)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            ACCOUNT_EXECUTE_SELECTOR,
            ExecLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)
            ),
            abi.encodePacked(target, innerCallData)
        );
    }

    function _emvFields(uint96 amountCents) private pure returns (bytes memory) {
        return abi.encodePacked(
            bytes2(0),
            bytes4(0x12345678),
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

    function _cardDataBase(address account, bytes32 cardKeyHash) private pure returns (bytes32) {
        bytes32 accountSlot = keccak256(abi.encode(account, uint256(0)));
        return keccak256(abi.encode(cardKeyHash, accountSlot));
    }

    function _replaceEMVField(bytes memory fields, uint256 offset, bytes memory value)
        private
        pure
        returns (bytes memory)
    {
        for (uint256 i = 0; i < value.length; i++) {
            fields[offset + i] = value[i];
        }
        return fields;
    }
}
