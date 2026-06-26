// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "lib/kernel/test/base/KernelTestBase.sol";
import {EMVSigner, EMVTransactionData} from "../src/EMVSigner.sol";
import {EMVSettlement} from "../src/EMVSettlement.sol";
import {AcquirerConfig} from "../src/AcquirerConfig.sol";
import {EMVCardPolicy} from "../src/policy/EMVCardPolicy.sol";
import {EMVLimitPolicy} from "../src/policy/EMVLimitPolicy.sol";
import {ANSEncoding} from "../src/util/ANSEncoding.sol";
import {EMVCallData} from "../src/util/EMVCallData.sol";
import {DeployBaseSepolia} from "../script/DeployBaseSepolia.s.sol";
import {SIG_VALIDATION_SUCCESS_UINT, SIG_VALIDATION_FAILED_UINT} from "kernel/src/types/Constants.sol";
import {PackedUserOperation as KernelUserOp} from "kernel/src/interfaces/PackedUserOperation.sol";
import {P256} from "solady/utils/P256.sol";
import "forge-std/console.sol";

struct CallPolicyPermission {
    CallType callType;
    address target;
    bytes4 selector;
    uint256 valueLimit;
    CallPolicyParamRule[] rules;
}

struct CallPolicyParamRule {
    CallPolicyParamCondition condition;
    uint64 offset;
    bytes32[] params;
}

enum CallPolicyParamCondition {
    EQUAL,
    GREATER_THAN,
    LESS_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN_OR_EQUAL,
    NOT_EQUAL,
    ONE_OF
}

enum CallPolicyStatus {
    NA,
    Live,
    Deprecated
}

interface ICallPolicy {
    function onInstall(bytes calldata data) external payable;
    function status(bytes32 id, address account) external view returns (CallPolicyStatus);
    function encodedPermissions(bytes32 id, bytes32 permissionHash, address account)
        external
        view
        returns (bytes memory);
    function checkUserOpPolicy(bytes32 id, KernelUserOp calldata userOp) external payable returns (uint256);
}

interface IP256VerifierCodeDeployer {
    function deployRuntimeCode() external returns (bytes memory);
}

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract MaliciousEMVDelegate {
    address immutable token;
    address immutable recipient;
    uint256 immutable amount;

    constructor(address token_, address recipient_, uint256 amount_) {
        token = token_;
        recipient = recipient_;
        amount = amount_;
    }

    function execute(bytes calldata) external {
        IERC20Transfer(token).transfer(recipient, amount);
    }
}

contract EMVSignerTest is KernelTestBase {
    EMVSigner public emvSigner;
    EMVSettlement public emvSettlement;
    AcquirerConfig public acquirerConfig;
    EMVCardPolicy public emvCardPolicy;
    EMVLimitPolicy public emvLimitPolicy;
    ICallPolicy public callPolicy;
    address public merchantAddress;

    // Event declarations for testing
    event EMVSignatureValidated(address indexed kernel, bool success);
    event ReplayProtectionUpdated(
        address indexed kernel, bytes32 indexed keyHash, bytes4 unpredictableNumber, uint256 newATC
    );
    event EMVCardFrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardUnfrozen(address indexed account, bytes32 indexed keyHash);
    event EMVCardRevoked(address indexed account, bytes32 indexed keyHash);

    // Test P-256 keypair (ECDSA secp256r1)
    // Private key (reference only): 0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464
    bytes32 constant TEST_PUBKEY_X = 0x1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83;
    bytes32 constant TEST_PUBKEY_Y = 0xce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9;
    bytes32 constant OTHER_PUBKEY_X = bytes32(uint256(0x1234));
    bytes32 constant OTHER_PUBKEY_Y = bytes32(uint256(0x5678));
    address constant ZERODEV_CALL_POLICY_V0_0_5 = 0x85770b902D1e503D5f5141d9eaC16d0d08eEaDd2;

    // Test EMV data
    bytes constant TEST_ARQC = hex"1234567890ABCDEF";
    bytes constant TEST_UNPREDICTABLE_NUMBER = hex"12345678";
    bytes constant TEST_ATC = hex"0000";
    bytes constant TEST_AMOUNT = hex"000000010000";
    bytes constant TEST_CURRENCY = hex"0840"; // 840 USD in BCD format (n3 per EMV spec)
    bytes constant TEST_DATE = hex"231201";
    bytes constant TEST_TXN_TYPE = hex"00";
    bytes constant TEST_TVR = hex"0000000000";
    bytes constant TEST_CVM_RESULTS = hex"000000";
    bytes constant TEST_TERMINAL_ID = hex"5445535430303100"; // "TEST001" padded to 8 bytes with null
    bytes constant TEST_MERCHANT_ID = hex"4D45524348414E5430303132333400"; // Low 15 bytes of TEST_MERCHANT_ADDRESS
    address constant TEST_MERCHANT_ADDRESS = address(uint160(0x00000000004d45524348414E5430303132333400));
    bytes constant TEST_ACQUIRER_ID = hex"414351554952"; // "ACQUIR" as 6 bytes

    // Helper functions to convert bytes to integers for AcquirerConfig interface
    function bytesToUint48(bytes6 b) internal pure returns (uint48) {
        return uint48(bytes6(b));
    }

    function bytesToUint64(bytes8 b) internal pure returns (uint64) {
        return uint64(bytes8(b));
    }

    function bytesToUint120(bytes15 b) internal pure returns (uint120) {
        return uint120(bytes15(b));
    }

    function merchantIdFromAddress(address merchant) internal pure returns (uint120) {
        return uint120(uint160(merchant));
    }

    // Valid P-256 ECDSA signature (r||s, 64 bytes), low-s normalized.
    // Signed data: SHA-256(52-byte ATC(2)||PDOL(50) message) under the test key above.
    // Regenerate with: node script/generate-p256-test-sig.js
    bytes constant TEST_SIGNATURE = hex"e6a9a4f20d16a123252c98913b9f7cd740d20f4acdbb2d70d9edb86a70602797" // r
        hex"2502bc1502afe1072734ac5a0f16483bbf9f123c3b213699a8ddad289a3314d7"; // s

    function _testKeyHash() internal pure returns (bytes32) {
        return keccak256(abi.encode(TEST_PUBKEY_X, TEST_PUBKEY_Y));
    }

    function _otherKeyHash() internal pure returns (bytes32) {
        return keccak256(abi.encode(OTHER_PUBKEY_X, OTHER_PUBKEY_Y));
    }

    function _createEMVSignature() internal pure returns (bytes memory) {
        return abi.encodePacked(_testKeyHash(), TEST_PUBKEY_X, TEST_PUBKEY_Y, TEST_SIGNATURE);
    }

    function _createEMVSignatureForKey(bytes32 pubkeyX, bytes32 pubkeyY) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(pubkeyX, pubkeyY)), pubkeyX, pubkeyY, TEST_SIGNATURE);
    }

    function _createEMVPermissionSignature(bytes memory signature) internal pure returns (bytes memory) {
        return _createEMVPermissionSignatureForCardPolicy(1, signature, signature);
    }

    function _createEMVPermissionSignatureForCardPolicy(
        uint8 cardPolicyIndex,
        bytes memory policySignature,
        bytes memory signerSignature
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(cardPolicyIndex),
            bytes8(uint64(policySignature.length)),
            policySignature,
            bytes1(0xff),
            signerSignature
        );
    }

    function setUp() public override {
        super.setUp(); // Initialize KernelTestBase

        if (!P256.hasPrecompile()) {
            address p256VerifierCodeDeployer =
                deployCode("test/utils/P256VerifierCodeDeployer.sol:P256VerifierCodeDeployer");
            bytes memory p256VerifierCode = IP256VerifierCodeDeployer(p256VerifierCodeDeployer).deployRuntimeCode();
            vm.etch(address(0x100), p256VerifierCode);
        }

        // Deploy EMV components
        acquirerConfig = new AcquirerConfig();
        merchantAddress = TEST_MERCHANT_ADDRESS;

        // Set up acquirer fee recipient
        address acquirerAddress = makeAddr("acquirer");

        // Set up acquirer and register it
        uint48 testAcquirerId = bytesToUint48(bytes6(TEST_ACQUIRER_ID));
        acquirerConfig.setAcquirer(testAcquirerId, address(this)); // This test contract is the acquirer

        // Configure fees for this acquirer
        acquirerConfig.setAcquirerFee(testAcquirerId, acquirerAddress, 25); // 0.25% acquirer fee (25 basis points, within max 30)
        acquirerConfig.setSwipeFee(testAcquirerId, 50 * 10 ** 16); // $0.50 fixed swipe fee

        // Configure global network and interchange fees
        acquirerConfig.setNetworkFee(address(this), 15); // 0.15% network fee
        acquirerConfig.setInterchangeFee(address(this), 200); // 2.00% interchange fee

        // Merchant chooses its acquirer.
        vm.prank(merchantAddress);
        acquirerConfig.setMerchant(merchantIdFromAddress(merchantAddress), testAcquirerId);

        // Deploy settlement contract with configuration
        emvSettlement = new EMVSettlement(
            address(mockERC20), // token address
            address(acquirerConfig), // acquirer config address
            18 // token decimals
        );

        emvSigner = new EMVSigner();
        emvCardPolicy = new EMVCardPolicy();
        emvLimitPolicy = new EMVLimitPolicy();
        callPolicy = ICallPolicy(ZERODEV_CALL_POLICY_V0_0_5);

        // Mint tokens to the test contract and kernel
        mockERC20.mint(address(this), 1e24); // 1 million tokens with 18 decimals
        mockERC20.mint(address(kernel), 1e24); // 1 million tokens to kernel for EMV transfers

        // Verify test contract has tokens from the inherited mockERC20
        uint256 balance = mockERC20.balanceOf(address(this));
        console.log("Test contract balance from mockERC20:", balance);
    }

    // Helper to install EMVSigner as validator, executor, and hook
    function _installEMVSigner() internal {
        vm.deal(address(kernel), 1e18);

        // Install EMVSigner as validator with public key registration
        PackedUserOperation[] memory ops1 = new PackedUserOperation[](1);
        ops1[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_VALIDATOR,
                address(emvSigner),
                abi.encodePacked(
                    address(0), // No hook for validator
                    abi.encode(
                        abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y), // validator data - ATC + P-256 pubkey
                        hex"", // hook data
                        abi.encodePacked(kernel.execute.selector) // selector data - grant access to execute
                    )
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops1, payable(address(0xdeadbeef)));

        // Install EMVSettlement as executor
        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_EXECUTOR,
                address(emvSettlement),
                abi.encodePacked(
                    address(0), // No hook for executor
                    abi.encode(
                        abi.encode(address(mockERC20), address(acquirerConfig), uint8(18)), // executor data - configure token, registry, and decimals
                        hex"", // hook data
                        hex"" // selector data
                    )
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(ops2, payable(address(0xdeadbeef)));
    }

    function _emvPermission() internal pure returns (PermissionId) {
        return PermissionId.wrap(bytes4(0xe0e0e0e0));
    }

    function _emvPermissionKey() internal pure returns (bytes32) {
        return bytes32(PermissionId.unwrap(_emvPermission()));
    }

    function _installEMVCardPolicyFor(address account, bytes32 permission, uint16 atc, bytes32 pubkeyX, bytes32 pubkeyY)
        internal
    {
        vm.prank(account);
        emvCardPolicy.onInstall(abi.encodePacked(permission, abi.encode(atc, pubkeyX, pubkeyY)));
    }

    function _installKernelEMVCardPolicy() internal {
        _installEMVCardPolicyFor(address(kernel), _emvPermissionKey(), 0, TEST_PUBKEY_X, TEST_PUBKEY_Y);
    }

    function _uninstallEMVCardPolicyFor(address account, bytes32 permission) internal {
        vm.prank(account);
        emvCardPolicy.onUninstall(abi.encodePacked(permission));
    }

    function _installEMVLimitPolicyFor(address account, bytes32 permission, uint64 cycleMax, uint64 perTxnMax)
        internal
    {
        vm.prank(account);
        emvLimitPolicy.onInstall(abi.encodePacked(permission, abi.encode(cycleMax, perTxnMax)));
    }

    function _uninstallEMVLimitPolicyFor(address account, bytes32 permission) internal {
        vm.prank(account);
        emvLimitPolicy.onUninstall(abi.encodePacked(permission));
    }

    function _assertKernelCardReplayState(uint256 expectedATC, bytes4 unpredictableNumber, bool used) internal view {
        assertEq(emvCardPolicy.getExpectedATC(address(kernel), _testKeyHash()), expectedATC);
        assertEq(emvCardPolicy.isUnpredictableNumberUsed(address(kernel), _testKeyHash(), unpredictableNumber), used);
    }

    function _callPolicyInstallData(address target, bytes4 selector) internal pure returns (bytes memory) {
        CallPolicyPermission[] memory callPermissions = new CallPolicyPermission[](1);
        CallPolicyParamRule[] memory rules = new CallPolicyParamRule[](0);
        callPermissions[0] = CallPolicyPermission({
            callType: CALLTYPE_DELEGATECALL, target: target, selector: selector, valueLimit: 0, rules: rules
        });

        return abi.encode(callPermissions);
    }

    function _requireZeroDevCallPolicy() internal {
        vm.skip(
            address(callPolicy).code.length == 0,
            "ZeroDev CallPolicy is not deployed on this local chain; run this test on a fork"
        );
    }

    function _callPolicyPermissionData() internal view returns (bytes memory) {
        return abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, true, address(callPolicy))),
            _callPolicyInstallData(address(emvSettlement), emvSettlement.execute.selector)
        );
    }

    function _cardPolicyPermissionData(bytes32 pubkeyX, bytes32 pubkeyY) internal view returns (bytes memory) {
        return abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(emvCardPolicy))),
            abi.encode(uint16(0), pubkeyX, pubkeyY)
        );
    }

    function _limitPolicyPermissionData(uint64 cycleMax, uint64 perTxnMax) internal view returns (bytes memory) {
        return abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, true, address(emvLimitPolicy))),
            abi.encode(cycleMax, perTxnMax)
        );
    }

    function _signerPermissionData(bytes32 pubkeyX, bytes32 pubkeyY) internal view returns (bytes memory) {
        return abi.encodePacked(
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, true, address(emvSigner))),
            abi.encode(uint16(0), pubkeyX, pubkeyY)
        );
    }

    function _installEMVPermission(bytes[] memory permissions) internal {
        _requireZeroDevCallPolicy();
        _installEMVPermissionWithoutCallPolicyRequirement(permissions);
    }

    function _installEMVPermissionWithoutCallPolicyRequirement(bytes[] memory permissions) internal {
        vm.deal(address(kernel), 1e18);

        PermissionId permission = _emvPermission();
        ValidationId vId = ValidatorLib.permissionToIdentifier(permission);

        _installEMVPermission(vId, permissions);
    }

    function _installEMVPermission(ValidationId vId, bytes[] memory permissions) internal {
        ValidationId[] memory validators = new ValidationId[](1);
        validators[0] = vId;

        ValidationManager.ValidationConfig[] memory configs = new ValidationManager.ValidationConfig[](1);
        configs[0] = ValidationManager.ValidationConfig({nonce: uint32(1), hook: IHook(address(1))});

        bytes[] memory validatorData = new bytes[](1);
        validatorData[0] = abi.encode(permissions);

        bytes[] memory hookData = new bytes[](1);
        hookData[0] = hex"";

        PackedUserOperation[] memory installPermissionOps = new PackedUserOperation[](1);
        installPermissionOps[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(kernel.installValidations.selector, validators, configs, validatorData, hookData),
            true,
            true,
            false
        );
        entrypoint.handleOps(installPermissionOps, payable(address(0xdeadbeef)));

        PackedUserOperation[] memory grantAccessOps = new PackedUserOperation[](1);
        grantAccessOps[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(kernel.grantAccess.selector, vId, kernel.execute.selector, true),
            true,
            true,
            false
        );
        entrypoint.handleOps(grantAccessOps, payable(address(0xdeadbeef)));

        PackedUserOperation[] memory installExecutorOps = new PackedUserOperation[](1);
        installExecutorOps[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_EXECUTOR,
                address(emvSettlement),
                abi.encodePacked(
                    address(0),
                    abi.encode(abi.encode(address(mockERC20), address(acquirerConfig), uint8(18)), hex"", hex"")
                )
            ),
            true,
            true,
            false
        );
        entrypoint.handleOps(installExecutorOps, payable(address(0xdeadbeef)));
    }

    function _installEMVPermissionWithPolicies(uint64 cycleMax, uint64 perTxnMax) internal {
        bytes[] memory permissions = new bytes[](4);
        permissions[0] = _callPolicyPermissionData();
        permissions[1] = _cardPolicyPermissionData(TEST_PUBKEY_X, TEST_PUBKEY_Y);
        permissions[2] = _limitPolicyPermissionData(cycleMax, perTxnMax);
        permissions[3] = _signerPermissionData(TEST_PUBKEY_X, TEST_PUBKEY_Y);

        _installEMVPermission(permissions);
    }

    function _createEMVFields() internal pure returns (bytes memory) {
        // 52-byte applet message: ATC(2) || PDOL(50), SLICE-FROM-FRONT layout
        // (PaymentApplication.generateEcdsaAtGpo). 9F01 (acquirer) and 9F21 (time) are
        // DROPPED from the signed PDOL: settlement derives the acquirer from the signed merchant
        // ID, and time drifts between GPO signing and host reconstruction. The 7 contract-validated
        // fields are front-loaded; the advisory tail (country/date/MCC) follows.
        return abi.encodePacked(
            TEST_ATC, // 9F36 ATC (2)                       off 0
            TEST_UNPREDICTABLE_NUMBER, // 9F37 UN (4)        off 2
            TEST_TXN_TYPE, // 9C Transaction Type (1)        off 6
            TEST_CURRENCY, // 5F2A Currency (2)              off 7
            TEST_AMOUNT, // 9F02 Amount Authorised (6)       off 9
            hex"000000000000", // 9F03 Amount Other (6)      off 15
            hex"02", // 5F36 Currency Exponent (1)           off 21
            TEST_MERCHANT_ID, // 9F16 Merchant ID (15)       off 22
            TEST_TERMINAL_ID, // 9F1C Terminal ID (8)        off 37
            hex"0840", // 9F1A Terminal Country Code (2)     off 45
            TEST_DATE, // 9A Transaction Date (3)            off 47
            hex"5999" // 9F15 Merchant Category Code (2)     off 50  (message ends @52)
        );
    }

    function _signedPayloadHash() internal pure returns (bytes32) {
        return sha256(_createEMVFields());
    }

    function _createEMVFieldsWithByte(uint256 offset, bytes1 value) internal pure returns (bytes memory fields) {
        fields = _createEMVFields();
        fields[offset] = value;
    }

    function _replaceEMVField(bytes memory fields, uint256 offset, bytes memory value)
        internal
        pure
        returns (bytes memory)
    {
        for (uint256 i = 0; i < value.length; i++) {
            fields[offset + i] = value[i];
        }
        return fields;
    }

    function _createEMVTransactionData() internal pure returns (bytes memory) {
        // Legacy format for tests that need both fields and signature.
        return abi.encodePacked(_createEMVFields(), TEST_SIGNATURE);
    }

    function _createInvalidEMVTransactionData() internal pure returns (bytes memory) {
        // Encode without padding to allow single-slice extraction - with invalid signature length
        return abi.encodePacked(
            _createEMVFields(),
            hex"deadbeef" // Invalid short signature
        );
    }

    function _encodeEMVExecuteCall() internal view returns (bytes memory) {
        // First install the EMV processor as an executor
        bytes memory installExecutorCall = abi.encodeWithSelector(
            kernel.installModule.selector,
            MODULE_TYPE_EXECUTOR,
            address(emvSigner),
            abi.encodePacked(
                address(0), // No hook
                abi.encode(
                    abi.encode(address(mockERC20), merchantAddress, address(acquirerConfig), uint16(0)), // executor data
                    hex"" // hook data
                )
            )
        );

        // Then execute the EMV transfer
        bytes memory emvTransferCall =
            abi.encodeWithSelector(emvSettlement.execute.selector, _createEMVTransactionData());

        // Use batch execution to install executor and execute transfer
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({target: address(kernel), value: 0, callData: installExecutorCall});
        executions[1] = Execution({target: address(kernel), value: 0, callData: emvTransferCall});

        return encodeBatchExecute(executions);
    }

    function _encodeSimpleTransferCall() internal view returns (bytes memory) {
        return _encodeSimpleTransferCall(_createEMVFields());
    }

    function _encodeSimpleTransferCall(bytes memory emvFields) internal view returns (bytes memory) {
        return _encodeDelegateExecuteCall(address(emvSettlement), emvSettlement.execute.selector, emvFields);
    }

    function _encodeDelegateExecuteCall(address target, bytes4 selector, bytes memory emvFields)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)
            ),
            abi.encodePacked(target, abi.encodeWithSelector(selector, emvFields))
        );
    }

    function _prepareEMVUserOp(bytes memory callData, bool success) internal returns (PackedUserOperation memory op) {
        // Create a UserOperation that uses EMVSigner as the validator
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(emvSigner)),
            0 // parallel key
        );

        // Prepare signature: valid P-256 envelope or invalid short signature
        bytes memory signature;
        if (success) {
            signature = _createEMVSignature();
        } else {
            signature = hex"deadbeef";
        }

        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), nonceKey),
            initCode: "",
            callData: callData, // Contains EMV fields embedded in kernel.execute call
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _prepareEMVPermissionUserOp(bytes memory callData, bool success)
        internal
        returns (PackedUserOperation memory op)
    {
        PermissionId permission = _emvPermission();
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_PERMISSION),
            bytes20(PermissionId.unwrap(permission)),
            0
        );

        bytes memory signature;
        if (success) {
            signature = _createEMVSignature();
        } else {
            signature = hex"deadbeef";
        }
        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), nonceKey),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2000000), uint128(2000000))),
            preVerificationGas: 2000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: _createEMVPermissionSignature(signature)
        });
    }

    function _expectInvalidEMVPayload(bytes memory emvFields) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(_encodeSimpleTransferCall(emvFields), true);

        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function _expectEMVLimitPolicyFailure(bytes memory emvFields) internal {
        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall(emvFields);

        vm.prank(address(kernel));
        uint256 validationData = emvLimitPolicy.checkUserOpPolicy(bytes32(PermissionId.unwrap(_emvPermission())), op);

        assertEq(validationData, SIG_VALIDATION_FAILED_UINT);
    }

    function test_Deployment() public whenInitialized {
        assertTrue(address(emvSigner) != address(0));
        assertTrue(address(kernel) != address(0));
        assertTrue(address(entrypoint) != address(0));

        // Check that the kernel was initialized with MockValidator as root validator
        assertEq(ValidationId.unwrap(kernel.rootValidator()), ValidationId.unwrap(rootValidation));

        // EMVSigner should not be installed yet
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvSigner), ""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(emvSettlement), ""));
    }

    function test_ModuleType() public {
        assertTrue(emvSigner.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(emvSigner.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(emvSigner.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(emvSigner.isModuleType(MODULE_TYPE_FALLBACK));

        // Test EMVSettlement module types
        assertTrue(emvSettlement.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(emvSettlement.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(emvSettlement.isModuleType(MODULE_TYPE_HOOK));
    }

    function test_InvalidCallDataValidation() public whenInitialized {
        // Install EMVSigner as both validator and executor
        _installEMVSigner();

        // Create a UserOp with wrong function selector
        bytes memory wrongCallData = abi.encodeWithSelector(bytes4(keccak256("wrongFunction()")));
        PackedUserOperation memory userOp = _prepareEMVUserOp(wrongCallData, true);

        // The EntryPoint will wrap the signer failure in FailedOpWithRevert.
        vm.expectRevert(); // Just expect any revert since EntryPoint wraps errors
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(0x69)));
    }

    function test_ValidEMVTransaction() public whenInitialized {
        // Install EMVSigner as both validator and executor
        _installEMVSigner();

        // Verify that EMVSigner was installed properly
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvSigner), ""), "EMVSigner should be installed"
        );

        // Check test contract balance first
        uint256 testBalance = mockERC20.balanceOf(address(this));
        console.log("Test contract balance:", testBalance);

        // Fund the kernel with tokens for transfer (reasonable amount)
        mockERC20.transfer(address(kernel), 1e21); // 1,000 tokens
        vm.deal(address(kernel), 1e18);

        // Check that kernel has the tokens
        uint256 kernelBalance = mockERC20.balanceOf(address(kernel));
        console.log("Kernel balance before EMV transaction:", kernelBalance);
        assertGt(kernelBalance, 1e20, "Kernel should have enough tokens");

        // Create a UserOperation using EMVSigner as validator to execute simple transfer
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            true // successful signature
        );

        // Execute the operation through EntryPoint
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        // Check that the transfer was successful
        uint256 merchantBalance = mockERC20.balanceOf(merchantAddress);
        assertGt(merchantBalance, 0, "Merchant should have received tokens");

        // The amount should be 1e20 wei (100.00 dollars worth) minus all fees
        // Fees: 0.25% acquirer (0.25) + $0.50 swipe (0.50) + 0.15% network (0.15) + 2.00% interchange (2.00) = 2.90 tokens deducted
        // Expected merchant amount: 100 - 2.90 = 97.10 tokens = 97.10e18
        uint256 expectedMerchantAmount = 971e17; // 97.1 * 10^17 = 97.1e18
        assertEq(merchantBalance, expectedMerchantAmount, "Merchant should have received 97.1 tokens after all fees");
    }

    function test_InvalidEMVSignature() public whenInitialized {
        // Install EMVSigner as both validator and executor
        _installEMVSigner();

        // Fund the kernel with tokens for transfer
        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Create a UserOperation with invalid EMV signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            false // invalid signature
        );

        // Expect the operation to fail due to invalid signature format.
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_EMVSignatureBindsMessageFields() public whenInitialized {
        _installEMVSigner();

        mockERC20.transfer(address(kernel), 1e21);
        vm.deal(address(kernel), 1e18);

        // Every byte of the 52-byte ATC||PDOL message is signed, so tampering any
        // field invalidates the payload. Offsets per the canonical PDOL layout.
        _expectInvalidEMVPayload(_createEMVFieldsWithByte(0, bytes1(0x99))); // ATC
        _expectInvalidEMVPayload(_createEMVFieldsWithByte(2, bytes1(0x24))); // 9F37 UN
        _expectInvalidEMVPayload(_createEMVFieldsWithByte(9, bytes1(0x24))); // 9F02 Amount
        _expectInvalidEMVPayload(_createEMVFieldsWithByte(22, bytes1(0x80))); // 9F16 Merchant Id
        _expectInvalidEMVPayload(_createEMVFieldsWithByte(50, bytes1(0x01))); // 9F15 Merchant Category Code (tail)
    }

    function test_EMVSignerRejectsCompactPayload() public whenInitialized {
        _installEMVSigner();

        mockERC20.transfer(address(kernel), 1e21);
        vm.deal(address(kernel), 1e18);

        bytes memory compactFields = abi.encodePacked(
            bytes3("ICC"),
            TEST_AMOUNT,
            TEST_UNPREDICTABLE_NUMBER,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_ATC,
            TEST_CURRENCY
        );

        _expectInvalidEMVPayload(compactFields);
    }

    function test_EMVSignatureBindsSettlementRoutingFields() public whenInitialized {
        _installEMVSigner();

        mockERC20.transfer(address(kernel), 1e21);
        vm.deal(address(kernel), 1e18);

        address attackerMerchant = makeAddr("attackerMerchant");
        uint48 attackerAcquirerId = bytesToUint48(bytes6(TEST_ACQUIRER_ID));
        uint120 attackerMerchantId = merchantIdFromAddress(attackerMerchant);

        // Reuse the configured acquirer; register the attacker's merchant under it so the signature
        // over the merchant routing field is the only thing standing between the attacker and funds.
        vm.prank(attackerMerchant);
        acquirerConfig.setMerchant(attackerMerchantId, attackerAcquirerId);

        bytes memory reroutedFields = _createEMVFields();
        // Slice-from-front offsets: 9F16 Merchant @ 22, 9F1C Terminal @ 37.
        // 9F01 Acquirer is no longer in the signed message.
        reroutedFields = _replaceEMVField(reroutedFields, 22, abi.encodePacked(attackerMerchantId));
        reroutedFields = _replaceEMVField(reroutedFields, 37, abi.encodePacked(bytes8("BADTERM1")));

        _expectInvalidEMVPayload(reroutedFields);
        assertEq(mockERC20.balanceOf(attackerMerchant), 0, "Rerouted merchant should not receive funds");
    }

    function test_EMVLimitPolicyEnforcesAuxiliarySignedFields() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        // 9C Transaction Type @ 6 — only purchase (0x00) is accepted.
        _expectEMVLimitPolicyFailure(_createEMVFieldsWithByte(6, bytes1(0x09)));

        // 9F03 Amount, Other @ 15 — must be zero (no secondary amount / cashback).
        _expectEMVLimitPolicyFailure(_createEMVFieldsWithByte(15, bytes1(0x01)));

        // 5F36 Transaction Currency Exponent @ 21 — must equal the supported minor-unit exponent (2).
        _expectEMVLimitPolicyFailure(_createEMVFieldsWithByte(21, bytes1(0x03)));
    }

    function test_InstallEMVAsValidatorAndExecutor() public whenInitialized {
        // Install EMVSigner as both validator and executor
        _installEMVSigner();

        // Check that both modules were installed
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvSigner), ""));
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(emvSettlement), ""));
    }

    function test_MerchantRegistryIntegration() public whenInitialized {
        // Install EMVSigner as both validator and executor
        _installEMVSigner();

        // Fund the kernel with tokens for transfer
        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Check initial balances
        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);

        // Create a UserOperation using EMVSigner as validator to execute EMV transfer
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            true // successful signature
        );

        // Execute the operation through EntryPoint
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        // Check that the transfer was successful
        uint256 merchantBalanceAfter = mockERC20.balanceOf(merchantAddress);
        assertGt(merchantBalanceAfter, merchantBalanceBefore);

        // The amount should be 100.00 dollars = 1e20 wei (based on TEST_AMOUNT) minus all fees
        // Fees: 0.25% acquirer (0.25) + $0.50 swipe (0.50) + 0.15% network (0.15) + 2.00% interchange (2.00) = 2.90 tokens deducted
        // Expected merchant amount: 100 - 2.90 = 97.10 tokens = 97.10e18
        uint256 expectedIncrease = 971e17; // 97.1 * 10^17 = 97.1e18
        assertEq(merchantBalanceAfter - merchantBalanceBefore, expectedIncrease);
    }

    // Removed test_DynamicDataAssembly - RSA-specific format no longer used in P-256

    function test_SecurityVulnerability_ValidatorExecutorSeparation() public whenInitialized {
        // This test verifies that the security vulnerability has been FIXED:
        // EMV validation now prevents execution that doesn't match EMV constraints

        // Install EMVSigner as validator with access to execute
        _installEMVSigner();

        // Fund the kernel with tokens
        mockERC20.transfer(address(kernel), 1e21);
        vm.deal(address(kernel), 1e18);

        // Try to create a malicious UserOperation:
        // - Uses valid EMV signature for validation
        // - But tries to execute a DIFFERENT action (transfer to attacker instead of merchant)
        address attacker = makeAddr("attacker");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            // MALICIOUS: Transfer to attacker instead of merchant, ignoring EMV data
            abi.encodeWithSelector(
                kernel.execute.selector,
                ExecMode.wrap(bytes32(0)),
                ExecLib.encodeSingle(
                    address(mockERC20),
                    0,
                    abi.encodeWithSelector(
                        mockERC20.transfer.selector,
                        attacker, // Attacker tries to get the funds!
                        1e21 // Much more than the EMV amount!
                    )
                )
            ),
            true // Valid EMV signature
        );

        // SECURITY FIX: The operation should now FAIL during validation
        vm.expectRevert(); // Should revert with InvalidExecutionRecipient or InvalidExecutionAmount
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        // Verify that the attack was prevented:
        uint256 attackerBalance = mockERC20.balanceOf(attacker);
        uint256 merchantBalance = mockERC20.balanceOf(merchantAddress);

        // Security is now enforced:
        assertEq(attackerBalance, 0, "Attacker should NOT receive funds");
        assertEq(merchantBalance, 0, "Merchant should also not receive funds (transaction failed)");
    }

    function test_ZeroPublicKeyBlocked() public {
        // Test that zero P-256 public key is blocked during installation
        bytes32 zeroPubkeyX = bytes32(0);
        bytes32 zeroPubkeyY = bytes32(0);

        // Create a new validator for this test
        EMVSigner testValidator = new EMVSigner();

        // Try to install with zero public key - should fail with InvalidPublicKeySize
        vm.expectRevert(EMVSigner.InvalidPublicKeySize.selector);
        testValidator.onInstall(abi.encode(uint16(0), zeroPubkeyX, zeroPubkeyY));
    }

    // Note: Direct validateUserOp gas measurement test removed due to memory/calldata conversion issues
    // Gas measurement can be done through the full E2E test flow via EntryPoint

    function test_GasMeasurement_CompleteEMVTransaction() public whenInitialized {
        // Comprehensive gas measurement test for complete EMV flow through entrypoint
        // This test measures the TOTAL gas cost of an EMV transaction from start to finish

        _installEMVSigner();

        // Fund the kernel
        mockERC20.transfer(address(kernel), 1e21); // 1000 tokens
        vm.deal(address(kernel), 10 ether);

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);

        // Create a UserOperation using EMVSigner
        PackedUserOperation memory userOp = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            true // successful signature
        );

        // Execute through EntryPoint
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Measure gas for the complete transaction
        uint256 gasBefore = gasleft();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        uint256 gasUsed = gasBefore - gasleft();

        // Verify transaction succeeded
        uint256 merchantBalanceAfter = mockERC20.balanceOf(merchantAddress);
        assertGt(merchantBalanceAfter, merchantBalanceBefore, "Merchant should have received tokens");

        // Report gas usage
        console.log("\n========== GAS MEASUREMENT: Complete EMV Transaction ==========");
        console.log("Total gas used:", gasUsed);

        // The gas used by this test will be captured by forge snapshot
        // Run: forge snapshot --match-test test_GasMeasurement_CompleteEMVTransaction
    }

    function test_GasMeasurement_CompleteEMVTransaction_LimitPolicy() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        mockERC20.transfer(address(kernel), 1e21);
        vm.deal(address(kernel), 10 ether);

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);

        PackedUserOperation memory userOp = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        uint256 gasBefore = gasleft();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        uint256 gasUsed = gasBefore - gasleft();

        uint256 merchantBalanceAfter = mockERC20.balanceOf(merchantAddress);
        assertGt(merchantBalanceAfter, merchantBalanceBefore, "Merchant should have received tokens");

        (, uint64 cycleMax, uint64 cycleTotal, uint64 perTxnMax) =
            emvLimitPolicy.getLimits(address(kernel), bytes32(PermissionId.unwrap(_emvPermission())));
        assertEq(cycleMax, type(uint64).max);
        assertEq(perTxnMax, type(uint64).max);
        assertEq(cycleTotal, 10_000);

        console.log("\n========== GAS MEASUREMENT: Permission Policy EMV Transaction ==========");
        console.log("Total gas used:", gasUsed);
    }

    function test_EMVPermissionInstallsLimitPolicyAndSigner() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        PermissionId permission = _emvPermission();
        ValidationManager.PermissionConfig memory config = kernel.permissionConfig(permission);

        assertEq(PassFlag.unwrap(config.permissionFlag), PassFlag.unwrap(ValidatorLib.encodeFlag(false, true)));
        assertEq(address(config.signer), address(emvSigner));
        assertEq(config.policyData.length, 3);
        assertEq(
            PolicyData.unwrap(config.policyData[0]),
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, true, address(callPolicy)))
        );
        assertEq(
            PolicyData.unwrap(config.policyData[1]),
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, false, address(emvCardPolicy)))
        );
        assertEq(
            PolicyData.unwrap(config.policyData[2]),
            PolicyData.unwrap(ValidatorLib.encodePolicyData(false, true, address(emvLimitPolicy)))
        );
        assertEq(emvCardPolicy.getPermissionKeyHash(address(kernel), _emvPermissionKey()), _testKeyHash());
        assertEq(emvSigner.getAuthorizedKeyHash(address(kernel), _emvPermissionKey()), _testKeyHash());
    }

    function test_EMVCardPolicyRejectsSignatureForDifferentRegisteredKey() public whenInitialized {
        _installKernelEMVCardPolicy();

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignatureForKey(OTHER_PUBKEY_X, OTHER_PUBKEY_Y);

        vm.prank(address(kernel));
        vm.expectRevert(
            abi.encodeWithSelector(EMVCardPolicy.UnexpectedPublicKey.selector, _testKeyHash(), _otherKeyHash())
        );
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);
    }

    function test_EMVCardPolicyRejectsTamperedSignatureKeyEnvelope() public whenInitialized {
        _installKernelEMVCardPolicy();

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = abi.encodePacked(_testKeyHash(), OTHER_PUBKEY_X, OTHER_PUBKEY_Y, TEST_SIGNATURE);

        vm.prank(address(kernel));
        vm.expectRevert(EMVCardPolicy.InvalidPublicKey.selector);
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);
    }

    function test_EMVPermissionRejectsMismatchedCardPolicyAndSignerKeys() public whenInitialized {
        bytes[] memory permissions = new bytes[](4);
        permissions[0] = _callPolicyPermissionData();
        permissions[1] = _cardPolicyPermissionData(OTHER_PUBKEY_X, OTHER_PUBKEY_Y);
        permissions[2] = _limitPolicyPermissionData(type(uint64).max, type(uint64).max);
        permissions[3] = _signerPermissionData(TEST_PUBKEY_X, TEST_PUBKEY_Y);

        _installEMVPermission(permissions);

        assertEq(emvCardPolicy.getPermissionKeyHash(address(kernel), _emvPermissionKey()), _otherKeyHash());
        assertEq(emvSigner.getAuthorizedKeyHash(address(kernel), _emvPermissionKey()), _testKeyHash());

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(mockERC20.balanceOf(merchantAddress), merchantBalanceBefore);
    }

    function test_EMVPermissionRejectsMissingCardPolicySignatureSegment() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = abi.encodePacked(bytes1(0xff), _createEMVSignature());

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(mockERC20.balanceOf(merchantAddress), merchantBalanceBefore);
    }

    function test_EMVPermissionRejectsWrongCardPolicySignatureKey() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        bytes memory wrongPolicySignature = _createEMVSignatureForKey(OTHER_PUBKEY_X, OTHER_PUBKEY_Y);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = _createEMVPermissionSignatureForCardPolicy(1, wrongPolicySignature, _createEMVSignature());

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(mockERC20.balanceOf(merchantAddress), merchantBalanceBefore);
    }

    function test_EMVPermissionRejectsPolicySignatureOrderError() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        bytes memory signature = _createEMVSignature();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = abi.encodePacked(
            bytes1(uint8(1)),
            bytes8(uint64(signature.length)),
            signature,
            bytes1(uint8(1)),
            bytes8(uint64(0)),
            bytes1(0xff),
            signature
        );

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(mockERC20.balanceOf(merchantAddress), merchantBalanceBefore);
    }

    function test_EMVPermissionRejectsMissingSignerPrefix() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        bytes memory signature = _createEMVSignature();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = abi.encodePacked(bytes1(uint8(1)), bytes8(uint64(signature.length)), signature);

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        assertEq(mockERC20.balanceOf(merchantAddress), merchantBalanceBefore);
    }

    function test_EMVPermissionInvalidSignerDoesNotBurnCardReplayState() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        bytes memory policySignature = _createEMVSignature();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = _createEMVPermissionSignatureForCardPolicy(1, policySignature, hex"deadbeef");

        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(emvCardPolicy.getExpectedATC(address(kernel), _testKeyHash()), 0);
        assertFalse(
            emvCardPolicy.isUnpredictableNumberUsed(address(kernel), _testKeyHash(), bytes4(TEST_UNPREDICTABLE_NUMBER))
        );
    }

    function test_EMVPermissionWithoutCardPolicyDoesNotProvideReplayProtection() public whenInitialized {
        bytes[] memory permissions = new bytes[](3);
        permissions[0] = _callPolicyPermissionData();
        permissions[1] = _limitPolicyPermissionData(type(uint64).max, type(uint64).max);
        permissions[2] = _signerPermissionData(TEST_PUBKEY_X, TEST_PUBKEY_Y);

        _installEMVPermission(permissions);

        bytes memory signerOnlySignature = abi.encodePacked(bytes1(0xff), _createEMVSignature());
        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = signerOnlySignature;
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = signerOnlySignature;
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        uint256 expectedMerchantAmount = 971e17;
        assertEq(mockERC20.balanceOf(merchantAddress) - merchantBalanceBefore, expectedMerchantAmount * 2);
        assertEq(emvCardPolicy.getPermissionKeyHash(address(kernel), _emvPermissionKey()), bytes32(0));
    }

    function test_EMVPermissionWithoutCallPolicyCanDelegatecallUnapprovedTarget() public whenInitialized {
        bytes[] memory permissions = new bytes[](3);
        permissions[0] = _cardPolicyPermissionData(TEST_PUBKEY_X, TEST_PUBKEY_Y);
        permissions[1] = _limitPolicyPermissionData(type(uint64).max, type(uint64).max);
        permissions[2] = _signerPermissionData(TEST_PUBKEY_X, TEST_PUBKEY_Y);

        _installEMVPermissionWithoutCallPolicyRequirement(permissions);

        address attacker = makeAddr("callPolicyBypassAttacker");
        uint256 stolenAmount = 1e20;
        MaliciousEMVDelegate malicious = new MaliciousEMVDelegate(address(mockERC20), attacker, stolenAmount);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(
            _encodeDelegateExecuteCall(address(malicious), MaliciousEMVDelegate.execute.selector, _createEMVFields()),
            true
        );
        ops[0].signature = _createEMVPermissionSignatureForCardPolicy(0, _createEMVSignature(), _createEMVSignature());

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));

        assertEq(mockERC20.balanceOf(attacker), stolenAmount);
        assertEq(mockERC20.balanceOf(merchantAddress), merchantBalanceBefore);
    }

    function testFuzz_EMVCardPolicyMalformedSignatureLengthDoesNotMutateReplayState(uint8 signatureLength)
        public
        whenInitialized
    {
        vm.assume(signatureLength != 160);
        _installKernelEMVCardPolicy();

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = new bytes(signatureLength);

        vm.prank(address(kernel));
        vm.expectRevert(abi.encodeWithSelector(EMVCardPolicy.InvalidSignatureLength.selector, uint256(signatureLength)));
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);

        _assertKernelCardReplayState(0, bytes4(TEST_UNPREDICTABLE_NUMBER), false);
    }

    function testFuzz_EMVCardPolicyMalformedEMVFieldLengthDoesNotMutateReplayState(uint8 fieldLength)
        public
        whenInitialized
    {
        vm.assume(fieldLength != 52);
        _installKernelEMVCardPolicy();

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall(new bytes(fieldLength));
        op.signature = _createEMVSignature();

        vm.prank(address(kernel));
        vm.expectRevert(abi.encodeWithSelector(EMVCallData.InvalidEMVFieldLength.selector, uint256(fieldLength)));
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);

        _assertKernelCardReplayState(0, bytes4(TEST_UNPREDICTABLE_NUMBER), false);
    }

    function test_EMVCardPolicyCheckSignatureRejectsWrongKeyAndMalformedLength() public {
        _installEMVCardPolicyFor(address(this), _emvPermissionKey(), 0, TEST_PUBKEY_X, TEST_PUBKEY_Y);

        bytes32 signedPayloadHash = _signedPayloadHash();

        vm.expectRevert(
            abi.encodeWithSelector(EMVCardPolicy.UnexpectedPublicKey.selector, _testKeyHash(), _otherKeyHash())
        );
        emvCardPolicy.checkSignaturePolicy(
            _emvPermissionKey(),
            address(this),
            signedPayloadHash,
            _createEMVSignatureForKey(OTHER_PUBKEY_X, OTHER_PUBKEY_Y)
        );

        vm.expectRevert(abi.encodeWithSelector(EMVCardPolicy.InvalidSignatureLength.selector, uint256(4)));
        emvCardPolicy.checkSignaturePolicy(_emvPermissionKey(), address(this), signedPayloadHash, hex"deadbeef");
    }

    function test_EMVCardPolicyUninstallClearsPermissionMappingAndBlocksPolicyUse() public whenInitialized {
        _installKernelEMVCardPolicy();
        _uninstallEMVCardPolicyFor(address(kernel), _emvPermissionKey());

        assertEq(emvCardPolicy.getPermissionKeyHash(address(kernel), _emvPermissionKey()), bytes32(0));
        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(kernel), _testKeyHash()));
        _assertKernelCardReplayState(0, bytes4(TEST_UNPREDICTABLE_NUMBER), false);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignature();

        vm.prank(address(kernel));
        vm.expectRevert(EMVCardPolicy.PublicKeyNotRegistered.selector);
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);
    }

    function test_EMVCardPolicyReinstallSwitchesPermissionKey() public whenInitialized {
        _installKernelEMVCardPolicy();
        _installEMVCardPolicyFor(address(kernel), _emvPermissionKey(), 0, OTHER_PUBKEY_X, OTHER_PUBKEY_Y);

        assertEq(emvCardPolicy.getPermissionKeyHash(address(kernel), _emvPermissionKey()), _otherKeyHash());
        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(kernel), _testKeyHash()));
        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(kernel), _otherKeyHash()));

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignature();

        vm.prank(address(kernel));
        vm.expectRevert(
            abi.encodeWithSelector(EMVCardPolicy.UnexpectedPublicKey.selector, _otherKeyHash(), _testKeyHash())
        );
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);
    }

    function test_EMVLimitPolicyFailedValidationDoesNotMutateCycleTotal() public whenInitialized {
        bytes32 permission = _emvPermissionKey();

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();

        _installEMVLimitPolicyFor(address(kernel), permission, type(uint64).max, 9_999);
        vm.prank(address(kernel));
        assertEq(emvLimitPolicy.checkUserOpPolicy(permission, op), SIG_VALIDATION_FAILED_UINT);
        (,, uint64 cycleTotal,) = emvLimitPolicy.getLimits(address(kernel), permission);
        assertEq(cycleTotal, 0);

        _installEMVLimitPolicyFor(address(kernel), permission, 9_999, type(uint64).max);
        vm.prank(address(kernel));
        assertEq(emvLimitPolicy.checkUserOpPolicy(permission, op), SIG_VALIDATION_FAILED_UINT);
        (,, cycleTotal,) = emvLimitPolicy.getLimits(address(kernel), permission);
        assertEq(cycleTotal, 0);

        _installEMVLimitPolicyFor(address(kernel), permission, type(uint64).max, type(uint64).max);
        op.callData = _encodeSimpleTransferCall(_createEMVFieldsWithByte(6, bytes1(0x09)));
        vm.prank(address(kernel));
        assertEq(emvLimitPolicy.checkUserOpPolicy(permission, op), SIG_VALIDATION_FAILED_UINT);
        (,, cycleTotal,) = emvLimitPolicy.getLimits(address(kernel), permission);
        assertEq(cycleTotal, 0);
    }

    function test_EMVLimitPolicyCycleTotalResetsAfterCycleWindow() public whenInitialized {
        bytes32 permission = _emvPermissionKey();
        _installEMVLimitPolicyFor(address(kernel), permission, 15_000, type(uint64).max);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();

        vm.prank(address(kernel));
        assertEq(emvLimitPolicy.checkUserOpPolicy(permission, op), SIG_VALIDATION_SUCCESS_UINT);

        (uint64 firstCycle,, uint64 cycleTotal,) = emvLimitPolicy.getLimits(address(kernel), permission);
        assertEq(cycleTotal, 10_000);

        vm.warp(uint256(firstCycle) + 1 days);
        vm.prank(address(kernel));
        assertEq(emvLimitPolicy.checkUserOpPolicy(permission, op), SIG_VALIDATION_SUCCESS_UINT);

        (uint64 secondCycle,, uint64 secondCycleTotal,) = emvLimitPolicy.getLimits(address(kernel), permission);
        assertEq(secondCycle, firstCycle + 1 days);
        assertEq(secondCycleTotal, 10_000);
    }

    function test_EMVLimitPolicyUninstallClearsLimitsAndFailsClosed() public whenInitialized {
        bytes32 permission = _emvPermissionKey();
        _installEMVLimitPolicyFor(address(kernel), permission, 15_000, type(uint64).max);

        _uninstallEMVLimitPolicyFor(address(kernel), permission);
        (, uint64 cycleMax, uint64 cycleTotal, uint64 perTxnMax) = emvLimitPolicy.getLimits(address(kernel), permission);
        assertEq(cycleMax, 0);
        assertEq(cycleTotal, 0);
        assertEq(perTxnMax, 0);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        vm.prank(address(kernel));
        assertEq(emvLimitPolicy.checkUserOpPolicy(permission, op), SIG_VALIDATION_FAILED_UINT);
    }

    function test_EMVSignerRejectsTamperedSignatureKeyEnvelope() public whenInitialized {
        emvSigner.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        KernelUserOp memory op;
        op.sender = address(this);
        op.callData = _encodeSimpleTransferCall();
        op.signature = abi.encodePacked(_testKeyHash(), OTHER_PUBKEY_X, OTHER_PUBKEY_Y, TEST_SIGNATURE);

        vm.expectRevert(EMVSigner.InvalidPublicKey.selector);
        emvSigner.validateUserOp(op, bytes32(0));
    }

    function test_EMVSignerRejectsUnauthorizedSignatureKeyEnvelope() public whenInitialized {
        emvSigner.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        KernelUserOp memory op;
        op.sender = address(this);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignatureForKey(OTHER_PUBKEY_X, OTHER_PUBKEY_Y);

        vm.expectRevert(EMVSigner.PublicKeyNotRegistered.selector);
        emvSigner.validateUserOp(op, bytes32(0));
    }

    function test_EMVSignerPermissionModeRejectsUnauthorizedSignatureKeyEnvelope() public whenInitialized {
        emvSigner.onInstall(abi.encodePacked(_emvPermissionKey(), abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y)));

        KernelUserOp memory op;
        op.sender = address(this);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignatureForKey(OTHER_PUBKEY_X, OTHER_PUBKEY_Y);

        vm.expectRevert(EMVSigner.PublicKeyNotRegistered.selector);
        emvSigner.checkUserOpSignature(_emvPermissionKey(), op, bytes32(0));
    }

    // ========== ACQUIRER CONFIG TESTS ==========

    function test_AcquirerConfigBasics() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address testMerchantAddress = address(0x789);
        uint120 merchantId = merchantIdFromAddress(testMerchantAddress);

        // Register acquirer (owner-only)
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Merchant chooses this acquirer.
        vm.prank(testMerchantAddress);
        acquirerConfig.setMerchant(merchantId, testAcquirerId);

        // Check registration
        assertTrue(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertTrue(acquirerConfig.isMerchantRegistered(merchantId));
        assertEq(acquirerConfig.getMerchantAddress(merchantId), testMerchantAddress);
        (, uint48 selectedAcquirerId) = acquirerConfig.getMerchantConfig(merchantId);
        assertEq(selectedAcquirerId, testAcquirerId);

        // Test removal
        vm.prank(testMerchantAddress);
        acquirerConfig.removeMerchant(merchantId);
        assertFalse(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertFalse(acquirerConfig.isMerchantRegistered(merchantId));
        assertEq(acquirerConfig.getMerchantAddress(merchantId), address(0));
    }

    function test_AcquirerConfigSetMerchantWithANSString() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address testMerchantAddress = makeAddr("merchantWithStringId");
        uint120 merchantId = bytesToUint120(bytes15("Merchant001234"));

        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        vm.prank(testMerchantAddress);
        acquirerConfig.setMerchant("Merchant001234", testAcquirerId);

        assertTrue(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertTrue(acquirerConfig.isMerchantRegistered(merchantId));
        assertEq(acquirerConfig.getMerchantAddress(merchantId), testMerchantAddress);
        (, uint48 selectedAcquirerId) = acquirerConfig.getMerchantConfig(merchantId);
        assertEq(selectedAcquirerId, testAcquirerId);
    }

    function test_AcquirerConfigSetMerchantWithSpecialANSString() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address testMerchantAddress = makeAddr("merchantWithSpecialStringId");
        uint120 merchantId = bytesToUint120(bytes15("MERCH-1_$~!"));

        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        vm.prank(testMerchantAddress);
        acquirerConfig.setMerchant("MERCH-1_$~!", testAcquirerId);

        assertTrue(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertEq(acquirerConfig.getMerchantAddress(merchantId), testMerchantAddress);
    }

    function test_AcquirerConfigSetMerchantWithMaxLengthANSString() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address testMerchantAddress = makeAddr("merchantWithLongStringId");
        uint120 merchantId = bytesToUint120(bytes15("abcDEF012345678"));

        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        vm.prank(testMerchantAddress);
        acquirerConfig.setMerchant("abcDEF012345678", testAcquirerId);

        assertTrue(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertEq(acquirerConfig.getMerchantAddress(merchantId), testMerchantAddress);
    }

    function test_AcquirerConfigRejectsTooLongANSMerchantId() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        vm.expectRevert(abi.encodeWithSelector(AcquirerConfig.InvalidMerchantIdLength.selector, 16));
        acquirerConfig.setMerchant("1234567890123456", testAcquirerId);
    }

    function test_AcquirerConfigRejectsInvalidANSMerchantIdCharacter() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        string memory invalidMerchantId = string(abi.encodePacked("MERCHANT", bytes1(0x1F)));

        vm.expectRevert(abi.encodeWithSelector(ANSEncoding.InvalidANSCharacter.selector, bytes1(0x1F)));
        acquirerConfig.setMerchant(invalidMerchantId, testAcquirerId);
    }

    function test_AcquirerConfigRejectsEmptyANSMerchantId() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        vm.expectRevert(AcquirerConfig.InvalidMerchantId.selector);
        acquirerConfig.setMerchant("", testAcquirerId);
    }

    function test_MerchantControlsSelectedAcquirer() public {
        uint48 firstAcquirerId = bytesToUint48(bytes6("ACQ001"));
        uint48 secondAcquirerId = bytesToUint48(bytes6("ACQ002"));
        address firstAcquirer = makeAddr("firstAcquirer");
        address merchant = makeAddr("merchantController");
        uint120 merchantId = merchantIdFromAddress(merchant);
        address attacker = makeAddr("merchantAttacker");

        acquirerConfig.setAcquirer(firstAcquirerId, firstAcquirer);
        acquirerConfig.setAcquirer(secondAcquirerId, address(this));

        vm.prank(merchant);
        acquirerConfig.setMerchant(merchantId, firstAcquirerId);
        (, uint48 selectedAcquirerId) = acquirerConfig.getMerchantConfig(merchantId);
        assertEq(selectedAcquirerId, firstAcquirerId);

        vm.prank(attacker);
        acquirerConfig.setMerchant(merchantIdFromAddress(attacker), secondAcquirerId);
        (, selectedAcquirerId) = acquirerConfig.getMerchantConfig(merchantId);
        assertEq(selectedAcquirerId, firstAcquirerId);

        vm.prank(merchant);
        acquirerConfig.setMerchant(merchantId, secondAcquirerId);
        assertEq(acquirerConfig.getMerchantAddress(merchantId), merchant);
        (, selectedAcquirerId) = acquirerConfig.getMerchantConfig(merchantId);
        assertEq(selectedAcquirerId, secondAcquirerId);
    }

    function test_MerchantIdCollisionCannotOverwriteOrRemove() public {
        uint48 firstAcquirerId = bytesToUint48(bytes6("ACQ001"));
        uint48 secondAcquirerId = bytesToUint48(bytes6("ACQ002"));
        address merchant = address(uint160(0x1111111111000000000000000000000000000001));
        address collidingMerchant = address(uint160(0x2222222222000000000000000000000000000001));
        uint120 merchantId = merchantIdFromAddress(merchant);

        assertEq(merchantId, merchantIdFromAddress(collidingMerchant));

        acquirerConfig.setAcquirer(firstAcquirerId, address(this));
        acquirerConfig.setAcquirer(secondAcquirerId, address(this));
        vm.prank(merchant);
        acquirerConfig.setMerchant(merchantId, firstAcquirerId);

        vm.prank(collidingMerchant);
        vm.expectRevert(
            abi.encodeWithSelector(AcquirerConfig.UnauthorizedMerchant.selector, merchantId, collidingMerchant)
        );
        acquirerConfig.setMerchant(merchantId, secondAcquirerId);

        vm.prank(collidingMerchant);
        vm.expectRevert(
            abi.encodeWithSelector(AcquirerConfig.UnauthorizedMerchant.selector, merchantId, collidingMerchant)
        );
        acquirerConfig.removeMerchant(merchantId);

        assertEq(acquirerConfig.getMerchantAddress(merchantId), merchant);
        (, uint48 selectedAcquirerId) = acquirerConfig.getMerchantConfig(merchantId);
        assertEq(selectedAcquirerId, firstAcquirerId);
    }

    function test_AcquirerAndSwipeFees() public {
        address acquirer = makeAddr("testAcquirer");
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address testMerchant = makeAddr("testMerchant");
        uint120 testMerchantId = merchantIdFromAddress(testMerchant);

        // Register acquirer (owner-only)
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Set up acquirer fees
        acquirerConfig.setAcquirerFee(testAcquirerId, acquirer, 25); // 0.25% (within max 30)

        // Set up fixed swipe fee
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether);

        // Merchant chooses this acquirer
        vm.prank(testMerchant);
        acquirerConfig.setMerchant(testMerchantId, testAcquirerId);

        // Test payment distribution calculation
        uint256 totalAmount = 10 ether;
        AcquirerConfig.FeeRecipient[] memory feeRecipients =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, totalAmount);

        // Verify fee structure (should have acquirer fee, swipe fee, and merchant)
        assertGt(feeRecipients.length, 2);

        // Find the merchant recipient (should be last with fee=0)
        AcquirerConfig.FeeRecipient memory merchantRecipient = feeRecipients[feeRecipients.length - 1];
        assertEq(merchantRecipient.recipient, testMerchant);
        assertEq(merchantRecipient.fee, 0); // Merchant fee must be 0
    }

    function test_AcquirerConfigNotRegistered() public {
        uint120 unregisteredMerchantId = bytesToUint120(bytes15("UNREGISTERED123"));

        // Test payment distribution calculation with an unregistered merchant.
        uint256 totalAmount = 10 ether;

        // The acquirer is now derived on-chain from the card-signed merchant ID. An unregistered
        // merchant has no selected acquirer binding, so distribution fails loud with UnknownMerchant
        // (no caller-supplied acquirer to validate, so InvalidAcquirerId no longer applies here).
        vm.expectRevert(abi.encodeWithSelector(AcquirerConfig.UnknownMerchant.selector, unregisteredMerchantId));
        acquirerConfig.calculatePaymentDistribution(unregisteredMerchantId, totalAmount);
    }

    function test_UnregisteredMerchantReverts() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        uint120 unregisteredMerchantId = bytesToUint120(bytes15("UNREG_MERCHANT"));
        address feeRecipient = makeAddr("feeRecipient");

        // Register acquirer and set fee recipient
        acquirerConfig.setAcquirer(testAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(testAcquirerId, feeRecipient, 25);

        // The silent fallback to the acquirer fee recipient for an unregistered merchant was REMOVED:
        // it would quietly divert the merchant's funds. Distribution now derives the acquirer from the
        // card-signed merchant ID, and an unregistered merchant (no selected acquirer binding) fails
        // loud with UnknownMerchant rather than paying out to a fallback address.
        uint256 totalAmount = 10 ether;
        vm.expectRevert(abi.encodeWithSelector(AcquirerConfig.UnknownMerchant.selector, unregisteredMerchantId));
        acquirerConfig.calculatePaymentDistribution(unregisteredMerchantId, totalAmount);
    }

    function test_DuplicateRecipientAccumulation() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address sharedRecipient = makeAddr("sharedRecipient");
        address testMerchantAddress = makeAddr("merchant");
        uint120 testMerchantId = merchantIdFromAddress(testMerchantAddress);

        // Register acquirer and set the SAME address for all fee recipients
        acquirerConfig.setAcquirer(testAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(testAcquirerId, sharedRecipient, 25); // 0.25%
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether); // 1 token swipe fee

        // Set global fees to same recipient to test accumulation
        acquirerConfig.setNetworkFee(sharedRecipient, 15); // 0.15%
        acquirerConfig.setInterchangeFee(sharedRecipient, 200); // 2.00%

        // Merchant chooses this acquirer.
        vm.prank(testMerchantAddress);
        acquirerConfig.setMerchant(testMerchantId, testAcquirerId);

        // Test payment distribution - should accumulate fees for shared recipient
        uint256 totalAmount = 100 ether;
        AcquirerConfig.FeeRecipient[] memory feeRecipients =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, totalAmount);

        // Should have fewer recipients due to accumulation
        // Expected: 1 accumulated fee recipient + 1 merchant = 2 total
        assertGe(feeRecipients.length, 2, "Should have at least 2 recipients");
        assertLe(feeRecipients.length, 2, "Should have at most 2 recipients");

        // Find the accumulated fee recipient
        bool foundAccumulated = false;
        for (uint256 i = 0; i < feeRecipients.length; i++) {
            if (feeRecipients[i].recipient == sharedRecipient) {
                foundAccumulated = true;
                // Should have accumulated: acquirer (0.25%) + network (0.15%) + interchange (2.00%) + swipe.
                uint256 expectedAccumulatedFee = (totalAmount * 240) / 10000 + 1 ether;
                assertEq(
                    feeRecipients[i].fee,
                    expectedAccumulatedFee,
                    "Should accumulate percentage fees for shared recipient"
                );
                break;
            }
        }
        assertTrue(foundAccumulated, "Should find the accumulated fee recipient");
    }

    function test_ClearTransientStorageFunction() public {
        // Create a simple fee recipients array
        AcquirerConfig.FeeRecipient[] memory testRecipients = new AcquirerConfig.FeeRecipient[](2);
        testRecipients[0] = AcquirerConfig.FeeRecipient({fee: 100, recipient: makeAddr("recipient1")});
        testRecipients[1] = AcquirerConfig.FeeRecipient({fee: 200, recipient: makeAddr("recipient2")});

        // Test that the public clearTransientStorage function exists and can be called
        acquirerConfig.clearTransientStorage(testRecipients, 2);

        // If we get here without reverting, the function works
        assertTrue(true, "clearTransientStorage function should be callable");
    }

    function test_AllDifferentFeeRecipients() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));

        // Create different addresses for each fee type
        address acquirerRecipient = makeAddr("acquirerRecipient");
        address networkRecipient = makeAddr("networkRecipient");
        address interchangeRecipient = makeAddr("interchangeRecipient");
        address merchantRecipient = makeAddr("merchantRecipient");
        uint120 testMerchantId = merchantIdFromAddress(merchantRecipient);

        // Register acquirer and set different recipients for each fee type
        acquirerConfig.setAcquirer(testAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(testAcquirerId, acquirerRecipient, 25); // 0.25%
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether); // 1 token swipe fee

        // Set different global fee recipients
        acquirerConfig.setNetworkFee(networkRecipient, 15); // 0.15%
        acquirerConfig.setInterchangeFee(interchangeRecipient, 200); // 2.00%

        // Merchant chooses this acquirer.
        vm.prank(merchantRecipient);
        acquirerConfig.setMerchant(testMerchantId, testAcquirerId);

        // Test payment distribution - should have 4 separate recipients (acquirer gets percentage + swipe)
        uint256 totalAmount = 100 ether;
        AcquirerConfig.FeeRecipient[] memory feeRecipients =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, totalAmount);

        // Should have 4 recipients: acquirer, interchange, network, merchant
        assertEq(feeRecipients.length, 4, "Should have 4 separate recipients when all fee addresses are different");

        // Verify each recipient has the correct fee amount
        bool foundAcquirer = false;
        bool foundNetwork = false;
        bool foundInterchange = false;
        bool foundMerchant = false;

        for (uint256 i = 0; i < feeRecipients.length; i++) {
            if (feeRecipients[i].recipient == acquirerRecipient) {
                foundAcquirer = true;
                uint256 expectedAcquirerFee = (totalAmount * 25) / 10000 + 1 ether;
                assertEq(feeRecipients[i].fee, expectedAcquirerFee, "Acquirer should get fee plus swipe");
            } else if (feeRecipients[i].recipient == networkRecipient) {
                foundNetwork = true;
                uint256 expectedNetworkFee = (totalAmount * 15) / 10000; // 0.15%
                assertEq(feeRecipients[i].fee, expectedNetworkFee, "Network fee should be 0.15%");
            } else if (feeRecipients[i].recipient == interchangeRecipient) {
                foundInterchange = true;
                uint256 expectedInterchangeFee = (totalAmount * 200) / 10000; // 2.00%
                assertEq(feeRecipients[i].fee, expectedInterchangeFee, "Interchange fee should be 2.00%");
            } else if (feeRecipients[i].recipient == merchantRecipient) {
                foundMerchant = true;
                assertEq(feeRecipients[i].fee, 0, "Merchant fee must be 0");
                // Verify merchant is the last entry
                assertEq(i, feeRecipients.length - 1, "Merchant should be the last recipient");
            }
        }

        // Verify all recipients were found
        assertTrue(foundAcquirer, "Should find acquirer recipient");
        assertTrue(foundNetwork, "Should find network recipient");
        assertTrue(foundInterchange, "Should find interchange recipient");
        assertTrue(foundMerchant, "Should find merchant recipient");
    }

    // ========== ADDITIONAL COVERAGE TESTS ==========

    function test_AcquirerConfigGetters() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address merchantAddr = makeAddr("merchant");
        uint120 testMerchantId = merchantIdFromAddress(merchantAddr);

        // Register acquirer
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Test isAcquirerRegistered
        assertTrue(acquirerConfig.isAcquirerRegistered(testAcquirerId));
        assertFalse(acquirerConfig.isAcquirerRegistered(999));

        // Test getAcquirerAddress
        assertEq(acquirerConfig.getAcquirerAddress(testAcquirerId), address(this));

        // Merchant chooses this acquirer.
        vm.prank(merchantAddr);
        acquirerConfig.setMerchant(testMerchantId, testAcquirerId);

        // Test merchant-derived ID helpers
        assertEq(acquirerConfig.getMerchantAddress(testMerchantId), merchantAddr);
        (address configuredMerchant, uint48 configuredAcquirerId) = acquirerConfig.getMerchantConfig(testMerchantId);
        assertEq(configuredMerchant, merchantAddr);
        assertEq(configuredAcquirerId, testAcquirerId);

        // Set acquirer fee and test getAcquirerConfig
        acquirerConfig.setAcquirerFee(testAcquirerId, makeAddr("feeRecipient"), 25);
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether);
        (address feeRecipient, uint256 feeRate, uint256 swipeFee) = acquirerConfig.getAcquirerConfig(testAcquirerId);
        assertEq(feeRecipient, makeAddr("feeRecipient"));
        assertEq(feeRate, 25);
        assertEq(swipeFee, 1 ether);
    }

    function test_AcquirerConfigBatchOperations() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));
        address merchant = makeAddr("merchant");
        uint120 merchantId = merchantIdFromAddress(merchant);

        vm.prank(merchant);
        acquirerConfig.setMerchant(merchantId, testAcquirerId);

        assertTrue(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertEq(acquirerConfig.getMerchantAddress(merchantId), merchant);
    }

    function test_AcquirerConfigInvalidMerchantAddress() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        vm.expectRevert(AcquirerConfig.InvalidMerchantId.selector);
        acquirerConfig.setMerchant(0, testAcquirerId);
    }

    function test_AcquirerConfigInvalidIds() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Test invalid merchant ID
        vm.expectRevert(AcquirerConfig.InvalidMerchantId.selector);
        acquirerConfig.setMerchant(0, testAcquirerId);
    }

    function test_AcquirerConfigUnauthorizedAccess() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Try to access as unauthorized user
        address unauthorized = makeAddr("unauthorized");
        vm.startPrank(unauthorized);

        vm.expectRevert(
            abi.encodeWithSelector(AcquirerConfig.UnauthorizedAcquirer.selector, testAcquirerId, unauthorized)
        );
        acquirerConfig.setAcquirerFee(testAcquirerId, makeAddr("fee"), 10);

        vm.expectRevert(
            abi.encodeWithSelector(AcquirerConfig.UnauthorizedAcquirer.selector, testAcquirerId, unauthorized)
        );
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether);

        vm.stopPrank();
    }

    function test_InvalidAcquirerId() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        // Try to access as unauthorized user
        address unauthorized = makeAddr("unauthorized");

        vm.startPrank(unauthorized);

        vm.expectRevert(AcquirerConfig.InvalidAcquirerId.selector);
        acquirerConfig.setMerchant(merchantIdFromAddress(unauthorized), testAcquirerId);

        vm.stopPrank();
    }

    function test_AcquirerConfigInvalidAcquirerId() public {
        // Test with unregistered acquirer (address(0))
        uint48 unregisteredAcquirerId = 999;

        vm.expectRevert(AcquirerConfig.InvalidAcquirerId.selector);
        acquirerConfig.setMerchant(merchantIdFromAddress(address(this)), unregisteredAcquirerId);
    }

    function test_AcquirerConfigFeeRateValidation() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Test acquirer fee with address(0)
        vm.expectRevert(AcquirerConfig.InvalidFeeRate.selector);
        acquirerConfig.setAcquirerFee(testAcquirerId, address(0), 10);

        // Test acquirer fee rate too high (max is 30)
        vm.expectRevert(AcquirerConfig.InvalidFeeRate.selector);
        acquirerConfig.setAcquirerFee(testAcquirerId, makeAddr("fee"), 31);

        // Test network fee with address(0)
        vm.expectRevert(AcquirerConfig.InvalidFeeRate.selector);
        acquirerConfig.setNetworkFee(address(0), 10);

        // Test network fee rate too high (max is 15)
        vm.expectRevert(AcquirerConfig.InvalidFeeRate.selector);
        acquirerConfig.setNetworkFee(makeAddr("network"), 16);

        // Test interchange fee with address(0)
        vm.expectRevert(AcquirerConfig.InvalidFeeRate.selector);
        acquirerConfig.setInterchangeFee(address(0), 100);

        // Test interchange fee rate too high (max is 250)
        vm.expectRevert(AcquirerConfig.InvalidFeeRate.selector);
        acquirerConfig.setInterchangeFee(makeAddr("interchange"), 251);
    }

    function test_AcquirerConfigSetAcquirerZeroId() public {
        vm.expectRevert(AcquirerConfig.InvalidAcquirerId.selector);
        acquirerConfig.setAcquirer(0, address(this));
    }

    function test_EMVSettlementErrors() public {
        // Test constructor with invalid token address
        vm.expectRevert(EMVSettlement.InvalidConfig.selector);
        new EMVSettlement(address(0), address(acquirerConfig), 18);

        // Test constructor with invalid acquirer config
        vm.expectRevert(EMVSettlement.InvalidConfig.selector);
        new EMVSettlement(address(mockERC20), address(0), 18);

        // Test constructor with invalid decimals
        vm.expectRevert(EMVSettlement.InvalidDecimals.selector);
        new EMVSettlement(address(mockERC20), address(acquirerConfig), 1);
    }

    function test_EMVSettlementUninstall() public {
        // Call onUninstall (does nothing but needs coverage)
        emvSettlement.onUninstall("");
    }

    function test_EMVSettlementGetters() public {
        // Test getSettlementConfig
        (address token, address config, uint8 dec) = emvSettlement.getSettlementConfig();
        assertEq(token, address(mockERC20));
        assertEq(config, address(acquirerConfig));
        assertEq(dec, 18);

        // Test isInitialized
        assertTrue(emvSettlement.isInitialized(address(this)));
    }

    function test_EMVSignerErrors() public {
        // Test onInstall with empty data
        EMVSigner testValidator = new EMVSigner();
        vm.expectRevert(EMVSigner.InvalidConfig.selector);
        testValidator.onInstall("");
    }

    function test_EMVSignerUninstall() public whenInitialized {
        _installEMVSigner();

        bytes32 keyHash = _testKeyHash();

        assertEq(emvSigner.getAuthorizedKeyHash(address(kernel), bytes32(0)), keyHash);

        // Call onUninstall
        vm.prank(address(kernel));
        emvSigner.onUninstall("");

        // isInitialized remains an unconditional interface response.
        assertTrue(emvSigner.isInitialized(address(kernel)));
        assertEq(emvSigner.getAuthorizedKeyHash(address(kernel), bytes32(0)), bytes32(0));
    }

    function test_EMVSignerIsInitialized() public {
        // Create a new validator
        EMVSigner testValidator = new EMVSigner();

        // EMVSigner does not track account-level initialization for this interface method.
        assertTrue(testValidator.isInitialized(address(this)));

        // Install it with public key
        testValidator.onInstall(abi.encode(uint16(1), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        // The interface response remains unconditional after installation.
        assertTrue(testValidator.isInitialized(address(this)));
    }

    function test_CallPolicyValidationConfig() public {
        _requireZeroDevCallPolicy();

        bytes32 permission = bytes32(PermissionId.unwrap(_emvPermission()));
        callPolicy.onInstall(
            abi.encodePacked(permission, _callPolicyInstallData(address(emvSettlement), emvSettlement.execute.selector))
        );

        bytes32 permissionHash =
            keccak256(abi.encodePacked(bytes1(0xff), address(emvSettlement), emvSettlement.execute.selector));

        assertEq(uint256(callPolicy.status(permission, address(this))), uint256(CallPolicyStatus.Live));
        assertGt(callPolicy.encodedPermissions(permission, permissionHash, address(this)).length, 0);
    }

    function test_CallPolicyRejectsWrongTargetOrSelector() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)
            ),
            abi.encodePacked(
                address(mockERC20),
                abi.encodeWithSelector(mockERC20.transfer.selector, makeAddr("attacker"), uint256(1e20))
            )
        );

        vm.prank(address(kernel));
        vm.expectRevert();
        callPolicy.checkUserOpPolicy(bytes32(PermissionId.unwrap(_emvPermission())), op);

        op.callData = abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)
            ),
            abi.encodePacked(
                address(emvSettlement), abi.encodeWithSelector(bytes4(keccak256("wrong(bytes)")), _createEMVFields())
            )
        );

        vm.prank(address(kernel));
        vm.expectRevert();
        callPolicy.checkUserOpPolicy(bytes32(PermissionId.unwrap(_emvPermission())), op);
    }

    function test_DeployBaseSepoliaUsesAccountExecuteSelector() public {
        DeployBaseSepolia deployScript = new DeployBaseSepolia();

        assertEq(deployScript.validatorSelector(), kernel.execute.selector);
        assertTrue(deployScript.validatorSelector() != EMVSettlement.execute.selector);
    }

    function test_EMVLimitPolicyInvalidCurrency() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        // Build a valid 52-byte message, then corrupt the currency (5F2A @ off 7) to 0x0000.
        bytes memory invalidCurrencyFields = _replaceEMVField(_createEMVFields(), 7, hex"0000");

        _expectEMVLimitPolicyFailure(invalidCurrencyFields);
    }

    function test_EMVLimitPolicyRejectsNonCanonicalCurrencyEncoding() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        // 840 encoded as uint16 decimal is 0x0348, but EMV 5F2A must be canonical n3 BCD-style 0x0840.
        _expectEMVLimitPolicyFailure(_replaceEMVField(_createEMVFields(), 7, hex"0348"));

        // Same rule for USN 997: 0x03e5 is uint16 decimal, not canonical 0x0997.
        _expectEMVLimitPolicyFailure(_replaceEMVField(_createEMVFields(), 7, hex"03e5"));
    }

    function test_EMVCardPolicyReplayProtection() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        mockERC20.transfer(address(kernel), 2e21);
        vm.deal(address(kernel), 2e18);

        // First transaction should succeed
        PackedUserOperation[] memory ops1 = new PackedUserOperation[](1);
        ops1[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        entrypoint.handleOps(ops1, payable(address(0xdeadbeef)));

        // Try to replay the same transaction (same unpredictable number)
        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        ops2[0].signature = ops1[0].signature; // Same signature = same unpredictable number

        vm.expectRevert();
        entrypoint.handleOps(ops2, payable(address(0xdeadbeef)));
    }

    function test_EMVSignerERC1271Validation() public {
        // Install the validator with public key for this test contract
        emvSigner.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        // For P-256 EMV, the signature is over the full 52-byte validator payload.
        bytes32 signedDataHash = _signedPayloadHash();

        // Test isValidSignatureWithSender - should return ERC1271_MAGICVALUE for valid signature
        bytes4 result = emvSigner.isValidSignatureWithSender(address(this), signedDataHash, _createEMVSignature());
        assertEq(result, ERC1271_MAGICVALUE);

        // Test with invalid signature (wrong hash)
        bytes32 wrongHash = keccak256("wrong data");
        bytes4 invalidResult = emvSigner.isValidSignatureWithSender(address(this), wrongHash, _createEMVSignature());
        assertEq(invalidResult, ERC1271_INVALID);
    }

    function test_EMVSettlementInvalidAmount() public whenInitialized {
        _installEMVSigner();

        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Create a 52-byte EMV message with amount = 0 (amount @ off 9).
        bytes memory zeroAmountData = _replaceEMVField(_createEMVFields(), 9, hex"000000000000");

        // Direct call to settlement should revert
        vm.prank(address(kernel));
        vm.expectRevert(EMVSettlement.InvalidAmount.selector);
        emvSettlement.execute(zeroAmountData);
    }

    function test_EMVSettlementInvalidBCDLength() public {
        // Create EMV data with invalid BCD length (not 6 bytes) by reading at wrong offset
        // The function expects the amount at offset 14, and will try to read 6 bytes
        // If we provide data that's too short, it will read out of bounds
        bytes memory shortData = abi.encodePacked(
            TEST_ARQC, // 8 bytes
            hex"AABBCCDD" // Only 4 more bytes, so offset 14 will be out of bounds
        );

        // Direct call should revert (out of bounds access or returns 0)
        vm.prank(address(kernel));
        vm.expectRevert();
        emvSettlement.execute(shortData);
    }

    function test_EMVSettlementInvalidBCDDigits() public {
        bytes memory invalidBCDData = _replaceEMVField(_createEMVFields(), 9, hex"0000000000FF");

        // Direct call should revert with InvalidAmount (BCD extraction returns 0)
        vm.prank(address(kernel));
        vm.expectRevert(EMVSettlement.InvalidAmount.selector);
        emvSettlement.execute(invalidBCDData);
    }

    // Note: BelowTransactionMinimum error is difficult to test in isolation because
    // SafeTransferLib.safeTransfer may fail first when there are insufficient funds.
    // The logic is tested indirectly through integration tests where fee calculations work correctly.

    function test_AcquirerConfigInvalidAcquirerIdInModifier() public {
        // This tests line 78: the first check in onlyAcquirer modifier
        uint48 unregisteredAcquirer = 12345;

        // Try to set merchant for unregistered acquirer - should hit InvalidAcquirerId at line 77-78
        vm.expectRevert(AcquirerConfig.InvalidAcquirerId.selector);
        acquirerConfig.setMerchant(merchantIdFromAddress(address(this)), unregisteredAcquirer);
    }

    function test_EMVSettlementOnUninstallCoverage() public {
        // Explicitly test onUninstall to get coverage
        emvSettlement.onUninstall(hex"");
    }

    function test_EMVSettlementInvalidBCDReturnsZero() public {
        bytes memory shortBCD = _replaceEMVField(_createEMVFields(), 9, hex"0000000000FF");

        vm.prank(address(kernel));
        vm.expectRevert(EMVSettlement.InvalidAmount.selector);
        emvSettlement.execute(shortBCD);
    }

    function test_EMVSignerInvalidSignatureFails() public whenInitialized {
        _installEMVSigner();

        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Create a UserOp with signature that fails P-256 validation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(_encodeSimpleTransferCall(), false); // false = invalid signature

        // Signature validation should fail, returning SIG_VALIDATION_FAILED_UINT
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_EMVLimitPolicySetSpendingLimits() public {
        bytes32 permission = bytes32(PermissionId.unwrap(_emvPermission()));
        emvLimitPolicy.onInstall(abi.encodePacked(permission, abi.encode(type(uint64).max, type(uint64).max)));

        emvLimitPolicy.setCycleMax(permission, 25_000);
        emvLimitPolicy.setPerTxnMax(permission, 10_000);

        (, uint64 cycleMax,, uint64 perTxnMax) = emvLimitPolicy.getLimits(address(this), permission);
        assertEq(cycleMax, 25_000);
        assertEq(perTxnMax, 10_000);
    }

    function test_EMVLimitPolicySetSpendingLimitsRequiresInitializedPolicy() public {
        bytes32 permission = bytes32(PermissionId.unwrap(_emvPermission()));

        vm.expectRevert(abi.encodeWithSelector(EMVLimitPolicy.PolicyNotInitialized.selector, address(this), permission));
        emvLimitPolicy.setCycleMax(permission, 25_000);

        vm.expectRevert(abi.encodeWithSelector(EMVLimitPolicy.PolicyNotInitialized.selector, address(this), permission));
        emvLimitPolicy.setPerTxnMax(permission, 10_000);
    }

    function test_EMVLimitPolicyPerTransactionLimit() public whenInitialized {
        _installEMVPermissionWithPolicies(type(uint64).max, 9_999);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        vm.prank(address(kernel));
        uint256 validationData = emvLimitPolicy.checkUserOpPolicy(bytes32(PermissionId.unwrap(_emvPermission())), op);

        assertEq(validationData, SIG_VALIDATION_FAILED_UINT);
    }

    function test_EMVLimitPolicyCycleLimit() public whenInitialized {
        _installEMVPermissionWithPolicies(9_999, type(uint64).max);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        vm.prank(address(kernel));
        uint256 validationData = emvLimitPolicy.checkUserOpPolicy(bytes32(PermissionId.unwrap(_emvPermission())), op);

        assertEq(validationData, SIG_VALIDATION_FAILED_UINT);
    }

    function test_EMVLimitPolicyCycleTotalUpdatesOnValidation() public whenInitialized {
        _installEMVPermissionWithPolicies(15_000, type(uint64).max);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        vm.prank(address(kernel));
        uint256 validationData = emvLimitPolicy.checkUserOpPolicy(bytes32(PermissionId.unwrap(_emvPermission())), op);
        assertEq(validationData, SIG_VALIDATION_SUCCESS_UINT);

        (,, uint64 cycleTotal,) =
            emvLimitPolicy.getLimits(address(kernel), bytes32(PermissionId.unwrap(_emvPermission())));
        assertEq(cycleTotal, 10_000);
    }

    function test_EMVCardPolicyAtcGapAccepted() public whenInitialized {
        // Strictly-increasing ATC: a card-signed ATC ABOVE the expected (a gap left by an
        // off-chain-declined tap that incremented the card without reaching the validator) PASSES.
        _installKernelEMVCardPolicy();

        bytes memory fields = _replaceEMVField(_createEMVFields(), 0, hex"0005"); // ATC 5 @ byte 0
        fields = _replaceEMVField(fields, 2, hex"55667788"); // fresh 9F37 UN @ byte 2

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall(fields);
        op.signature = _createEMVSignature();

        vm.prank(address(kernel));
        uint256 validationData = emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);
        assertEq(validationData, SIG_VALIDATION_SUCCESS_UINT, "ATC gap accepted");
        assertEq(emvCardPolicy.getExpectedATC(address(kernel), _testKeyHash()), 6);
    }

    function test_EMVCardPolicyInvalidATCSequence() public whenInitialized {
        // With strictly-increasing ATC, ONLY a card-signed ATC BELOW the expected reverts
        // (replay / regression) — a higher one is tolerated (see the gap test above).
        _installEMVPermissionWithPolicies(type(uint64).max, type(uint64).max);

        // A valid default tap (ATC 0) settles and advances the expected ATC to 1.
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVPermissionUserOp(_encodeSimpleTransferCall(), true);
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
        (uint256 expected,,) = emvCardPolicy.getCardState(address(kernel), _testKeyHash());
        assertEq(expected, 1, "expected ATC advanced after the valid tap");

        // A subsequent ATC 0 (< expected 1) with a FRESH UN reverts at the ATC check.
        bytes memory low = _replaceEMVField(_createEMVFields(), 2, hex"99887766"); // fresh UN, ATC stays 0
        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall(low);
        op.signature = _createEMVSignature();
        vm.prank(address(kernel));
        vm.expectRevert(abi.encodeWithSelector(EMVCardPolicy.InvalidATCSequence.selector, uint16(1), uint16(0)));
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);
    }

    function test_AcquirerConfigAddressZeroInFeeRecipient() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        address merchant = makeAddr("merchant");
        uint120 testMerchantId = merchantIdFromAddress(merchant);

        // Register acquirer
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Try to call calculatePaymentDistribution with address(0) for fee recipient
        // This would happen if acquirerFeeRecipient is not set (defaults to address(0))
        // The _addOrAccumulateFee function should revert with InvalidFee

        // Don't set acquirer fee (it defaults to address(0))
        // Set other required values
        acquirerConfig.setSwipeFee(testAcquirerId, 0); // No swipe fee
        acquirerConfig.setNetworkFee(makeAddr("network"), 0); // No network fee
        acquirerConfig.setInterchangeFee(makeAddr("interchange"), 0); // No interchange fee
        vm.prank(merchant);
        acquirerConfig.setMerchant(testMerchantId, testAcquirerId);

        // This should work since all fees are 0, so no fee recipients are added
        AcquirerConfig.FeeRecipient[] memory result =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, 100 ether);

        // Should only have merchant (all fees are 0)
        assertEq(result.length, 1);
        assertEq(result[0].recipient, merchant);
        assertEq(result[0].fee, 0);
    }

    function test_EMVSignerTargetMismatch() public whenInitialized {
        _installEMVSigner();

        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Try with wrong target in callData (not emvSettlement)
        bytes memory wrongTargetCallData = abi.encodeWithSelector(
            kernel.execute.selector,
            ExecMode.wrap(bytes32(0)),
            ExecLib.encodeSingle(
                address(mockERC20), // Wrong target! Should be emvSettlement
                0,
                abi.encodeWithSelector(mockERC20.transfer.selector, makeAddr("attacker"), 1e20)
            )
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(wrongTargetCallData, true);

        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_EMVSignerCallDataTooShort() public whenInitialized {
        _installEMVSigner();

        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Try with callData that's too short (less than required for target extraction)
        bytes memory shortCallData = abi.encodeWithSelector(kernel.execute.selector);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(shortCallData, true);

        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_EMVSettlementInvalidFeeRecipientZero() public {
        // Test branch at line 167: when a non-merchant fee is 0
        uint48 testAcquirerId = bytesToUint48(bytes6(TEST_ACQUIRER_ID));
        uint120 testMerchantId = merchantIdFromAddress(TEST_MERCHANT_ADDRESS);

        // Set fees to 0 to trigger the zero-fee check
        acquirerConfig.setAcquirerFee(testAcquirerId, makeAddr("acquirer"), 0); // 0% fee
        acquirerConfig.setSwipeFee(testAcquirerId, 0); // 0 swipe fee
        acquirerConfig.setNetworkFee(makeAddr("network"), 0); // 0% fee
        acquirerConfig.setInterchangeFee(makeAddr("interchange"), 0); // 0% fee

        // This should work - when all fees are 0, they're not added to the array
        AcquirerConfig.FeeRecipient[] memory result =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, 100 ether);

        // Should only have merchant
        assertEq(result.length, 1);
        assertEq(result[0].fee, 0);
    }

    function test_Coverage100Percent() public {
        // Final test to ensure maximum coverage
        // This test exercises remaining edge cases

        // Test AcquirerConfig with minimal setup
        AcquirerConfig testConfig = new AcquirerConfig();
        uint48 newAcquirer = 99999;
        testConfig.setAcquirer(newAcquirer, address(this));

        // Verify registration
        assertTrue(testConfig.isAcquirerRegistered(newAcquirer));
        assertEq(testConfig.getAcquirerAddress(newAcquirer), address(this));

        // Test with zero fees to hit all zero-fee branches
        testConfig.setAcquirerFee(newAcquirer, address(this), 0);
        testConfig.setSwipeFee(newAcquirer, 0);
        testConfig.setNetworkFee(address(this), 0);
        testConfig.setInterchangeFee(address(this), 0);

        uint120 merchantId = merchantIdFromAddress(address(this));
        testConfig.setMerchant(merchantId, newAcquirer);

        AcquirerConfig.FeeRecipient[] memory feeRec = testConfig.calculatePaymentDistribution(merchantId, 1 ether);

        assertEq(feeRec.length, 1); // Only merchant when all fees are 0
    }

    function test_GetRegisteredKeyHash() public whenInitialized {
        _installKernelEMVCardPolicy();

        bytes32 keyHash = _testKeyHash();

        assertEq(emvCardPolicy.computeKeyHash(TEST_PUBKEY_X, TEST_PUBKEY_Y), keyHash);
        assertEq(emvCardPolicy.getPermissionKeyHash(address(kernel), _emvPermissionKey()), keyHash);
        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(kernel), keyHash), "Key hash should be registered");

        (uint256 expectedATC, bool initialized) = emvCardPolicy.getEMVStorage(address(kernel), keyHash);
        assertTrue(initialized);
        assertEq(expectedATC, 0, "ATC should match installed value");
    }

    function test_GetRegisteredKeyHash_NotInstalled() public {
        bytes32 keyHash = _testKeyHash();

        assertFalse(emvCardPolicy.isPublicKeyRegistered(address(0x123), keyHash));
        (uint256 expectedATC, bool initialized) = emvCardPolicy.getEMVStorage(address(0x123), keyHash);
        assertFalse(initialized);
        assertEq(expectedATC, 0);
    }

    function test_MultiplePublicKeysCanBeInstalledForSameAccount() public {
        bytes32 secondPubkeyX = bytes32(uint256(0x1234));
        bytes32 secondPubkeyY = bytes32(uint256(0x5678));
        bytes32 secondKeyHash = emvCardPolicy.computeKeyHash(secondPubkeyX, secondPubkeyY);

        _installEMVCardPolicyFor(address(this), bytes32(uint256(1)), 0, TEST_PUBKEY_X, TEST_PUBKEY_Y);
        _installEMVCardPolicyFor(address(this), bytes32(uint256(2)), 7, secondPubkeyX, secondPubkeyY);

        assertTrue(emvCardPolicy.isInitialized(address(this)));
        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(this), _testKeyHash()));
        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(this), secondKeyHash));
        assertEq(emvCardPolicy.getExpectedATC(address(this), _testKeyHash()), 0);
        assertEq(emvCardPolicy.getExpectedATC(address(this), secondKeyHash), 7);
    }

    function test_FreezeCardBlocksUserOpsAndEmits() public whenInitialized {
        _installKernelEMVCardPolicy();

        bytes32 keyHash = _testKeyHash();
        vm.expectEmit(true, true, false, true, address(emvCardPolicy));
        emit EMVCardFrozen(address(kernel), keyHash);
        vm.prank(address(kernel));
        emvCardPolicy.freezeCard(keyHash);

        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(kernel), keyHash));
        assertTrue(emvCardPolicy.isCardFrozen(address(kernel), keyHash));

        (uint256 expectedATC, bool initialized, bool frozen) = emvCardPolicy.getCardState(address(kernel), keyHash);
        assertEq(expectedATC, 0);
        assertTrue(initialized);
        assertTrue(frozen);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignature();

        vm.prank(address(kernel));
        vm.expectRevert(abi.encodeWithSelector(EMVCardPolicy.CardFrozen.selector, keyHash));
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);

        assertEq(emvCardPolicy.getExpectedATC(address(kernel), keyHash), 0);
        assertFalse(
            emvCardPolicy.isUnpredictableNumberUsed(address(kernel), keyHash, bytes4(TEST_UNPREDICTABLE_NUMBER))
        );
    }

    function test_UnfreezeCardRestoresUserOpsAndEmits() public whenInitialized {
        _installKernelEMVCardPolicy();

        bytes32 keyHash = _testKeyHash();
        vm.prank(address(kernel));
        emvCardPolicy.freezeCard(keyHash);

        vm.expectEmit(true, true, false, true, address(emvCardPolicy));
        emit EMVCardUnfrozen(address(kernel), keyHash);
        vm.prank(address(kernel));
        emvCardPolicy.unfreezeCard(keyHash);

        assertTrue(emvCardPolicy.isPublicKeyRegistered(address(kernel), keyHash));
        assertFalse(emvCardPolicy.isCardFrozen(address(kernel), keyHash));

        (uint256 expectedATC, bool initialized, bool frozen) = emvCardPolicy.getCardState(address(kernel), keyHash);
        assertEq(expectedATC, 0);
        assertTrue(initialized);
        assertFalse(frozen);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignature();

        vm.prank(address(kernel));
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);

        assertEq(emvCardPolicy.getExpectedATC(address(kernel), keyHash), 1);
        assertTrue(emvCardPolicy.isUnpredictableNumberUsed(address(kernel), keyHash, bytes4(TEST_UNPREDICTABLE_NUMBER)));
    }

    function test_FreezeCardBlocksERC1271() public {
        bytes32 keyHash = _testKeyHash();

        _installEMVCardPolicyFor(address(this), _emvPermissionKey(), 0, TEST_PUBKEY_X, TEST_PUBKEY_Y);
        emvCardPolicy.freezeCard(keyHash);

        bytes32 signedPayloadHash = _signedPayloadHash();
        bytes memory signature = _createEMVSignature();

        vm.expectRevert(abi.encodeWithSelector(EMVCardPolicy.CardFrozen.selector, keyHash));
        emvCardPolicy.checkSignaturePolicy(_emvPermissionKey(), address(this), signedPayloadHash, signature);

        emvCardPolicy.unfreezeCard(keyHash);

        uint256 result =
            emvCardPolicy.checkSignaturePolicy(_emvPermissionKey(), address(this), signedPayloadHash, signature);
        assertEq(result, SIG_VALIDATION_SUCCESS_UINT);
    }

    function test_RevokeCardRemovesRegistrationAndEmits() public whenInitialized {
        _installKernelEMVCardPolicy();

        bytes32 keyHash = _testKeyHash();
        vm.expectEmit(true, true, false, true, address(emvCardPolicy));
        emit EMVCardRevoked(address(kernel), keyHash);
        vm.prank(address(kernel));
        emvCardPolicy.revokeCard(keyHash);

        assertFalse(emvCardPolicy.isPublicKeyRegistered(address(kernel), keyHash));
        assertFalse(emvCardPolicy.isCardFrozen(address(kernel), keyHash));

        (uint256 expectedATC, bool initialized) = emvCardPolicy.getEMVStorage(address(kernel), keyHash);
        assertEq(expectedATC, 0);
        assertFalse(initialized);

        (uint256 cardATC, bool cardInitialized, bool frozen) = emvCardPolicy.getCardState(address(kernel), keyHash);
        assertEq(cardATC, 0);
        assertFalse(cardInitialized);
        assertFalse(frozen);

        vm.expectRevert(EMVCardPolicy.PublicKeyNotRegistered.selector);
        emvCardPolicy.getExpectedATC(address(kernel), keyHash);

        KernelUserOp memory op;
        op.sender = address(kernel);
        op.callData = _encodeSimpleTransferCall();
        op.signature = _createEMVSignature();

        vm.prank(address(kernel));
        vm.expectRevert(EMVCardPolicy.PublicKeyNotRegistered.selector);
        emvCardPolicy.checkUserOpPolicy(_emvPermissionKey(), op);
    }

    function test_FreezeUnfreezeAndRevokeRequireRegisteredCard() public {
        bytes32 keyHash = _testKeyHash();

        vm.expectRevert(EMVCardPolicy.PublicKeyNotRegistered.selector);
        emvCardPolicy.freezeCard(keyHash);

        vm.expectRevert(EMVCardPolicy.PublicKeyNotRegistered.selector);
        emvCardPolicy.unfreezeCard(keyHash);

        vm.expectRevert(EMVCardPolicy.PublicKeyNotRegistered.selector);
        emvCardPolicy.revokeCard(keyHash);
    }

    function test_InvalidSender() public {
        // Install validator first
        emvSigner.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        bytes32 testHash = keccak256("test");

        // Try to call isValidSignatureWithSender with address(0) as sender - should revert
        vm.expectRevert(EMVSigner.InvalidSender.selector);
        emvSigner.isValidSignatureWithSender(address(0), testHash, TEST_SIGNATURE);
    }

    function test_InvalidSender_WithInvalidSignature() public {
        // This test verifies that InvalidSender is caught BEFORE signature validation
        // Even with completely invalid signature data, InvalidSender should be the error

        // Create invalid signature data (just random bytes)
        bytes memory invalidSigData = hex"deadbeefcafebabe";
        bytes32 testHash = keccak256("test");

        // Try to call isValidSignatureWithSender with address(0) as sender
        // Should revert with InvalidSender, NOT with signature validation errors
        vm.expectRevert(EMVSigner.InvalidSender.selector);
        emvSigner.isValidSignatureWithSender(address(0), testHash, invalidSigData);
    }

    function test_PublicKeyNotRegistered() public {
        // Test that isValidSignatureWithSender reverts when public key is not registered
        bytes32 testHash = keccak256("test");
        address uninitializedAccount = makeAddr("uninitialized");

        // Try to validate signature for an account that never installed the validator
        vm.expectRevert(EMVSigner.PublicKeyNotRegistered.selector);
        emvSigner.isValidSignatureWithSender(uninitializedAccount, testHash, _createEMVSignature());
    }

    function test_InvalidSignatureLength_WrongSignatureLength() public {
        // Install validator first
        emvSigner.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        bytes32 dynamicDataHash = _signedPayloadHash();

        // Try with wrong signature length (32 bytes instead of 64)
        bytes memory shortSignature = new bytes(32);

        // Should return INVALID, not revert (ERC-1271 behavior)
        bytes4 result = emvSigner.isValidSignatureWithSender(address(this), dynamicDataHash, shortSignature);
        assertEq(result, ERC1271_INVALID, "Should return INVALID for wrong signature length");
    }

    function test_InvalidSignatureLength_EmptySignature() public {
        // Install validator first
        emvSigner.onInstall(abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y));

        bytes32 dynamicDataHash = _signedPayloadHash();

        // Try with empty signature
        bytes memory emptySignature = hex"";

        // Should return INVALID, not revert (ERC-1271 behavior)
        bytes4 result = emvSigner.isValidSignatureWithSender(address(this), dynamicDataHash, emptySignature);
        assertEq(result, ERC1271_INVALID, "Should return INVALID for empty signature");
    }

    // ========== P-256 END-TO-END TESTS ==========

    function test_FFI_CompleteEndToEndTransaction() public whenInitialized {
        // Ensure kernel has ETH for gas
        vm.deal(address(kernel), 10 ether);

        bytes memory emvFields = _createEMVFields();

        console.log("=== P-256 Fixture Data ===");
        console.log("EMV Fields:", emvFields.length, "bytes");
        console.log("Signature:", TEST_SIGNATURE.length, "bytes");

        // STEP 2: Setup acquirer configuration
        uint48 e2eAcquirerId = bytesToUint48(bytes6(TEST_ACQUIRER_ID));

        address e2eMerchant = TEST_MERCHANT_ADDRESS;

        acquirerConfig.setAcquirer(e2eAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(e2eAcquirerId, address(this), 25); // 0.25%
        acquirerConfig.setSwipeFee(e2eAcquirerId, 50 * 10 ** 16); // $0.50
        vm.prank(e2eMerchant);
        acquirerConfig.setMerchant(merchantIdFromAddress(e2eMerchant), e2eAcquirerId);

        console.log("=== Acquirer Configuration Complete ===");

        // STEP 3: Install EMVSigner with P-256 public key
        PackedUserOperation[] memory installValOps = new PackedUserOperation[](1);
        installValOps[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_VALIDATOR,
                address(emvSigner),
                abi.encodePacked(
                    address(0),
                    abi.encode(
                        abi.encode(uint16(0), TEST_PUBKEY_X, TEST_PUBKEY_Y),
                        hex"",
                        abi.encodePacked(kernel.execute.selector)
                    )
                )
            ),
            true,
            true,
            false
        );

        entrypoint.handleOps(installValOps, payable(address(0xdeadbeef)));

        // Verify EMVSigner was installed
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvSigner), ""), "EMVSigner should be installed"
        );
        console.log("=== EMVSigner Installed ===");

        // STEP 4: Install EMVSettlement executor
        PackedUserOperation[] memory installExecOps = new PackedUserOperation[](1);
        installExecOps[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_EXECUTOR,
                address(emvSettlement),
                abi.encodePacked(
                    address(0),
                    abi.encode(abi.encode(address(mockERC20), address(acquirerConfig), uint8(18)), hex"", hex"")
                )
            ),
            true,
            true,
            false
        );

        entrypoint.handleOps(installExecOps, payable(address(0xdeadbeef)));

        // Verify EMVSettlement was installed
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(emvSettlement), ""),
            "EMVSettlement should be installed"
        );
        console.log("=== EMVSettlement Installed ===");

        // STEP 5: Fund the kernel with tokens
        uint256 transferAmount = 1e20; // 100 tokens ($100)
        mockERC20.transfer(address(kernel), transferAmount * 2); // 2x for fees
        vm.deal(address(kernel), 10 ether); // Ensure ETH for gas

        uint256 merchantBalanceBefore = mockERC20.balanceOf(e2eMerchant);
        uint256 kernelBalanceBefore = mockERC20.balanceOf(address(kernel));

        console.log("=== Kernel Funded ===");
        console.log("Kernel ERC20 balance:", kernelBalanceBefore);

        // STEP 6: Create UserOperation with EMV data in callData and P-256 signature in signature
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(emvSigner)),
            0
        );

        bytes memory emvCallData = abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)
            ),
            abi.encodePacked(address(emvSettlement), abi.encodeWithSelector(emvSettlement.execute.selector, emvFields))
        );

        PackedUserOperation[] memory emvOps = new PackedUserOperation[](1);
        emvOps[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), nonceKey),
            initCode: "",
            callData: emvCallData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2000000), uint128(2000000))),
            preVerificationGas: 2000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: _createEMVSignature()
        });

        console.log("=== Executing EMV Transaction ===");

        // STEP 7: Execute transaction through entrypoint
        entrypoint.handleOps(emvOps, payable(address(0xdeadbeef)));

        // STEP 8: Verify balances changed correctly
        uint256 kernelBalanceAfter = mockERC20.balanceOf(address(kernel));
        uint256 merchantBalanceAfter = mockERC20.balanceOf(e2eMerchant);

        console.log("=== Transaction Complete ===");
        console.log("Kernel balance after:", kernelBalanceAfter);
        console.log("Merchant balance after:", merchantBalanceAfter);

        // Merchant should have received tokens
        assertGt(merchantBalanceAfter, merchantBalanceBefore, "Merchant should have received tokens");

        // Kernel should have spent tokens
        assertLt(kernelBalanceAfter, kernelBalanceBefore, "Kernel should have spent tokens");

        // Calculate expected merchant amount (after fees: 2.40% + $0.50)
        uint256 percentageFees = (transferAmount * 240) / 10000; // 2.40%
        uint256 fixedFee = 50 * 10 ** 16; // $0.50
        uint256 expectedMerchantAmount = transferAmount - percentageFees - fixedFee;

        uint256 merchantReceived = merchantBalanceAfter - merchantBalanceBefore;
        assertEq(merchantReceived, expectedMerchantAmount, "Merchant should receive correct amount after fees");

        // STEP 9: Verify the direct signer key remained installed.
        assertEq(emvSigner.getAuthorizedKeyHash(address(kernel), bytes32(0)), _testKeyHash());

        console.log("Complete end-to-end FFI EMV transaction successful!");
        console.log("Merchant received:", merchantReceived / 1e18, "tokens");
    }

    // Helper function to convert uint256 to string
    function _uint256ToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    // Helper function to truncate string to max length
    function _truncateString(string memory str, uint256 maxLen) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        if (strBytes.length <= maxLen) {
            return str;
        }
        bytes memory truncated = new bytes(maxLen);
        for (uint256 i = 0; i < maxLen; i++) {
            truncated[i] = strBytes[i];
        }
        return string(truncated);
    }

    // Helper to convert string to bytes6 (for acquirer ID)
    function _stringToBytes6(string memory str) internal pure returns (bytes6) {
        bytes memory strBytes = bytes(str);
        bytes memory padded = new bytes(6);
        uint256 len = strBytes.length < 6 ? strBytes.length : 6;
        for (uint256 i = 0; i < len; i++) {
            padded[i] = strBytes[i];
        }
        return bytes6(padded);
    }

    // Helper to convert string to bytes8 (for terminal ID)
    function _stringToBytes8(string memory str) internal pure returns (bytes8) {
        bytes memory strBytes = bytes(str);
        bytes memory padded = new bytes(8);
        uint256 len = strBytes.length < 8 ? strBytes.length : 8;
        for (uint256 i = 0; i < len; i++) {
            padded[i] = strBytes[i];
        }
        return bytes8(padded);
    }

    // Helper to convert string to bytes15 (for merchant ID)
    function _stringToBytes15(string memory str) internal pure returns (bytes15) {
        bytes memory strBytes = bytes(str);
        bytes memory padded = new bytes(15);
        uint256 len = strBytes.length < 15 ? strBytes.length : 15;
        for (uint256 i = 0; i < len; i++) {
            padded[i] = strBytes[i];
        }
        return bytes15(padded);
    }
}
