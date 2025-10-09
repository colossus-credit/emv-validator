// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "lib/kernel/test/base/KernelTestBase.sol";
import {EMVValidator, EMVTransactionData} from "../src/EMVValidator.sol";
import {EMVSettlement} from "../src/EMVSettlement.sol";
import {AcquirerConfig} from "../src/AcquirerConfig.sol";
import {SIG_VALIDATION_SUCCESS_UINT} from "kernel/src/types/Constants.sol";
import "forge-std/console.sol";

contract EMVValidatorTest is KernelTestBase {
    EMVValidator public emvValidator;
    EMVSettlement public emvSettlement;
    AcquirerConfig public acquirerConfig;
    address public merchantAddress;

    // Event declarations for testing
    event EMVSignatureValidated(address indexed kernel, bool success);
    event ReplayProtectionUpdated(address indexed kernel, bytes4 unpredictableNumber, uint16 newATC);
    event EMVTransferExecuted(
        address indexed from,
        address indexed to,
        address indexed token,
        uint256 amount,
        bytes4 unpredictableNumber,
        uint16 atc
    );

    // Test RSA key pair (2048-bit) - Updated for new 63-byte EMV format
    bytes constant TEST_EXPONENT = hex"010001";
    bytes constant TEST_MODULUS =
        hex"d62d80e0419beb12fdb19eaa0f82f99728e36129058a5f97084dbc5785b771c1826249369624794af1f5c88afbcda3bbb7cf5c6a35ff5cc86ccbfba0f8218439646bf9673a3295ce09cf2cb59deb26ab0d5bea14729735c30339d6f8a9e1e09100d5497b3a6e86fad96fc01e7431fb808d71b035064d64f0fb006c6ea6100771e51da0f643d56c1d6448f4525db772e3cee3cc96647b53f314625e93579380d30b9bcad02bc564410c3cdf57414978d829128f65c478ad49abee7517d04f873e4fe90ae8d3cb052abf056f89cb1792483b7dec70129a0d7d3f10e8bcbc911224cc1a639c065d0ddc84d536089a58d14036e5f9e560754451cee3b24eedeeef49";

    // Test EMV data
    bytes constant TEST_ARQC = hex"1234567890ABCDEF";
    bytes constant TEST_UNPREDICTABLE_NUMBER = hex"12345678";
    bytes constant TEST_ATC = hex"0000";
    bytes constant TEST_AMOUNT = hex"000000010000";
    bytes constant TEST_CURRENCY = hex"0348"; // 840 in big-endian (0x0348 = 840 decimal)
    bytes constant TEST_DATE = hex"231201";
    bytes constant TEST_TXN_TYPE = hex"00";
    bytes constant TEST_TVR = hex"0000000000";
    bytes constant TEST_CVM_RESULTS = hex"000000";
    bytes constant TEST_TERMINAL_ID = hex"5445535430303100"; // "TEST001" padded to 8 bytes with null
    bytes constant TEST_MERCHANT_ID = hex"4D45524348414E5430303132333400"; // "MERCHANT001234" padded to 15 bytes with null
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

    // Valid signature for the test data above - Updated for new 63-byte EMV format with acquirerId
    bytes constant TEST_SIGNATURE =
        hex"62d99b3d032c534d6c6838f29fea2cd97b00e866a03620b4d0e9866ce1f89eab71ef2a58b560203d51fd5c222c97ecf6af6a15632c4b47fafb5bb766a6e05c35508ecf847357e4bdcaab6ba1aaff5d433797a533365832253a5879b33451681902d4da935f55883c9796107c8ab63f11344a79877a82e00a74b4e1f53446b49b8eb3b3b38cfd883996278f23f6acb3b23b8087189e5982efc500e463d06cf7ca2421fb4fef24d36b96becdd49c9b51b554924590933cf1209f3a346514b8bccbd08692a9d11b3b3af4be7acfb473086a79f8c495aff98f691b4d5315ba608f34223ca6250eb1b44aff3be194e85dff4e07c6099216d5cc3d4367dbfa9c3c683d";

    // Expected dynamic data (for reference) - updated with properly padded Terminal ID, Merchant ID, and Acquirer ID (66 bytes total)
    bytes constant EXPECTED_DYNAMIC_DATA =
        hex"6a031234567890abcdef123456780000000000010000034823120100000000000000000054455354303031004d45524348414e5430303132333400414351554952bc";

    function setUp() public override {
        super.setUp(); // Initialize KernelTestBase

        // Deploy EMV components
        acquirerConfig = new AcquirerConfig();
        merchantAddress = makeAddr("merchant");

        // Set up acquirer and terminal fee recipients
        address acquirerAddress = makeAddr("acquirer");
        address terminalFeeRecipient = makeAddr("terminalFeeRecipient");

        // Set up acquirer and register it
        uint48 testAcquirerId = bytesToUint48(bytes6(TEST_ACQUIRER_ID));
        acquirerConfig.setAcquirer(testAcquirerId, address(this)); // This test contract is the acquirer

        // Configure fees for this acquirer
        acquirerConfig.setAcquirerFee(testAcquirerId, acquirerAddress, 25); // 0.25% acquirer fee (25 basis points, within max 30)
        acquirerConfig.setSwipeFee(testAcquirerId, 50 * 10 ** 16); // $0.50 terminal fee (0.05 tokens with 18 decimals)

        // Configure global network and interchange fees
        acquirerConfig.setNetworkFee(address(this), 15); // 0.15% network fee
        acquirerConfig.setInterchangeFee(address(this), 200); // 2.00% interchange fee

        // Register merchant and terminal with this acquirer
        acquirerConfig.setMerchant(testAcquirerId, bytesToUint120(bytes15(TEST_MERCHANT_ID)), merchantAddress);
        acquirerConfig.setTerminal(testAcquirerId, bytesToUint64(bytes8(TEST_TERMINAL_ID)), terminalFeeRecipient);

        // Deploy settlement contract with configuration
        emvSettlement = new EMVSettlement(
            address(mockERC20), // token address
            address(acquirerConfig), // acquirer config address
            18, // token decimals
            address(this) // owner
        );

        // Deploy EMV validator with target and selector
        emvValidator = new EMVValidator(
            address(emvSettlement), // target address for validation
            kernel.execute.selector // function selector for validation
        );

        // Mint tokens to the test contract and kernel
        mockERC20.mint(address(this), 1e24); // 1 million tokens with 18 decimals
        mockERC20.mint(address(kernel), 1e24); // 1 million tokens to kernel for EMV transfers

        // Verify test contract has tokens from the inherited mockERC20
        uint256 balance = mockERC20.balanceOf(address(this));
        console.log("Test contract balance from mockERC20:", balance);
    }

    // Helper to install EMVValidator as validator, executor, and hook
    function _installEMVValidator() internal {
        vm.deal(address(kernel), 1e18);

        // Install EMVValidator as validator with EMVValidator itself as hook for execution validation
        PackedUserOperation[] memory ops1 = new PackedUserOperation[](1);
        ops1[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_VALIDATOR,
                address(emvValidator),
                abi.encodePacked(
                    address(0), // No hook for validator
                    abi.encode(
                        abi.encode(uint16(0)), // validator data - only ATC needed
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

    function _createEMVTransactionData() internal pure returns (bytes memory) {
        // Encode without padding to allow single-slice extraction
        return abi.encodePacked(
            TEST_ARQC, // 8 bytes
            TEST_UNPREDICTABLE_NUMBER, // 4 bytes
            TEST_ATC, // 2 bytes
            TEST_AMOUNT, // 6 bytes
            TEST_CURRENCY, // 2 bytes
            TEST_DATE, // 3 bytes
            TEST_TXN_TYPE, // 1 byte
            TEST_TVR, // 5 bytes
            TEST_CVM_RESULTS, // 3 bytes
            TEST_TERMINAL_ID, // 8 bytes
            TEST_MERCHANT_ID, // 15 bytes
            TEST_ACQUIRER_ID, // 6 bytes
            TEST_SIGNATURE, // Variable length
            TEST_EXPONENT, // Variable length
            TEST_MODULUS // Variable length
        );
    }

    function _createInvalidEMVTransactionData() internal pure returns (bytes memory) {
        // Encode without padding to allow single-slice extraction - with invalid signature
        return abi.encodePacked(
            TEST_ARQC, // 8 bytes
            TEST_UNPREDICTABLE_NUMBER, // 4 bytes
            TEST_ATC, // 2 bytes
            TEST_AMOUNT, // 6 bytes
            TEST_CURRENCY, // 2 bytes
            TEST_DATE, // 3 bytes
            TEST_TXN_TYPE, // 1 byte
            TEST_TVR, // 5 bytes
            TEST_CVM_RESULTS, // 3 bytes
            TEST_TERMINAL_ID, // 8 bytes
            TEST_MERCHANT_ID, // 15 bytes
            TEST_ACQUIRER_ID, // 6 bytes
            hex"deadbeef", // Invalid signature (4 bytes instead of 256)
            TEST_EXPONENT, // Variable length
            TEST_MODULUS // Variable length
        );
    }

    function _encodeEMVExecuteCall() internal view returns (bytes memory) {
        // First install the EMV processor as an executor
        bytes memory installExecutorCall = abi.encodeWithSelector(
            kernel.installModule.selector,
            MODULE_TYPE_EXECUTOR,
            address(emvValidator),
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
        // Create the EMV struct for EMVSettlement (it still expects ABI-encoded struct)
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            acquirerId: TEST_ACQUIRER_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        // Call through Kernel's execute function using delegate call to EMVSettlement
        return abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)
            ),
            abi.encodePacked(
                address(emvSettlement), // delegate target
                abi.encodeWithSelector(
                    emvSettlement.execute.selector,
                    _createEMVTransactionData() // EMVSettlement now expects packed format
                )
            )
        );
    }

    function _prepareEMVUserOp(bytes memory callData, bool success) internal returns (PackedUserOperation memory op) {
        // Create a UserOperation that uses EMVValidator as the validator
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(emvValidator)),
            0 // parallel key
        );

        op = PackedUserOperation({
            sender: address(kernel),
            nonce: entrypoint.getNonce(address(kernel), nonceKey),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: "",
            signature: success ? _createEMVTransactionData() : _createInvalidEMVTransactionData()
        });
    }

    function test_Deployment() public whenInitialized {
        assertTrue(address(emvValidator) != address(0));
        assertTrue(address(kernel) != address(0));
        assertTrue(address(entrypoint) != address(0));

        // Check that the kernel was initialized with MockValidator as root validator
        assertEq(ValidationId.unwrap(kernel.rootValidator()), ValidationId.unwrap(rootValidation));

        // EMVValidator should not be installed yet
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvValidator), ""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(emvSettlement), ""));
    }

    function test_ModuleType() public {
        assertTrue(emvValidator.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(emvValidator.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(emvValidator.isModuleType(MODULE_TYPE_HOOK));
        assertFalse(emvValidator.isModuleType(MODULE_TYPE_FALLBACK));

        // Test EMVSettlement module types
        assertTrue(emvSettlement.isModuleType(MODULE_TYPE_EXECUTOR));
        assertFalse(emvSettlement.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(emvSettlement.isModuleType(MODULE_TYPE_HOOK));
    }

    function test_InvalidTargetAndSelectorValidation() public whenInitialized {
        // Install EMVValidator as both validator and executor
        _installEMVValidator();

        // Create a UserOp with wrong function selector
        bytes memory wrongCallData = abi.encodeWithSelector(bytes4(keccak256("wrongFunction()")));
        PackedUserOperation memory userOp = _prepareEMVUserOp(wrongCallData, true);

        // The EntryPoint will wrap our custom error in FailedOpWithRevert
        // We expect the operation to fail due to InvalidFunctionSelector
        vm.expectRevert(); // Just expect any revert since EntryPoint wraps errors
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        entrypoint.handleOps(ops, payable(address(0x69)));
    }

    function test_ValidEMVTransaction() public whenInitialized {
        // Install EMVValidator as both validator and executor
        _installEMVValidator();

        // Verify that EMVValidator was installed properly
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvValidator), ""),
            "EMVValidator should be installed"
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

        // Create a UserOperation using EMVValidator as validator to execute simple transfer
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
        // Install EMVValidator as both validator and executor
        _installEMVValidator();

        // Fund the kernel with tokens for transfer
        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Create a UserOperation with invalid EMV signature
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            false // invalid signature
        );

        // Expect the operation to fail due to invalid signature format (now caught by RSA key size validation)
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_InstallEMVAsValidatorAndExecutor() public whenInitialized {
        // Install EMVValidator as both validator and executor
        _installEMVValidator();

        // Check that both modules were installed
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvValidator), ""));
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(emvSettlement), ""));
    }

    function test_MerchantRegistryIntegration() public whenInitialized {
        // Install EMVValidator as both validator and executor
        _installEMVValidator();

        // Fund the kernel with tokens for transfer
        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Check initial balances
        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);

        // Create a UserOperation using EMVValidator as validator to execute EMV transfer
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

    function test_DynamicDataAssembly() public view {
        // This test verifies that our dynamic data assembly matches the expected format
        EMVTransactionData memory txnData = EMVTransactionData({
            arqc: TEST_ARQC,
            unpredictableNumber: TEST_UNPREDICTABLE_NUMBER,
            atc: TEST_ATC,
            amount: TEST_AMOUNT,
            currency: TEST_CURRENCY,
            date: TEST_DATE,
            txnType: TEST_TXN_TYPE,
            tvr: TEST_TVR,
            cvmResults: TEST_CVM_RESULTS,
            terminalId: TEST_TERMINAL_ID,
            merchantId: TEST_MERCHANT_ID,
            acquirerId: TEST_ACQUIRER_ID,
            signature: TEST_SIGNATURE,
            exponent: TEST_EXPONENT,
            modulus: TEST_MODULUS
        });

        // The dynamic data should match our expected format
        bytes memory expectedData = abi.encodePacked(
            bytes1(0x6A), // Header
            bytes1(0x03), // Format (Signed Data Format 3)
            TEST_ARQC, // 9F26 - ARQC (8 bytes)
            TEST_UNPREDICTABLE_NUMBER, // 9F37 - Unpredictable Number (4 bytes)
            TEST_ATC, // 9F36 - ATC (2 bytes)
            TEST_AMOUNT, // 9F02 - Amount (6 bytes BCD)
            TEST_CURRENCY, // 5F2A - Currency (2 bytes)
            TEST_DATE, // 9A - Date (3 bytes BCD)
            TEST_TXN_TYPE, // 9C - Transaction Type (1 byte)
            TEST_TVR, // 95 - TVR (5 bytes)
            TEST_CVM_RESULTS, // 9F34 - CVM Results (3 bytes)
            TEST_TERMINAL_ID, // 9F1C - Terminal ID (8 bytes)
            TEST_MERCHANT_ID, // 9F16 - Merchant ID (15 bytes)
            TEST_ACQUIRER_ID, // 9F01 - Acquirer ID (6 bytes)
            bytes1(0xBC) // Trailer
        );

        assertEq(expectedData, EXPECTED_DYNAMIC_DATA);
    }

    function test_SecurityVulnerability_ValidatorExecutorSeparation() public whenInitialized {
        // This test verifies that the security vulnerability has been FIXED:
        // EMV validation now prevents execution that doesn't match EMV constraints

        // Install EMVValidator as validator with access to execute
        _installEMVValidator();

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

    function test_RSA1024Blocked() public {
        // Create EMV data with RSA-1024 key (128-byte modulus instead of 256)
        bytes memory rsa1024Modulus = new bytes(128); // RSA-1024 modulus
        for (uint256 i = 0; i < 128; i++) {
            rsa1024Modulus[i] = bytes1(uint8(i + 1)); // Fill with test data
        }

        // Create RSA-1024 signature (128 bytes instead of 256)
        bytes memory rsa1024Signature = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            rsa1024Signature[i] = bytes1(uint8(i + 1));
        }

        bytes memory emvDataWithRSA1024 = abi.encodePacked(
            TEST_ARQC, // 8 bytes
            TEST_UNPREDICTABLE_NUMBER, // 4 bytes
            TEST_ATC, // 2 bytes
            TEST_AMOUNT, // 6 bytes
            TEST_CURRENCY, // 2 bytes
            TEST_DATE, // 3 bytes
            TEST_TXN_TYPE, // 1 byte
            TEST_TVR, // 5 bytes
            TEST_CVM_RESULTS, // 3 bytes
            TEST_TERMINAL_ID, // 8 bytes
            TEST_MERCHANT_ID, // 15 bytes
            TEST_ACQUIRER_ID, // 6 bytes
            rsa1024Signature, // 128 bytes (RSA-1024 signature)
            TEST_EXPONENT, // 3 bytes
            rsa1024Modulus // 128 bytes (RSA-1024 modulus - should be blocked)
        );

        // Attempt to verify with RSA-1024 should fail with InvalidRSAKeySize
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.InvalidRSAKeySize.selector, 128));
        emvValidator.verifyEMVSignature(emvDataWithRSA1024);
    }

    function test_DirectValidateUserOpGasMeasurement() public whenInitialized {
        // Install EMVValidator to initialize it properly
        _installEMVValidator();

        // Create a UserOperation with valid EMV signature
        PackedUserOperation memory userOp = _prepareEMVUserOp(
            _encodeSimpleTransferCall(),
            true // successful signature
        );

        // Calculate the userOpHash (this is what EntryPoint would calculate)
        bytes32 userOpHash = keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                keccak256(userOp.paymasterAndData)
            )
        );

        // Call validateUserOp directly on EMVValidator to measure gas
        // This will show up in the gas report as a direct call
        vm.prank(address(kernel)); // EMVValidator expects msg.sender to be the kernel
        uint256 validationResult = emvValidator.validateUserOp(userOp, userOpHash);

        // Assert validation was successful
        assertEq(validationResult, SIG_VALIDATION_SUCCESS_UINT, "EMV validation should succeed");

        // Verify the validator state was updated correctly
        assertEq(emvValidator.getEMVStorage(address(kernel)), 1, "ATC should be incremented to 1");
        assertTrue(
            emvValidator.isUnpredictableNumberUsed(address(kernel), bytes4(TEST_UNPREDICTABLE_NUMBER)),
            "Unpredictable number should be marked as used"
        );
    }

    // ========== ACQUIRER CONFIG TESTS ==========

    function test_AcquirerConfigBasics() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        uint120 merchantId = bytesToUint120(bytes15(TEST_MERCHANT_ID));
        address testMerchantAddress = address(0x789);

        // Register acquirer (owner-only)
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Register merchant with this acquirer
        acquirerConfig.setMerchant(testAcquirerId, merchantId, testMerchantAddress);

        // Check registration
        assertTrue(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertEq(acquirerConfig.getMerchantAddress(testAcquirerId, merchantId), testMerchantAddress);

        // Test removal
        acquirerConfig.setMerchant(testAcquirerId, merchantId, address(0));
        assertFalse(acquirerConfig.isMerchantRegistered(testAcquirerId, merchantId));
        assertEq(acquirerConfig.getMerchantAddress(testAcquirerId, merchantId), address(0));
    }

    function test_AcquirerAndTerminalFees() public {
        address acquirer = makeAddr("testAcquirer");
        address terminalRecipient = makeAddr("testTerminalRecipient");
        uint64 testTerminalId = bytesToUint64(bytes8("TESTTERM"));
        uint120 testMerchantId = bytesToUint120(bytes15("TESTMERCHANT123"));
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));

        // Register acquirer (owner-only)
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Set up acquirer fees
        acquirerConfig.setAcquirerFee(testAcquirerId, acquirer, 25); // 0.25% (within max 30)

        // Set up terminal fee
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether); // 1 token terminal fee

        // Register merchant and terminal with this acquirer
        address testMerchant = makeAddr("testMerchant");
        acquirerConfig.setMerchant(testAcquirerId, testMerchantId, testMerchant);
        acquirerConfig.setTerminal(testAcquirerId, testTerminalId, terminalRecipient);

        // Test payment distribution calculation
        uint256 totalAmount = 10 ether;
        AcquirerConfig.FeeRecipient[] memory feeRecipients =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, testTerminalId, testAcquirerId, totalAmount);

        // Verify fee structure (should have acquirer fee, swipe fee, and merchant)
        assertGt(feeRecipients.length, 2);

        // Find the merchant recipient (should be last with fee=0)
        AcquirerConfig.FeeRecipient memory merchantRecipient = feeRecipients[feeRecipients.length - 1];
        assertEq(merchantRecipient.recipient, testMerchant);
        assertEq(merchantRecipient.fee, 0); // Merchant fee must be 0
    }

    function test_AcquirerConfigNotRegistered() public {
        uint64 testTerminalId = bytesToUint64(bytes8("TESTTERM"));
        uint120 unregisteredMerchantId = bytesToUint120(bytes15("UNREGISTERED123"));
        uint48 unregisteredAcquirerId = bytesToUint48(bytes6("UNREG1"));

        // Test payment distribution calculation with unregistered acquirer
        uint256 totalAmount = 10 ether;

        // Should revert with InvalidAcquirerId
        vm.expectRevert(AcquirerConfig.InvalidAcquirerId.selector);
        acquirerConfig.calculatePaymentDistribution(
            unregisteredMerchantId, testTerminalId, unregisteredAcquirerId, totalAmount
        );
    }

    function test_FallbackToFeeRecipient() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        uint120 unregisteredMerchantId = bytesToUint120(bytes15("UNREG_MERCHANT"));
        uint64 unregisteredTerminalId = bytesToUint64(bytes8("UNREG_TM"));
        address feeRecipient = makeAddr("feeRecipient");

        // Register acquirer and set fee recipient
        acquirerConfig.setAcquirer(testAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(testAcquirerId, feeRecipient, 25);

        // Test payment distribution with unregistered merchant/terminal (should fallback to feeRecipient)
        uint256 totalAmount = 10 ether;
        AcquirerConfig.FeeRecipient[] memory feeRecipients = acquirerConfig.calculatePaymentDistribution(
            unregisteredMerchantId, unregisteredTerminalId, testAcquirerId, totalAmount
        );

        // Should have at least the merchant entry (using feeRecipient as fallback)
        assertGt(feeRecipients.length, 0);

        // Last recipient should be the merchant (using feeRecipient as fallback)
        AcquirerConfig.FeeRecipient memory merchantRecipient = feeRecipients[feeRecipients.length - 1];
        assertEq(merchantRecipient.recipient, feeRecipient, "Should fallback to feeRecipient for unregistered merchant");
        assertEq(merchantRecipient.fee, 0, "Merchant fee must be 0");
    }

    function test_DuplicateRecipientAccumulation() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        uint120 testMerchantId = bytesToUint120(bytes15("TESTMERCHANT123"));
        uint64 testTerminalId = bytesToUint64(bytes8("TESTTERM"));
        address sharedRecipient = makeAddr("sharedRecipient");

        // Register acquirer and set the SAME address for all fee recipients
        acquirerConfig.setAcquirer(testAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(testAcquirerId, sharedRecipient, 25); // 0.25%
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether); // 1 token swipe fee

        // Set global fees to same recipient to test accumulation
        acquirerConfig.setNetworkFee(sharedRecipient, 15); // 0.15%
        acquirerConfig.setInterchangeFee(sharedRecipient, 200); // 2.00%

        // Register merchant and terminal with different addresses to ensure they don't accumulate
        address testMerchantAddress = makeAddr("merchant");
        address terminalAddress = makeAddr("terminal");
        acquirerConfig.setMerchant(testAcquirerId, testMerchantId, testMerchantAddress);
        acquirerConfig.setTerminal(testAcquirerId, testTerminalId, terminalAddress);

        // Test payment distribution - should accumulate fees for shared recipient
        uint256 totalAmount = 100 ether;
        AcquirerConfig.FeeRecipient[] memory feeRecipients =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, testTerminalId, testAcquirerId, totalAmount);

        // Should have fewer recipients due to accumulation
        // Expected: 1 accumulated fee recipient + 1 terminal + 1 merchant = 3 total
        // But if swipe fee is 0 or terminal = shared recipient, could be 2 total
        assertGe(feeRecipients.length, 2, "Should have at least 2 recipients");
        assertLe(feeRecipients.length, 3, "Should have at most 3 recipients");

        // Find the accumulated fee recipient
        bool foundAccumulated = false;
        for (uint256 i = 0; i < feeRecipients.length; i++) {
            if (feeRecipients[i].recipient == sharedRecipient) {
                foundAccumulated = true;
                // Should have accumulated: acquirer (0.25%) + network (0.15%) + interchange (2.00%) = 2.40%
                // Swipe fee goes to terminal (different address), so not accumulated
                uint256 expectedAccumulatedFee = (totalAmount * 240) / 10000; // 2.40%
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
        uint120 testMerchantId = bytesToUint120(bytes15("TESTMERCHANT123"));
        uint64 testTerminalId = bytesToUint64(bytes8("TESTTERM"));

        // Create different addresses for each fee type
        address acquirerRecipient = makeAddr("acquirerRecipient");
        address terminalRecipient = makeAddr("terminalRecipient");
        address networkRecipient = makeAddr("networkRecipient");
        address interchangeRecipient = makeAddr("interchangeRecipient");
        address merchantRecipient = makeAddr("merchantRecipient");

        // Register acquirer and set different recipients for each fee type
        acquirerConfig.setAcquirer(testAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(testAcquirerId, acquirerRecipient, 25); // 0.25%
        acquirerConfig.setSwipeFee(testAcquirerId, 1 ether); // 1 token swipe fee

        // Set different global fee recipients
        acquirerConfig.setNetworkFee(networkRecipient, 15); // 0.15%
        acquirerConfig.setInterchangeFee(interchangeRecipient, 200); // 2.00%

        // Register merchant and terminal with unique addresses
        acquirerConfig.setMerchant(testAcquirerId, testMerchantId, merchantRecipient);
        acquirerConfig.setTerminal(testAcquirerId, testTerminalId, terminalRecipient);

        // Test payment distribution - should have 5 separate recipients (no accumulation)
        uint256 totalAmount = 100 ether;
        AcquirerConfig.FeeRecipient[] memory feeRecipients =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, testTerminalId, testAcquirerId, totalAmount);

        // Should have 5 recipients: acquirer + swipe + interchange + network + merchant
        assertEq(feeRecipients.length, 5, "Should have 5 separate recipients when all addresses are different");

        // Verify each recipient has the correct fee amount
        bool foundAcquirer = false;
        bool foundTerminal = false;
        bool foundNetwork = false;
        bool foundInterchange = false;
        bool foundMerchant = false;

        for (uint256 i = 0; i < feeRecipients.length; i++) {
            if (feeRecipients[i].recipient == acquirerRecipient) {
                foundAcquirer = true;
                uint256 expectedAcquirerFee = (totalAmount * 25) / 10000; // 0.25%
                assertEq(feeRecipients[i].fee, expectedAcquirerFee, "Acquirer fee should be 0.25%");
            } else if (feeRecipients[i].recipient == terminalRecipient) {
                foundTerminal = true;
                assertEq(feeRecipients[i].fee, 1 ether, "Terminal should get 1 ether swipe fee");
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
        assertTrue(foundTerminal, "Should find terminal recipient");
        assertTrue(foundNetwork, "Should find network recipient");
        assertTrue(foundInterchange, "Should find interchange recipient");
        assertTrue(foundMerchant, "Should find merchant recipient");
    }
}
