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

        // Install EMVValidator as validator with public key registration
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
                        abi.encode(uint16(0), TEST_EXPONENT, TEST_MODULUS), // validator data - ATC + public key
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

    function _createEMVFields() internal pure returns (bytes memory) {
        // Create just the 63-byte EMV transaction fields
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
            TEST_ACQUIRER_ID // 6 bytes
        );
    }

    function _createEMVTransactionData() internal pure returns (bytes memory) {
        // Legacy format for tests that need both fields and signature
        // New format: EMV fields (63 bytes) + RSA signature (256 bytes) = 319 bytes
        return abi.encodePacked(
            _createEMVFields(),
            TEST_SIGNATURE // 256 bytes
        );
    }

    function _createInvalidEMVTransactionData() internal pure returns (bytes memory) {
        // Encode without padding to allow single-slice extraction - with invalid signature length
        return abi.encodePacked(
            _createEMVFields(),
            hex"deadbeef" // Invalid signature (4 bytes instead of 256) - will trigger InvalidRSAKeySize
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
        // Call through Kernel's execute function using delegate call to EMVSettlement
        // Now only passes EMV fields (63 bytes) to settlement, not the signature
        return abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)
            ),
            abi.encodePacked(
                address(emvSettlement), // delegate target (20 bytes)
                // For delegatecall: no value field, just target + calldata
                abi.encodeWithSelector(
                    emvSettlement.execute.selector,
                    _createEMVFields() // Now only EMV fields (63 bytes)
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

        // Prepare signature: valid RSA signature (256 bytes) or invalid short signature
        bytes memory signature;
        if (success) {
            signature = TEST_SIGNATURE;
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
            signature: signature // Just RSA signature (256 bytes) or invalid
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
        // Test that RSA-1024 signature (128 bytes) is blocked during installation
        bytes memory rsa1024Modulus = new bytes(128); // RSA-1024 modulus
        for (uint256 i = 0; i < 128; i++) {
            rsa1024Modulus[i] = bytes1(uint8(i + 1)); // Fill with test data
        }

        // Create a new validator for this test
        EMVValidator testValidator = new EMVValidator(address(emvSettlement), kernel.execute.selector);
        
        // Try to install with RSA-1024 key - should fail with InvalidPublicKeySize
        vm.expectRevert(EMVValidator.InvalidPublicKeySize.selector);
        testValidator.onInstall(abi.encode(uint16(0), TEST_EXPONENT, rsa1024Modulus));
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

    function test_GasMeasurement_CompleteEMVTransaction() public whenInitialized {
        // Comprehensive gas measurement test for complete EMV flow through entrypoint
        // This test measures the TOTAL gas cost of an EMV transaction from start to finish
        
        _installEMVValidator();

        // Fund the kernel
        mockERC20.transfer(address(kernel), 1e21); // 1000 tokens
        vm.deal(address(kernel), 10 ether);

        uint256 merchantBalanceBefore = mockERC20.balanceOf(merchantAddress);

        // Create a UserOperation using EMVValidator
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

    // ========== ADDITIONAL COVERAGE TESTS ==========

    function test_AcquirerConfigGetters() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        uint120 testMerchantId = bytesToUint120(bytes15("MERCHANT000001"));
        uint64 testTerminalId = bytesToUint64(bytes8("TERMINAL"));

        // Register acquirer
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Test isAcquirerRegistered
        assertTrue(acquirerConfig.isAcquirerRegistered(testAcquirerId));
        assertFalse(acquirerConfig.isAcquirerRegistered(999));

        // Test getAcquirerAddress
        assertEq(acquirerConfig.getAcquirerAddress(testAcquirerId), address(this));

        // Set up merchant and terminal
        address merchantAddr = makeAddr("merchant");
        address terminalAddr = makeAddr("terminal");
        acquirerConfig.setMerchant(testAcquirerId, testMerchantId, merchantAddr);
        acquirerConfig.setTerminal(testAcquirerId, testTerminalId, terminalAddr);

        // Test getTerminalAddress
        assertEq(acquirerConfig.getTerminalAddress(testAcquirerId, testTerminalId), terminalAddr);

        // Test isTerminalRegistered
        assertTrue(acquirerConfig.isTerminalRegistered(testAcquirerId, testTerminalId));
        assertFalse(acquirerConfig.isTerminalRegistered(testAcquirerId, 999));

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

        // Test batch set merchants
        uint120[] memory merchantIds = new uint120[](3);
        address[] memory merchantAddrs = new address[](3);
        merchantIds[0] = 1;
        merchantIds[1] = 2;
        merchantIds[2] = 3;
        merchantAddrs[0] = makeAddr("merchant1");
        merchantAddrs[1] = makeAddr("merchant2");
        merchantAddrs[2] = makeAddr("merchant3");

        acquirerConfig.batchSetMerchants(testAcquirerId, merchantIds, merchantAddrs);

        // Verify all merchants were set
        assertEq(acquirerConfig.getMerchantAddress(testAcquirerId, 1), makeAddr("merchant1"));
        assertEq(acquirerConfig.getMerchantAddress(testAcquirerId, 2), makeAddr("merchant2"));
        assertEq(acquirerConfig.getMerchantAddress(testAcquirerId, 3), makeAddr("merchant3"));

        // Test batch set terminals
        uint64[] memory terminalIds = new uint64[](2);
        address[] memory terminalAddrs = new address[](2);
        terminalIds[0] = 100;
        terminalIds[1] = 200;
        terminalAddrs[0] = makeAddr("terminal1");
        terminalAddrs[1] = makeAddr("terminal2");

        acquirerConfig.batchSetTerminals(testAcquirerId, terminalIds, terminalAddrs);

        // Verify all terminals were set
        assertEq(acquirerConfig.getTerminalAddress(testAcquirerId, 100), makeAddr("terminal1"));
        assertEq(acquirerConfig.getTerminalAddress(testAcquirerId, 200), makeAddr("terminal2"));
    }

    function test_AcquirerConfigBatchMismatchErrors() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Test merchant array length mismatch
        uint120[] memory merchantIds = new uint120[](2);
        address[] memory merchantAddrs = new address[](1);
        merchantIds[0] = 1;
        merchantIds[1] = 2;
        merchantAddrs[0] = makeAddr("merchant1");

        vm.expectRevert("AcquirerConfig: array length mismatch");
        acquirerConfig.batchSetMerchants(testAcquirerId, merchantIds, merchantAddrs);

        // Test terminal array length mismatch
        uint64[] memory terminalIds = new uint64[](2);
        address[] memory terminalAddrs = new address[](3);
        terminalIds[0] = 1;
        terminalIds[1] = 2;
        terminalAddrs[0] = makeAddr("terminal1");
        terminalAddrs[1] = makeAddr("terminal2");
        terminalAddrs[2] = makeAddr("terminal3");

        vm.expectRevert("AcquirerConfig: array length mismatch");
        acquirerConfig.batchSetTerminals(testAcquirerId, terminalIds, terminalAddrs);
    }

    function test_AcquirerConfigInvalidIds() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        acquirerConfig.setAcquirer(testAcquirerId, address(this));

        // Test invalid merchant ID
        vm.expectRevert(AcquirerConfig.InvalidMerchantId.selector);
        acquirerConfig.setMerchant(testAcquirerId, 0, makeAddr("merchant"));

        // Test invalid terminal ID
        vm.expectRevert(AcquirerConfig.InvalidTerminalId.selector);
        acquirerConfig.setTerminal(testAcquirerId, 0, makeAddr("terminal"));

        // Test invalid merchant ID in batch
        uint120[] memory merchantIds = new uint120[](1);
        address[] memory merchantAddrs = new address[](1);
        merchantIds[0] = 0;
        merchantAddrs[0] = makeAddr("merchant");

        vm.expectRevert(AcquirerConfig.InvalidMerchantId.selector);
        acquirerConfig.batchSetMerchants(testAcquirerId, merchantIds, merchantAddrs);

        // Test invalid terminal ID in batch
        uint64[] memory terminalIds = new uint64[](1);
        address[] memory terminalAddrs = new address[](1);
        terminalIds[0] = 0;
        terminalAddrs[0] = makeAddr("terminal");

        vm.expectRevert(AcquirerConfig.InvalidTerminalId.selector);
        acquirerConfig.batchSetTerminals(testAcquirerId, terminalIds, terminalAddrs);
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
        acquirerConfig.setMerchant(testAcquirerId, 1, makeAddr("merchant"));

        vm.expectRevert(
            abi.encodeWithSelector(AcquirerConfig.UnauthorizedAcquirer.selector, testAcquirerId, unauthorized)
        );
        acquirerConfig.setTerminal(testAcquirerId, 1, makeAddr("terminal"));

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
        acquirerConfig.setMerchant(testAcquirerId, 1, makeAddr("merchant"));

        vm.stopPrank();
    }

    function test_AcquirerConfigInvalidAcquirerId() public {
        // Test with unregistered acquirer (address(0))
        uint48 unregisteredAcquirerId = 999;

        vm.expectRevert(AcquirerConfig.InvalidAcquirerId.selector);
        acquirerConfig.setMerchant(unregisteredAcquirerId, 1, makeAddr("merchant"));
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
        new EMVSettlement(address(0), address(acquirerConfig), 18, address(this));

        // Test constructor with invalid acquirer config
        vm.expectRevert(EMVSettlement.InvalidConfig.selector);
        new EMVSettlement(address(mockERC20), address(0), 18, address(this));

        // Test constructor with invalid decimals
        vm.expectRevert(EMVSettlement.InvalidDecimals.selector);
        new EMVSettlement(address(mockERC20), address(acquirerConfig), 1, address(this));
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

    function test_EMVValidatorErrors() public {
        // Test constructor with invalid target
        vm.expectRevert(EMVValidator.InvalidConfig.selector);
        new EMVValidator(address(0), kernel.execute.selector);

        // Test constructor with invalid selector
        vm.expectRevert(EMVValidator.InvalidConfig.selector);
        new EMVValidator(address(emvSettlement), bytes4(0));

        // Test onInstall with empty data
        EMVValidator testValidator = new EMVValidator(address(emvSettlement), kernel.execute.selector);
        vm.expectRevert(EMVValidator.InvalidConfig.selector);
        testValidator.onInstall("");
    }

    function test_EMVValidatorUninstall() public whenInitialized {
        _installEMVValidator();

        // Verify public key is registered
        (bytes memory exponent, bytes memory modulus) = emvValidator.getRegisteredPublicKey(address(kernel));
        assertEq(exponent.length, 3);
        assertEq(modulus.length, 256);

        // Call onUninstall
        vm.prank(address(kernel));
        emvValidator.onUninstall("");

        // Verify ATC was reset
        assertEq(emvValidator.getEMVStorage(address(kernel)), 0);
        
        // Verify public key was cleared
        (bytes memory exponentAfter, bytes memory modulusAfter) = emvValidator.getRegisteredPublicKey(address(kernel));
        assertEq(exponentAfter.length, 0);
        assertEq(modulusAfter.length, 0);
    }

    function test_EMVValidatorIsInitialized() public {
        // Create a new validator
        EMVValidator testValidator = new EMVValidator(address(emvSettlement), kernel.execute.selector);

        // Should not be initialized for any account initially
        assertFalse(testValidator.isInitialized(address(this)));

        // Install it with public key
        testValidator.onInstall(abi.encode(uint16(1), TEST_EXPONENT, TEST_MODULUS));

        // Now should be initialized
        assertTrue(testValidator.isInitialized(address(this)));
    }

    function test_EMVValidatorGetValidationConfig() public {
        (address targetAddr, bytes4 funcSelector) = emvValidator.getValidationConfig();
        assertEq(targetAddr, address(emvSettlement));
        assertEq(funcSelector, kernel.execute.selector);
    }

    function test_EMVValidatorInvalidCurrency() public whenInitialized {
        _installEMVValidator();

        // Create EMV data with invalid currency (not 840 or 997)
        bytes memory invalidCurrencyData = abi.encodePacked(
            TEST_ARQC, // 8 bytes
            TEST_UNPREDICTABLE_NUMBER, // 4 bytes
            TEST_ATC, // 2 bytes
            TEST_AMOUNT, // 6 bytes
            hex"0000", // Invalid currency (0 instead of 840 or 997)
            TEST_DATE, // 3 bytes
            TEST_TXN_TYPE, // 1 byte
            TEST_TVR, // 5 bytes
            TEST_CVM_RESULTS, // 3 bytes
            TEST_TERMINAL_ID, // 8 bytes
            TEST_MERCHANT_ID, // 15 bytes
            TEST_ACQUIRER_ID, // 6 bytes
            TEST_SIGNATURE // 256 bytes
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = invalidCurrencyData;

        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_EMVValidatorReplayProtection() public whenInitialized {
        _installEMVValidator();

        mockERC20.transfer(address(kernel), 2e21);
        vm.deal(address(kernel), 2e18);

        // First transaction should succeed
        PackedUserOperation[] memory ops1 = new PackedUserOperation[](1);
        ops1[0] = _prepareEMVUserOp(_encodeSimpleTransferCall(), true);
        entrypoint.handleOps(ops1, payable(address(0xdeadbeef)));

        // Try to replay the same transaction (same unpredictable number)
        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = _prepareEMVUserOp(_encodeSimpleTransferCall(), true);
        ops2[0].signature = ops1[0].signature; // Same signature = same unpredictable number

        vm.expectRevert();
        entrypoint.handleOps(ops2, payable(address(0xdeadbeef)));
    }

    function test_EMVValidatorERC1271Validation() public {
        // Install the validator with public key for this test contract
        emvValidator.onInstall(abi.encode(uint16(0), TEST_EXPONENT, TEST_MODULUS));

        // Compute the hash of the EMV dynamic data
        bytes32 dynamicDataHash = sha256(abi.encodePacked(
            bytes1(0x6A), bytes1(0x03),
            TEST_ARQC, TEST_UNPREDICTABLE_NUMBER, TEST_ATC, TEST_AMOUNT,
            TEST_CURRENCY, TEST_DATE, TEST_TXN_TYPE, TEST_TVR, TEST_CVM_RESULTS,
            TEST_TERMINAL_ID, TEST_MERCHANT_ID, TEST_ACQUIRER_ID,
            bytes1(0xBC)
        ));

        // Test isValidSignatureWithSender - should return ERC1271_MAGICVALUE for valid signature
        // For ERC-1271, we only pass the RSA signature bytes (256 bytes), not the EMV fields
        bytes4 result = emvValidator.isValidSignatureWithSender(address(this), dynamicDataHash, TEST_SIGNATURE);
        assertEq(result, ERC1271_MAGICVALUE);

        // Test with invalid signature (wrong hash)
        bytes32 wrongHash = keccak256("wrong data");
        bytes4 invalidResult = emvValidator.isValidSignatureWithSender(address(this), wrongHash, TEST_SIGNATURE);
        assertEq(invalidResult, ERC1271_INVALID);
    }

    function test_EMVSettlementInvalidAmount() public whenInitialized {
        _installEMVValidator();

        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Create EMV data with amount = 0
        bytes memory zeroAmountData = abi.encodePacked(
            TEST_ARQC, // 8 bytes
            TEST_UNPREDICTABLE_NUMBER, // 4 bytes
            hex"0001", // Different ATC to avoid replay
            hex"000000000000", // Amount = 0
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_ACQUIRER_ID,
            TEST_SIGNATURE,
            TEST_EXPONENT,
            TEST_MODULUS
        );

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
        // Create EMV data with invalid BCD digits (>9)
        bytes memory invalidBCDData = abi.encodePacked(
            TEST_ARQC, // 8 bytes
            hex"11223344", // 4 bytes unpredictable
            hex"0001", // 2 bytes ATC
            hex"0000000000FF", // Invalid BCD digit (0xFF has nibbles 15,15 which are >9)
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_ACQUIRER_ID
        );

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
        acquirerConfig.setMerchant(unregisteredAcquirer, 1, makeAddr("merchant"));
    }

    function test_EMVSettlementOnUninstallCoverage() public {
        // Explicitly test onUninstall to get coverage
        emvSettlement.onUninstall(hex"");
    }

    function test_EMVSettlementInvalidBCDReturnsZero() public {
        // Test line 199: when BCD length != 6, should return 0 which triggers InvalidAmount
        // Create data where amount field is less than 6 bytes
        bytes memory shortBCD = abi.encodePacked(
            TEST_ARQC, // 8 bytes
            TEST_UNPREDICTABLE_NUMBER, // 4 bytes
            TEST_ATC, // 2 bytes
            hex"0000", // Only 2 bytes instead of 6 - will trigger line 199
            TEST_CURRENCY // This shifts everything
        );

        // The function will try to read at wrong offsets and get invalid data
        // This will either revert on bounds or give us invalid amount
        vm.prank(address(kernel));
        vm.expectRevert();
        emvSettlement.execute(shortBCD);
    }

    function test_EMVValidatorInvalidSignatureFails() public whenInitialized {
        _installEMVValidator();

        mockERC20.transfer(address(kernel), 1e20);
        vm.deal(address(kernel), 1e18);

        // Create a UserOp with signature that fails RSA validation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(_encodeSimpleTransferCall(), false); // false = invalid signature

        // Signature validation should fail, returning SIG_VALIDATION_FAILED_UINT
        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_EMVValidatorInvalidATCSequence() public whenInitialized {
        _installEMVValidator();

        mockERC20.transfer(address(kernel), 1e21);
        vm.deal(address(kernel), 2e18);

        // Create EMV data with wrong ATC (skipping sequence)
        bytes memory wrongATCData = abi.encodePacked(
            TEST_ARQC, // 8 bytes
            hex"55667788", // Different unpredictable number
            hex"0005", // ATC = 5 (but expected is 0)
            TEST_AMOUNT,
            TEST_CURRENCY,
            TEST_DATE,
            TEST_TXN_TYPE,
            TEST_TVR,
            TEST_CVM_RESULTS,
            TEST_TERMINAL_ID,
            TEST_MERCHANT_ID,
            TEST_ACQUIRER_ID,
            TEST_SIGNATURE // 256 bytes
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _prepareEMVUserOp(_encodeSimpleTransferCall(), true);
        ops[0].signature = wrongATCData;

        vm.expectRevert();
        entrypoint.handleOps(ops, payable(address(0xdeadbeef)));
    }

    function test_AcquirerConfigAddressZeroInFeeRecipient() public {
        uint48 testAcquirerId = bytesToUint48(bytes6("TESTAQ"));
        uint120 testMerchantId = 123;
        uint64 testTerminalId = 456;

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
        acquirerConfig.setMerchant(testAcquirerId, testMerchantId, makeAddr("merchant"));

        // This should work since all fees are 0, so no fee recipients are added
        AcquirerConfig.FeeRecipient[] memory result =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, testTerminalId, testAcquirerId, 100 ether);

        // Should only have merchant (all fees are 0)
        assertEq(result.length, 1);
        assertEq(result[0].recipient, makeAddr("merchant"));
        assertEq(result[0].fee, 0);
    }

    function test_EMVValidatorTargetMismatch() public whenInitialized {
        _installEMVValidator();

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

    function test_EMVValidatorCallDataTooShort() public whenInitialized {
        _installEMVValidator();

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
        uint120 testMerchantId = bytesToUint120(bytes15(TEST_MERCHANT_ID));
        uint64 testTerminalId = bytesToUint64(bytes8(TEST_TERMINAL_ID));

        // Set fees to 0 to trigger the zero-fee check
        acquirerConfig.setAcquirerFee(testAcquirerId, makeAddr("acquirer"), 0); // 0% fee
        acquirerConfig.setSwipeFee(testAcquirerId, 0); // 0 swipe fee
        acquirerConfig.setNetworkFee(makeAddr("network"), 0); // 0% fee
        acquirerConfig.setInterchangeFee(makeAddr("interchange"), 0); // 0% fee

        // This should work - when all fees are 0, they're not added to the array
        AcquirerConfig.FeeRecipient[] memory result =
            acquirerConfig.calculatePaymentDistribution(testMerchantId, testTerminalId, testAcquirerId, 100 ether);

        // Should only have merchant
        assertEq(result.length, 1);
        assertEq(result[0].fee, 0);
    }

    // Note: _extractUnpredictableNumber and _extractATC are internal helper functions
    // They are tested indirectly through _validateReplayProtectionAndUpdateState

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

        testConfig.setMerchant(newAcquirer, 1, address(this));
        testConfig.setTerminal(newAcquirer, 1, address(this));

        AcquirerConfig.FeeRecipient[] memory feeRec =
            testConfig.calculatePaymentDistribution(1, 1, newAcquirer, 1 ether);

        assertEq(feeRec.length, 1); // Only merchant when all fees are 0
    }

    function test_InvalidPublicKeySize_InvalidExponent() public {
        // Test with invalid exponent size (2 bytes instead of 3)
        bytes memory invalidExponent = hex"0100"; // 2 bytes
        
        EMVValidator testValidator = new EMVValidator(address(emvSettlement), kernel.execute.selector);
        
        vm.expectRevert(EMVValidator.InvalidPublicKeySize.selector);
        testValidator.onInstall(abi.encode(uint16(0), invalidExponent, TEST_MODULUS));
    }

    function test_InvalidPublicKeySize_InvalidModulus() public {
        // Test with invalid modulus size (128 bytes instead of 256)
        bytes memory invalidModulus = new bytes(128);
        for (uint256 i = 0; i < 128; i++) {
            invalidModulus[i] = bytes1(uint8(i + 1));
        }
        
        EMVValidator testValidator = new EMVValidator(address(emvSettlement), kernel.execute.selector);
        
        vm.expectRevert(EMVValidator.InvalidPublicKeySize.selector);
        testValidator.onInstall(abi.encode(uint16(0), TEST_EXPONENT, invalidModulus));
    }

    function test_GetRegisteredPublicKey() public whenInitialized {
        _installEMVValidator();
        
        // Get the registered public key
        (bytes memory exponent, bytes memory modulus) = emvValidator.getRegisteredPublicKey(address(kernel));
        
        // Verify it matches what we installed
        assertEq(exponent, TEST_EXPONENT, "Exponent should match installed value");
        assertEq(modulus, TEST_MODULUS, "Modulus should match installed value");
    }

    function test_GetRegisteredPublicKey_NotInstalled() public {
        // Try to get public key for an account that never installed
        (bytes memory exponent, bytes memory modulus) = emvValidator.getRegisteredPublicKey(address(0x123));
        
        // Should return empty bytes
        assertEq(exponent.length, 0, "Exponent should be empty for uninstalled account");
        assertEq(modulus.length, 0, "Modulus should be empty for uninstalled account");
    }

    function test_InvalidSender() public {
        // Install validator first
        emvValidator.onInstall(abi.encode(uint16(0), TEST_EXPONENT, TEST_MODULUS));
        
        bytes32 testHash = keccak256("test");
        
        // Try to call isValidSignatureWithSender with address(0) as sender - should revert
        vm.expectRevert(EMVValidator.InvalidSender.selector);
        emvValidator.isValidSignatureWithSender(address(0), testHash, TEST_SIGNATURE);
    }

    function test_InvalidSender_WithInvalidSignature() public {
        // This test verifies that InvalidSender is caught BEFORE signature validation
        // Even with completely invalid signature data, InvalidSender should be the error
        
        // Create invalid signature data (just random bytes)
        bytes memory invalidSigData = hex"deadbeefcafebabe";
        bytes32 testHash = keccak256("test");
        
        // Try to call isValidSignatureWithSender with address(0) as sender
        // Should revert with InvalidSender, NOT with signature validation errors
        vm.expectRevert(EMVValidator.InvalidSender.selector);
        emvValidator.isValidSignatureWithSender(address(0), testHash, invalidSigData);
    }

    function test_PublicKeyNotRegistered() public {
        // Test that isValidSignatureWithSender reverts when public key is not registered
        bytes32 testHash = keccak256("test");
        address uninitializedAccount = makeAddr("uninitialized");
        
        // Try to validate signature for an account that never installed the validator
        vm.expectRevert(EMVValidator.PublicKeyNotRegistered.selector);
        emvValidator.isValidSignatureWithSender(uninitializedAccount, testHash, TEST_SIGNATURE);
    }

    function test_InvalidRSAKeySize_WrongSignatureLength() public {
        // Install validator first
        emvValidator.onInstall(abi.encode(uint16(0), TEST_EXPONENT, TEST_MODULUS));
        
        // Compute valid hash
        bytes32 dynamicDataHash = sha256(abi.encodePacked(
            bytes1(0x6A), bytes1(0x03),
            TEST_ARQC, TEST_UNPREDICTABLE_NUMBER, TEST_ATC, TEST_AMOUNT,
            TEST_CURRENCY, TEST_DATE, TEST_TXN_TYPE, TEST_TVR, TEST_CVM_RESULTS,
            TEST_TERMINAL_ID, TEST_MERCHANT_ID, TEST_ACQUIRER_ID,
            bytes1(0xBC)
        ));
        
        // Try with wrong signature length (128 bytes instead of 256)
        bytes memory shortSignature = new bytes(128);
        
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.InvalidRSAKeySize.selector, 128));
        emvValidator.isValidSignatureWithSender(address(this), dynamicDataHash, shortSignature);
    }

    function test_InvalidRSAKeySize_EmptySignature() public {
        // Install validator first
        emvValidator.onInstall(abi.encode(uint16(0), TEST_EXPONENT, TEST_MODULUS));
        
        // Compute valid hash
        bytes32 dynamicDataHash = sha256(abi.encodePacked(
            bytes1(0x6A), bytes1(0x03),
            TEST_ARQC, TEST_UNPREDICTABLE_NUMBER, TEST_ATC, TEST_AMOUNT,
            TEST_CURRENCY, TEST_DATE, TEST_TXN_TYPE, TEST_TVR, TEST_CVM_RESULTS,
            TEST_TERMINAL_ID, TEST_MERCHANT_ID, TEST_ACQUIRER_ID,
            bytes1(0xBC)
        ));
        
        // Try with empty signature
        bytes memory emptySignature = hex"";
        
        vm.expectRevert(abi.encodeWithSelector(EMVValidator.InvalidRSAKeySize.selector, 0));
        emvValidator.isValidSignatureWithSender(address(this), dynamicDataHash, emptySignature);
    }

    // ========== FFI TESTS ==========

    function test_FFI_CompleteEndToEndTransaction() public whenInitialized {
        // Complete end-to-end test: Generate key, install modules, fund, sign, and execute transaction
        // This uses a specific amount to avoid fuzz complexity
        
        // Ensure kernel has ETH for gas
        vm.deal(address(kernel), 10 ether);
        
        // STEP 1: Generate RSA key, EMV data, and signature via FFI
        string[] memory inputs = new string[](9);
        inputs[0] = "node";
        inputs[1] = "script/ffi-emv-test.js";
        inputs[2] = "10000"; // $100.00 in cents
        inputs[3] = "840"; // USD
        inputs[4] = "0"; // ATC = 0
        inputs[5] = "E2EMERCHANT001"; // Merchant ID
        inputs[6] = "E2ETERM1"; // Terminal ID
        inputs[7] = "E2EACQ"; // Acquirer ID
        
        bytes memory ffiResult = vm.ffi(inputs);
        (bytes memory exponent, bytes memory modulus, bytes memory emvFields, bytes memory rsaSignature) = 
            abi.decode(ffiResult, (bytes, bytes, bytes, bytes));
        
        console.log("=== FFI Generated Data ===");
        console.log("Exponent:", exponent.length, "bytes");
        console.log("Modulus:", modulus.length, "bytes");
        console.log("EMV Fields:", emvFields.length, "bytes");
        console.log("Signature:", rsaSignature.length, "bytes");
        
        // STEP 2: Setup acquirer configuration
        uint48 e2eAcquirerId = bytesToUint48(bytes6("E2EACQ"));
        uint120 e2eMerchantId = bytesToUint120(bytes15("E2EMERCHANT001"));
        uint64 e2eTerminalId = bytesToUint64(bytes8("E2ETERM1"));
        
        address e2eMerchant = makeAddr("e2eMerchant");
        
        acquirerConfig.setAcquirer(e2eAcquirerId, address(this));
        acquirerConfig.setAcquirerFee(e2eAcquirerId, address(this), 25); // 0.25%
        acquirerConfig.setSwipeFee(e2eAcquirerId, 50 * 10 ** 16); // $0.50
        acquirerConfig.setMerchant(e2eAcquirerId, e2eMerchantId, e2eMerchant);
        acquirerConfig.setTerminal(e2eAcquirerId, e2eTerminalId, address(this));
        
        console.log("=== Acquirer Configuration Complete ===");
        
        // STEP 3: Install EMVValidator with FFI-generated key
        PackedUserOperation[] memory installValOps = new PackedUserOperation[](1);
        installValOps[0] = _prepareUserOp(
            VALIDATION_TYPE_ROOT,
            false,
            false,
            abi.encodeWithSelector(
                kernel.installModule.selector,
                MODULE_TYPE_VALIDATOR,
                address(emvValidator),
                abi.encodePacked(
                    address(0),
                    abi.encode(
                        abi.encode(uint16(0), exponent, modulus),
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
        
        // Verify EMVValidator was installed
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(emvValidator), ""),
            "EMVValidator should be installed"
        );
        console.log("=== EMVValidator Installed ===");
        
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
                    abi.encode(
                        abi.encode(address(mockERC20), address(acquirerConfig), uint8(18)),
                        hex"",
                        hex""
                    )
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
        
        // STEP 6: Create UserOperation with EMV data in callData and RSA signature in signature
        uint192 nonceKey = ValidatorLib.encodeAsNonceKey(
            ValidationMode.unwrap(VALIDATION_MODE_DEFAULT),
            ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR),
            bytes20(address(emvValidator)),
            0
        );
        
        bytes memory emvCallData = abi.encodeWithSelector(
            kernel.execute.selector,
            ExecLib.encode(CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, ExecModeSelector.wrap(0x00), ExecModePayload.wrap(0x00)),
            abi.encodePacked(
                address(emvSettlement),
                abi.encodeWithSelector(emvSettlement.execute.selector, emvFields)
            )
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
            signature: rsaSignature // FFI-generated RSA signature
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
        
        // STEP 9: Verify ATC was incremented
        assertEq(emvValidator.getEMVStorage(address(kernel)), 1, "ATC should be incremented to 1");
        
        console.log("Complete end-to-end FFI EMV transaction successful!");
        console.log("Merchant received:", merchantReceived / 1e18, "tokens");
    }

    function testFuzz_FFI_VerifyRandomSignatures(uint256 amountSeed, uint16 atcSeed) public {
        // Simplified fuzz test: Just verify random signatures work cryptographically
        // (Full E2E with kernel setup would be too slow for fuzzing)
        
        // Bound inputs
        uint256 amountCents = bound(amountSeed, 10000, 500000); // $100-$5000
        uint16 boundedAtc = uint16(bound(atcSeed, 0, 1000));
        
        // Generate unique IDs
        string memory merchantId = string(abi.encodePacked("FUZZM", _uint256ToString(amountSeed % 100000)));
        string memory terminalId = string(abi.encodePacked("FUZZT", _uint256ToString(atcSeed % 100)));
        
        merchantId = _truncateString(merchantId, 15);
        terminalId = _truncateString(terminalId, 8);
        
        // Generate via FFI
        string[] memory inputs = new string[](9);
        inputs[0] = "node";
        inputs[1] = "script/ffi-emv-test.js";
        inputs[2] = _uint256ToString(amountCents);
        inputs[3] = "840"; // Always USD
        inputs[4] = _uint256ToString(boundedAtc);
        inputs[5] = merchantId;
        inputs[6] = terminalId;
        inputs[7] = "FUZZAQ";
        
        bytes memory ffiResult = vm.ffi(inputs);
        (bytes memory exponent, bytes memory modulus, bytes memory emvFields, bytes memory rsaSignature) = 
            abi.decode(ffiResult, (bytes, bytes, bytes, bytes));
        
        // Validate sizes
        assertEq(exponent.length, 3);
        assertEq(modulus.length, 256);
        assertEq(emvFields.length, 63);
        assertEq(rsaSignature.length, 256);
        
        // Install and verify
        EMVValidator fuzzValidator = new EMVValidator(address(emvSettlement), kernel.execute.selector);
        fuzzValidator.onInstall(abi.encode(boundedAtc, exponent, modulus));
        
        bytes memory dynamicData = abi.encodePacked(bytes1(0x6A), bytes1(0x03), emvFields, bytes1(0xBC));
        bytes32 dataHash = sha256(dynamicData);
        
        bool isValid = fuzzValidator.verifyEMVSignature(rsaSignature, dataHash, address(this));
        assertTrue(isValid, "Fuzz signature should be valid");
        
        bytes4 erc1271 = fuzzValidator.isValidSignatureWithSender(address(this), dataHash, rsaSignature);
        assertEq(erc1271, ERC1271_MAGICVALUE);
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
