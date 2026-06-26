// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";
import {AcquirerConfig} from "../src/AcquirerConfig.sol";
import {ColossusTestToken} from "../test/util/ColossusTestToken.sol";
import {EMVSettlement} from "../src/EMVSettlement.sol";
import {EMVSigner} from "../src/EMVSigner.sol";
import {EMVCardPolicy} from "../src/policy/EMVCardPolicy.sol";
import {EMVLimitPolicy} from "../src/policy/EMVLimitPolicy.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_POLICY, MODULE_TYPE_SIGNER} from "kernel/src/types/Constants.sol";

contract SmokeBaseSepolia is Script {
    uint256 private constant BASE_SEPOLIA_CHAIN_ID = 84532;

    error SmokeCheckFailed(string check);

    function run() external view {
        if (block.chainid != BASE_SEPOLIA_CHAIN_ID) {
            revert SmokeCheckFailed("chain id");
        }

        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        uint8 expectedTokenDecimals = uint8(vm.envOr("TOKEN_DECIMALS", uint256(6)));
        uint256 expectedInitialSupply = vm.envOr("INITIAL_TOKEN_SUPPLY", uint256(0));

        address tokenAddress = vm.envAddress("TOKEN_ADDRESS");
        address acquirerConfigAddress = vm.envAddress("ACQUIRER_CONFIG_ADDRESS");
        address settlementAddress = vm.envAddress("EMV_SETTLEMENT_ADDRESS");
        address signerAddress = vm.envAddress("EMV_SIGNER_ADDRESS");
        address cardPolicyAddress = vm.envAddress("EMV_CARD_POLICY_ADDRESS");
        address limitPolicyAddress = vm.envAddress("EMV_LIMIT_POLICY_ADDRESS");

        _assertHasCode(tokenAddress, "token code");
        _assertHasCode(acquirerConfigAddress, "acquirer config code");
        _assertHasCode(settlementAddress, "settlement code");
        _assertHasCode(signerAddress, "signer code");
        _assertHasCode(cardPolicyAddress, "card policy code");
        _assertHasCode(limitPolicyAddress, "limit policy code");

        ColossusTestToken token = ColossusTestToken(tokenAddress);
        AcquirerConfig acquirerConfig = AcquirerConfig(acquirerConfigAddress);
        EMVSettlement settlement = EMVSettlement(settlementAddress);
        EMVSigner signer = EMVSigner(signerAddress);
        EMVCardPolicy cardPolicy = EMVCardPolicy(cardPolicyAddress);
        EMVLimitPolicy limitPolicy = EMVLimitPolicy(limitPolicyAddress);

        _assertEqString(token.name(), "Colossus Test Token", "token name");
        _assertEqString(token.symbol(), "COLT", "token symbol");
        _assertEqUint8(token.decimals(), expectedTokenDecimals, "token decimals");
        _assertEqAddress(token.owner(), deployer, "token owner");
        _assertEqUint256(token.totalSupply(), expectedInitialSupply, "token total supply");
        _assertEqUint256(token.balanceOf(deployer), expectedInitialSupply, "deployer token balance");

        _assertEqAddress(acquirerConfig.owner(), deployer, "acquirer config owner");

        (address settlementToken, address settlementConfig, uint8 settlementDecimals) = settlement.getSettlementConfig();
        _assertEqAddress(settlementToken, tokenAddress, "settlement token");
        _assertEqAddress(settlementConfig, acquirerConfigAddress, "settlement acquirer config");
        _assertEqUint8(settlementDecimals, expectedTokenDecimals, "settlement decimals");
        _assertTrue(settlement.isModuleType(MODULE_TYPE_EXECUTOR), "settlement executor module type");
        _assertTrue(settlement.isInitialized(address(0)), "settlement initialized");

        _assertTrue(signer.isModuleType(MODULE_TYPE_SIGNER), "signer module type");
        _assertTrue(signer.isInitialized(address(0)), "signer initialized");
        _assertTrue(cardPolicy.isModuleType(MODULE_TYPE_POLICY), "card policy module type");
        _assertTrue(cardPolicy.isInitialized(address(0)), "card policy initialized");
        _assertTrue(limitPolicy.isModuleType(MODULE_TYPE_POLICY), "limit policy module type");
        _assertTrue(limitPolicy.isInitialized(address(0)), "limit policy initialized");

        console2.log("Base Sepolia smoke test passed");
        console2.log("ColossusTestToken:", tokenAddress);
        console2.log("AcquirerConfig:", acquirerConfigAddress);
        console2.log("EMVSettlement:", settlementAddress);
        console2.log("EMVSigner:", signerAddress);
        console2.log("EMVCardPolicy:", cardPolicyAddress);
        console2.log("EMVLimitPolicy:", limitPolicyAddress);
    }

    function _assertHasCode(address account, string memory check) private view {
        if (account.code.length == 0) {
            revert SmokeCheckFailed(check);
        }
    }

    function _assertTrue(bool actual, string memory check) private pure {
        if (!actual) {
            revert SmokeCheckFailed(check);
        }
    }

    function _assertEqAddress(address actual, address expected, string memory check) private pure {
        if (actual != expected) {
            revert SmokeCheckFailed(check);
        }
    }

    function _assertEqUint8(uint8 actual, uint8 expected, string memory check) private pure {
        if (actual != expected) {
            revert SmokeCheckFailed(check);
        }
    }

    function _assertEqUint256(uint256 actual, uint256 expected, string memory check) private pure {
        if (actual != expected) {
            revert SmokeCheckFailed(check);
        }
    }

    function _assertEqString(string memory actual, string memory expected, string memory check) private pure {
        if (keccak256(bytes(actual)) != keccak256(bytes(expected))) {
            revert SmokeCheckFailed(check);
        }
    }
}
