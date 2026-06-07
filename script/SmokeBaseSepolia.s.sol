// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";
import {AcquirerConfig} from "../src/AcquirerConfig.sol";
import {ColossusTestToken} from "../src/ColossusTestToken.sol";
import {EMVSettlement} from "../src/EMVSettlement.sol";
import {EMVValidator} from "../src/EMVValidator.sol";
import {IERC7579Account} from "kernel/src/interfaces/IERC7579Account.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR} from "kernel/src/types/Constants.sol";

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
        address validatorAddress = vm.envAddress("EMV_VALIDATOR_ADDRESS");

        _assertHasCode(tokenAddress, "token code");
        _assertHasCode(acquirerConfigAddress, "acquirer config code");
        _assertHasCode(settlementAddress, "settlement code");
        _assertHasCode(validatorAddress, "validator code");

        ColossusTestToken token = ColossusTestToken(tokenAddress);
        AcquirerConfig acquirerConfig = AcquirerConfig(acquirerConfigAddress);
        EMVSettlement settlement = EMVSettlement(settlementAddress);
        EMVValidator validator = EMVValidator(validatorAddress);

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
        _assertEqAddress(settlement.owner(), deployer, "settlement owner");
        _assertTrue(settlement.isModuleType(MODULE_TYPE_EXECUTOR), "settlement executor module type");
        _assertTrue(settlement.isInitialized(address(0)), "settlement initialized");

        (address validationTarget, bytes4 validationSelector) = validator.getValidationConfig();
        _assertEqAddress(validationTarget, settlementAddress, "validator target");
        _assertEqBytes4(validationSelector, IERC7579Account.execute.selector, "validator account selector");
        _assertTrue(validationSelector != EMVSettlement.execute.selector, "validator must not use settlement selector");
        _assertTrue(validator.isModuleType(MODULE_TYPE_VALIDATOR), "validator module type");

        console2.log("Base Sepolia smoke test passed");
        console2.log("ColossusTestToken:", tokenAddress);
        console2.log("AcquirerConfig:", acquirerConfigAddress);
        console2.log("EMVSettlement:", settlementAddress);
        console2.log("EMVValidator:", validatorAddress);
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

    function _assertEqBytes4(bytes4 actual, bytes4 expected, string memory check) private pure {
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
