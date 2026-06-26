// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";
import {AcquirerConfig} from "../src/AcquirerConfig.sol";
import {ColossusTestToken} from "../test/util/ColossusTestToken.sol";
import {EMVSettlement} from "../src/EMVSettlement.sol";
import {EMVValidator} from "../src/EMVValidator.sol";
import {IERC7579Account} from "kernel/src/interfaces/IERC7579Account.sol";

contract DeployBaseSepolia is Script {
    function validatorSelector() public pure returns (bytes4) {
        return IERC7579Account.execute.selector;
    }

    function run()
        external
        returns (
            ColossusTestToken token,
            AcquirerConfig acquirerConfig,
            EMVSettlement emvSettlement,
            EMVValidator emvValidator
        )
    {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        // Base Sepolia deployments default the local test token to 6 decimals unless overridden.
        uint256 tokenDecimals = vm.envOr("TOKEN_DECIMALS", uint256(6));
        uint256 initialTokenSupply = vm.envOr("INITIAL_TOKEN_SUPPLY", uint256(0));

        if (tokenDecimals > type(uint8).max) {
            revert("TOKEN_DECIMALS exceeds uint8");
        }

        vm.startBroadcast(deployerPrivateKey);

        token = new ColossusTestToken(deployer, uint8(tokenDecimals));
        if (initialTokenSupply != 0) {
            token.mint(deployer, initialTokenSupply);
        }
        acquirerConfig = new AcquirerConfig();
        emvSettlement = new EMVSettlement(address(token), address(acquirerConfig), uint8(tokenDecimals));
        emvValidator = new EMVValidator(address(emvSettlement), validatorSelector());

        (address validationTarget, bytes4 validationSelector) = emvValidator.getValidationConfig();
        require(validationTarget == address(emvSettlement), "invalid validator target");
        require(validationSelector == validatorSelector(), "invalid validator selector");

        vm.stopBroadcast();

        console2.log("ColossusTestToken:", address(token));
        console2.log("AcquirerConfig:", address(acquirerConfig));
        console2.log("EMVSettlement:", address(emvSettlement));
        console2.log("EMVValidator:", address(emvValidator));
        console2.log("Deployer owner/minter:", deployer);
        console2.log("Token decimals:", tokenDecimals);
        console2.log("Initial token supply:", initialTokenSupply);
    }
}
