// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";
import {AcquirerConfig} from "../src/AcquirerConfig.sol";
import {ColossusTestToken} from "../src/ColossusTestToken.sol";
import {EMVSettlement} from "../src/EMVSettlement.sol";
import {EMVValidator} from "../src/EMVValidator.sol";

contract DeployBaseSepolia is Script {
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
        uint256 tokenDecimals = vm.envOr("TOKEN_DECIMALS", uint256(18));
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
        emvSettlement = new EMVSettlement(address(token), address(acquirerConfig), uint8(tokenDecimals), deployer);
        emvValidator = new EMVValidator(address(emvSettlement), EMVSettlement.execute.selector);

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
