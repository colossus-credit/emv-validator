// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Ownable} from "solady/auth/Ownable.sol";
import {ERC20} from "solady/tokens/ERC20.sol";

contract ColossusTestToken is ERC20, Ownable {
    error InvalidOwner();

    uint8 private immutable _decimals;

    constructor(address owner_, uint8 decimals_) {
        if (owner_ == address(0)) {
            revert InvalidOwner();
        }

        _decimals = decimals_;
        _initializeOwner(owner_);
    }

    function name() public pure override returns (string memory) {
        return "Colossus Test Token";
    }

    function symbol() public pure override returns (string memory) {
        return "COLT";
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
