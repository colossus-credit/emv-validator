// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EMVLimitPolicy} from "./EMVLimitPolicy.sol";

/// @dev Backwards-compatible name for integrations that still import EMVSettlementPolicy.
contract EMVSettlementPolicy is EMVLimitPolicy {}
