// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EMVSigner} from "./EMVSigner.sol";

/// @dev Backwards-compatible name for integrations that still import EMVValidator.
contract EMVValidator is EMVSigner {}
