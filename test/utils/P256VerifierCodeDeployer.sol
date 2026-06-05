// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {P256Verifier} from "p256-verifier/src/P256Verifier.sol";

/// @dev Test-only bridge compiled with P256Verifier's pinned Solidity 0.8.21 pragma.
contract P256VerifierCodeDeployer {
    function deployRuntimeCode() external returns (bytes memory) {
        P256Verifier verifier = new P256Verifier();
        return address(verifier).code;
    }
}
