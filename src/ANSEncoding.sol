// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

library ANSEncoding {
    error InvalidANSCharacter(bytes1 character);

    function encode(string calldata value) internal pure returns (bytes memory encoded) {
        uint256 length;
        assembly {
            length := value.length
        }

        for (uint256 i = 0; i < length;) {
            uint8 character;
            assembly {
                character := byte(0, calldataload(add(value.offset, i)))
            }
            if (!_isANS(character)) revert InvalidANSCharacter(bytes1(character));

            unchecked {
                ++i;
            }
        }

        encoded = new bytes(length);
        assembly {
            calldatacopy(add(encoded, 0x20), value.offset, length)
        }
    }

    function _isANS(uint8 character) private pure returns (bool) {
        return character >= 0x20 && character <= 0x7E;
    }
}
