// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library BCDEncoding {
    error InvalidBCDLength();

    function extractAmountCents(bytes calldata bcdAmount) internal pure returns (uint96 amount) {
        if (bcdAmount.length != 6) {
            revert InvalidBCDLength();
        }

        for (uint256 i = 0; i < 6;) {
            uint8 byteValue = uint8(bcdAmount[i]);
            uint8 highNibble = byteValue >> 4;
            uint8 lowNibble = byteValue & 0x0F;

            if (highNibble > 9 || lowNibble > 9) {
                return 0;
            }

            amount = amount * 100 + highNibble * 10 + lowNibble;
            unchecked {
                ++i;
            }
        }
    }

    function extractAmountFromBCD(bytes calldata bcdAmount, uint8 tokenDecimals) internal pure returns (uint256) {
        return uint256(extractAmountCents(bcdAmount)) * 10 ** (tokenDecimals - 2);
    }
}
