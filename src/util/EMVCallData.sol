// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BCDEncoding} from "./BCDEncoding.sol";
import {IERC7579Account} from "kernel/src/interfaces/IERC7579Account.sol";
import {CALLTYPE_DELEGATECALL} from "kernel/src/types/Constants.sol";
import {CallType, ExecMode} from "kernel/src/types/Types.sol";
import {ExecLib} from "kernel/src/utils/ExecLib.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

library EMVCallData {
    error InvalidEMVCallData();
    error InvalidEMVFieldLength(uint256 actual);

    uint256 internal constant EMV_FIELDS_LENGTH = 52;
    uint256 internal constant AMOUNT_OFFSET = 9;

    function extractEMVFields(bytes calldata callData) internal pure returns (bytes calldata emvFields) {
        if (callData.length < 4 || bytes4(callData[0:4]) != IERC7579Account.execute.selector) {
            revert InvalidEMVCallData();
        }

        if (callData.length < 68) {
            revert InvalidEMVCallData();
        }

        ExecMode mode = ExecMode.wrap(bytes32(callData[4:36]));
        (CallType callType,,,) = ExecLib.decode(mode);
        if (callType != CALLTYPE_DELEGATECALL) {
            revert InvalidEMVCallData();
        }

        uint256 executionDataOffset = uint256(bytes32(callData[36:68]));
        uint256 executionDataLengthOffset = 4 + executionDataOffset;
        if (callData.length < executionDataLengthOffset + 32) {
            revert InvalidEMVCallData();
        }

        uint256 executionDataLength =
            uint256(bytes32(callData[executionDataLengthOffset:executionDataLengthOffset + 32]));
        uint256 executionDataStart = executionDataLengthOffset + 32;
        if (callData.length < executionDataStart + executionDataLength) {
            revert InvalidEMVCallData();
        }

        bytes calldata executionCallData = callData[executionDataStart:executionDataStart + executionDataLength];
        (, bytes calldata settlementCallData) = LibERC7579.decodeDelegate(executionCallData);
        if (settlementCallData.length < 68) {
            revert InvalidEMVCallData();
        }

        uint256 emvDataOffset = uint256(bytes32(settlementCallData[4:36]));
        uint256 emvDataLengthOffset = 4 + emvDataOffset;
        if (settlementCallData.length < emvDataLengthOffset + 32) {
            revert InvalidEMVCallData();
        }

        uint256 emvDataLength = uint256(bytes32(settlementCallData[emvDataLengthOffset:emvDataLengthOffset + 32]));
        uint256 emvDataStart = emvDataLengthOffset + 32;
        if (settlementCallData.length < emvDataStart + emvDataLength) {
            revert InvalidEMVCallData();
        }
        if (emvDataLength != EMV_FIELDS_LENGTH) {
            revert InvalidEMVFieldLength(emvDataLength);
        }

        return settlementCallData[emvDataStart:emvDataStart + emvDataLength];
    }

    function extractAmountCents(bytes calldata callData) internal pure returns (uint64) {
        bytes calldata emvFields = extractEMVFields(callData);
        return extractAmountCentsFromFields(emvFields);
    }

    function extractAmountCentsFromFields(bytes calldata emvFields) internal pure returns (uint64) {
        if (emvFields.length != EMV_FIELDS_LENGTH) {
            revert InvalidEMVFieldLength(emvFields.length);
        }

        return uint64(BCDEncoding.extractAmountCents(emvFields[AMOUNT_OFFSET:AMOUNT_OFFSET + 6]));
    }
}
