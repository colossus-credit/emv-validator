// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyBase} from "kernel/src/sdk/moduleBase/PolicyBase.sol";
import {PackedUserOperation} from "kernel/src/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED_UINT, SIG_VALIDATION_SUCCESS_UINT} from "kernel/src/types/Constants.sol";
import {EMVCallData} from "../util/EMVCallData.sol";

contract EMVLimitPolicy is PolicyBase {
    uint64 private constant CYCLE_DURATION = 1 days;
    uint256 private constant TXN_TYPE_OFFSET = 6;
    uint256 private constant CURRENCY_OFFSET = 7;
    uint256 private constant AMOUNT_OTHER_OFFSET = 15;
    uint256 private constant CURRENCY_EXP_OFFSET = 21;
    uint8 private constant SUPPORTED_TXN_TYPE = 0x00;
    uint8 private constant SUPPORTED_CURRENCY_EXPONENT = 2;

    error PolicyNotInitialized(address account, bytes32 permission);
    event EMVPolicyCycleMaxUpdated(address indexed account, bytes32 indexed permission, uint64 cycleMax);
    event EMVPolicyPerTxnMaxUpdated(address indexed account, bytes32 indexed permission, uint64 perTxnMax);

    struct Config {
        uint64 perTxnMax;
        uint64 cycle;
        uint64 cycleMax;
        uint64 cycleTotal;
    }

    mapping(address account => mapping(bytes32 permission => Config config)) private configs;

    function _policyOninstall(bytes32 permission, bytes calldata data) internal override {
        (uint64 cycleMax, uint64 perTxnMax) = abi.decode(data, (uint64, uint64));

        configs[msg.sender][permission] =
            Config({perTxnMax: perTxnMax, cycle: _currentCycleTimestamp(), cycleMax: cycleMax, cycleTotal: 0});
    }

    function _policyOnUninstall(bytes32 permission, bytes calldata) internal override {
        delete configs[msg.sender][permission];
    }

    function setCycleMax(bytes32 permission, uint64 cycleMax) external {
        Config storage config = configs[msg.sender][permission];
        if (config.cycleMax == 0 && config.perTxnMax == 0) {
            revert PolicyNotInitialized(msg.sender, permission);
        }

        config.cycleMax = cycleMax;
        emit EMVPolicyCycleMaxUpdated(msg.sender, permission, cycleMax);
    }

    function setPerTxnMax(bytes32 permission, uint64 perTxnMax) external {
        Config storage config = configs[msg.sender][permission];
        if (config.cycleMax == 0 && config.perTxnMax == 0) {
            revert PolicyNotInitialized(msg.sender, permission);
        }

        config.perTxnMax = perTxnMax;
        emit EMVPolicyPerTxnMaxUpdated(msg.sender, permission, perTxnMax);
    }

    function isInitialized(address) external pure override returns (bool) {
        return true;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        Config storage config = configs[msg.sender][id];

        bytes calldata emvFields = EMVCallData.extractEMVFields(userOp.callData);
        if (!_isAcceptedEMVFields(emvFields)) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        uint64 amount = EMVCallData.extractAmountCentsFromFields(emvFields);
        if (amount == 0 || amount > config.perTxnMax) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        uint64 currentCycle = _currentCycleTimestamp();
        uint64 cycleTotal = config.cycleTotal;
        if (currentCycle >= config.cycle + CYCLE_DURATION) {
            cycleTotal = 0;
            config.cycle = currentCycle;
        }

        uint256 attemptedTotal = uint256(cycleTotal) + amount;
        if (attemptedTotal > config.cycleMax) {
            return SIG_VALIDATION_FAILED_UINT;
        }

        config.cycleTotal = uint64(attemptedTotal);
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external view override returns (uint256) {
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function getLimits(address account, bytes32 permission)
        external
        view
        returns (uint64 cycle, uint64 cycleMax, uint64 cycleTotal, uint64 perTxnMax)
    {
        Config storage config = configs[account][permission];
        return (config.cycle, config.cycleMax, config.cycleTotal, config.perTxnMax);
    }

    function _currentCycleTimestamp() internal view returns (uint64) {
        return uint64((block.timestamp / CYCLE_DURATION) * CYCLE_DURATION);
    }

    function _isAcceptedEMVFields(bytes calldata emvFields) internal pure returns (bool) {
        if (uint8(emvFields[TXN_TYPE_OFFSET]) != SUPPORTED_TXN_TYPE) {
            return false;
        }

        bytes2 currencyBytes = bytes2(emvFields[CURRENCY_OFFSET:CURRENCY_OFFSET + 2]);
        uint16 currency = uint16(currencyBytes);
        if (currency != 0x0840 && currency != 0x0997) {
            return false;
        }

        if (bytes6(emvFields[AMOUNT_OTHER_OFFSET:AMOUNT_OTHER_OFFSET + 6]) != bytes6(0)) {
            return false;
        }

        return uint8(emvFields[CURRENCY_EXP_OFFSET]) == SUPPORTED_CURRENCY_EXPONENT;
    }
}
