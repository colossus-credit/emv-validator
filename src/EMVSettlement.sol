// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {AcquirerConfig} from "./AcquirerConfig.sol";
import {MODULE_TYPE_EXECUTOR} from "kernel/src/types/Constants.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/**
 * @title EMVSettlement
 * @dev Handles EMV transaction settlement and ERC20 token transfers
 * @notice Processes EMV transaction data and executes corresponding token transfers
 */
contract EMVSettlement is Ownable {
    // ========== EVENTS ==========

    event EMVTransferExecuted(address indexed from, address indexed to, address indexed token, uint256 amount);

    event EMVMultiTransferExecuted(
        address indexed from, address indexed token, uint256 totalAmount, uint256 recipientCount
    );
    event EMVSettlementConfigured(address indexed account, address token, address recipient);
    event NetworkFeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    // ========== STORAGE ==========

    // Immutable configuration - accessible in both regular call and delegate call contexts
    address public immutable configuredToken; // ERC20 token address for this settlement instance
    AcquirerConfig public immutable acquirerConfig; // Registry for merchant address validation
    uint8 public immutable decimals; // Token decimals for amount conversion

    // ========== CONSTRUCTOR ==========

    constructor(address _tokenAddress, address _acquirerConfigAddress, uint8 _decimals, address _owner) {
        if (_tokenAddress == address(0) || _acquirerConfigAddress == address(0)) {
            revert InvalidConfig();
        }

        if (_decimals < 2) {
            revert InvalidDecimals();
        }

        configuredToken = _tokenAddress;
        acquirerConfig = AcquirerConfig(_acquirerConfigAddress);
        decimals = _decimals;

        // Initialize Ownable
        _initializeOwner(_owner);
    }

    // ========== ERRORS ==========

    error InvalidAmount();
    error MerchantNotRegistered(bytes15 merchantId);
    error MerchantRegistryNotSet();
    error InvalidConfig();
    error InvalidDecimals();
    error InvalidNetworkFeeRate();
    error InvalidNetworkFeeRecipient();
    error TotalTransfersExceedAmount();
    error InvalidFee(uint256 position);
    error InvalidMerchantFee();
    error BelowTransactionMinimum();
    error InvalidBCDLength();

    // ========== MODULE LIFECYCLE ==========

    /**
     * @dev Install the module
     * @param data Installation data (not used - configuration is set in constructor)
     */
    function onInstall(bytes calldata data) external payable {
        // Configuration is set in constructor as immutable values
        // This function is called during module installation but config is already set
        emit EMVSettlementConfigured(msg.sender, configuredToken, address(0));
    }

    /**
     * @dev Uninstall the module
     * @param data Uninstallation data (not used for this contract)
     */
    function onUninstall(bytes calldata data) external payable {
        // Configuration is immutable, nothing to clean up
    }

    /**
     * @dev Check if module supports the given type
     */
    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == MODULE_TYPE_EXECUTOR;
    }

    /**
     * @dev Check if module is initialized for the smart account
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        // Configuration is immutable and set in constructor, so always initialized
        return configuredToken != address(0) && address(acquirerConfig) != address(0) && decimals >= 2;
    }

    // ========== SETTLEMENT FUNCTIONS ==========

    /**
     * @dev Execute the ERC20 transfer for a validated EMV transaction. The acquirer is derived
     *      on-chain from the card-signed merchant ID, not passed in.
     * @param emvData The card-signed message (the bytes the UserOp signature covers).
     */
    function execute(bytes calldata emvData) external payable {
        (uint256 amountOffset, uint256 merchantOffset) = _emvSettlementOffsets(emvData);

        bytes calldata amountBytes = emvData[amountOffset:amountOffset + 6];
        uint120 merchantId = uint120(bytes15(emvData[merchantOffset:merchantOffset + 15]));

        // Extract amount from EMV BCD format (6 bytes) using immutable decimals
        uint256 transferAmount = _extractAmountFromBCD(amountBytes, decimals);

        if (transferAmount == 0) {
            revert InvalidAmount();
        }

        // Distribution — AcquirerConfig derives the acquirer on-chain from the card-signed merchant ID.
        AcquirerConfig.FeeRecipient[] memory feeRecipients =
            acquirerConfig.calculatePaymentDistribution(merchantId, transferAmount);

        // Process payments to all recipients
        _processFeePayments(feeRecipients, transferAmount);
    }

    // ========== CONFIGURATION FUNCTIONS ==========

    /**
     * @dev Get the configured token, acquirer config, and decimals
     * @return tokenAddress The configured ERC20 token address
     * @return configAddress The acquirer config address
     * @return tokenDecimals The configured token decimals
     */
    function getSettlementConfig()
        external
        view
        returns (address tokenAddress, address configAddress, uint8 tokenDecimals)
    {
        return (configuredToken, address(acquirerConfig), decimals);
    }

    // ========== INTERNAL FUNCTIONS ==========

    function _emvSettlementOffsets(bytes calldata emvData)
        internal
        pure
        returns (uint256 amountOffset, uint256 merchantOffset)
    {
        // 52-byte ATC(2) || PDOL(50) slice-from-front message. 9F01 (acquirer) and 9F21 (time)
        // are not signed; the merchant-selected acquirer is derived on-chain from 9F16.
        if (emvData.length == 52) {
            return (9, 22);
        }

        revert InvalidBCDLength();
    }

    /**
     * @dev Process payments to fee recipients including fees and merchant remainder
     * @param feeRecipients Array of fee recipients with calculated amounts
     * @param totalAmount Total transaction amount
     */
    function _processFeePayments(AcquirerConfig.FeeRecipient[] memory feeRecipients, uint256 totalAmount) internal {
        uint256 totalFees = 0;

        // Process all fees (excluding merchant)
        uint256 i = 0;
        for (; i < feeRecipients.length - 1;) {
            // Validate non-merchant fees are non-zero
            if (feeRecipients[i].fee == 0) revert InvalidFee(i);

            uint256 feeAmount = feeRecipients[i].fee;
            totalFees += feeAmount;

            SafeTransferLib.safeTransfer(configuredToken, feeRecipients[i].recipient, feeAmount);
            unchecked {
                ++i;
            }
        }

        // Check if total fees exceed or equal transaction amount
        if (totalFees >= totalAmount) revert BelowTransactionMinimum();

        // Handle merchant payment (last recipient, fee must be 0)
        // i should now point to the last element (merchant)
        if (feeRecipients[i].fee != 0) revert InvalidMerchantFee();

        uint256 merchantAmount = totalAmount - totalFees;
        if (merchantAmount > 0) {
            SafeTransferLib.safeTransfer(configuredToken, feeRecipients[i].recipient, merchantAmount);
        }
    }

    /**
     * @dev Extract amount from EMV BCD format
     * @param bcdAmount 6-byte BCD encoded amount
     * @param tokenDecimals Number of decimals for the token
     * @return Amount in token units based on provided decimals
     */
    function _extractAmountFromBCD(bytes calldata bcdAmount, uint8 tokenDecimals) internal pure returns (uint256) {
        if (bcdAmount.length != 6) {
            revert InvalidBCDLength();
        }

        uint256 amount = 0;
        for (uint256 i = 0; i < 6; i++) {
            uint8 byte_val = uint8(bcdAmount[i]);
            uint8 high_nibble = byte_val >> 4;
            uint8 low_nibble = byte_val & 0x0F;

            // Validate BCD digits (0-9)
            if (high_nibble > 9 || low_nibble > 9) {
                return 0;
            }

            amount = amount * 100 + high_nibble * 10 + low_nibble;
        }

        // Convert from cents to token units using provided decimals
        // EMV amounts are typically in cents (2 decimal places)
        // So we need to convert: cents -> token units
        // Example: If token has 6 decimals, multiply by 10^(6-2) = 10^4
        return amount * 10 ** (tokenDecimals - 2);
    }
}
