// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {Ownable} from "solady/auth/Ownable.sol";

/**
 * @title AcquirerConfig
 * @dev Registry for approved merchants with 4-fee structure: acquirer, swipe, interchange, network
 * @notice Uses per-acquirer configuration with owner-controlled acquirer assignment
 */
contract AcquirerConfig is Ownable {
    // Struct to represent a fee recipient
    struct FeeRecipient {
        uint256 fee; // Fee amount (0 for merchant)
        address recipient; // Address to receive payment
    }

    // Struct to hold per-acquirer data
    struct AcquirerData {
        address acquirerFeeRecipient; // Address to receive acquirer fees
        uint256 acquirerFeeRate; // Acquirer fee rate in basis points (0-30)
        uint256 swipeFee; // Fixed swipe fee amount
        mapping(uint120 => address) merchants; // Merchant ID (15 bytes -> uint120) to address mapping
        mapping(uint64 => address) terminals; // Terminal ID (8 bytes -> uint64) to address mapping
    }

    // Basis points constants
    uint256 private constant ONE_HUNDRED_PERCENT_BP = 10000;
    uint256 private constant ACQUIRER_FEE_MAX_BP = 30; // Max 0.30%
    uint256 private constant NETWORK_FEE_MAX_BP = 15; // Max 0.15%
    uint256 private constant INTERCHANGE_FEE_MAX_BP = 250; // Max 2.50%

    // Mappings
    mapping(uint48 => address) public acquirerAddresses; // Acquirer ID (6 bytes -> uint48) to authorized address
    mapping(uint48 => AcquirerData) private acquirerData; // Acquirer ID (6 bytes -> uint48) to configuration data

    // Network configuration (global, owner-controlled)
    address public networkFeeRecipient; // Address to receive network fees
    uint256 public networkFeeRate; // Network fee rate in basis points (0-15)

    // Interchange configuration (global, owner-controlled)
    address public interchangeFeeRecipient; // Address to receive interchange fees
    uint256 public interchangeFeeRate; // Interchange fee rate in basis points (0-250)

    // Events
    event AcquirerSet(uint48 indexed acquirerId, address indexed acquirerAddress);
    event MerchantSet(uint48 indexed acquirerId, uint120 indexed merchantId, address recipient);
    event TerminalSet(uint48 indexed acquirerId, uint64 indexed terminalId, address recipient);
    event AcquirerFeeUpdated(
        uint48 indexed acquirerId,
        address indexed oldRecipient,
        address indexed newRecipient,
        uint256 oldRate,
        uint256 newRate
    );
    event NetworkFeeUpdated(
        address indexed oldRecipient, address indexed newRecipient, uint256 oldRate, uint256 newRate
    );
    event InterchangeFeeUpdated(
        address indexed oldRecipient, address indexed newRecipient, uint256 oldRate, uint256 newRate
    );
    event SwipeFeeUpdated(uint48 indexed acquirerId, uint256 oldFee, uint256 newFee);

    // Errors
    error InvalidAcquirerId();
    error InvalidMerchantId();
    error InvalidTerminalId();
    error InvalidFeeRate();
    error InvalidSwipeFee();
    error InvalidFee(uint256 position);
    error InvalidMerchantFee();
    error UnauthorizedAcquirer(uint48 acquirerId, address caller);

    // Modifiers
    modifier onlyAcquirer(uint48 acquirerId) {
        if (acquirerAddresses[acquirerId] == address(0)) {
            revert InvalidAcquirerId();
        }
        if (acquirerAddresses[acquirerId] != msg.sender) {
            revert UnauthorizedAcquirer(acquirerId, msg.sender);
        }
        _;
    }

    constructor() {
        _initializeOwner(msg.sender);
    }

    // ========== INTERNAL FUNCTIONS ==========

    /**
     * @dev Add fee to array or accumulate if recipient already exists
     * @param feeRecipients The fee recipients array
     * @param index Current index in the array (will be incremented if new recipient added)
     * @param recipient The fee recipient address
     * @param feeAmount The fee amount to add or accumulate
     */
    function _addOrAccumulateFee(
        FeeRecipient[] memory feeRecipients,
        uint256 index,
        address recipient,
        uint256 feeAmount
    ) internal returns (uint256 newIndex) {
        if (recipient == address(0)) revert InvalidFee(index);

        // Check if recipient already exists using transient storage
        uint256 existingIndex;
        assembly {
            existingIndex := tload(recipient)
        }

        if (existingIndex == 0) {
            // New recipient - store index + 1 in transient storage (0 means not found)
            assembly {
                tstore(recipient, add(index, 1))
            }
            feeRecipients[index] = FeeRecipient({fee: feeAmount, recipient: recipient});
            return index + 1;
        } else {
            // Existing recipient - accumulate fee (existingIndex is 1-based)
            feeRecipients[existingIndex - 1].fee += feeAmount;
            return index; // Don't increment index
        }
    }

    /**
     * @dev Clear transient storage for all fee recipients (internal version)
     * @param feeRecipients The fee recipients array
     * @param length Number of recipients to clear (excluding merchant)
     */
    function _clearTransientStorage(FeeRecipient[] memory feeRecipients, uint256 length) internal {
        for (uint256 i = 0; i < length; i++) {
            address recipient = feeRecipients[i].recipient;
            assembly {
                tstore(recipient, 0)
            }
        }
    }

    /**
     * @dev Clear transient storage for all fee recipients (public version)
     * @param feeRecipients The fee recipients array
     * @param length Number of recipients to clear
     */
    function clearTransientStorage(FeeRecipient[] memory feeRecipients, uint256 length) external {
        _clearTransientStorage(feeRecipients, length);
    }

    // ========== OWNER FUNCTIONS ==========

    /**
     * @dev Register or update an acquirer address (owner only)
     * @param acquirerId The acquirer ID from EMV data (9F01) as uint48
     * @param acquirerAddress Address authorized to manage this acquirer's configuration
     */
    function setAcquirer(uint48 acquirerId, address acquirerAddress) external onlyOwner {
        if (acquirerId == 0) revert InvalidAcquirerId();

        acquirerAddresses[acquirerId] = acquirerAddress;
        emit AcquirerSet(acquirerId, acquirerAddress);
    }

    // ========== ACQUIRER FUNCTIONS ==========

    /**
     * @dev Set merchant address (register, update, or remove) - onlyAcquirer
     * @param acquirerId The acquirer ID managing this merchant
     * @param merchantId The merchant ID from EMV data (9F16) as uint120
     * @param merchantAddress Address of the merchant (use address(0) to remove)
     */
    function setMerchant(uint48 acquirerId, uint120 merchantId, address merchantAddress)
        external
        onlyAcquirer(acquirerId)
    {
        if (merchantId == 0) revert InvalidMerchantId();

        acquirerData[acquirerId].merchants[merchantId] = merchantAddress;
        emit MerchantSet(acquirerId, merchantId, merchantAddress);
    }

    /**
     * @dev Set terminal address (register, update, or remove) - onlyAcquirer
     * @param acquirerId The acquirer ID managing this terminal
     * @param terminalId The terminal ID from EMV data (9F1C) as uint64
     * @param terminalAddress Address of the terminal swipe fee recipient (use address(0) to remove)
     */
    function setTerminal(uint48 acquirerId, uint64 terminalId, address terminalAddress)
        external
        onlyAcquirer(acquirerId)
    {
        if (terminalId == 0) revert InvalidTerminalId();

        acquirerData[acquirerId].terminals[terminalId] = terminalAddress;
        emit TerminalSet(acquirerId, terminalId, terminalAddress);
    }

    /**
     * @dev Get the registered address for a merchant ID
     * @param acquirerId The acquirer ID as uint48
     * @param merchantId The merchant ID as uint120
     * @return merchantAddress The registered address (address(0) if not registered)
     */
    function getMerchantAddress(uint48 acquirerId, uint120 merchantId) external view returns (address) {
        return acquirerData[acquirerId].merchants[merchantId];
    }

    /**
     * @dev Get the registered address for a terminal ID
     * @param acquirerId The acquirer ID as uint48
     * @param terminalId The terminal ID as uint64
     * @return terminalAddress The registered address (address(0) if not registered)
     */
    function getTerminalAddress(uint48 acquirerId, uint64 terminalId) external view returns (address) {
        return acquirerData[acquirerId].terminals[terminalId];
    }

    /**
     * @dev Check if a merchant is registered
     * @param acquirerId The acquirer ID as uint48
     * @param merchantId The merchant ID as uint120
     * @return isRegistered True if the merchant is registered
     */
    function isMerchantRegistered(uint48 acquirerId, uint120 merchantId) external view returns (bool) {
        return acquirerData[acquirerId].merchants[merchantId] != address(0);
    }

    /**
     * @dev Check if a terminal is registered
     * @param acquirerId The acquirer ID as uint48
     * @param terminalId The terminal ID as uint64
     * @return isRegistered True if the terminal is registered
     */
    function isTerminalRegistered(uint48 acquirerId, uint64 terminalId) external view returns (bool) {
        return acquirerData[acquirerId].terminals[terminalId] != address(0);
    }

    /**
     * @dev Batch set multiple merchants - onlyAcquirer
     * @param acquirerId The acquirer ID managing these merchants
     * @param merchantIds Array of merchant IDs as uint120
     * @param addresses Array of corresponding addresses (use address(0) to remove)
     */
    function batchSetMerchants(uint48 acquirerId, uint120[] calldata merchantIds, address[] calldata addresses)
        external
        onlyAcquirer(acquirerId)
    {
        require(merchantIds.length == addresses.length, "AcquirerConfig: array length mismatch");

        for (uint256 i = 0; i < merchantIds.length; i++) {
            uint120 merchantId = merchantIds[i];
            address merchantAddress = addresses[i];

            if (merchantId == 0) revert InvalidMerchantId();

            acquirerData[acquirerId].merchants[merchantId] = merchantAddress;
            emit MerchantSet(acquirerId, merchantId, merchantAddress);
        }
    }

    /**
     * @dev Batch set multiple terminals - onlyAcquirer
     * @param acquirerId The acquirer ID managing these terminals
     * @param terminalIds Array of terminal IDs as uint64
     * @param addresses Array of corresponding addresses (use address(0) to remove)
     */
    function batchSetTerminals(uint48 acquirerId, uint64[] calldata terminalIds, address[] calldata addresses)
        external
        onlyAcquirer(acquirerId)
    {
        require(terminalIds.length == addresses.length, "AcquirerConfig: array length mismatch");

        for (uint256 i = 0; i < terminalIds.length; i++) {
            uint64 terminalId = terminalIds[i];
            address terminalAddress = addresses[i];

            if (terminalId == 0) revert InvalidTerminalId();

            acquirerData[acquirerId].terminals[terminalId] = terminalAddress;
            emit TerminalSet(acquirerId, terminalId, terminalAddress);
        }
    }

    /**
     * @dev Set the acquirer fee configuration - onlyAcquirer
     * @param acquirerId The acquirer ID as uint48
     * @param _acquirerFeeRecipient New acquirer fee recipient address
     * @param _acquirerFeeRate New acquirer fee rate in basis points (0-30 = 0.00%-0.30%)
     */
    function setAcquirerFee(uint48 acquirerId, address _acquirerFeeRecipient, uint256 _acquirerFeeRate)
        external
        onlyAcquirer(acquirerId)
    {
        if (_acquirerFeeRecipient == address(0)) revert InvalidFeeRate();
        if (_acquirerFeeRate > ACQUIRER_FEE_MAX_BP) revert InvalidFeeRate();

        address oldRecipient = acquirerData[acquirerId].acquirerFeeRecipient;
        uint256 oldRate = acquirerData[acquirerId].acquirerFeeRate;

        acquirerData[acquirerId].acquirerFeeRecipient = _acquirerFeeRecipient;
        acquirerData[acquirerId].acquirerFeeRate = _acquirerFeeRate;

        emit AcquirerFeeUpdated(acquirerId, oldRecipient, _acquirerFeeRecipient, oldRate, _acquirerFeeRate);
    }

    /**
     * @dev Set the network fee configuration - owner only
     * @param _networkFeeRecipient New network fee recipient address
     * @param _networkFeeRate New network fee rate in basis points (0-15 = 0.00%-0.15%)
     */
    function setNetworkFee(address _networkFeeRecipient, uint256 _networkFeeRate) external onlyOwner {
        if (_networkFeeRecipient == address(0)) revert InvalidFeeRate();
        if (_networkFeeRate > NETWORK_FEE_MAX_BP) revert InvalidFeeRate();

        address oldRecipient = networkFeeRecipient;
        uint256 oldRate = networkFeeRate;

        networkFeeRecipient = _networkFeeRecipient;
        networkFeeRate = _networkFeeRate;

        emit NetworkFeeUpdated(oldRecipient, _networkFeeRecipient, oldRate, _networkFeeRate);
    }

    /**
     * @dev Set the interchange fee configuration - owner only
     * @param _interchangeFeeRecipient New interchange fee recipient address
     * @param _interchangeFeeRate New interchange fee rate in basis points (0-250 = 0.00%-2.50%)
     */
    function setInterchangeFee(address _interchangeFeeRecipient, uint256 _interchangeFeeRate) external onlyOwner {
        if (_interchangeFeeRecipient == address(0)) revert InvalidFeeRate();
        if (_interchangeFeeRate > INTERCHANGE_FEE_MAX_BP) {
            revert InvalidFeeRate();
        }

        address oldRecipient = interchangeFeeRecipient;
        uint256 oldRate = interchangeFeeRate;

        interchangeFeeRecipient = _interchangeFeeRecipient;
        interchangeFeeRate = _interchangeFeeRate;

        emit InterchangeFeeUpdated(oldRecipient, _interchangeFeeRecipient, oldRate, _interchangeFeeRate);
    }

    /**
     * @dev Set the swipe fee amount - onlyAcquirer
     * @param acquirerId The acquirer ID as uint48
     * @param _swipeFee New swipe fee amount (0.00-0.15 in token base units)
     */
    function setSwipeFee(uint48 acquirerId, uint256 _swipeFee) external onlyAcquirer(acquirerId) {
        // Note: Upper bound validation depends on token decimals and should be checked by caller
        // For example, for 18-decimal token: 0.15 = 150000000000000000 wei
        uint256 oldFee = acquirerData[acquirerId].swipeFee;
        acquirerData[acquirerId].swipeFee = _swipeFee;

        emit SwipeFeeUpdated(acquirerId, oldFee, _swipeFee);
    }

    // ========== VIEW FUNCTIONS ==========

    /**
     * @dev Get acquirer configuration data
     * @param acquirerId The acquirer ID as uint48
     * @return feeRecipient The acquirer fee recipient address
     * @return feeRate The acquirer fee rate in basis points
     * @param swipeFee The swipe fee amount
     */
    function getAcquirerConfig(uint48 acquirerId)
        external
        view
        returns (address feeRecipient, uint256 feeRate, uint256 swipeFee)
    {
        return (
            acquirerData[acquirerId].acquirerFeeRecipient,
            acquirerData[acquirerId].acquirerFeeRate,
            acquirerData[acquirerId].swipeFee
        );
    }

    /**
     * @dev Check if an acquirer is registered
     * @param acquirerId The acquirer ID as uint48
     * @return isRegistered True if the acquirer is registered
     */
    function isAcquirerRegistered(uint48 acquirerId) external view returns (bool) {
        return acquirerAddresses[acquirerId] != address(0);
    }

    /**
     * @dev Get the address authorized to manage an acquirer
     * @param acquirerId The acquirer ID as uint48
     * @return acquirerAddress The authorized address
     */
    function getAcquirerAddress(uint48 acquirerId) external view returns (address) {
        return acquirerAddresses[acquirerId];
    }

    /**
     * @dev Calculate payment distribution for a transaction with 4-fee structure
     * @param merchantId The merchant ID as uint120
     * @param terminalId The terminal ID as uint64
     * @param acquirerId The acquirer ID as uint48 - used to access per-acquirer configuration
     * @param totalAmount The total transaction amount
     * @return feeRecipients Array of fee recipients with calculated amounts, merchant last with fee=0
     */
    function calculatePaymentDistribution(uint120 merchantId, uint64 terminalId, uint48 acquirerId, uint256 totalAmount)
        external
        returns (FeeRecipient[] memory feeRecipients)
    {
        // Validate acquirer is registered
        if (acquirerAddresses[acquirerId] == address(0)) {
            revert InvalidAcquirerId();
        }

        // Read acquirer data once into memory to avoid multiple storage reads
        address acquirerFeeRecipient = acquirerData[acquirerId].acquirerFeeRecipient;
        uint256 acquirerFeeRate = acquirerData[acquirerId].acquirerFeeRate;
        uint256 swipeFee = acquirerData[acquirerId].swipeFee;

        // Cache global fee recipients to local variables for assembly use
        address _interchangeFeeRecipient = interchangeFeeRecipient;
        address _networkFeeRecipient = networkFeeRecipient;

        // Get merchant and terminal addresses, fallback to feeRecipient if not registered
        address merchantAddress = acquirerData[acquirerId].merchants[merchantId];
        if (merchantAddress == address(0)) {
            merchantAddress = acquirerFeeRecipient;
        }

        address terminalAddress = acquirerData[acquirerId].terminals[terminalId];
        if (terminalAddress == address(0)) {
            terminalAddress = acquirerFeeRecipient;
        }

        // Calculate all percentage fees on full transaction amount using per-acquirer rates
        uint256 acquirerFeeAmount = (totalAmount * acquirerFeeRate) / ONE_HUNDRED_PERCENT_BP;
        uint256 networkFeeAmount = (totalAmount * networkFeeRate) / ONE_HUNDRED_PERCENT_BP;
        uint256 interchangeFeeAmount = (totalAmount * interchangeFeeRate) / ONE_HUNDRED_PERCENT_BP;

        // Declare fixed size array for maximum 5 recipients (4 fees + merchant)
        feeRecipients = new FeeRecipient[](5);
        uint256 index = 0;

        // Add acquirer fee if non-zero
        if (acquirerFeeAmount > 0) {
            index = _addOrAccumulateFee(feeRecipients, index, acquirerFeeRecipient, acquirerFeeAmount);
        }

        // Add swipe fee if non-zero (per-acquirer swipe fee)
        if (swipeFee > 0) {
            index = _addOrAccumulateFee(feeRecipients, index, terminalAddress, swipeFee);
        }

        // Add interchange fee if non-zero
        if (interchangeFeeAmount > 0) {
            index = _addOrAccumulateFee(feeRecipients, index, _interchangeFeeRecipient, interchangeFeeAmount);
        }

        // Add network fee if non-zero
        if (networkFeeAmount > 0) {
            index = _addOrAccumulateFee(feeRecipients, index, _networkFeeRecipient, networkFeeAmount);
        }

        // Add merchant (always last, fee must be 0) - no deduplication for merchant
        feeRecipients[index] = FeeRecipient({
            fee: 0, // Merchant fee must be 0
            recipient: merchantAddress
        });
        unchecked {
            ++index;
        }

        // Clean up transient storage before returning (exclude merchant)
        _clearTransientStorage(feeRecipients, index - 1);

        // Resize array to actual number of recipients
        assembly {
            mstore(feeRecipients, index)
        }

        return feeRecipients;
    }
}
