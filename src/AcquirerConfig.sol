// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {ANSEncoding} from "./util/ANSEncoding.sol";
import {Ownable} from "solady/auth/Ownable.sol";

/**
 * @title AcquirerConfig
 * @dev Registry for owner-approved acquirers with acquirer-managed merchants and fee configuration.
 * @notice Merchant IDs are merchant-chosen 15-byte identifiers (e.g. a 15-char ASCII id carried in
 *         EMV tag 9F16) bound to merchant addresses by the registered acquirer.
 */
contract AcquirerConfig is Ownable {
    struct FeeRecipient {
        uint256 fee;
        address recipient;
    }

    struct AcquirerData {
        address acquirerFeeRecipient;
        uint256 acquirerFeeRate;
        uint256 swipeFee;
    }

    struct MerchantData {
        address merchant;
        uint48 acquirerId;
    }

    uint256 private constant ONE_HUNDRED_PERCENT_BP = 10000;
    uint256 private constant ACQUIRER_FEE_MAX_BP = 30;
    uint256 private constant NETWORK_FEE_MAX_BP = 15;
    uint256 private constant INTERCHANGE_FEE_MAX_BP = 250;
    uint256 private constant MERCHANT_ID_MAX_LENGTH = 15;

    mapping(uint48 => address) public acquirers;
    mapping(uint48 => AcquirerData) private acquirerData;
    mapping(uint120 => MerchantData) public merchantData;

    address public networkFeeRecipient;
    uint256 public networkFeeRate;

    address public interchangeFeeRecipient;
    uint256 public interchangeFeeRate;

    event AcquirerSet(uint48 indexed acquirerId, address indexed acquirerAddress);
    event MerchantSet(uint48 indexed acquirerId, uint120 indexed merchantId, address indexed merchant);
    event MerchantRemoved(uint48 indexed acquirerId, uint120 indexed merchantId, address indexed merchant);
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

    error InvalidAcquirerId();
    error InvalidAcquirerAddress();
    error InvalidMerchantId();
    error InvalidMerchantAddress();
    error InvalidMerchantIdLength(uint256 length);
    error InvalidFeeRate();
    error InvalidFee(uint256 position);
    error InvalidMerchantFee();
    error UnauthorizedAcquirer(uint48 acquirerId, address caller);
    error UnknownMerchant(uint120 merchantId);

    modifier onlyAcquirer(uint48 acquirerId) {
        if (acquirers[acquirerId] == address(0)) {
            revert InvalidAcquirerId();
        }
        if (acquirers[acquirerId] != msg.sender) {
            revert UnauthorizedAcquirer(acquirerId, msg.sender);
        }
        _;
    }

    constructor() {
        _initializeOwner(msg.sender);
    }

    function _addOrAccumulateFee(
        FeeRecipient[] memory feeRecipients,
        uint256 index,
        address recipient,
        uint256 feeAmount
    ) internal returns (uint256 newIndex) {
        if (recipient == address(0)) revert InvalidFee(index);

        uint256 existingIndex;
        assembly {
            existingIndex := tload(recipient)
        }

        if (existingIndex == 0) {
            assembly {
                tstore(recipient, add(index, 1))
            }
            feeRecipients[index] = FeeRecipient({fee: feeAmount, recipient: recipient});
            return index + 1;
        }

        feeRecipients[existingIndex - 1].fee += feeAmount;
        return index;
    }

    function _clearTransientStorage(FeeRecipient[] memory feeRecipients, uint256 length) internal {
        for (uint256 i = 0; i < length; i++) {
            address recipient = feeRecipients[i].recipient;
            assembly {
                tstore(recipient, 0)
            }
        }
    }

    function setAcquirer(uint48 acquirerId, address acquirerAddress) external onlyOwner {
        if (acquirerId == 0) revert InvalidAcquirerId();
        if (acquirerAddress == address(0)) revert InvalidAcquirerAddress();

        acquirers[acquirerId] = acquirerAddress;
        emit AcquirerSet(acquirerId, acquirerAddress);
    }

    function setMerchant(uint120 merchantId, uint48 acquirerId, address merchant) external onlyAcquirer(acquirerId) {
        _setMerchant(merchantId, acquirerId, merchant);
    }

    function setMerchant(string calldata merchantIdANSString, uint48 acquirerId, address merchant)
        external
        onlyAcquirer(acquirerId)
    {
        bytes memory encodedMerchantId = ANSEncoding.encode(merchantIdANSString);
        uint256 length = encodedMerchantId.length;
        if (length > MERCHANT_ID_MAX_LENGTH) revert InvalidMerchantIdLength(length);

        _setMerchant(uint120(bytes15(encodedMerchantId)), acquirerId, merchant);
    }

    function _setMerchant(uint120 merchantId, uint48 acquirerId, address merchant) internal {
        if (merchantId == 0) revert InvalidMerchantId();
        if (merchant == address(0)) revert InvalidMerchantAddress();

        MerchantData memory currentMerchant = merchantData[merchantId];
        if (currentMerchant.merchant != address(0) && currentMerchant.acquirerId != acquirerId) {
            revert UnauthorizedAcquirer(currentMerchant.acquirerId, msg.sender);
        }

        merchantData[merchantId] = MerchantData({merchant: merchant, acquirerId: acquirerId});
        emit MerchantSet(acquirerId, merchantId, merchant);
    }

    function removeMerchant(uint120 merchantId) external {
        MerchantData memory merchant = merchantData[merchantId];
        if (merchant.merchant == address(0)) revert UnknownMerchant(merchantId);
        if (acquirers[merchant.acquirerId] != msg.sender) {
            revert UnauthorizedAcquirer(merchant.acquirerId, msg.sender);
        }

        delete merchantData[merchantId];
        emit MerchantRemoved(merchant.acquirerId, merchantId, merchant.merchant);
    }

    function getMerchantAddress(uint120 merchantId) external view returns (address) {
        return merchantData[merchantId].merchant;
    }

    function getMerchantConfig(uint120 merchantId) external view returns (address merchantAddress, uint48 acquirerId) {
        MerchantData memory merchant = merchantData[merchantId];
        return (merchant.merchant, merchant.acquirerId);
    }

    function isMerchantRegistered(uint120 merchantId) external view returns (bool) {
        return merchantData[merchantId].merchant != address(0);
    }

    function isMerchantRegistered(uint48 acquirerId, uint120 merchantId) external view returns (bool) {
        MerchantData memory merchant = merchantData[merchantId];
        return merchant.merchant != address(0) && merchant.acquirerId == acquirerId;
    }

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

    function setNetworkFee(address _networkFeeRecipient, uint256 _networkFeeRate) external onlyOwner {
        if (_networkFeeRecipient == address(0)) revert InvalidFeeRate();
        if (_networkFeeRate > NETWORK_FEE_MAX_BP) revert InvalidFeeRate();

        address oldRecipient = networkFeeRecipient;
        uint256 oldRate = networkFeeRate;

        networkFeeRecipient = _networkFeeRecipient;
        networkFeeRate = _networkFeeRate;

        emit NetworkFeeUpdated(oldRecipient, _networkFeeRecipient, oldRate, _networkFeeRate);
    }

    function setInterchangeFee(address _interchangeFeeRecipient, uint256 _interchangeFeeRate) external onlyOwner {
        if (_interchangeFeeRecipient == address(0)) revert InvalidFeeRate();
        if (_interchangeFeeRate > INTERCHANGE_FEE_MAX_BP) revert InvalidFeeRate();

        address oldRecipient = interchangeFeeRecipient;
        uint256 oldRate = interchangeFeeRate;

        interchangeFeeRecipient = _interchangeFeeRecipient;
        interchangeFeeRate = _interchangeFeeRate;

        emit InterchangeFeeUpdated(oldRecipient, _interchangeFeeRecipient, oldRate, _interchangeFeeRate);
    }

    function setSwipeFee(uint48 acquirerId, uint256 _swipeFee) external onlyAcquirer(acquirerId) {
        uint256 oldFee = acquirerData[acquirerId].swipeFee;
        acquirerData[acquirerId].swipeFee = _swipeFee;

        emit SwipeFeeUpdated(acquirerId, oldFee, _swipeFee);
    }

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

    function isAcquirerRegistered(uint48 acquirerId) external view returns (bool) {
        return acquirers[acquirerId] != address(0);
    }

    function getAcquirerAddress(uint48 acquirerId) external view returns (address) {
        return acquirers[acquirerId];
    }

    function calculatePaymentDistribution(uint120 merchantId, uint256 totalAmount)
        external
        returns (FeeRecipient[] memory feeRecipients)
    {
        MerchantData memory merchant = merchantData[merchantId];
        uint48 acquirerId = merchant.acquirerId;
        if (merchant.merchant == address(0) || acquirers[acquirerId] == address(0)) {
            revert UnknownMerchant(merchantId);
        }

        feeRecipients = new FeeRecipient[](5);
        uint256 index = 0;

        if (merchant.acquirerId != 0) {
            address acquirerFeeRecipient = acquirerData[acquirerId].acquirerFeeRecipient;
            uint256 acquirerFeeRate = acquirerData[acquirerId].acquirerFeeRate;
            uint256 swipeFee = acquirerData[acquirerId].swipeFee;

            address _interchangeFeeRecipient = interchangeFeeRecipient;
            address _networkFeeRecipient = networkFeeRecipient;

            uint256 acquirerFeeAmount = (totalAmount * acquirerFeeRate) / ONE_HUNDRED_PERCENT_BP;
            uint256 networkFeeAmount = (totalAmount * networkFeeRate) / ONE_HUNDRED_PERCENT_BP;
            uint256 interchangeFeeAmount = (totalAmount * interchangeFeeRate) / ONE_HUNDRED_PERCENT_BP;

            if (acquirerFeeAmount > 0) {
                index = _addOrAccumulateFee(feeRecipients, index, acquirerFeeRecipient, acquirerFeeAmount);
            }

            if (swipeFee > 0) {
                index = _addOrAccumulateFee(feeRecipients, index, acquirerFeeRecipient, swipeFee);
            }

            if (interchangeFeeAmount > 0) {
                index = _addOrAccumulateFee(feeRecipients, index, _interchangeFeeRecipient, interchangeFeeAmount);
            }

            if (networkFeeAmount > 0) {
                index = _addOrAccumulateFee(feeRecipients, index, _networkFeeRecipient, networkFeeAmount);
            }
        }

        feeRecipients[index] = FeeRecipient({fee: 0, recipient: merchant.merchant});
        unchecked {
            ++index;
        }

        _clearTransientStorage(feeRecipients, index - 1);

        assembly {
            mstore(feeRecipients, index)
        }

        return feeRecipients;
    }
}
