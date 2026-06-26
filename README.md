# Kernel EMV Signer

An **ERC-7579 compliant signer/policy module set** for smart contract wallets that enables on-chain validation of EMV (Europay, Mastercard, Visa) payment card transactions using P-256 signatures.

## Overview

This project enables smart contract wallets to accept payment card transactions by validating EMV P-256 signatures on-chain and automatically settling funds to merchants with a configurable multi-party fee structure. It integrates with the [Kernel](https://github.com/zerodev-xyz/kernel) ERC-4337 smart contract wallet framework.

### Key Features

- **🔐 EMV Signature Validation**: On-chain verification of P-256 signed payment card transactions
- **🎯 ERC-7579 Compliant**: Signer and policy modules for modular smart accounts
- **💰 Multi-Fee Settlement**: Configurable fee distribution (acquirer, swipe, interchange, network)
- **🛡️ Replay Protection**: Dual protection via unpredictable numbers and application transaction counters (ATC)
- **⚡ Gas Optimized**: Assembly-optimized calldata extraction and storage operations
- **🌐 Merchant Registry**: Decentralized registry for acquirers and merchant-selected routing

## Architecture

### Core Contracts

1. **`EMVSigner.sol`**
   - ERC-7579 signer module
   - Validates EMV P-256 signatures over the card-signed payload
   - Binds signatures to the configured card public key
   - Does not support standalone validator installation; use it through a permission with policies

2. **`EMVCardPolicy.sol`**
   - ERC-7579 policy module
   - Registers card public keys per account/permission
   - Enforces replay protection with unpredictable numbers and ATC
   - Supports card freeze, unfreeze, and revoke controls

3. **`EMVLimitPolicy.sol`**
   - ERC-7579 policy module
   - Enforces supported transaction type, currency, and amount fields
   - Tracks per-transaction and 24-hour cycle limits

4. **`EMVSettlement.sol`**
   - ERC-7579 executor module
   - Processes EMV transaction data and distributes funds
   - Extracts BCD-encoded amounts and merchant identifiers
   - Executes ERC20 token transfers to all fee recipients
   - Calculates merchant remainder after fee deductions

5. **`AcquirerConfig.sol`**
   - Merchant-selected acquirer registry
   - Configurable four-tier fee structure:
     - Acquirer fee (0-0.30%)
     - Fixed acquirer swipe fee
     - Interchange fee (0-2.50%)
     - Network fee (0-0.15%)
   - Per-acquirer fee configuration with merchant-controlled assignment
   - Gas-optimized fee deduplication using transient storage (EIP-1153)

## How It Works

### Transaction Flow

```
1. Payment Card → EMV Terminal
   └─ Generates ARQC (Authorization Request Cryptogram)
   └─ Signs transaction data with card's P-256 private key

2. Terminal → Smart Contract Wallet (via ERC-4337 UserOp)
   └─ Packs EMV data into signature field
   └─ Calls Kernel.execute() targeting EMVSettlement

3. Permission validation runs policies and signer
   ├─ ZeroDev CallPolicy verifies target address and function selector
   ├─ EMVCardPolicy checks replay protection (unpredictableNumber + ATC)
   ├─ EMVLimitPolicy validates transaction limits and accepted EMV fields
   └─ EMVSigner verifies the P-256 signature

4. If valid → EMVSettlement executes
   ├─ Extracts transaction amount (BCD format)
   ├─ Queries AcquirerConfig for fee distribution
   ├─ Transfers fees to recipients
   └─ Sends remainder to merchant
```

### EMV Data Format

Transactions pack the 52-byte card-signed ATC + PDOL message:

```
ATC(2) + UnpredictableNumber(4) + TxnType(1) + Currency(2) +
Amount(6) + AmountOther(6) + CurrencyExponent(1) + MerchantId(15) +
TerminalId(8) + TerminalCountry(2) + TxnDate(3) + MCC(2)
```

Amounts are BCD-encoded (e.g., `0x000000012345` = $123.45).

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/kernel-emv.git
cd kernel-emv

# Install dependencies (Foundry required)
forge install
```

### Dependencies

- [Foundry](https://book.getfoundry.sh/)
- [Kernel](https://github.com/zerodev-xyz/kernel) (ERC-7579 smart account framework)
- [Solady](https://github.com/Vectorized/solady) (Optimized utilities)

## Usage

### Building

```bash
forge build
```

### Testing

```bash
# Run all tests
forge test

# Run with verbosity
forge test -vvv

# Run specific test
forge test --match-test testValidateUserOp_Success

# Gas report
forge test --gas-report
```

### Deployment

Deploy the contracts in order:

```bash
# 1. Deploy AcquirerConfig
forge create src/AcquirerConfig.sol:AcquirerConfig \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY

# 2. Deploy EMVSettlement
forge create src/EMVSettlement.sol:EMVSettlement \
  --constructor-args <TOKEN> <ACQUIRER_CONFIG> <DECIMALS> <OWNER> \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY

# 3. Deploy EMVSigner
forge create src/EMVSigner.sol:EMVSigner \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY

# 4. Deploy EMVCardPolicy
forge create src/policy/EMVCardPolicy.sol:EMVCardPolicy \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY

# 5. Deploy EMVLimitPolicy
forge create src/policy/EMVLimitPolicy.sol:EMVLimitPolicy \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY
```

### Configuration

```solidity
// 1. Configure acquirer
acquirerConfig.setAcquirer(acquirerId, acquirerAddress);
acquirerConfig.setAcquirerFee(acquirerId, feeRecipient, 15); // 0.15%

// 2. Merchant selects an acquirer. merchantId is derived from msg.sender's low 15 bytes.
acquirerConfig.setMerchant(acquirerId);

// 3. Set global fees
acquirerConfig.setNetworkFee(networkRecipient, 10); // 0.10%
acquirerConfig.setInterchangeFee(interchangeRecipient, 180); // 1.80%
acquirerConfig.setSwipeFee(acquirerId, swipeFeeAmount);
```

## Gas Optimization

The contracts employ several gas optimization techniques:

- **Assembly calldata extraction**: Direct calldataload for field extraction
- **Storage batching**: Minimize SSTORE operations via grouped updates
- **Transient storage (EIP-1153)**: Temporary fee deduplication without SSTORE costs
- **Immutable configuration**: Reduces SLOAD costs for fixed values
- **Memory packing**: Efficient data structure layouts

## Security Considerations

### Replay Protection

- **Unpredictable Numbers**: Each transaction requires a unique 4-byte nonce
- **ATC Validation**: Enforces monotonically increasing transaction counters
- **Per-Account State**: Isolated replay protection for each smart account

### Currency Restrictions

- Only USD (840) and USN (997) currency codes accepted
- Prevents incorrect amount interpretations

### Signature Scheme

- **P-256 only**: EMVSigner verifies the card-signed SHA-256 payload with secp256r1.
- Signature envelope binds the permission to the configured P-256 public key

### Target Validation

- ZeroDev CallPolicy validates both target address and function selector
- Prevents signature reuse across different contexts

## Testing

Comprehensive test suite covering:

- ✅ Valid EMV signature validation
- ✅ Invalid signature rejection
- ✅ Replay attack prevention
- ✅ ATC sequence validation
- ✅ Currency code restrictions
- ✅ Fee calculation and distribution
- ✅ Merchant registry operations
- ✅ Gas optimization verification

## License

MIT

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Resources

- [EMV Book 2](https://www.emvco.com/specifications/): Integrated Circuit Card Specifications for Payment Systems
- [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579): Minimal Modular Smart Accounts
- [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337): Account Abstraction Using Alt Mempool
- [Kernel Documentation](https://docs.zerodev.app/)
