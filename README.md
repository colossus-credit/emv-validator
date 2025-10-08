# Kernel EMV Validator

An **ERC-7579 compliant validator module** for smart contract wallets that enables on-chain validation of EMV (Europay, Mastercard, Visa) payment card transactions using cryptographic Combined Data Authentication (CDA).

## Overview

This project enables smart contract wallets to accept payment card transactions by validating EMV CDA signatures on-chain and automatically settling funds to merchants with a configurable multi-party fee structure. It integrates with the [Kernel](https://github.com/zerodev-xyz/kernel) ERC-4337 smart contract wallet framework.

### Key Features

- **🔐 EMV CDA Validation**: On-chain verification of RSA-2048 signed payment card transactions
- **🎯 ERC-7579 Compliant**: Fully compatible validator module for modular smart accounts
- **💰 Multi-Fee Settlement**: Configurable fee distribution (acquirer, swipe, interchange, network)
- **🛡️ Replay Protection**: Dual protection via unpredictable numbers and application transaction counters (ATC)
- **⚡ Gas Optimized**: Assembly-optimized calldata extraction and storage operations
- **🌐 Merchant Registry**: Decentralized registry for acquirers, merchants, and terminals

## Architecture

### Core Contracts

1. **`EMVValidator.sol`**
   - ERC-7579 validator module
   - Validates EMV CDA signatures using RSA-2048 with SHA-256
   - Implements replay protection (unpredictable numbers + ATC)
   - Enforces target address and function selector validation
   - Supports USD (840) and USN (997) currency codes

2. **`EMVSettlement.sol`**
   - ERC-7579 executor module
   - Processes EMV transaction data and distributes funds
   - Extracts BCD-encoded amounts and merchant identifiers
   - Executes ERC20 token transfers to all fee recipients
   - Calculates merchant remainder after fee deductions

3. **`AcquirerConfig.sol`**
   - Centralized merchant and terminal registry
   - Configurable four-tier fee structure:
     - Acquirer fee (0-0.30%)
     - Terminal swipe fee (fixed amount)
     - Interchange fee (0-2.50%)
     - Network fee (0-0.15%)
   - Per-acquirer configuration with owner-controlled assignment
   - Gas-optimized fee deduplication using transient storage (EIP-1153)

## How It Works

### Transaction Flow

```
1. Payment Card → EMV Terminal
   └─ Generates ARQC (Authorization Request Cryptogram)
   └─ Signs transaction data with card's RSA private key

2. Terminal → Smart Contract Wallet (via ERC-4337 UserOp)
   └─ Packs EMV data into signature field
   └─ Calls Kernel.execute() targeting EMVSettlement

3. EMVValidator validates signature
   ├─ Verifies RSA-2048 signature (PKCS#1 v1.5 + SHA-256)
   ├─ Checks replay protection (unpredictableNumber + ATC)
   ├─ Validates currency code (USD/USN only)
   └─ Verifies target address and function selector

4. If valid → EMVSettlement executes
   ├─ Extracts transaction amount (BCD format)
   ├─ Queries AcquirerConfig for fee distribution
   ├─ Transfers fees to recipients
   └─ Sends remainder to merchant
```

### EMV Data Format

Transactions pack 63 bytes of EMV data + RSA components:

```
ARQC(8) + UnpredictableNumber(4) + ATC(2) + Amount(6) + 
Currency(2) + Date(3) + TxnType(1) + TVR(5) + CVMResults(3) +
TerminalId(8) + MerchantId(15) + AcquirerId(6) +
Signature(256) + Exponent(3) + Modulus(256)
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
- [SolRsaVerify](https://github.com/adria0/SolRsaVerify) (RSA signature verification)

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

# 3. Deploy EMVValidator
forge create src/EMVValidator.sol:EMVValidator \
  --constructor-args <TARGET> <SELECTOR> \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY
```

### Configuration

```solidity
// 1. Configure acquirer
acquirerConfig.setAcquirer(acquirerId, acquirerAddress);
acquirerConfig.setAcquirerFee(acquirerId, feeRecipient, 15); // 0.15%

// 2. Register merchants
acquirerConfig.setMerchant(acquirerId, merchantId, merchantAddress);

// 3. Register terminals
acquirerConfig.setTerminal(acquirerId, terminalId, terminalAddress);

// 4. Set global fees
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

### RSA Key Size

- **RSA-2048 only**: RSA-1024 explicitly rejected for security
- Uses PKCS#1 v1.5 padding with SHA-256

### Target Validation

- Validates both target address and function selector
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
