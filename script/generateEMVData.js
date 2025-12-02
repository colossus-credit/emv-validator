#!/usr/bin/env node

/**
 * Random EMV Data Generator
 * 
 * Generates random but valid 63-byte EMV transaction data
 * 
 * Usage:
 *   node script/generateEMVData.js [options]
 *   
 * Options:
 *   --amount <dollars>     Amount in dollars (e.g., 100.00), default: random 1-1000
 *   --currency <code>      Currency code: 840 (USD) or 997 (USN), default: 840
 *   --atc <number>         ATC counter (0-65535), default: random
 *   --merchant <id>        Merchant ID (15 chars), default: random
 *   --terminal <id>        Terminal ID (8 chars), default: random
 *   --acquirer <id>        Acquirer ID (6 chars), default: random
 *   --json                 Output as JSON
 *   
 * Example:
 *   node script/generateEMVData.js --amount 150.50 --currency 840 --merchant MERCHANT001
 */

const crypto = require('crypto');

/**
 * Convert decimal amount to 6-byte BCD format
 * @param {number} amountInCents - Amount in cents (e.g., 10000 = $100.00)
 * @returns {Buffer} 6-byte BCD encoded amount
 */
function amountToBCD(amountInCents) {
    // Pad to 12 digits (6 bytes BCD)
    const amountStr = amountInCents.toString().padStart(12, '0');
    
    // Convert each pair of digits to BCD
    const bcdBytes = [];
    for (let i = 0; i < 12; i += 2) {
        const highNibble = parseInt(amountStr[i], 10);
        const lowNibble = parseInt(amountStr[i + 1], 10);
        bcdBytes.push((highNibble << 4) | lowNibble);
    }
    
    return Buffer.from(bcdBytes);
}

/**
 * Convert date to 3-byte BCD format (YYMMDD)
 * @param {Date} date - Date object
 * @returns {Buffer} 3-byte BCD encoded date
 */
function dateToBCD(date) {
    const year = (date.getFullYear() % 100).toString().padStart(2, '0');
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    
    const dateStr = year + month + day;
    
    const bcdBytes = [];
    for (let i = 0; i < 6; i += 2) {
        const highNibble = parseInt(dateStr[i], 10);
        const lowNibble = parseInt(dateStr[i + 1], 10);
        bcdBytes.push((highNibble << 4) | lowNibble);
    }
    
    return Buffer.from(bcdBytes);
}

/**
 * Generate random ASCII string padded with nulls
 * @param {number} length - Total length in bytes
 * @param {string} prefix - Optional prefix string
 * @returns {Buffer}
 */
function randomPaddedString(length, prefix = '') {
    const buffer = Buffer.alloc(length);
    
    if (prefix.length > length) {
        throw new Error(`Prefix too long: ${prefix.length} > ${length}`);
    }
    
    // Write prefix
    buffer.write(prefix, 0, 'ascii');
    
    // Fill remaining with random alphanumeric or pad with nulls
    for (let i = prefix.length; i < length; i++) {
        // Mix of alphanumeric and null padding
        if (i < Math.min(prefix.length + 4, length - 1)) {
            // Add some random chars after prefix
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            buffer[i] = chars.charCodeAt(Math.floor(Math.random() * chars.length));
        } else {
            buffer[i] = 0; // Null padding
        }
    }
    
    return buffer;
}

/**
 * Generate random but valid EMV transaction data
 */
function generateEMVData(options = {}) {
    const {
        amount = Math.floor(Math.random() * 100000) + 100, // Random $1-$1000 in cents
        currency = 840, // USD by default
        atc = Math.floor(Math.random() * 65536), // Random ATC 0-65535
        merchantId = null,
        terminalId = null,
        acquirerId = null,
        txnType = 0x00, // Purchase
        date = new Date()
    } = options;
    
    // Validate inputs
    if (currency !== 840 && currency !== 997) {
        throw new Error('Currency must be 840 (USD) or 997 (USN)');
    }
    
    if (atc < 0 || atc > 65535) {
        throw new Error('ATC must be 0-65535');
    }
    
    // Generate fields
    const fields = {
        arqc: crypto.randomBytes(8), // Random 8-byte cryptogram
        unpredictableNumber: crypto.randomBytes(4), // Random 4-byte number
        atc: Buffer.from([(atc >> 8) & 0xFF, atc & 0xFF]), // 2-byte ATC (big-endian)
        amount: amountToBCD(amount), // 6-byte BCD amount
        currency: Buffer.from([(currency >> 8) & 0xFF, currency & 0xFF]), // 2-byte currency (big-endian)
        date: dateToBCD(date), // 3-byte BCD date
        txnType: Buffer.from([txnType]), // 1-byte transaction type
        tvr: Buffer.alloc(5), // 5-byte TVR (all zeros for simplicity)
        cvmResults: Buffer.alloc(3), // 3-byte CVM results (all zeros)
        terminalId: terminalId ? Buffer.from(terminalId.padEnd(8, '\0').slice(0, 8), 'ascii') : randomPaddedString(8, 'TERM'),
        merchantId: merchantId ? Buffer.from(merchantId.padEnd(15, '\0').slice(0, 15), 'ascii') : randomPaddedString(15, 'MERCHANT'),
        acquirerId: acquirerId ? Buffer.from(acquirerId.padEnd(6, '\0').slice(0, 6), 'ascii') : randomPaddedString(6, 'ACQ')
    };
    
    // Concatenate all fields
    const emvData = Buffer.concat([
        fields.arqc,
        fields.unpredictableNumber,
        fields.atc,
        fields.amount,
        fields.currency,
        fields.date,
        fields.txnType,
        fields.tvr,
        fields.cvmResults,
        fields.terminalId,
        fields.merchantId,
        fields.acquirerId
    ]);
    
    if (emvData.length !== 63) {
        throw new Error(`Invalid EMV data length: ${emvData.length} (expected 63)`);
    }
    
    return {
        hex: emvData.toString('hex'),
        fields: {
            arqc: fields.arqc.toString('hex'),
            unpredictableNumber: fields.unpredictableNumber.toString('hex'),
            atc: atc,
            amount: (amount / 100).toFixed(2),
            amountCents: amount,
            currency: currency === 840 ? 'USD (840)' : 'USN (997)',
            currencyCode: currency,
            date: date.toISOString().split('T')[0],
            txnType: txnType,
            terminalId: fields.terminalId.toString('hex'),
            merchantId: fields.merchantId.toString('hex'),
            acquirerId: fields.acquirerId.toString('hex')
        }
    };
}

// Parse command line arguments
function parseArgs(args) {
    const options = {};
    
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--amount':
                options.amount = Math.floor(parseFloat(args[++i]) * 100); // Convert dollars to cents
                break;
            case '--currency':
                options.currency = parseInt(args[++i]);
                break;
            case '--atc':
                options.atc = parseInt(args[++i]);
                break;
            case '--merchant':
                options.merchantId = args[++i];
                break;
            case '--terminal':
                options.terminalId = args[++i];
                break;
            case '--acquirer':
                options.acquirerId = args[++i];
                break;
            case '--json':
                options.json = true;
                break;
            case '--help':
            case '-h':
                return null;
        }
    }
    
    return options;
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args.includes('--help') || args.includes('-h')) {
        console.log('EMV Data Generator\n');
        console.log('Usage: node script/generateEMVData.js [options]\n');
        console.log('Options:');
        console.log('  --amount <dollars>     Amount in dollars (e.g., 100.00), default: random 1-1000');
        console.log('  --currency <code>      Currency code: 840 (USD) or 997 (USN), default: 840');
        console.log('  --atc <number>         ATC counter (0-65535), default: random');
        console.log('  --merchant <id>        Merchant ID (max 15 chars), default: random');
        console.log('  --terminal <id>        Terminal ID (max 8 chars), default: random');
        console.log('  --acquirer <id>        Acquirer ID (max 6 chars), default: random');
        console.log('  --json                 Output as JSON');
        console.log('  --help, -h             Show this help\n');
        console.log('Example:');
        console.log('  node script/generateEMVData.js --amount 150.50 --currency 840 --merchant MERCHANT001');
        process.exit(0);
    }
    
    const options = parseArgs(args);
    
    try {
        const result = generateEMVData(options);
        
        if (options.json) {
            console.log(JSON.stringify(result, null, 2));
        } else {
            console.log('\n=== Generated EMV Transaction Data ===\n');
            console.log(`EMV Data (63 bytes): 0x${result.hex}`);
            console.log('\n=== Field Breakdown ===');
            console.log(`ARQC:                ${result.fields.arqc}`);
            console.log(`Unpredictable Number: ${result.fields.unpredictableNumber}`);
            console.log(`ATC:                 ${result.fields.atc}`);
            console.log(`Amount:              $${result.fields.amount} (${result.fields.amountCents} cents)`);
            console.log(`Currency:            ${result.fields.currency}`);
            console.log(`Date:                ${result.fields.date}`);
            console.log(`Transaction Type:    0x${result.fields.txnType.toString(16).padStart(2, '0')}`);
            console.log(`Terminal ID (hex):   ${result.fields.terminalId}`);
            console.log(`Merchant ID (hex):   ${result.fields.merchantId}`);
            console.log(`Acquirer ID (hex):   ${result.fields.acquirerId}`);
            console.log('\n=== Next Step ===');
            console.log(`To sign this data, run:`);
            console.log(`  node script/signEMVData.js ${result.hex} <privateKeyPath>`);
        }
    } catch (error) {
        console.error('\n✗ Error generating EMV data:');
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = { generateEMVData, amountToBCD, dateToBCD };

