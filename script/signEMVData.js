#!/usr/bin/env node

/**
 * EMV Data Signer - Format 05 (CDA)
 *
 * Signs EMV transaction data using raw RSA (no PKCS#1 padding) per EMV Book 2 CDA Format 05
 *
 * Usage:
 *   node script/signEMVData.js <emvDataHex> <privateKeyPath>
 *
 * Where:
 *   - emvDataHex: 63 bytes of packed EMV fields in hex (with or without 0x prefix)
 *   - privateKeyPath: Path to PEM-encoded RSA-2048 private key file
 *
 * EMV Field Structure (63 bytes total):
 *   - ARQC (8 bytes)           [offset 0]
 *   - Unpredictable Number (4) [offset 8]
 *   - ATC (2 bytes)            [offset 12]
 *   - Amount (6 bytes, BCD)    [offset 14]
 *   - Currency (2 bytes)       [offset 20]
 *   - Date (3 bytes, BCD)      [offset 22]
 *   - Transaction Type (1)     [offset 25]
 *   - TVR (5 bytes)            [offset 26]
 *   - CVM Results (3 bytes)    [offset 31]
 *   - Terminal ID (8 bytes)    [offset 34]
 *   - Merchant ID (15 bytes)   [offset 42]
 *   - Acquirer ID (6 bytes)    [offset 57]
 *
 * Format 05 signed block (256 bytes for RSA-2048):
 *   Byte 0:       0x6A (header)
 *   Byte 1:       0x05 (format)
 *   Byte 2:       0x02 (hash algo = SHA-256)
 *   Byte 3:       0x32 (ICC dynamic data length = 50)
 *   Byte 4:       0x08 (dynamic number length = 8)
 *   Bytes 5-12:   ICC Dynamic Number (8 bytes, random)
 *   Byte 13:      CID (9F27, 1 byte = 0x80 for ARQC)
 *   Bytes 14-21:  AC/ARQC (9F26, 8 bytes)
 *   Bytes 22-53:  Transaction Data Hash (SHA-256, 32 bytes)
 *   Bytes 54-222: 0xBB padding (169 bytes)
 *   Bytes 223-254: Outer Hash = SHA-256(bytes[1..223] || UN)
 *   Byte 255:     0xBC (trailer)
 */

const crypto = require('crypto');
const fs = require('fs');

/**
 * Build Format 05 signed block (256 bytes) and sign with raw RSA
 */
function assembleFormat05Block(emvFieldsHex) {
    const cleanHex = emvFieldsHex.startsWith('0x') ? emvFieldsHex.slice(2) : emvFieldsHex;

    if (cleanHex.length !== 126) {
        throw new Error(`Invalid EMV fields length: expected 126 hex chars (63 bytes), got ${cleanHex.length}`);
    }

    const emvFields = Buffer.from(cleanHex, 'hex');

    // Extract fields from emvFields
    const arqc = emvFields.slice(0, 8);     // 8 bytes
    const un = emvFields.slice(8, 12);       // 4 bytes (Unpredictable Number)

    // Generate random ICC Dynamic Number (8 bytes)
    const iccDynamicNumber = crypto.randomBytes(8);

    // CID = 0x80 (ARQC generated)
    const cid = 0x80;

    // Compute Transaction Data Hash (SHA-256 of transaction-related data)
    // For our purposes, hash the emvFields themselves as the transaction data
    const txDataHash = crypto.createHash('sha256').update(emvFields).digest();

    // Build the 256-byte block
    const block = Buffer.alloc(256);

    block[0] = 0x6A;  // header
    block[1] = 0x05;  // format
    block[2] = 0x02;  // hash algo = SHA-256
    block[3] = 0x32;  // ICC dynamic data length = 50
    block[4] = 0x08;  // dynamic number length = 8

    // Bytes 5-12: ICC Dynamic Number
    iccDynamicNumber.copy(block, 5);

    // Byte 13: CID
    block[13] = cid;

    // Bytes 14-21: AC (ARQC)
    arqc.copy(block, 14);

    // Bytes 22-53: Transaction Data Hash (32 bytes)
    txDataHash.copy(block, 22);

    // Bytes 54-222: 0xBB padding (169 bytes)
    for (let i = 54; i <= 222; i++) {
        block[i] = 0xBB;
    }

    // Bytes 223-254: Outer Hash = SHA-256(block[1..223] || UN)
    const outerHashInput = Buffer.concat([
        block.slice(1, 223),  // bytes 1..222 (222 bytes)
        un                     // 4 bytes
    ]);
    const outerHash = crypto.createHash('sha256').update(outerHashInput).digest();
    outerHash.copy(block, 223);

    // Byte 255: trailer
    block[255] = 0xBC;

    return { block, iccDynamicNumber, txDataHash, outerHash };
}

/**
 * Raw RSA sign (no padding): signature = block^d mod n
 * Node.js crypto doesn't directly support RSA_NO_PADDING for sign,
 * but we can use privateEncrypt with RSA_NO_PADDING
 */
function rawRsaSign(block, privateKey) {
    return crypto.privateEncrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_NO_PADDING,
        },
        block
    );
}

function signEMVData(emvFieldsHex, privateKeyPath) {
    if (!fs.existsSync(privateKeyPath)) {
        throw new Error(`Private key file not found: ${privateKeyPath}`);
    }

    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

    // Build Format 05 block
    const { block, iccDynamicNumber, txDataHash, outerHash } = assembleFormat05Block(emvFieldsHex);

    console.log('\n=== EMV Format 05 Signing ===');
    console.log(`EMV Fields (63 bytes): ${emvFieldsHex}`);
    console.log(`Format 05 Block (256 bytes): 0x${block.toString('hex')}`);
    console.log(`ICC Dynamic Number: 0x${iccDynamicNumber.toString('hex')}`);
    console.log(`Transaction Data Hash: 0x${txDataHash.toString('hex')}`);
    console.log(`Outer Hash: 0x${outerHash.toString('hex')}`);

    // Raw RSA sign (no PKCS#1 padding)
    const signature = rawRsaSign(block, privateKey);

    console.log(`\n=== RSA Signature (raw, no padding) ===`);
    console.log(`Signature Length: ${signature.length} bytes`);
    console.log(`Signature (hex): 0x${signature.toString('hex')}`);

    // Extract public key info using JWK format (more reliable than DER parsing)
    const publicKey = crypto.createPublicKey(privateKey);
    const jwk = publicKey.export({ format: 'jwk' });

    console.log(`\n=== Public Key Info ===`);
    console.log(`Key Size: ${jwk.n ? Buffer.from(jwk.n, 'base64url').length * 8 : 'unknown'} bits`);

    // JWK 'n' is the modulus in base64url encoding, 'e' is the exponent
    const modulus = Buffer.from(jwk.n, 'base64url');
    const exponent = Buffer.from(jwk.e, 'base64url');

    console.log(`Exponent (3 bytes): 0x${exponent.toString('hex')}`);
    console.log(`Modulus (256 bytes): 0x${modulus.toString('hex')}`);

    // Compute hash of the old-style dynamic data for backwards compat in return value
    const hash = crypto.createHash('sha256').update(block).digest();

    return {
        signature: signature.toString('hex'),
        hash: hash.toString('hex'),
        exponent: exponent.toString('hex'),
        modulus: modulus.toString('hex'),
        dynamicData: block.toString('hex'),
        iccDynamicNumber: iccDynamicNumber.toString('hex'),
    };
}

// Keep assembleDynamicData for backwards compat (now wraps assembleFormat05Block)
function assembleDynamicData(emvFieldsHex) {
    const { block } = assembleFormat05Block(emvFieldsHex);
    return block;
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);

    if (args.length < 2) {
        console.error('Usage: node signEMVData.js <emvDataHex> <privateKeyPath>');
        process.exit(1);
    }

    const [emvDataHex, privateKeyPath] = args;

    try {
        const result = signEMVData(emvDataHex, privateKeyPath);
        console.log('\n=== Success ===');
        console.log('Format 05 signature generation complete!');
    } catch (error) {
        console.error('\n=== Error ===');
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = { signEMVData, assembleDynamicData, assembleFormat05Block, rawRsaSign };
