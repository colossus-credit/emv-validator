#!/usr/bin/env node

/**
 * EMV Data Signer
 * 
 * This script signs EMV transaction data using RSA-2048 with PKCS#1 v1.5 padding and SHA-256
 * 
 * Usage:
 *   node script/signEMVData.js <emvDataHex> <privateKeyPath>
 *   
 * Where:
 *   - emvDataHex: 63 bytes of packed EMV fields in hex (with or without 0x prefix)
 *   - privateKeyPath: Path to PEM-encoded RSA-2048 private key file
 *   
 * Example:
 *   node script/signEMVData.js 1234567890abcdef123456780000000000010000034823120100000000000000000054455354303031004d45524348414e5430303132333400414351554952 ./test-key.pem
 *   
 * EMV Field Structure (63 bytes total):
 *   - ARQC (8 bytes)
 *   - Unpredictable Number (4 bytes)
 *   - ATC (2 bytes)
 *   - Amount (6 bytes, BCD)
 *   - Currency (2 bytes)
 *   - Date (3 bytes, BCD YYMMDD)
 *   - Transaction Type (1 byte)
 *   - TVR (5 bytes)
 *   - CVM Results (3 bytes)
 *   - Terminal ID (8 bytes)
 *   - Merchant ID (15 bytes)
 *   - Acquirer ID (6 bytes)
 */

const crypto = require('crypto');
const fs = require('fs');

function assembleDynamicData(emvFieldsHex) {
    // Remove 0x prefix if present
    const cleanHex = emvFieldsHex.startsWith('0x') ? emvFieldsHex.slice(2) : emvFieldsHex;
    
    // Validate length (63 bytes = 126 hex chars)
    if (cleanHex.length !== 126) {
        throw new Error(`Invalid EMV fields length: expected 126 hex chars (63 bytes), got ${cleanHex.length}`);
    }
    
    // Assemble according to EMV Book 2, Annex C.5 (Signed Data Format 3)
    // Format: 0x6A (header) + 0x03 (format) + EMV fields (63 bytes) + 0xBC (trailer)
    const dynamicData = '6a' + '03' + cleanHex + 'bc';
    
    return Buffer.from(dynamicData, 'hex');
}

function signEMVData(emvFieldsHex, privateKeyPath) {
    // Read private key
    if (!fs.existsSync(privateKeyPath)) {
        throw new Error(`Private key file not found: ${privateKeyPath}`);
    }
    
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    
    // Assemble dynamic data
    const dynamicData = assembleDynamicData(emvFieldsHex);
    
    console.log('\n=== EMV Data Signing ===');
    console.log(`EMV Fields (63 bytes): ${emvFieldsHex}`);
    console.log(`Dynamic Data (66 bytes): 0x${dynamicData.toString('hex')}`);
    
    // Create SHA-256 hash
    const hash = crypto.createHash('sha256').update(dynamicData).digest();
    console.log(`SHA-256 Hash: 0x${hash.toString('hex')}`);
    
    // Sign using RSA-2048 with PKCS#1 v1.5 padding
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(dynamicData);
    
    const signature = signer.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    });
    
    console.log(`\n=== RSA Signature ===`);
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
    
    return {
        signature: signature.toString('hex'),
        hash: hash.toString('hex'),
        exponent: exponent.toString('hex'),
        modulus: modulus.toString('hex'),
        dynamicData: dynamicData.toString('hex')
    };
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args.length < 2) {
        console.error('Usage: node signEMVData.js <emvDataHex> <privateKeyPath>');
        console.error('\nExample:');
        console.error('  node script/signEMVData.js 1234567890abcdef123456780000000000010000034823120100000000000000000054455354303031004d45524348414e5430303132333400414351554952 ./test-key.pem');
        process.exit(1);
    }
    
    const [emvDataHex, privateKeyPath] = args;
    
    try {
        const result = signEMVData(emvDataHex, privateKeyPath);
        console.log('\n=== Success ===');
        console.log('Signature generation complete!');
    } catch (error) {
        console.error('\n=== Error ===');
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = { signEMVData, assembleDynamicData };

