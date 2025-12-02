#!/usr/bin/env node

/**
 * RSA-2048 Key Pair Generator
 * 
 * Generates an RSA-2048 key pair for EMV signing
 * 
 * Usage:
 *   node script/generateRSAKey.js [outputPrefix]
 *   
 * Example:
 *   node script/generateRSAKey.js my-card
 *   
 * This will create:
 *   - my-card-private.pem (private key)
 *   - my-card-public.pem (public key)
 *   - my-card-contract-data.json (public key in contract format)
 */

const crypto = require('crypto');
const fs = require('fs');

function generateRSAKeyPair(outputPrefix = 'emv-key') {
    console.log('Generating RSA-2048 key pair...\n');
    
    // Generate RSA-2048 key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicExponent: 0x010001, // 65537
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    // Save keys
    const privateKeyPath = `${outputPrefix}-private.pem`;
    const publicKeyPath = `${outputPrefix}-public.pem`;
    
    fs.writeFileSync(privateKeyPath, privateKey);
    fs.writeFileSync(publicKeyPath, publicKey);
    
    console.log(`✓ Private key saved to: ${privateKeyPath}`);
    console.log(`✓ Public key saved to: ${publicKeyPath}`);
    
    // Extract modulus and exponent for contract
    const pubKeyObj = crypto.createPublicKey(publicKey);
    const pubKeyDer = pubKeyObj.export({ type: 'spki', format: 'der' });
    
    // Extract modulus (last 256 bytes) and exponent
    const modulusOffset = pubKeyDer.length - 256 - 5;
    const modulus = pubKeyDer.slice(modulusOffset, modulusOffset + 256);
    const exponent = Buffer.from([0x01, 0x00, 0x01]); // Standard exponent 65537
    
    // Create contract data JSON
    const contractData = {
        exponent: '0x' + exponent.toString('hex'),
        modulus: '0x' + modulus.toString('hex'),
        exponentLength: exponent.length,
        modulusLength: modulus.length
    };
    
    const contractDataPath = `${outputPrefix}-contract-data.json`;
    fs.writeFileSync(contractDataPath, JSON.stringify(contractData, null, 2));
    
    console.log(`✓ Contract data saved to: ${contractDataPath}\n`);
    
    console.log('=== Public Key for Contract ===');
    console.log(`Exponent (${exponent.length} bytes): ${contractData.exponent}`);
    console.log(`Modulus (${modulus.length} bytes): ${contractData.modulus}`);
    
    return { privateKey, publicKey, exponent, modulus };
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    const outputPrefix = args[0] || 'emv-key';
    
    try {
        generateRSAKeyPair(outputPrefix);
        console.log('\n✓ Key pair generation complete!');
    } catch (error) {
        console.error('\n✗ Error generating key pair:');
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = { generateRSAKeyPair };

