#!/usr/bin/env node

/**
 * FFI EMV Signer
 * 
 * This script is called by Foundry tests via FFI to generate keys, EMV data, and signatures
 * 
 * Usage:
 *   node script/ffi-emv-signer.js generate-key
 *   node script/ffi-emv-signer.js generate-data <amount> <currency> <atc> <merchant> <terminal> <acquirer>
 *   node script/ffi-emv-signer.js sign <emvDataHex> <privateKeyHex>
 *   
 * Output is JSON format for easy parsing in Solidity tests
 */

const crypto = require('crypto');

// Import helper functions
const { generateRSAKeyPair } = require('./generateRSAKey.js');
const { generateEMVData } = require('./generateEMVData.js');
const { signEMVData, assembleDynamicData } = require('./signEMVData.js');

/**
 * Generate RSA-2048 key pair and return as JSON
 * Silent mode for FFI - redirects console output
 */
function generateKey() {
    const fs = require('fs');
    
    // Suppress console.log output for FFI
    const originalLog = console.log;
    console.log = () => {};
    
    const { privateKey, publicKey, exponent, modulus} = generateRSAKeyPair('temp-ffi-key');
    
    // Restore console.log
    console.log = originalLog;
    
    // Clean up generated files (check existence first)
    const filesToDelete = [
        'temp-ffi-key-private.pem',
        'temp-ffi-key-public.pem',
        'temp-ffi-key-contract-data.json'
    ];
    
    filesToDelete.forEach(file => {
        try {
            if (fs.existsSync(file)) {
                fs.unlinkSync(file);
            }
        } catch (e) {
            // Ignore cleanup errors
        }
    });
    
    return {
        privateKey: privateKey,
        publicKey: publicKey,
        exponent: exponent.toString('hex'),
        modulus: modulus.toString('hex')
    };
}

/**
 * Generate EMV data with specified parameters
 */
function generateData(amountCents, currency, atc, merchantId, terminalId, acquirerId) {
    const result = generateEMVData({
        amount: parseInt(amountCents),
        currency: parseInt(currency),
        atc: parseInt(atc),
        merchantId: merchantId || undefined,
        terminalId: terminalId || undefined,
        acquirerId: acquirerId || undefined
    });
    
    return {
        emvData: result.hex,
        fields: result.fields
    };
}

/**
 * Sign EMV data with provided private key
 */
function sign(emvDataHex, privateKeyHex) {
    const fs = require('fs');
    
    // Write private key to temp file
    const tempKeyPath = 'temp-ffi-sign-key.pem';
    fs.writeFileSync(tempKeyPath, privateKeyHex);
    
    try {
        const result = signEMVData(emvDataHex, tempKeyPath);
        
        // Clean up temp file (check existence first)
        if (fs.existsSync(tempKeyPath)) {
            fs.unlinkSync(tempKeyPath);
        }
        
        return {
            signature: result.signature,
            hash: result.hash,
            exponent: result.exponent,
            modulus: result.modulus
        };
    } catch (error) {
        // Clean up temp file even on error
        try { 
            if (fs.existsSync(tempKeyPath)) {
                fs.unlinkSync(tempKeyPath);
            }
        } catch (e) {
            // Ignore cleanup errors
        }
        throw error;
    }
}

/**
 * Complete flow: generate key, data, and sign
 * Silent mode for FFI
 */
function completeFlow(amountCents, currency, atc, merchantId, terminalId, acquirerId) {
    // Suppress all console output for FFI
    const originalLog = console.log;
    const originalError = console.error;
    console.log = () => {};
    console.error = () => {};
    
    try {
        // Generate key
        const keyData = generateKey();
        
        // Generate EMV data
        const emvData = generateData(amountCents, currency, atc, merchantId, terminalId, acquirerId);
        
        // Sign the data
        const fs = require('fs');
        const tempKeyPath = 'temp-ffi-complete-key.pem';
        fs.writeFileSync(tempKeyPath, keyData.privateKey);
        
        try {
            const signResult = signEMVData(emvData.emvData, tempKeyPath);
            
            // Clean up temp file (check existence first)
            try {
                if (fs.existsSync(tempKeyPath)) {
                    fs.unlinkSync(tempKeyPath);
                }
            } catch (e) {
                // Ignore cleanup errors
            }
            
            // Restore console before returning
            console.log = originalLog;
            console.error = originalError;
            
            return {
                exponent: keyData.exponent,
                modulus: keyData.modulus,
                emvData: emvData.emvData,
                signature: signResult.signature,
                hash: signResult.hash,
                fields: emvData.fields
            };
        } catch (error) {
            // Clean up temp file on error
            try { 
                if (fs.existsSync(tempKeyPath)) {
                    fs.unlinkSync(tempKeyPath);
                }
            } catch (e) {
                // Ignore cleanup errors
            }
            throw error;
        }
    } finally {
        // Always restore console
        console.log = originalLog;
        console.error = originalError;
    }
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    const command = args[0];
    
    try {
        let result;
        
        switch (command) {
            case 'generate-key':
                result = generateKey();
                break;
                
            case 'generate-data':
                if (args.length < 7) {
                    throw new Error('Usage: generate-data <amount> <currency> <atc> <merchant> <terminal> <acquirer>');
                }
                result = generateData(args[1], args[2], args[3], args[4], args[5], args[6]);
                break;
                
            case 'sign':
                if (args.length < 3) {
                    throw new Error('Usage: sign <emvDataHex> <privateKeyHex>');
                }
                result = sign(args[1], args[2]);
                break;
                
            case 'complete':
                if (args.length < 7) {
                    throw new Error('Usage: complete <amount> <currency> <atc> <merchant> <terminal> <acquirer>');
                }
                result = completeFlow(args[1], args[2], args[3], args[4], args[5], args[6]);
                break;
                
            default:
                throw new Error(`Unknown command: ${command}`);
        }
        
        // Output JSON for FFI parsing
        console.log(JSON.stringify(result));
        
    } catch (error) {
        console.error(JSON.stringify({ error: error.message }));
        process.exit(1);
    }
}

module.exports = { generateKey, generateData, sign, completeFlow };

