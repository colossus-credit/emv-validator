#!/usr/bin/env node

/**
 * FFI EMV Test Helper
 * 
 * Outputs EMV signing data in ABI-encodable format for Foundry tests
 * 
 * Usage:
 *   node script/ffi-emv-test.js <amount> <currency> <atc> <merchant> <terminal> <acquirer>
 *   
 * Output format (hex string that can be abi.decoded as):
 *   (bytes exponent, bytes modulus, bytes emvData, bytes signature)
 */

const { completeFlow } = require('./ffi-emv-signer.js');

function abiEncode(exponent, modulus, emvData, signature) {
    // Simple ABI encoding for (bytes, bytes, bytes, bytes)
    // Format: offset1, offset2, offset3, offset4, length1, data1, length2, data2, length3, data3, length4, data4
    
    const exp = Buffer.from(exponent, 'hex');
    const mod = Buffer.from(modulus, 'hex');
    const emv = Buffer.from(emvData, 'hex');
    const sig = Buffer.from(signature, 'hex');
    
    // Calculate offsets (each offset is 32 bytes)
    const offset1 = 0x80; // After 4 offset fields (4 * 32 = 128 = 0x80)
    const offset2 = offset1 + 32 + exp.length + (32 - (exp.length % 32)) % 32; // Align to 32 bytes
    const offset3 = offset2 + 32 + mod.length + (32 - (mod.length % 32)) % 32;
    const offset4 = offset3 + 32 + emv.length + (32 - (emv.length % 32)) % 32;
    
    const parts = [];
    
    // Offsets (4 * 32 bytes)
    parts.push(Buffer.from(offset1.toString(16).padStart(64, '0'), 'hex'));
    parts.push(Buffer.from(offset2.toString(16).padStart(64, '0'), 'hex'));
    parts.push(Buffer.from(offset3.toString(16).padStart(64, '0'), 'hex'));
    parts.push(Buffer.from(offset4.toString(16).padStart(64, '0'), 'hex'));
    
    // Exponent: length + data (padded to 32-byte boundary)
    parts.push(Buffer.from(exp.length.toString(16).padStart(64, '0'), 'hex'));
    parts.push(exp);
    if (exp.length % 32 !== 0) {
        parts.push(Buffer.alloc(32 - (exp.length % 32)));
    }
    
    // Modulus: length + data (padded to 32-byte boundary)
    parts.push(Buffer.from(mod.length.toString(16).padStart(64, '0'), 'hex'));
    parts.push(mod);
    if (mod.length % 32 !== 0) {
        parts.push(Buffer.alloc(32 - (mod.length % 32)));
    }
    
    // EMV Data: length + data (padded to 32-byte boundary)
    parts.push(Buffer.from(emv.length.toString(16).padStart(64, '0'), 'hex'));
    parts.push(emv);
    if (emv.length % 32 !== 0) {
        parts.push(Buffer.alloc(32 - (emv.length % 32)));
    }
    
    // Signature: length + data (padded to 32-byte boundary)
    parts.push(Buffer.from(sig.length.toString(16).padStart(64, '0'), 'hex'));
    parts.push(sig);
    if (sig.length % 32 !== 0) {
        parts.push(Buffer.alloc(32 - (sig.length % 32)));
    }
    
    return Buffer.concat(parts).toString('hex');
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args.length < 6) {
        console.error('Usage: node script/ffi-emv-test.js <amount> <currency> <atc> <merchant> <terminal> <acquirer>');
        process.exit(1);
    }
    
    try {
        const result = completeFlow(args[0], args[1], args[2], args[3], args[4], args[5]);
        
        // Output ABI-encoded data
        const encoded = abiEncode(result.exponent, result.modulus, result.emvData, result.signature);
        console.log('0x' + encoded);
        
    } catch (error) {
        console.error(error.message);
        process.exit(1);
    }
}

