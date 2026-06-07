#!/usr/bin/env node

const crypto = require('crypto');

const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const P256_HALF_N = P256_N / 2n;

function normalizeS(s) {
  const sBigInt = BigInt(`0x${s.toString('hex')}`);
  const normalized = sBigInt > P256_HALF_N ? P256_N - sBigInt : sBigInt;
  return Buffer.from(normalized.toString(16).padStart(64, '0'), 'hex');
}

(async () => {
  // Test P-256 keypair
  const privateKeyHex = '519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464';
  const pubkeyXHex = '1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83';
  const pubkeyYHex = 'ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9';

  // Test EMV data: 63-byte packed validator payload
  const ARQC = '1234567890ABCDEF'; // 8 bytes
  const UN = '12345678'; // 4 bytes
  const ATC = '0000'; // 2 bytes
  const Amount = '000000010000'; // 6 bytes (BCD format: n12)
  const Currency = '0840'; // 2 bytes (BCD format: n3, 840 = USD per ISO 4217)
  const Date = '231201'; // 3 bytes
  const TxnType = '00'; // 1 byte
  const TVR = '0000000000'; // 5 bytes
  const CVMResults = '000000'; // 3 bytes
  const TerminalId = '5445535430303100'; // 8 bytes
  const MerchantId = '4D45524348414E5430303132333400'; // 15 bytes
  const AcquirerId = '414351554952'; // 6 bytes

  const signedData = Buffer.from(
    ARQC +
    UN +
    ATC +
    Amount +
    Currency +
    Date +
    TxnType +
    TVR +
    CVMResults +
    TerminalId +
    MerchantId +
    AcquirerId,
    'hex'
  );
  console.log('Signed data (63 bytes):', signedData.toString('hex'));

  const hash = crypto.createHash('sha256').update(signedData).digest();
  console.log('SHA-256 hash:', hash.toString('hex'));

  // Generate signature using WebCrypto
  async function generateSignature() {
    const { webcrypto } = crypto;

    const privateKey = await webcrypto.subtle.importKey(
      'pkcs8',
      Buffer.from(
        '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420' +
        privateKeyHex +
        'a14403420004' +
        pubkeyXHex +
        pubkeyYHex,
        'hex'
      ),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign']
    );

    const signatureBuffer = await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      signedData
    );

    return Buffer.from(signatureBuffer);
  }

  const signature = await generateSignature();
  const r = signature.slice(0, 32);
  const s = normalizeS(signature.slice(32, 64));
  const normalizedSignature = Buffer.concat([r, s]);

  console.log('\n=== P-256 ECDSA Signature ===');
  console.log('r:', r.toString('hex'));
  console.log('s:', s.toString('hex'));
  console.log('\n=== Solidity Constant ===');
  console.log('bytes constant TEST_SIGNATURE =');
  console.log('    hex"' + r.toString('hex') + '"  // r');
  console.log('    hex"' + s.toString('hex') + '"; // s');

  // Verify
  const { webcrypto } = crypto;
  const publicKey = await webcrypto.subtle.importKey(
    'spki',
    Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004' + pubkeyXHex + pubkeyYHex, 'hex'),
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );

  const isValid = await webcrypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    normalizedSignature,
    signedData
  );

  console.log('\nSignature valid:', isValid);
})().catch(console.error);
