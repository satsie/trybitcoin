const stringUtils = require('./stringUtils');
const schnorr = require('bip-schnorr');
const forge = require('node-forge');

        // "asm": "002093f5ff817f1953be6cc714676b5f9169f1322fa2647053acce88358444ca2fef",
        // "asm": "0020fd02d8db5e4ef12b09d5f8f035a4758fa87fe528ed2527d5fe3f5680592ba2e3",

// This is an extremely simplified example of what a transaction looks like.
// so many fields have been removed, and some have even been changed to accomodate
// a beginner audience (i.e. vin => inputs). This is NOT canonical!!!!
let mockTxToSign = {
  "inputs": [
    {
      "address": "14wiw5uGiZtFNqmwEfDZJM8k2qzxxd9fS5",
      "scriptSig": ""
    },
    {
      "address": "1w2f2SMHjPFXFrxaj2gvYnMDnM79ybPWL",
      "scriptSig": ""
    }
  ],
  "outputs": [
    {
      "value": 1.50000000,
      "address": "1AGUB3hAXyQdCwy5ddLcyMFN8kY2qPiEMg"
    },
    {
      "value": 0.50000000,
      "address": "14wiw5uGiZtFNqmwEfDZJM8k2qzxxd9fS5"
    }
  ]
}

function verifySignature(aPublicKeyHex, aMessage, aSignature) {
    const publicKeyBuffer = Buffer.from(aPublicKeyHex, 'hex');
    const signatureBuffer = Buffer.from(aSignature, 'hex');
    const messageBuffer = stringUtils.convertToFixedBuffer(aMessage, 32);

    // the bip-schnorr lib will throw an error if this is not valid
    schnorr.verify(publicKeyBuffer, messageBuffer, signatureBuffer);
    return {valid: true};
}

function hash(inputString) {
    // from https://remarkablemark.org/blog/2021/08/29/javascript-generate-sha-256-hexadecimal-hash/
    const utf8 = new TextEncoder().encode(inputString);

    // Using forge because window.crypto.subtle (subtle crypto) is restricted to secure origins,
    // aka https or localhost. Planning to move to https but that is going to require some updates
    // to the CD pipeline.
    let md = forge.md.sha256.create();
    md.update(Buffer.from(utf8, 'utf-8'));
    const hashHex = md.digest().toHex();

    return {hash: hashHex};
}

module.exports = {
    verifySignature,
    hash,
    mockTxToSign
}