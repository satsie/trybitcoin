const stringUtils = require('./stringUtils');
const schnorr = require('bip-schnorr');
const forge = require('node-forge');

// This is an extremely simplified example of what a transaction looks like.
// so many fields have been removed, and some have even been changed to accomodate
// a beginner audience (i.e. vin => inputs). This is NOT canonical!!!!
// Script sigs (should have saved the hex values but it doesn't matter):
// "asm": "002093f5ff817f1953be6cc714676b5f9169f1322fa2647053acce88358444ca2fef",
// "asm": "0020fd02d8db5e4ef12b09d5f8f035a4758fa87fe528ed2527d5fe3f5680592ba2e3",
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

// More mock data. This is not the actual transaction hashe or the hex data
let mockTxId = '7a37db6dae291ce730ab8de40650844d627a20a096f323836636236e200a55b5';
let rawSignedTx = '0200000001797a827a25bdf354b9f9440d7de2ded6596cc2c8b8dc2eaf936a476049f898c4000000006a473044022034c2cde7e751cb6d72bceb73cbad5614f43d60a59142f6eef20a40786f683772022070b9a8c6d71d9ea628fa943e51ccf5d35bafd71e364f00e1dfbacb5b8b873c5901210227d85ba011276cf25b51df6a188b75e604b38770a462b2d0e9fb2fc839ef5d3ffdffffff03c41b1a1e010000001976a914a96c7dbd1264f69bb52549618f3c59c9440f3c6f88ac80d1f008000000001976a91460baa0f494b38ce3c940dea67f3804dc52d1fb9488ac80f0fa02000000001976a914ba27f99e007c7f605a8305e318c1abde3cd220ac88ac00000000';

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
    mockTxId,
    mockTxToSign,
    rawSignedTx
}