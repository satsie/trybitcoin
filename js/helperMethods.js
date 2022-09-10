const stringUtils = require('./stringUtils');
const schnorr = require('bip-schnorr');
const forge = require('node-forge');

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
    hash
}