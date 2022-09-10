const stringUtils = require('./stringUtils');
const schnorr = require('bip-schnorr');

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

    return window.crypto.subtle.digest('SHA-256', utf8).then((hashBuffer) => {
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray
        .map((bytes) => bytes.toString(16).padStart(2, '0'))
        .join('');
        return {hash: hashHex};
    });
}

module.exports = {
    verifySignature,
    hash
}