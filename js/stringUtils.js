function hexEncode(aString){
    var hex, i;

    var result = "";
    for (i=0; i< aString.length; i++) {
        hex = aString.charCodeAt(i).toString(16);
        result += ("000"+hex).slice(-4);
    }

    return result;
}

function convertToHexBuffer(aString) {
    const hexString = hexEncode(aString);
    const buffer = Buffer.from(hexString, 'hex');
    return buffer;
}

// Converts to a hex buffer of length 32
function convertToFixedBuffer(aString, size) {
    const buffer = convertToHexBuffer(aString);
    return Buffer.concat([buffer], size);
}

module.exports = {
    convertToFixedBuffer
}