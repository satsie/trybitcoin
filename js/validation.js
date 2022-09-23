// The lessons that expect the user to input JavaScript
const javaScriptLessons = [1, 2, 3, 4, 5, 7];
const bitcoinRpcLessons = [6, 8, 9];
const totalNumberLessons = 10;

function checkResult(lessonNumber, resultToCheck) {
    let checkedResult = resultToCheck;

    if (lessonNumber === 4) {
        const cypherpunksWriteCodeHash = '42cc22190b177e5c48e32fe87c214d88eb21cac7780aad65b8b816d77cf22820';
        if (resultToCheck.result.hash !== cypherpunksWriteCodeHash) {
            checkedResult.success = false;
            checkedResult.result.error = 'The hash does not match! Try running: hash(\'Cypherpunks write code\')'
        }
    }

    return checkedResult;
}

// sanity check the user command before sending it off to eval()
// provides minor protection against blindly running eval() on user input, but the security
// still needs to be revisited
// returns true if the sanity check passes
function userInputSanityCheck(aCurrentLesson, aLowercaseInputString) {
    const errorResponse = {
        lesson0: 'Please type \'start\'',
        lesson1: 'Please type \'generateKeys()\'',
        lesson2: 'Please invoke the \'signMessage\' function',
        lesson3: 'Please invoke the \'verifySignature\' function',
        lesson4: 'Please invoke the \'hash\' function with the input \'Cypherpunks write code\'',
        lesson5: 'Please type \'createAddress()\'',
        lesson6: 'Please type \'bitcoin-cli getbalance\'',
        lesson7: 'Please type \'signTransaction(privateKey, transaction)\'',
        lesson8: 'Please copy and paste all of the \'bitcoin-cli sendrawtransaction\' command, including the giant string of letters and numbers. That is the transaction in hex format, and it is required.',
        lesson9: 'Please type \'bitcoin-cli getbalance\'',
    };

    // lowercase because the input is normalized before it gets to this method
    const expectedCommandBeginning = {
        lesson0: 'start',
        lesson1: 'generatekeys(',
        lesson2: 'signmessage(',
        lesson3: 'verifysignature(',
        lesson4: 'hash(',
        lesson5: 'createaddress(',
        lesson6: 'bitcoin-cli getbalance',
        lesson7: 'signtransaction(',
        lesson8: 'bitcoin-cli sendrawtransaction',
        lesson9: 'bitcoin-cli getbalance'
    }

    // It's ok if the user wants to put a semicolon at the end, but remove it to
    // make validation simpler
    if (aLowercaseInputString.endsWith(';')) {
        aLowercaseInputString = aLowercaseInputString.slice(0, -1);
    }

    // If this is a javascript lesson, check that the user input ends with a closing parenthesis
    if (javaScriptLessons.includes(aCurrentLesson) && !aLowercaseInputString.endsWith(')')) {
        return errorResponse[`lesson${aCurrentLesson}`];
    }

    // check the beginning of the user input. For javascript commands this makes sure
    // that there is an opening parenthesis. Without parenthesis, the user could invoke
    // `eval(myFunction)` instead of `eval(myFunction())`. The former would just return
    // the function definition instead of the evaulation
    if (aLowercaseInputString.startsWith(expectedCommandBeginning[`lesson${aCurrentLesson}`])) {
        return true;
    }

    if (errorResponse[`lesson${aCurrentLesson}`]) {
        return errorResponse[`lesson${aCurrentLesson}`];
    }

    return false;
}

module.exports = {
    bitcoinRpcLessons,
    checkResult,
    javaScriptLessons,
    totalNumberLessons,
    userInputSanityCheck
}