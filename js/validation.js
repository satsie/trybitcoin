
function checkResult(lessonNumber, resultToCheck) {
    let checkedResult = resultToCheck;

    if (lessonNumber === 5) {
        console.log(resultToCheck.result.hash);
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
        lesson1: 'Please type \'start\'',
        lesson2: 'Please type \'generateKeys()\'',
        lesson3: 'Please invoke the \'signMessage\' function',
        lesson4: 'Please invoke the \'verifySignature\' function',
        lesson5: 'Please invoke the \'hash\' function with the input \'Cypherpunks write code\'',
        lesson6: 'Please type \'createAddress()\''
    };

    // lowercase because the input is normalized before it gets to this method
    const expectedCommandBeginning = {
        lesson1: 'start',
        lesson2: 'generatekeys(',
        lesson3: 'signmessage(',
        lesson4: 'verifysignature(',
        lesson5: 'hash(',
        lesson6: 'createaddress('
    }

    // It's ok if the user wants to put a semicolon at the end, but remove it to
    // make validation a little simpler
    if (aLowercaseInputString.endsWith(';')) {
        aLowercaseInputString = aLowercaseInputString.slice(0, -1);
    }

    if (aCurrentLesson !== 1 && !aLowercaseInputString.endsWith(')')) {
        return errorResponse[`lesson${aCurrentLesson}`];
    }

    // check for the opening parenthesis in the function call because without it
    // the user could essentially invoke `eval(myFunction)` instead of `eval(myFunction())`.
    // The former would just return the function definition
    if (aLowercaseInputString.startsWith(expectedCommandBeginning[`lesson${aCurrentLesson}`])) {
        return true;
    }

    if (errorResponse[`lesson${aCurrentLesson}`]) {
        return errorResponse[`lesson${aCurrentLesson}`];
    }

    return false;
}

module.exports = {
    checkResult,
    userInputSanityCheck
}