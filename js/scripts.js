var $ = require('jquery');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const schnorr = require('bip-schnorr');
const stringUtils = require('./stringUtils');
const constants = require('./constants');

let mostRecentCommand;
let privateKey;
let publicKey;
let message;
let signature;

// store the lesson number in local storage so the user can leave and come back
let currentLesson = parseInt(localStorage.getItem('currentLesson'), 10) || 1;
let localDataString = localStorage.getItem('localData') || '';
let localData = {};
try {
    localData = JSON.parse(localDataString);
} catch (e) {
    console.log('Error parsing localData. Setting to empty object.');
}

// Populate any existing values from the local storage
if (Object.keys(localData).length > 0) {
    if (localData.mostRecentCommand) {
        mostRecentCommand = localData.mostRecentCommand;
    }

    if (localData.privateKey) {
        privateKey = localData.privateKey;
    }

    if (localData.publicKey) {
        publicKey = localData.publicKey;
    }

    if (localData.message) {
        message = localData.message;
    }

    if (localData.signature) {
        signature = localData.signature;
    }
}

// Hide the previous lesson page and show the next one
function startLesson(newLessonNumber) {
    // hide the current lesson
    $('.lesson' + currentLesson).hide();

    // Show the new lesson
    $('.lesson' + newLessonNumber).show();

    // persist the new lesson number
    currentLesson = newLessonNumber;
    localStorage.setItem('currentLesson', currentLesson);

    // If there is no lesson to show, display the final page
    if (!$('.lesson' + currentLesson).length) {
        $('.final').show();
    }
}

// Increment the current lesson counter, save to local storage, and call
// startLesson() to refresh the lesson page
function advanceLesson() {
    startLesson(currentLesson + 1);
}

function saveToLocalStorage(key, value) {
    localData[key] = value;
    localStorage.setItem('localData', JSON.stringify(localData));
}

function generateKeys() {
    // literally just the example from https://github.com/guggero/bip-schnorr
    // TODO actually generate some that are different every time
    const privateKeyHex = 'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF';
    const publicKeyHex = 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659';

    // Save the keys for use in subsequent lessons
    privateKey = privateKeyHex;
    publicKey = publicKeyHex;

    // Also persist to local storage
    saveToLocalStorage('privateKey', privateKey);
    saveToLocalStorage('publicKey', publicKey);

    return {publicKey: publicKeyHex, privateKey: privateKeyHex};
}

function signMessage(privateKeyHex, messageString) {
    if (messageString === undefined) {
        throw Error('message parameter is undefined');
    }

    // save the message to local storage
    saveToLocalStorage('message', messageString);
    message = messageString;

    // bip-schnorr lib requires the message to be 32 bytes
    const messageBuffer = stringUtils.convertToMessageBuffer(message);

    const schnorrSig = schnorr.sign(privateKeyHex, messageBuffer);
    const schnorrSigHex = schnorrSig.toString('hex');

    // save the signature to local store
    saveToLocalStorage('signature', schnorrSigHex);
    signature = schnorrSigHex;

    return {signature: schnorrSigHex};
}

function verifySignature(aPublicKeyHex, aMessage, aSignature) {
    const publicKeyBuffer = Buffer.from(aPublicKeyHex, 'hex');
    const signatureBuffer = Buffer.from(aSignature, 'hex');
    const messageBuffer = stringUtils.convertToMessageBuffer(aMessage);

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
        lesson5: 'Please invoke the \'hash\' function with the input \'Cypherpunks write code\''
    };

    // lowercase because the input is normalized before it gets to this method
    const expectedCommandBeginning = {
        lesson1: 'start',
        lesson2: 'generatekeys(',
        lesson3: 'signmessage(',
        lesson4: 'verifysignature(',
        lesson5: 'hash('
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

async function evaluateCode(userInput) {
    let returnObject = {
        success: true,
        result: ''
    };

    // Some protections for blindly feeding user input into eval()
    if (userInput.indexOf('var') !== -1 || userInput.indexOf('function') !== -1
        || userInput.indexOf('eval') !== -1) {
        returnObject.result = 'undefined;' + userInput;
        return returnObject;
    }

    try {
        const evalResult = await eval(userInput);
        returnObject.result = evalResult;
    } catch (e) {
        returnObject.success = false;
        returnObject.result = {error: `Error while trying to execute '${userInput}'. Message: ${e.message}`};
    }

    return returnObject;
}

function printResult($userInput, $consolePrompt, isError, aResult) {
    let result = aResult;

    const userInputString = $('.console-input').val();

    // take the user input and dispaly as a label
    $('.prompt-completed').clone()
        .removeClass('prompt-completed')
        .insertBefore($consolePrompt)
        .find('code')
        .text(userInputString);

    // clear the user input
    $userInput.val('');

    if (isError === true) {
        result = '<strong class = "error">' + result + '</strong>';
    }

    // print the result
    $('.prompt-result').clone()
      .removeClass('prompt-result')
      .insertBefore($consolePrompt)
      .find('code')
      [isError ? 'html' : 'text'](result);
}

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

// This is the same opening line as 'document ready()'
$(function() {
    // all custom jQuery will go here
    //  .html:              <p id="demo"></p>
    //  .js:                $("#demo").html("Hello, World!");

    console.log('current lesson: ' + currentLesson);

    const $console = $('.console');
    const $consolePrompt = $('.console-prompt');
    const $userInput = $('.console-input');

    // Focus on the user input box
    $userInput.trigger('focus');

    if (currentLesson !== 1) {
        // hide lesson 1, which is turned on by default
        $('.lesson1').hide();

        startLesson(currentLesson);
    }

    // If the user clicks anywhere in the console box, focus the cursor on the input line
    $console.on('click', function (e) {
        $userInput.trigger('focus');
    });

    $userInput.on('keydown', async function (e) {
        const userInputString = $('.console-input').val();
        const lowercaseUserInputString = userInputString.toLowerCase();

        if (e.key === constants.keyMap.ENTER) {
            // save the most recent command
            mostRecentCommand = userInputString;
            saveToLocalStorage('mostRecentCommand', userInputString);

            // do nothing if there is no user input
            if (userInputString.length === 0) {
                return;
            }

            if (lowercaseUserInputString.includes('reset')) {
                // hide the current lesson by resetting the CSS
                window.location.reload();

                // reset to lesson 1
                currentLesson = 1;
                localStorage.setItem('currentLesson', currentLesson);
                startLesson(currentLesson);

                // clear the user input
                $userInput.val('');

                // clear the rest of the data stored locally
                localStorage.setItem('localData', {});
                return;
            }

            // skip to a certain lesson. mainly for development use. The lessons build on each other
            // and store variables from previous lessons. Skipping ahead will cause issues.
            if (lowercaseUserInputString.startsWith('startlesson(')) {
                const lessonNumberArray = lowercaseUserInputString.match(/\(([^()]*)\)/);
                const newLessonNumber = parseInt(lessonNumberArray[1], 10);
                startLesson(newLessonNumber);

                // clear the user input
                $userInput.val('');
                return;
            }

            if (lowercaseUserInputString.includes('showanswer()')) {
                // TODO show the answer
            }

            let result = '';
            let error = true;

            const sanityCheckResult = userInputSanityCheck(currentLesson, lowercaseUserInputString)
            result = sanityCheckResult;

            if (sanityCheckResult === true && currentLesson === 1) {
                error = false;
                result = '';

                // move onto the next lesson automatically
                advanceLesson();
            } else if (sanityCheckResult === true){
                const evalResult = await evaluateCode(userInputString);

                // The user input ran successfully, but did it evaluate to the correct answer?
                const checkedResult = checkResult(currentLesson, evalResult);
                result = JSON.stringify(checkedResult.result, undefined, 2);

                if (checkedResult.success === true) {
                    error = false;
                    advanceLesson();
                }
            }

            printResult($userInput, $consolePrompt, error, result);
        }

        // enter the most recent command if the user presses the up arrow
        if (e.key === constants.keyMap.UP) {
            if (mostRecentCommand) {
                $userInput.val(mostRecentCommand);
            }
        };
    });
});