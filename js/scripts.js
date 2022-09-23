var $ = require('jquery');
const Buffer = require('safe-buffer').Buffer;
const schnorr = require('bip-schnorr');
const stringUtils = require('./stringUtils');
const constants = require('./constants');
const lessonLogic = require('./lessonLogic');
const validation = require('./validation');

let mostRecentCommand;
let privateKey;
let publicKey;
let message;
let signature;
// For lesson 7
let transaction = lessonLogic.mockTxToSign;

// store the lesson number in local storage so the user can leave and come back
let currentLesson = parseInt(localStorage.getItem('currentLesson'), 10) || 0;
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

    let finalLesson = false;
    // If there is no lesson to show, display the final page
    if (!$('.lesson' + currentLesson).length) {
        $('.final').show();
        finalLesson = true;
    }

    // Progress indicator
    // Do not show it for lesson 0 (welcome page), or the final page
    if (newLessonNumber === 0 || finalLesson === true) {
        $("#lessonNumber").html('');
    } else {
        $("#lessonNumber").html(`${newLessonNumber} / ${validation.totalNumberLessons}`);
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
    const messageBuffer = stringUtils.convertToFixedBuffer(message, 32);

    const schnorrSig = schnorr.sign(privateKeyHex, messageBuffer);
    const schnorrSigHex = schnorrSig.toString('hex');

    // save the signature to local store
    saveToLocalStorage('signature', schnorrSigHex);
    signature = schnorrSigHex;

    return {message: messageString, signature: schnorrSigHex};
}

function verifySignature(aPublicKeyHex, aMessage, aSignature) {
    return lessonLogic.verifySignature(aPublicKeyHex, aMessage, aSignature);
}

function hash(inputString) {
    return lessonLogic.hash(inputString);
}

// The fact that this accepts an address is misleading. Since we can't use 32 byte Schnorr
// friendly keys (see helper method), we just throw away whatever the user provides. The parameter
// is here to make the user feel like they are passing in a pub key, since one is required
// for address creation.
function createAddress(aPublicKey) {
    // TODO can return an error if the user does not provide a public key
    return lessonLogic.createAddress();
}

// This is not actually signing a transaction, but it would be cool to implement in a future version
function signTransaction(privateKeyHex, transactionToSign) {
    transactionToSign.inputs[0].scriptSig = "002093f5ff817f1953be6cc714676b5f9169f1322fa2647053acce88358444ca2fef";
    transactionToSign.inputs[1].scriptSig = "0020fd02d8db5e4ef12b09d5f8f035a4758fa87fe528ed2527d5fe3f5680592ba2e3";

    return {transaction: transactionToSign};
}

async function evaluateCode(userInput, lessonNumber) {
    let returnObject = {
        success: true,
        result: ''
    };

    // If this is not a JavaScript lesson, this is a bitcoin-cli lesson
    if (validation.bitcoinRpcLessons.includes(lessonNumber)) {
        return lessonLogic.evaluateBitcoinRPC(userInput, lessonNumber);
    }

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

// This is the same opening line as 'document ready()'
$(function() {
    // all custom jQuery will go here
    //  .html:              <p id="demo"></p>
    //  .js:                $("#demo").html("Hello, World!");

    // Fill in the JSON for lesson 7
    $("#lesson7UnsignedTx").html(JSON.stringify(lessonLogic.mockTxToSign, null, 2));
    $("#lesson8BroadcastTx").val(`bitcoin-cli sendrawtransaction ${lessonLogic.rawSignedTx}`);

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

                // reset to lesson 0
                currentLesson = 0;
                localStorage.setItem('currentLesson', currentLesson);
                startLesson(currentLesson);

                // clear the user input
                $userInput.val('');

                // clear the rest of the data stored locally
                localStorage.setItem('localData', {});

                // Reset the mock transaction for lesson 7. Can move this into a
                // generalized reset method in case other lesson data needs to be
                // cleaned up
                transaction.inputs[0].scriptSig = "";
                transaction.inputs[1].scriptSig = "";

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

            const sanityCheckResult = validation.userInputSanityCheck(currentLesson, lowercaseUserInputString)
            result = sanityCheckResult;

            // Special case for lesson 0
            if (sanityCheckResult === true && currentLesson === 0) {
                error = false;
                result = '';

                // move onto the next lesson automatically
                advanceLesson();
            } else if (sanityCheckResult === true){
                const evalResult = await evaluateCode(userInputString, currentLesson);

                // The user input ran successfully, but did it evaluate to the correct answer?
                const checkedResult = validation.checkResult(currentLesson, evalResult);
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