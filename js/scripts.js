var $ = require('jquery');
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const schnorr = require('bip-schnorr');


String.prototype.hexEncode = function(){
    var hex, i;

    var result = "";
    for (i=0; i<this.length; i++) {
        hex = this.charCodeAt(i).toString(16);
        result += ("000"+hex).slice(-4);
    }

    return result;
}

const keyMap = {
    ENTER: 'Enter',
    LEFT: 37,
    UP: 38,
    RIGHT: 39,
    DOWN: 40,
    L: 76
}

let privateKey;
let publicKey;

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
    if (localData.privateKey) {
        privateKey = localData.privateKey;
    }
    if (localData.publicKey) {
        publicKey = localData.publicKey;
    }
}

// Hide the previous lesson page and show the next one
function startLesson(lessonNumber) {
    console.log('starting lesson ' + lessonNumber);

    // hide the previous lesson
    const previousLesson = lessonNumber - 1;
    $('.lesson' + previousLesson).hide();

    // Show the current lesson
    $('.lesson' + lessonNumber).show();

    // TODO what if there is no lesson? show a 404 page or message?
}

// Increment the current lesson counter, save to local storage, and call
// startLesson() to refresh the lesson page
function advanceLesson() {
    ++currentLesson;
    localStorage.setItem('currentLesson', currentLesson);
    startLesson(currentLesson);
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

function saveToLocalStorage(key, value) {
    localData[key] = value;
    localStorage.setItem('localData', JSON.stringify(localData));
}

function sign(privateKeyHex, messageString) {
    // save the message to local storage
    saveToLocalStorage('message', messageString);

    const hexMessage = messageString.hexEncode();

    // bip-schnorr lib requires the message to be 32 bytes
    const messageBuffer = Buffer.from(hexMessage, 'hex');
    const totalLength = 32;
    const messageBufferPadded = Buffer.concat([messageBuffer], totalLength);

    const schnorrSig = schnorr.sign(privateKey, messageBufferPadded);
    return schnorrSig.toString('hex');
}

function evaluateCode(userInput) {
    // Some protections for running eval()
    if (userInput.indexOf('var') !== -1 || userInput.indexOf('function') !== -1) {
        return 'undefined;' + userInput;
    }

    // TODO error handling. What if user types in something invalid?
    return eval(userInput);
}

// document ready()
$(function() {
    // all custom jQuery will go here
    //  .html:              <p id="demo"></p>
    //  .js:                $("#demo").html("Hello, World!");

    console.log('current lesson: ' + currentLesson);
    if (currentLesson !== 1) {
        // hide lesson 1, which is turned on by default
        $('.lesson1').hide();

        startLesson(currentLesson);
    }

    const $console = $('.console');
    const $consolePrompt = $('.console-prompt');
    const $userInput = $('.console-input');

    // If the user clicks anywhere in the console box, focus the cursor on the input line
    $console.on('click', function (e) {
        $userInput.trigger('focus');
    });

    $userInput.on('keydown', function (e) {
        const userInputString = $('.console-input').val();
        const lowercaseUserInputString = userInputString.toLowerCase();

        if (e.key === keyMap.ENTER) {

            // do nothing if there is no user input
            if (userInputString.length === 0) {
                // window.reset();
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

            if (lowercaseUserInputString.includes('showanswer()')) {
                // TODO show the answer
            }

            // take the user input and dispaly as a label
            $('.prompt-completed').clone()
                .removeClass('prompt-completed')
                .insertBefore($consolePrompt)
                .find('code')
                .text(userInputString);

            // clear the user input
            $userInput.val('');

            let result = '';
            let error = true;

            // check what the user entered. this code will eventually need to route to different lessons
            if (currentLesson === 1) {
                if (lowercaseUserInputString === 'start') {
                    error = false;

                    advanceLesson();
                    // move onto the next lesson automatically. Eventually will want to put a button in place
                } else {
                    result = 'Please type \'start\'';
                }
            } else if (currentLesson === 2) {
                // Some protections against an attack. Need to revist how dangerous running eval() is.
                if (lowercaseUserInputString.includes('generatekeys')) {
                    const evalResult = evaluateCode(userInputString);
                    result = JSON.stringify(evalResult, undefined, 2);
                    error = false;
                    advanceLesson();
                } else {
                    result = 'Please type \'generateKeys()\'';
                }
            } else if (currentLesson === 3) {
                if (lowercaseUserInputString.includes('sign')) {
                    const evalResult = evaluateCode(userInputString);

                    result = JSON.stringify(evalResult.toString('hex'), undefined, 2);
                    error = false;
                    advanceLesson();
                }
            }

            if (error === true) {
                result = '<strong class = "error">' + result + '</strong>';
            }

            // print the result
            $('.prompt-result').clone()
              .removeClass('prompt-result')
              .insertBefore($consolePrompt)
              .find('code')
              [error ? 'html' : 'text'](result);
        }

        if (e.key === keyMap.UP) {
            // TODO look at history if user presses up
        };
    });
});