# Try Bitcoin

![tryBitcoinScreenshot](https://user-images.githubusercontent.com/1823216/187526534-136c4540-1efb-438b-b12d-61222aae43bc.png)

[![Build & deploy](https://github.com/satsie/trybitcoin/actions/workflows/s3-deploy.yml/badge.svg)](https://github.com/satsie/trybitcoin/actions/workflows/s3-deploy.yml)

Try Bitcoin is an interactive Bitcoin tutorial inspired by and forked from [Try Regex](http://tryregex.com), which is inspired by [Try Ruby](http://tryruby.org/) and [Try Haskell](http://tryhaskell.org/). 

It illustrates Bitcoin fundamentals using JavaScript and some Bitcoin Core RPC commands. Programming experience is helpful, but not required.

Because this is targeted towards beginners, many low level details like address types, segwit, and fee calculation are not covered. Many of the exercises involve mocked data to some degree. In an effort to not overwhelm the reader, some things have been **extremely simplified**. For example, transaction details such as sequence number have been removed.

This project is not designed to teach exact commands and libraries. Many of the commands you see here are custom to this code base, and will not work quite the same outside of it. This material is intented to help users understand how Bitcoin works, and provide them with the context needed to go a level deeper. After this tutorial, students that wish to continue their Bitcoin journey should feel comfortable enough picking up a  technical book like Mastering Bitcoin or diving into more a comprehensive resource like [Learn Me a Bitcoin](https://learnmeabitcoin.com/).

## Warning!

This tutorial asks the user to write JavaScript and it executes the raw input using the [`eval()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval) command. Allowing a user to run arbitrary code is never a good idea. Use at your own risk!

Along those lines, the code in this project is for educational purposes only. Using any of this code for production, particulary anything that involves cryptographic operations, is not advised.

## Installing

You will need Node (>= 0.9) and npm.

Try Bitcoin uses [gulp](http://gulpjs.com/) for building and other development tools, and [browserify](https://browserify.org/) for package management. 

To install npm and gulp:

```
sudo apt install npm
sudo apt install gulp
```

To initialize the project, run the following:

```
npm install
gulp build
```

## Running

It's static HTML, you don't need anything special to serve the files.

Helpful commands:

- `gulp build`: turn LESS code into CSS, compile all JS with browserify so the browser can access node-flavored commonjs modules.
- `gulp dev`: Build and run the site. Uses [browser-sync](http://browsersync.io/) to watch for any changes to the HTML, CSS, or JS code updates. Compiles and injects changes as they're made.


## License

Try Bitcoin is released under the MIT license.
