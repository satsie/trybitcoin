# Try Bitcoin

Try Bitcoin is an interactive Bitcoin tutorial inspired by and forked from [Try Regex](http://tryregex.com), which is inspired by [Try Ruby](http://tryruby.org/) and [Try Haskell](http://tryhaskell.org/). 

## Warning!

This tutorial asks the user to write JavaScript and it executes the raw input using the [`eval()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval) command. Allowing a user to run arbitrary code is never a good idea. Use at your own risk!

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

- `gulp build`: turn LESS code into CSS, compile all JS with browserify so the browser can access node-flavored commonjs modules, and start. Run [browser-sync](http://browsersync.io/) to watch for any changes to the HTML, CSS, or JS code updates. Compile and inject changes as they're made.
- `gulp lint`: TODO

## License

Try Bitcoin is released under the MIT license.
