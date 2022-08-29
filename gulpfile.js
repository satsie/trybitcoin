const gulp = require('gulp');
const browserify = require('browserify');
const source = require('vinyl-source-stream');
const browserSync = require('browser-sync').create();
const plugins = require('gulp-load-plugins')();
var through = require('through2');

var lessConfig = {
    buildDir: 'build',
    minify: false
};

gulp.task('less', function () {
    return gulp.src('less/main.less')
        .pipe(plugins.less({ compress: true }))
        .on('error', function (err) {
            var parseError = plugins.util.colors.red.bold('Parse error:');
            plugins.util.log(parseError, err.message);
        })
        .pipe(plugins.autoprefixer())
        .pipe(lessConfig.minify ? plugins.minifyCss() : through.obj())
        .pipe(gulp.dest(lessConfig.buildDir))
        .pipe(browserSync.stream());
});

// Browserify basically allows the code to use npm modules
gulp.task('browserify', function() {
    return browserify('js/scripts.js')
        .bundle()
        //Pass desired output filename to vinyl-source-stream
        // This is the file that index.js is looking for
        .pipe(source('build/bundle.js'))
        // Start piping stream to tasks!
        .pipe(gulp.dest('./'))
        .pipe(browserSync.stream());
});

gulp.task('browser-sync', function() {
    browserSync.init({
        server: {
            baseDir: "./"
        }
    });

    gulp.watch("*.html").on("change", browserSync.reload);
    gulp.watch("./js/scripts.js", gulp.series('browserify'));

    // This probabaly doesn't belong in this task?
    gulp.watch('less/*.less', gulp.series('less'));

});

// build and launch the app
gulp.task('dev', gulp.series('less', 'browserify', 'browser-sync'));

// just build
gulp.task('build', gulp.series('less', 'browserify'));
