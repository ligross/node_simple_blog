var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var mongoose        = require('mongoose');

var routes = require('./routes/index');
var users = require('./routes/users');
var auth = require('./routes/auth');

var app = express();
var redisLib = require('redis');
var redis = redisLib.createClient();
var session = require('express-session');
var flash = require('connect-flash');
var RedisStore = require('connect-redis')(session);
var lifetime = 5 * 24 * 60 * 60 * 1000;
var secret = 'SUCH WOW';
var sessionStore = new RedisStore({
    client: redis,
    ttl   : lifetime / 1000,
    prefix: 'SESSION:'
});

mongoose.connect('mongodb://localhost/node-blog');

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'bower_components')));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser(secret));

app.use(session({
    secret: secret,
    store: sessionStore,
    saveUninitialized: true,
    resave: true,
    cookie: {
        maxAge: lifetime
    }
}));

app.use(flash());

var passport = require('./lib/passport');

app.use(passport.initialize());
app.use(passport.session());

app.use('/', auth(passport));

app.use('/', routes);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});


module.exports = app;
