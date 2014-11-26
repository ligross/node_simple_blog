var User = require('../models/user');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var VKontakteStrategy = require('passport-vkontakte').Strategy;
var GithubStrategy = require('passport-github').Strategy;
var VKONTAKTE_APP_ID = '4642688';
var VKONTAKTE_APP_SECRET = 'qWooDqcS6PMdCecztxy4';
var GITHUB_CLIENT_ID = 'a97b7d5491640ade32d1';
var GITHUB_CLIENT_SECRET = 'd4df7b9d74f6427119c585e649252165b3a5575e';
var domain = 'localhost:3000';

if (VKONTAKTE_APP_ID === null || VKONTAKTE_APP_SECRET === null) {
    console.error('please set VKONTAKTE_APP_ID and VKONTAKTE_APP_SECRET');
    process.exit(0);
}

passport.use(new GithubStrategy({
        clientID: GITHUB_CLIENT_ID,
        clientSecret: GITHUB_CLIENT_SECRET,
        callbackURL: "http://" + domain + "/auth/github/callback"
    },
    function (accessToken, refreshToken, profile, done) {
        User.findOrCreate({ githubId: profile.id }, {
            username: profile.username,
            email: profile.id + '@example.com',
            password: Math.random() + 'test'
        }, function (err, user) {
            return done(err, user);
        });
    }
));

passport.use('github-authz', new GithubStrategy({
        clientID: GITHUB_CLIENT_ID,
        clientSecret: GITHUB_CLIENT_SECRET,
        callbackURL: "http://" + domain + "/connect/github/callback"
    },
    function (token, tokenSecret, profile, done) {
        User.findOne({'github.id': profile.id}, function (err, account) {
            if (err) {
                return done(err);
            }
            if (account) {
                return done(null, account);
            }
            var account = new User();
            account.github.id = profile.id;
            account.github.username = profile.username;
            return done(null, account);
        });
    }
));

passport.use(new VKontakteStrategy({
        clientID:     VKONTAKTE_APP_ID,
        clientSecret: VKONTAKTE_APP_SECRET,
        callbackURL:  "http://" + domain + "/auth/vk/callback"
    },
    function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ vkontakteId: profile.id }, {
            username: profile.displayName,
            email: profile.id + '@example.com',
            password: Math.random() + 'test'
        }, function (err, user) {
            return done(err, user);
        });
    }
));

passport.use('vk-authz', new VKontakteStrategy({
        clientID: VKONTAKTE_APP_ID,
        clientSecret: VKONTAKTE_APP_SECRET,
        callbackURL: "http://" + domain + "/connect/vk/callback"
    },
    function (token, tokenSecret, profile, done) {
        User.findOne({'vkontakte.id': profile.id}, function (err, account) {
            console.log(profile);
            if (err) {
                return done(err);
            }
            if (account) {
                return done(null, account);
            }
            var account = new User();
            account.vkontakte.id = profile.id;
            account.vkontakte.displayName = profile.displayName;
            return done(null, account);
        });
    }
));

passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    },
    function (email, password, done) {
        User.findOne({email: email}, function (err, user) {
            if (err) {
                return done(err);
            }

            if (!user || !user.comparePassword(password)) {
                return done(null, false, {message: 'Пользователь с такими данными не найден'});
            }
            return done(null, user);
        });
    }
));

passport.serializeUser(function (user, done) {
    done(null, user._id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

module.exports = passport;