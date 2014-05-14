/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var Passport = require('passport').Passport;
var Oauth2Strategy = require('passport-oauth2').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var async = require('async');
var http = require('http');

var E2EAuth = require('./e2e-auth').E2EAuth;

var Middleware = exports.Middleware = function(options){
    var self = this;
    var passport = this._passport = new Passport();

    options = options || {};

    var e2eAuthServerURL = options.e2eAuthServerURL || 'http://localhost:3000';

    this._e2eAuth = new E2EAuth({
        e2eAuthServerURL: e2eAuthServerURL
    });

    function verifyOauth2(req, accessToken, refreshToken, params, profile, done){

        self._e2eAuth.getUser(accessToken, function(err, user){
            if(err){
                return done(err);
            }

            if(!user){
                return done(null, false, 'Invalid Credentials');
            }

            if(req.session){
                req.session.e2eAccessToken = accessToken;
            }

            done(null, user);
        });
    }

    passport.use( new Oauth2Strategy({
        authorizationURL: e2eAuthServerURL + '/auth/oauth/auth',
        tokenURL: e2eAuthServerURL + '/auth/oauth/token',
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        passReqToCallback: true,
        skipUserProfile: false
    }, verifyOauth2));

    function verifyBearer(req, accessToken, done){
        self._e2eAuth.getUser(accessToken, function(err, user){
            if(err){
                return done(err);
            }

            if(!user){
                return done(null, false, 'Invalid Credentials');
            }

            req.e2eAccessToken = accessToken;

            done(null, user);
        });
    }

    passport.use( new BearerStrategy({
        passReqToCallback: true
    }, verifyBearer));

    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        done(null, {id: 'userId'});
    });
};

Middleware.prototype.initialize = function(){
    var self = this;
    var initialize = this._passport.initialize();
    var session = this._passport.session();

    return function(req, res, next) {
        async.series([
            function(done){
                initialize(req, res, done);
            },
            function(done){
                session(req, res, done);
            },
            function(done){
                if(req.session && req.session.e2eAccessToken){
                    if(!req.headers){
                        req.headers = {};
                    }

                    req.headers.authorization = 'Bearer ' + req.session.e2eAccessToken;
                }

                done();
            },
            function(done){
                self._passport.authenticate('bearer', function(err, user) {
                    if (err) { return done(err); }
                    if (!user) { return done() }
                    req.logIn(user, function(err) {
                        return done(err);
                    });
                })(req, res, done);
            }
        ], function(err){
            next(err);
        });
    }
};

Middleware.prototype.authenticate = function(options){
    return this._passport.authenticate('oauth2', options);
};

Middleware.prototype.userIs = function(roles, options){
    var userIsAuthenticated = this.userIsAuthenticated(options);

    options = options || {};

    return function(req, res, next){
        async.series([
            function(done){
                userIsAuthenticated(req, res, done);
            },
            function(done){
                req.user.is(roles, function(err, allowed){
                    if(err){
                        done(err);
                    }

                    if(!allowed){
                        if (options.failureRedirect) {
                            return res.redirect(options.failureRedirect);
                        }
                        return res.end(http.STATUS_CODES[403]);
                    }

                    done();
                });
            }
        ],function(err){
            next(err);
        });
    };
};

Middleware.prototype.userIsAuthenticated = function(options){

    options = options || {};

    return function(req, res, next){

        if(!req.user){
            if (options.failureRedirect) {
                return res.redirect(options.failureRedirect);
            }
            return res.end(http.STATUS_CODES[401]);
        }

        next();
    };
};

exports.Middleware = Middleware;