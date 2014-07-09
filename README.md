[![E2E logo](README/e2ebridge-logo.png)](http://e2ebridge.com)


# E2E Auth #


Web services always need a way to authenticate users for security reasons. Companies having multiple services and applications accessing these need a central user/role management and a generic way of authentication.

This module works with the E2E Auth Server and provide a simple authentication and authorization process for both resource servers and client applications.

## Installing

    npm install e2e-auth

## Resource Server

    var express = require('express');
    var E2EAuth = require('e2e-auth').Middleware;

    var app = express();

    var e2eAuth = new E2EAuth({
        e2eAuthServerURL: 'http://e2e-auth.example.com'
    });

    app.get('/public', function(req, res){
        ...
    });

    app.get('/private', e2eAuth.userIsAuthenticated(), function(req, res){
        ...
    });

    app.get('/restricted', e2eAuth.userIs('Admin'), function(req, res){
        ...
    });

    app.get('/custom-restriction', e2eAuth.userIsAuthenticated(), function(req, res){
        req.user.is('Custom-Role', function(err, allowed){
            ...
        });
    });


## Client Application

    var express = require('express');
    var bodyParser = require('body-parser');
    var cookieParser = require('cookie-parser');
    var session = require('express-session');
    var Client = require('node-rest-client').Client;

    var E2EAuth = require('e2e-auth').Middleware;

    var app = express();

    var e2eAuth = new E2EAuth({
        e2eAuthServerURL: 'http://e2e-auth.example.com'
        clientID: '{clientID}',
        clientSecret: {clientSecret},
        callbackURL: "http://my-app.example.com/auth/callback"
    });

    // Initial page redirecting to E2E authentication page
    app.get('/login', e2eAuth.authenticate());

    // Callback service parsing the authorization code and asking for the access token
    app.get('/auth/callback',
        e2eAuth.authenticate({ failureRedirect: '/login' }),
        function(req, res) {
            res.redirect('/index.html');
    });

    app.post('/do-something', function(req, res){
        var client = new Client();

        var headers = {
            Authorization : 'Bearer '+ req.session.e2eAccessToken
        };

        client.get('http://resource.example.com/some-resource', {headers: headers}, function(data) {
            ...
        });
    });

## Mock User

During development or tests it can be interesting to mock the user. This is done using the mockup option attribute. If it is defined the user returned is always the one defined in.

    var e2eAuth = new E2EAuth({
        e2eAuthServerURL: 'http://e2e-auth.example.com'
        clientID: '{clientID}',
        clientSecret: {clientSecret},
        callbackURL: "http://my-app.example.com/auth/callback",
        mockup: {
            user:{
                username: 'Mockup User',
                roles: ['Admin']
            }
        }
    });