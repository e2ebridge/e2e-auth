/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var express = require('express');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var E2EAuth = require('e2e-auth').Middleware;

var httpProxy = require('http-proxy');
var proxy = new httpProxy.RoutingProxy();

var e2eAuth = new E2EAuth({
    e2eAuthServerURL: 'http://{hostname}:{port}',
    clientID: '{ClientId}',
    clientSecret: '{ClientSecret}',
    callbackURL: "http://localhost:4000/callback",
    mockup: {
        user:{
            username: 'Mockup User',
            roles: ['Editor']
        }
    }
});


var app = express();

app.use(cookieParser());
app.use(session({secret: 'my secret session key', cookie: { maxAge: 30*60*1000 }}));

app.use(e2eAuth.initialize());

// Initial page redirecting to E2E
app.get('/login', e2eAuth.authenticate());

// Callback service parsing the authorization code and asking for the access token
app.get('/callback',e2eAuth.authenticate(),function(req, res) {
        res.redirect('/index.html');
});


app.get('/logout', e2eAuth.logout());

app.use('/', express['static'](__dirname+'/client'));

app.get('/user', function(req, res){
    if(req.user){
        res.send(JSON.stringify(req.user));
    } else {
        res.send(404);
    }
});

app.use('/api', function(req, res){

    req.headers.authorization = 'Bearer '+ req.session.e2eAccessToken;

    return proxy.proxyRequest(req,res,{
        host: 'localhost',
        port: 4001
    });
});

app.listen(4000);

console.log('Express server started on port 4000');