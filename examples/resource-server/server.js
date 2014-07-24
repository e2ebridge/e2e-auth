/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var express = require('express');
var bodyParser = require('body-parser');

var E2EAuth = require('e2e-auth').Middleware;

var e2eAuth = new E2EAuth({
    e2eAuthServerURL: 'http://{hostname}:{port}',
    mockup: {
        user:{
            username: 'Mockup User',
            roles: ['Editor']           // Change the roles to see the different behaviours
        }
    }
});

var app = express();
app.use(bodyParser());
app.use(e2eAuth.initialize());

var comments = require('./comments');

app.get('/comments',  function(req, res){
    res.send(200, JSON.stringify(comments.getAll()));
});

app.post('/comments', e2eAuth.userIs(['Editor','Author']), function(req, res){
    comments.add(req.body);
    res.send(200);
});

app.delete('/comments/:id', e2eAuth.userIs('Editor'), function(req, res){
    comments.delete(req.params.id);
    res.send(200);
});


app.listen(4001);
console.log('Express server started on port 4001');