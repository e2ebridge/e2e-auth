/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var util = require('util');

var Client = require('node-rest-client').Client;

var E2EAuth = function(options){
    this.setOptions(options);
};

function userIs(user, roles, callback){
    var allowed = false;

    if(!util.isArray(roles)){
        roles = [roles];
    }

    // call to e2e-auth-server using token

    roles.forEach(function(role){
        user.roles.forEach(function(userRole){
            if(role === userRole){
                allowed = true;
            }
        });
    });

    callback(null, allowed);
};

E2EAuth.prototype.setOptions = function(options){
    options = options || {};

    this._e2eAuthServerURL = options.e2eAuthServerURL || 'http://localhost:3000';
    this._authenticationDisabled = false;

    if(options.disableAuth === true) {
        this.mockup = {
            user: {
                disabled: true,
                id: '',
                username: '',
                auth: {
                    name: 'mock',
                    userId: ''
                },
                roles: [],
                is: function(roles, callback){
                    callback(null, true);
                },
                getAccessToken: function(){ return '<empty>' }
            }
        };
        this._authenticationDisabled = true;
    } else if(options.mockup){

        this.mockup = {
            user: {
                id: '',
                username: '',
                auth: {
                    name: 'mock',
                    userId: ''
                },
                roles: [],
                is: function(roles, callback){
                    userIs(this, roles, callback);
                },
                getAccessToken: function(){ return 'mock-token' }
            }
        };

        if(options.mockup.user) {
            this.mockup.user.username = options.mockup.user.username || '';
            this.mockup.user.roles = options.mockup.user.roles || [];
        }
    }
};

E2EAuth.prototype.getUser = function(token, trx, callback){
    var io;

    if(typeof trx === 'function'){
        callback = trx;
        trx = null;
    }

    if(this.mockup){
        return callback(null, this.mockup.user);
    }

    var client = new Client();

    var headers = {
        Authorization : 'Bearer '+token
    };

    if(trx){ io = trx.startIO('GET /api/users/me', 'REST', this._e2eAuthServerURL); }
    client.get(this._e2eAuthServerURL+'/api/users/me', {headers: headers}, function(user, response){
        if(io){ io.end(); }

        if(response.statusCode === 401){
            return callback(null, null);
        }

        if(response.statusCode >= 400 || typeof user !== 'object'){
            return callback(user, null);
        }

        user.getAccessToken = function(){
            return token;
        };

        user.is = function(roles, callback){
            userIs(user, roles, callback);
        };

        callback(null, user);
    }).on('error',function(){
        return callback(null, null);
    });


};

E2EAuth.prototype.disabled = function() {
    return this._authenticationDisabled === true;
};

E2EAuth.prototype.enabled = function() {
    return !this.disabled();
};

module.exports.E2EAuth = E2EAuth;
