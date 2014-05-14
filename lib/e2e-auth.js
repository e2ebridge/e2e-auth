/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var Client = require('node-rest-client').Client;

var E2EAuth = function(options){
    this.setOptions(options);
};

E2EAuth.prototype.setOptions = function(options){
    options = options || {};

    this._e2eAuthServerURL = options.e2eAuthServerURL || 'http://localhost:3000';
};

E2EAuth.prototype.getUser = function(token, callback){

    var client = new Client();

    var headers = {
        Authorization : 'Bearer '+token
    };

    client.get(this._e2eAuthServerURL+'/api/users/me', {headers: headers}, function(user, response){

        user.getAccessToken = function(){
            return token;
        };

        user.is = function(roles, callback){

            // call to e2e-auth-server using token

            var roles = roles.split(' ');
            var allowed = false;

            roles.forEach(function(role){
                user.roles.forEach(function(userRole){
                    if(role === userRole){
                        allowed = true;
                    }
                });
            });

            callback(null, allowed);
        };

        callback(null, user);
    });


};

module.exports.E2EAuth = E2EAuth;