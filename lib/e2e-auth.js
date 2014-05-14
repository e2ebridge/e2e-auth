/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var E2EAuth = function(options){
    this.setOptions(options);
};

E2EAuth.prototype.setOptions = function(options){
    options = options || {};

    this._e2eAuthServerURL = options.e2eAuthServerURL || 'http://localhost:3000';
};

E2EAuth.prototype.getUser = function(token, callback){

    var user = {
        id: 'userId'
    };

    user.is = function(roles, callback){

        // call to e2e-auth-server using token

        callback(null, true);
    };

    callback(null, user);
};

module.exports.E2EAuth = E2EAuth;