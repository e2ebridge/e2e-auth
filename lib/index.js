/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var E2EAuth = require('./e2e-auth').E2EAuth;
var Middleware = require('./middleware').Middleware;

module.exports = new E2EAuth();
module.exports.E2EAuth = E2EAuth;
module.exports.Middleware = Middleware;