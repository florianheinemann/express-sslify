"use strict";

var url = require('url');

var defaults = {
	port: null,
	trustProtoHeader: false,
	trustAzureHeader: false
};

/**
 * Apply options
 *
 * @param {Hash} options
 * @return {Hash}
 * @api private
 */
function applyOptions(options) {
	var settings = {};
	options = options || {};

	for (var option in defaults) {
		settings[option] = options[option] || defaults[option];
	}
	return settings;
}

/**
 * enforceHTTPS
 *
 * @param {Hash} options
 * @param {Number} options[port]
 * @param {Boolean} options[trustProtoHeader]
 * @param {Boolean} options[trustAzureHeader]
 * @api public
 */
var enforceHTTPS = function(options) {
	return function(req, res, next) {
		// Crash on pre-1.0.0-style arguments
		if(typeof options === 'boolean') {
			return next("express-sslify has changed the way how arguments are treated. Please check the readme.");
		}

		options = applyOptions(options);

		// First, check if directly requested via https
		var isHttps = req.secure;

		// Second, if the request headers can be trusted (e.g. because they are send
		// by a proxy), check if x-forward-proto is set to https
		if(!isHttps && options.trustProtoHeader) {
			isHttps = (req.headers["x-forwarded-proto"] === "https");
		}

		// Third, if trustAzureHeader is set, check for Azure's headers
		// indicating a SSL connection
		if(!isHttps && options.trustAzureHeader && req.headers["x-arr-ssl"]) {
			isHttps = true;
		}

		if(isHttps) {
			next();
		} else {
			// Only redirect GET methods
			if(req.method === "GET" || req.method === 'HEAD') {
				var hostname = url.parse('http://' + req.headers.host).hostname;

				var redirectUrl
				if (options.port != null) {
					redirectUrl = "https://" + hostname + ':' + options.port + req.url
				} else {
					redirectUrl = "https://" + hostname + req.url;
				}

				res.redirect(301, redirectUrl);
			} else {
				res.status(403).send("Please use HTTPS when submitting data to this server.");
			}
		}
	};
};

exports.HTTPS = enforceHTTPS;