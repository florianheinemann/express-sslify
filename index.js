"use strict";

var defaults = {
	trustProtoHeader: false,
	trustAzureHeader: false
};

/**
 * Apply options
 *
 * @param {Hash} [options]
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
 * @param {Hash} [options]
 * @param {Boolean} [options[trustProtoHeader]=false] - Set to true if the x-forwarded-proto HTTP header should be trusted (e.g. for typical reverse proxy configurations)
 * @param {Boolean} [options[trustAzureHeader]=false] - Set to true if Azure's x-arr-ssl HTTP header should be trusted (only use in Azure environments)
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
			isHttps = ((req.headers["x-forwarded-proto"] || '').substring(0,5) === 'https');
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
				res.redirect(301, "https://" + req.headers.host + req.originalUrl);
			} else {
				res.status(403).send("Please use HTTPS when submitting data to this server.");
			}
		}
	};
};

exports.HTTPS = enforceHTTPS;