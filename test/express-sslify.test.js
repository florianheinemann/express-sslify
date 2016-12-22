'use strict';

var expect = require('chai').expect;
var express = require('express');
var request = require('supertest');
var enforce = require('../index.js');

describe('express-sslify', function() {
	describe('HTTPS not enforced', function() {

		var app = express();

		app.get('/non-ssl',
			function(req, res){
				res.status(200).send('ok');
		});

		app.head('/non-ssl-head',
			function(req, res){
				res.status(200).send();
		});

		app.post('/non-ssl-post',
			function(req, res){
				res.status(200).send('ok');
		});

		var agent = request.agent(app);

		it('should accept non-ssl requests', function (done) {
			agent
				.get('/non-ssl')
				.expect(200, 'ok', done);
		})

		it('should accept non-ssl HEAD requests', function (done) {
			agent
				.head('/non-ssl-head')
				.expect(200, done);
		})

		it('should accept non-ssl POST requests', function (done) {
			agent
				.post('/non-ssl-post')
				.expect(200, 'ok', done);
		})
	})

	describe('HTTPS enforced', function() {

		var app = express();

		app.use(enforce.HTTPS());

		app.get('/ssl',
			function(req, res){
				res.status(200).send('ok');
		});

		app.head('/ssl-head',
			function(req, res){
				res.status(200).send();
		});

		app.post('/ssl-post',
			function(req, res){
				res.status(200).send('ok');
		});

		var agent = request.agent(app);

		it('should redirect non-SSL GET requests to HTTPS', function (done) {
			agent
				.get('/ssl')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
		})

		it('should redirect non-SSL HEAD requests to HTTPS', function (done) {
			agent
				.head('/ssl-head')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl-head$'), done);
		})

		it('should send error for non-SSL POST requests', function (done) {
			agent
				.post('/non-ssl-post')
				.expect(403, done);
		})
	})

	describe('Heroku-style proxy SSL flag', function() {

		var proxyTests = function(method) {

			var app = express();

			app[method]('/ssl', enforce.HTTPS(),
				function(req, res){
					res.status(200).send();
			});

			app[method]('/ssl-behind-proxy', enforce.HTTPS({ trustProtoHeader: true }),
				function(req, res){
					res.status(200).send();
			});

			var agent = request.agent(app);

			it('should ignore x-forwarded-proto if not activated (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl')
	      			.set('x-forwarded-proto', 'https')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
			})

			it('should accept request if flag set and activated (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-proxy')
	      			.set('x-forwarded-proto', 'https')
					.expect(200, done);
			})

			it('should accept request if flag set and activated (' + method.toUpperCase() + ') with comma/space separated list', function (done) {
				agent
					[method]('/ssl-behind-proxy')
					.set('x-forwarded-proto', 'https, http')
					.expect(200, done);
			})

			it('should accept request if flag set and activated (' + method.toUpperCase() + ') with comma separated list', function (done) {
				agent
					[method]('/ssl-behind-proxy')
					.set('x-forwarded-proto', 'https,http')
					.expect(200, done);
			})

			it('should redirect if activated but flag not set with https (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-proxy')
					.set('x-forwarded-proto', '')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl-behind-proxy$'), done);
			})

			it('should redirect if activated but flag only set with HTTP (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-proxy')
					.set('x-forwarded-proto', 'http')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl-behind-proxy$'), done);
			})

			it('should redirect if activated but header indicates that first hop was not HTTPS (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-proxy')
					.set('x-forwarded-proto', 'http, https')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl-behind-proxy$'), done);
			})

			it('should redirect if activated but flag not set (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-proxy')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl-behind-proxy$'), done);
			})

			it('should redirect if activated but wrong flag set (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-proxy')
	      			.set('x-arr-ssl', 'https')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl-behind-proxy$'), done);
			})
		}

		// Test GET requests
		proxyTests('get');

		// Test HEAD requests
		proxyTests('head');
	})

	describe('Azure-style proxy SSL flag', function() {

		var proxyTests = function(method) {

			var app = express();

			var xArrSslContent = '2048|128|DC=com, DC=microsoft, DC=corp, DC=redmond, CN=MSIT Machine Auth CA 2|C=US, S=WA, L=Redmond, O=Microsoft, OU=OrganizationName, CN=*.azurewebsites.net';

			app[method]('/ssl', enforce.HTTPS(),
				function(req, res){
					res.status(200).send();
			});

			app[method]('/ssl-behind-azure', enforce.HTTPS({trustAzureHeader: true}),
				function(req, res){
					res.status(200).send();
			});

			var agent = request.agent(app);

			it('should ignore x-arr-ssl if not activated (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl')
	      			.set('x-arr-ssl', xArrSslContent)
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
			})

			it('should accept request if flag set and activated (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-azure')
	      			.set('x-arr-ssl', xArrSslContent)
					.expect(200, done);
			})

			it('should redirect if activated but flag not set (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-azure')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl-behind-azure$'), done);
			})

			it('should redirect if activated but wrong flag set (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-azure')
	      			.set('x-forwarded-proto', 'https')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl-behind-azure$'), done);
			})
		}

		// Test GET requests
		proxyTests('get');

		// Test HEAD requests
		proxyTests('head');
	})

	describe('X-Forwarded-Host redirects', function() {

		var proxyTests = function(method) {

			var app = express();

			var xArrSslContent = '2048|128|DC=com, DC=microsoft, DC=corp, DC=redmond, CN=MSIT Machine Auth CA 2|C=US, S=WA, L=Redmond, O=Microsoft, OU=OrganizationName, CN=*.azurewebsites.net';

			app[method]('/ssl', enforce.HTTPS(),
				function(req, res){
					res.status(200).send();
			});

			app[method]('/ssl-with-redirect-trusted', enforce.HTTPS({trustXForwardedHostHeader: true}),
				function(req, res){
					res.status(200).send();
			});

			var agent = request.agent(app);

			it('should ignore x-forwarded-host if not activated (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl')
	      			.set('x-forwarded-host', 'malicious')
					.expect(301)
					.expect(function(res) {
						if(res.header.location.indexOf('malicious') != -1)
							throw new Error('should not redirect')
					})
					.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
			})

			it('should ignore x-forwarded-host if not set (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-with-redirect-trusted')
					.expect(301)
					.expect(function(res) {
						if(res.header.location.indexOf('localhost') != -1 && res.header.location.indexOf('127.0.0.1') != -1)
							throw new Error('should not redirect')
					})
					.expect('location', new RegExp('^https://[\\S]*/ssl-with-redirect-trusted$'), done);
			})

			it('should redirect if x-forwarded-host and flag is set (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-with-redirect-trusted')
	      			.set('x-forwarded-host', 'newhost123')
					.expect(301)
					.expect(function(res) {
						if(res.header.location.indexOf('newhost123') === -1)
							throw new Error('should redirect')
					})
					.expect('location', new RegExp('^https://[\\S]*/ssl-with-redirect-trusted$'), done);
			})
		}

		// Test GET requests
		proxyTests('get');

		// Test HEAD requests
		proxyTests('head');
	})

	describe('Pre-1.0.0-style arguments', function() {

		var app = express();

		app.get('/ssl', enforce.HTTPS(true),
			function(req, res){
				res.status(200).send('ok');
		});

		var agent = request.agent(app);

		it('should crash', function (done) {
			agent
				.get('/ssl')
      			.set('x-forwarded-proto', 'https')
				.expect(500, done);
		})
	})
})
