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
	      			.set('x-arr-ssl', 'https')
					.expect(301)
					.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
			})

			it('should accept request if flag set and activated (' + method.toUpperCase() + ')', function (done) {
				agent
					[method]('/ssl-behind-azure')
	      			.set('x-arr-ssl', 'https')
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

	describe('Custom SSL Port', function () {

		it('should redirect to specified port', function (done) {
			var app = express();

			app.use(enforce.HTTPS({ port: 3001 }));

			request.agent(app)
				.get('/ssl')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*\:3001/ssl$'), done);
		});
	});

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
