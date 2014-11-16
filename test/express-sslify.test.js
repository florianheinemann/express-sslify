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
				res.send(200, 'ok');
		});

		app.post('/non-ssl-post',
			function(req, res){
				res.send(200, 'ok');
		});

		var agent = request.agent(app);

		it('should accept non-ssl requests', function (done) {
			agent
				.get('/non-ssl')
				.expect(200, 'ok', done);
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
				res.send(200, 'ok');
		});

		app.post('/ssl-post',
			function(req, res){
				res.send(200, 'ok');
		});

		var agent = request.agent(app);

		it('should redirect non-SSL GET requests to HTTPS', function (done) {
			agent
				.get('/ssl')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
		})

		it('should send error for non-SSL POST requests', function (done) {
			agent
				.post('/non-ssl-post')
				.expect(403, done);
		})
	})

	describe('Heroku-style proxy SSL flag', function() {

		var app = express();

		app.get('/ssl', enforce.HTTPS(),
			function(req, res){
				res.send(200, 'ok');
		});

		app.get('/ssl-behind-proxy', enforce.HTTPS(true),
			function(req, res){
				res.send(200, 'ok');
		});

		var agent = request.agent(app);

		it('should ignore x-forwarded-proto if not activated', function (done) {
			agent
				.get('/ssl')
      			.set('x-forwarded-proto', 'https')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
		})

		it('should accept request if flag set and activated', function (done) {
			agent
				.get('/ssl-behind-proxy')
      			.set('x-forwarded-proto', 'https')
				.expect(200, 'ok', done);
		})

		it('should redirect if activated but flag not set', function (done) {
			agent
				.get('/ssl-behind-proxy')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl-behind-proxy$'), done);
		})

		it('should redirect if activated but wrong flag set', function (done) {
			agent
				.get('/ssl-behind-proxy')
      			.set('x-arr-ssl', 'https')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl-behind-proxy$'), done);
		})
	})

	describe('Azure-style proxy SSL flag', function() {

		var app = express();

		app.get('/ssl', enforce.HTTPS(),
			function(req, res){
				res.send(200, 'ok');
		});

		app.get('/ssl-behind-azure', enforce.HTTPS(false, true),
			function(req, res){
				res.send(200, 'ok');
		});

		var agent = request.agent(app);

		it('should ignore x-arr-ssl if not activated', function (done) {
			agent
				.get('/ssl')
      			.set('x-arr-ssl', 'https')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl$'), done);
		})

		it('should accept request if flag set and activated', function (done) {
			agent
				.get('/ssl-behind-azure')
      			.set('x-arr-ssl', 'https')
				.expect(200, 'ok', done);
		})

		it('should redirect if activated but flag not set', function (done) {
			agent
				.get('/ssl-behind-azure')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl-behind-azure$'), done);
		})

		it('should redirect if activated but wrong flag set', function (done) {
			agent
				.get('/ssl-behind-azure')
      			.set('x-forwarded-proto', 'https')
				.expect(301)
				.expect('location', new RegExp('^https://[\\S]*/ssl-behind-azure$'), done);
		})
	})
})