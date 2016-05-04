express-sslify
==============

This simple module enforces HTTPS connections on any incoming GET and HEAD requests. In case of a non-encrypted HTTP request, express-sslify automatically redirects to an HTTPS address using a 301 permanent redirect. Any other requests (e.g. POST) fail with a 403 error message.

express-sslify also works behind reverse proxies (load balancers) as they are for example used by Heroku and nodejitsu. In such cases, however, the `trustProxy` parameter has to be set (see below)

### Usage

First, install the module:

`$ npm install express-sslify --save`

Afterwards, require the module and *use* the `HTTPS()` method:
```javascript
var express = require('express');
var http = require('http');
var enforce = require('express-sslify');

var app = express();

// Use enforce.HTTPS({ trustProtoHeader: true }) in case you are behind
// a load balancer (e.g. Heroku). See further comments below
app.use(enforce.HTTPS());

http.createServer(app).listen(app.get('port'), function() {
	console.log('Express server listening on port ' + app.get('port'));
});
```

### Reverse Proxies (Heroku, nodejitsu and others)

Heroku, nodejitsu and other hosters often use reverse proxies which offer SSL endpoints but then forward unencrypted HTTP traffic to the website. This makes it difficult to detect if the original request was indeed via HTTPS. Luckily, most reverse proxies set the `x-forwarded-proto` header flag with the original request scheme. express-sslify is ready for such scenarios, but you have to specifically request the evaluation of this flag:

`app.use(enforce.HTTPS({ trustProtoHeader: true }))`

Please do *not* set this flag if you are not behind a proxy that is setting this flag as such flags can be easily spoofed in a direct client/server connection.

### Azure support

Azure has a slightly different way of signaling encrypted connections. To tell express-sslify to look out for Azure's x-arr-ssl header do the following:

`app.use(enforce.HTTPS({ trustAzureHeader: true }))`

Please do *not* set this flag if you are not behind an Azure proxy as this flag can easily be spoofed outside of an Azure environment.

### Custom SSL Port

Specify on which SSL port should connections be redirected by setting `port` in options.

`app.use(enforce.HTTPS({ port: 3001 }))`

This will redirect requests for example from `http://foo.bar:3000/baz` to `https://foo.bar:3001/baz`.


## Tests
Download the whole repository and call:
`$ npm install; npm test`

### Credits and License
express-sslify is licensed under the MIT license. If you'd like to be informed about new projects follow  [@TheSumOfAll](http://twitter.com/TheSumOfAll/).

Copyright (c) 2013-2014 Florian Heinemann
