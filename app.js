#!/usr/bin/env node

'use strict';

var express = require('express');
var https = require('https')
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var env = require("./helpers/env.js");
var utils = require("./helpers/utils.js");
var moment = require("moment");
var Decimal = require('decimal.js');
var bitcoin = require("bitcoin-core");
var pug = require("pug");
var dbApi = require("./controllers/database");
var momentDurationFormat = require("moment-duration-format");
var baseActionsRouter = require('./routes/router');
var serveStatic = require('serve-static')
var mongoose = require('mongoose')
const cron = require('node-cron')

var app = express();

// set app locals
app.locals.moment = moment;
app.locals.Decimal = Decimal;
app.locals.utils = utils;

var genesisAsset = env.genesisAsset;
if (!(env.genesisAsset)) {
    genesisAsset = "ASSET";
}
app.locals.genesisAsset = genesisAsset;

// view engine setup
app.set('views', path.join(__dirname, 'views'));

// ref: https://blog.stigok.com/post/disable-pug-debug-output-with-expressjs-web-app
app.engine('pug', (path, options, fn) => {
  options.debug = false;
  return pug.__express.call(null, path, options, fn);
});

app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(serveStatic(path.join(__dirname, 'public')))

// connect to mongo db database using mongoose
var dbConnect = 'mongodb://';
if (env.dbsettings.user && env.dbsettings.password) {
    dbConnect += env.dbsettings.user + ':' + env.dbsettings.password
}
dbConnect = dbConnect + '@' + env.dbsettings.address;
dbConnect = dbConnect + ':' + env.dbsettings.port;
dbConnect = dbConnect + '/' + env.dbsettings.database;

mongoose.Promise = Promise

var db = mongoose.connection;
db.on("error", function(err) {
    console.error(err);
    process.exit(1);
});

// connect to MongDB - should automatically try to reconnect if connection fails
mongoose.connect(dbConnect, {
        reconnectTries: Number.MAX_VALUE, // Never stop trying to reconnect
        reconnectInterval: 1000 ,
        useNewUrlParser: true
    }, function(err) {
    if (err) {
        console.error('Unable to connect to database: %s @ %s',
            env.dbsettings.user, dbConnect.split('@')[1]);
        console.error(err);
        process.exit(1);
    }
});

var mainstayConnect = 'https://' + env.attestation.host +
    '/api/v1/latestcommitment?position=' + env.attestation.position;

// Update attestation information once a minute
cron.schedule("* * * * *",()=> {
    dbApi.get_blockchain_info().then(function(info) {
        if (info) {
            global.attestedheight = info.latestAttestedHeight;
            global.attestationtxid = info.latestAttestationTxid;
            https.get(mainstayConnect, function(res) {
                res.setEncoding('utf8');
                res.on('data', function (chunk) {
                    var parsedResponse
                    try {
                        parsedResponse = JSON.parse(chunk)
                        global.attestedhash = parsedResponse["response"]["commitment"]
                        dbApi.get_block_hash(attestedhash).then(function(blockByHash) {
                            if (blockByHash) {
                                global.attestedheight = blockByHash.height
                                global.attestationtxid = parsedResponse["response"]["txid"]
                                info.latestAttestedHeight = global.attestedheight;
                                info.latestAttestationTxid = global.attestationtxid;
                                dbApi.update_blockchain_info(info).then(function(updated) {
                                }).catch(function(err) {
                                    console.log("ERROR: Could not save blockchain info for attestation update " + err);
                                });
                            }
                        }).catch(function(err) {
                            console.log("ERROR ATTESTATION_API: Failed getting block for commitment " + err);
                        });
                    } catch(err) {
                        console.log("ERROR ATTESTATION_API: Failed parsing http response " + err);
                    }
                });
            }).on('error', function(err) {
                console.log("ERROR ATTESTATION_API: Request Failed: " + err);
            }).end();
        }
    }).catch(function(err) {
        console.log("ERROR: Could not get blockchain info to update attestation " + err);
    });
})

app.use(function(req, res, next) {
	res.locals.env = env;
	next();
});

app.use('/', baseActionsRouter);

/// catch 404 and forwarding to error handler
app.use(function(req, res, next) {
	var err = new Error('Not Found');
	err.status = 404;
	next(err);
});

/// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
	app.use(function(err, req, res, next) {
		res.status(err.status || 500);
		res.render('error', {
			message: err.message,
			error: err
		});
	});
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
	res.status(err.status || 500);
	res.render('error', {
		message: "Internal Server Error",
		error: {}
	});
});

module.exports = app;
