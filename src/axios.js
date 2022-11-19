module.exports = function (RED) {
    const axios = require("axios");
    const http = require("http");
    const https = require("https");
    const mustache = require("mustache");
    const fs = require("fs");

    var bodyParser = require("body-parser");
    var multer = require("multer");
    var cookieParser = require("cookie-parser");
    var getBody = require('raw-body');
    var cors = require('cors');
    var onHeaders = require('on-headers');
    var typer = require('content-type');
    var mediaTyper = require('media-typer');
    var isUtf8 = require('is-utf8');
    var hashSum = require("hash-sum");

    function EndpointNode(n) {
        RED.nodes.createNode(this, n);
        const node = this;
        node.config = {
            ...n,
        };
    }

    RED.nodes.registerType("axios-endpoint", EndpointNode, {
        credentials: {
            username: { type: "text" },
            password: { type: "password" },
            bearerToken: { type: "password" },
            proxyUsername: { type: "text" },
            proxyPassword: { type: "password" },
        },
    });

    function RequestNode(n) {
        RED.nodes.createNode(this, n);
        const node = this;
        
        var nodeUrl = n.url;
        var isTemplatedUrl = (nodeUrl||"").indexOf("{{") != -1;
        

        // get request endpoint
        const endpoint = RED.nodes.getNode(n.endpoint);

        // http / https agent config
        const agentConfig = {
            keepAlive: n.keepAlive,
            rejectUnauthorized: endpoint.config.rejectUnauthorized,
        };

        // read ca certificate file
        if (endpoint.config.caCertPath) {
            try {
                agentConfig.ca = fs.readFileSync(endpoint.config.caCertPath);
            } catch (err) {
                node.error(new Error("ca cert read error"));
            }
        }

        // axios request base config
        const baseConfig = {
            method: n.method,
            baseURL: endpoint.config.baseURL,
            timeout: n.timeout || 30000,
            responseType: n.responseType,
            httpsAgent: new https.Agent(agentConfig),
            httpAgent: new http.Agent(agentConfig),
            headers: {},
        };

        // request authentication basic
        if (endpoint.credentials.username && endpoint.credentials.password) {
            baseConfig.auth = {
                username: endpoint.credentials.username,
                password: endpoint.credentials.password,
            };
        }

        // request authentication bearer token
        if (endpoint.credentials.bearerToken) {
            baseConfig.headers = {
                ...baseConfig.headers,
                Authorization: `Bearer ${endpoint.credentials.bearerToken}`,
            };
        }

        if (n.validateStatus === false) {
            baseConfig.validateStatus = function (status) {
                return true;
            };
        }

        // proxy config
        if (endpoint.proxyEnabled) {
            baseConfig.proxy = {
                protocol: n.proxyProtocol,
                host: n.proxyHost,
                port: n.proxyPort,
            };

            if (
                endpoint.credentials.proxyUsername &&
                endpoint.credentials.proxyPassword
            ) {
                baseConfig.proxy.auth = {
                    username: endpoint.credentials.proxyUsername,
                    password: endpoint.credentials.proxyPassword,
                };
            }
        }

        // count success and error
        let successCount = 0;
        let errorCount = 0;
        node.status({
            fill: "green",
            shape: "dot",
            text: `success ${successCount}, error ${errorCount}`,
        });

        node.on("input", async function (msg, send, done) {
            try {
                
                var url = "";
                
                if (msg.url) {
                    url = msg.url 
                } else if(isTemplatedUrl) {
                    url = mustache.render(nodeUrl,msg);
                } else {
                    url = nodeUrl
                }

                const config = {
                    ...baseConfig,
                    url: url,
                    headers: {
                        ...baseConfig.headers,
                        ...msg.headers,
                    },
                };

                if (config.method === "get") {
                    // in case of get-method use payload for params
                    config.params = msg.params || msg.payload;
                } else {
                    // in case of other mehthods
                    config.params = msg.params;
                    config.data = msg.payload;
                }

                axios
                    .request(config)
                    .then((response) => {
                        send({
                            ...msg,
                            headers: response.headers,
                            payload: response.data,
                            statusCode: response.status,
                        });

                        successCount++;
                        node.status({
                            fill: "green",
                            shape: "dot",
                            text: `success ${successCount}, error ${errorCount}`,
                        });

                        done();
                    })
                    .catch((err) => {
                        if (err.response) {
                            msg.payload = err.response.data;
                            msg.headers = err.response.headers;
                            msg.statusCode = err.response.status;
                        }
                        
                        errorCount++;
                        node.status({
                            fill: "red",
                            shape: "dot",
                            text: `success ${successCount}, error ${errorCount}`,
                        });
                        
                        done(err);
                    });
            } catch (err) {
                done(err);
            }
        });
    }

    RED.nodes.registerType("axios-request", RequestNode);




    /**
 * Copyright JS Foundation and other contributors, http://js.foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

    

    function rawBodyParser(req, res, next) {
        if (req.skipRawBodyParser) { next(); } // don't parse this if told to skip
        if (req._body) { return next(); }
        req.body = "";
        req._body = true;

        var isText = true;
        var checkUTF = false;

        if (req.headers['content-type']) {
            var contentType = typer.parse(req.headers['content-type'])
            if (contentType.type) {
                var parsedType = mediaTyper.parse(contentType.type);
                if (parsedType.type === "text") {
                    isText = true;
                } else if (parsedType.subtype === "xml" || parsedType.suffix === "xml") {
                    isText = true;
                } else if (parsedType.type !== "application") {
                    isText = false;
                } else if ((parsedType.subtype !== "octet-stream") 
                    && (parsedType.subtype !== "cbor")
                    && (parsedType.subtype !== "x-protobuf")) {
                    checkUTF = true;
                } else {
                    // application/octet-stream or application/cbor
                    isText = false;
                }

            }
        }

        getBody(req, {
            length: req.headers['content-length'],
            encoding: isText ? "utf8" : null
        }, function (err, buf) {
            if (err) { return next(err); }
            if (!isText && checkUTF && isUtf8(buf)) {
                buf = buf.toString()
            }
            req.body = buf;
            next();
        });
    }

    var corsSetup = false;

    function createRequestWrapper(node,req) {
        // This misses a bunch of properties (eg headers). Before we use this function
        // need to ensure it captures everything documented by Express and HTTP modules.
        var wrapper = {
            _req: req
        };
        var toWrap = [
            "param",
            "get",
            "is",
            "acceptsCharset",
            "acceptsLanguage",
            "app",
            "baseUrl",
            "body",
            "cookies",
            "fresh",
            "hostname",
            "ip",
            "ips",
            "originalUrl",
            "params",
            "path",
            "protocol",
            "query",
            "route",
            "secure",
            "signedCookies",
            "stale",
            "subdomains",
            "xhr",
            "socket" // TODO: tidy this up
        ];
        toWrap.forEach(function(f) {
            if (typeof req[f] === "function") {
                wrapper[f] = function() {
                    node.warn(RED._("httpin.errors.deprecated-call",{method:"msg.req."+f}));
                    var result = req[f].apply(req,arguments);
                    if (result === req) {
                        return wrapper;
                    } else {
                        return result;
                    }
                }
            } else {
                wrapper[f] = req[f];
            }
        });


        return wrapper;
    }
    function createResponseWrapper(node,res) {
        var wrapper = {
            _res: res
        };
        var toWrap = [
            "append",
            "attachment",
            "cookie",
            "clearCookie",
            "download",
            "end",
            "format",
            "get",
            "json",
            "jsonp",
            "links",
            "location",
            "redirect",
            "render",
            "send",
            "sendfile",
            "sendFile",
            "sendStatus",
            "set",
            "status",
            "type",
            "vary"
        ];
        toWrap.forEach(function(f) {
            wrapper[f] = function() {
                node.warn(RED._("httpin.errors.deprecated-call",{method:"msg.res."+f}));
                var result = res[f].apply(res,arguments);
                if (result === res) {
                    return wrapper;
                } else {
                    return result;
                }
            }
        });
        return wrapper;
    }

    var corsHandler = function(req,res,next) { next(); }

    if (RED.settings.httpNodeCors) {
        corsHandler = cors(RED.settings.httpNodeCors);
        RED.httpNode.options("*",corsHandler);
    }

    function AxiosHTTPIn(n) {
        RED.nodes.createNode(this,n);
        if (RED.settings.httpNodeRoot !== false) {

            if (!n.url) {
                this.warn(RED._("httpin.errors.missing-path"));
                return;
            }
            this.url = n.url;
            if (this.url[0] !== '/') {
                this.url = '/'+this.url;
            }
            this.method = n.method;
            this.upload = n.upload;
            this.swaggerDoc = n.swaggerDoc;

            var node = this;

            this.errorHandler = function(err,req,res,next) {
                node.warn(err);
                res.sendStatus(500);
            };

            this.callback = function(req,res) {
                var msgid = RED.util.generateId();
                res._msgid = msgid;
                if (node.method.match(/^(post|delete|put|options|patch)$/)) {
                    node.send({_msgid:msgid,req:req,res:createResponseWrapper(node,res),payload:req.body});
                } else if (node.method == "get") {
                    node.send({_msgid:msgid,req:req,res:createResponseWrapper(node,res),payload:req.query});
                } else {
                    node.send({_msgid:msgid,req:req,res:createResponseWrapper(node,res)});
                }
            };

            var httpMiddleware = function(req,res,next) { next(); }

            if (RED.settings.httpNodeMiddleware) {
                if (typeof RED.settings.httpNodeMiddleware === "function" || Array.isArray(RED.settings.httpNodeMiddleware)) {
                    httpMiddleware = RED.settings.httpNodeMiddleware;
                }
            }

            var maxApiRequestSize = RED.settings.apiMaxLength || '5mb';
            var jsonParser = bodyParser.json({limit:maxApiRequestSize});
            var urlencParser = bodyParser.urlencoded({limit:maxApiRequestSize,extended:true});

            var metricsHandler = function(req,res,next) { next(); }
            if (this.metric()) {
                metricsHandler = function(req, res, next) {
                    var startAt = process.hrtime();
                    onHeaders(res, function() {
                        if (res._msgid) {
                            var diff = process.hrtime(startAt);
                            var ms = diff[0] * 1e3 + diff[1] * 1e-6;
                            var metricResponseTime = ms.toFixed(3);
                            var metricContentLength = res.getHeader("content-length");
                            //assuming that _id has been set for res._metrics in HttpOut node!
                            node.metric("response.time.millis", {_msgid:res._msgid} , metricResponseTime);
                            node.metric("response.content-length.bytes", {_msgid:res._msgid} , metricContentLength);
                        }
                    });
                    next();
                };
            }

            var multipartParser = function(req,res,next) { next(); }
            if (this.upload) {
                var mp = multer({ storage: multer.memoryStorage() }).any();
                multipartParser = function(req,res,next) {
                    mp(req,res,function(err) {
                        req._body = true;
                        next(err);
                    })
                };
            }

            if (this.method == "get") {
                RED.httpNode.get(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,this.callback,this.errorHandler);
            } else if (this.method == "post") {
                RED.httpNode.post(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,multipartParser,rawBodyParser,this.callback,this.errorHandler);
            } else if (this.method == "put") {
                RED.httpNode.put(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            } else if (this.method == "patch") {
                RED.httpNode.patch(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            } else if (this.method == "delete") {
                RED.httpNode.delete(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            } else { // ALL
                RED.httpNode.all(this.url,cookieParser(),httpMiddleware,corsHandler,metricsHandler,jsonParser,urlencParser,rawBodyParser,this.callback,this.errorHandler);
            }

            this.on("close",function() {
                var node = this;
                RED.httpNode._router.stack.forEach(function(route,i,routes) {
                    if (route.route && route.route.path === node.url && route.route.methods[node.method]) {
                        routes.splice(i,1);
                    }
                });
            });
        } else {
            this.warn(RED._("httpin.errors.not-created"));
        }
    }
    RED.nodes.registerType("axios-in",AxiosHTTPIn);


    function AxiosHTTPOut(n) {
        RED.nodes.createNode(this,n);
        var node = this;
        this.headers = n.headers||{};
        this.statusCode = parseInt(n.statusCode);
        this.on("input",function(msg,_send,done) {
            if (msg.res) {
                var headers = RED.util.cloneMessage(node.headers);
                if (msg.headers) {
                    if (msg.headers.hasOwnProperty('x-node-red-request-node')) {
                        var headerHash = msg.headers['x-node-red-request-node'];
                        delete msg.headers['x-node-red-request-node'];
                        var hash = hashSum(msg.headers);
                        if (hash === headerHash) {
                            delete msg.headers;
                        }
                    }
                    if (msg.headers) {
                        for (var h in msg.headers) {
                            if (msg.headers.hasOwnProperty(h) && !headers.hasOwnProperty(h)) {
                                headers[h] = msg.headers[h];
                            }
                        }
                    }
                }
                if (Object.keys(headers).length > 0) {
                    msg.res._res.set(headers);
                }
                if (msg.cookies) {
                    for (var name in msg.cookies) {
                        if (msg.cookies.hasOwnProperty(name)) {
                            if (msg.cookies[name] === null || msg.cookies[name].value === null) {
                                if (msg.cookies[name]!==null) {
                                    msg.res._res.clearCookie(name,msg.cookies[name]);
                                } else {
                                    msg.res._res.clearCookie(name);
                                }
                            } else if (typeof msg.cookies[name] === 'object') {
                                msg.res._res.cookie(name,msg.cookies[name].value,msg.cookies[name]);
                            } else {
                                msg.res._res.cookie(name,msg.cookies[name]);
                            }
                        }
                    }
                }
                var statusCode = node.statusCode || parseInt(msg.statusCode) || 200;
                if (typeof msg.payload == "object" && !Buffer.isBuffer(msg.payload)) {
                    msg.res._res.status(statusCode).jsonp(msg.payload);
                } else {
                    if (msg.res._res.get('content-length') == null) {
                        var len;
                        if (msg.payload == null) {
                            len = 0;
                        } else if (Buffer.isBuffer(msg.payload)) {
                            len = msg.payload.length;
                        } else if (typeof msg.payload == "number") {
                            len = Buffer.byteLength(""+msg.payload);
                        } else {
                            len = Buffer.byteLength(msg.payload);
                        }
                        msg.res._res.set('content-length', len);
                    }

                    if (typeof msg.payload === "number") {
                        msg.payload = ""+msg.payload;
                    }
                    msg.res._res.status(statusCode).send(msg.payload);
                }
            } else {
                node.warn(RED._("httpin.errors.no-response"));
            }
            done();
        });
    }
    RED.nodes.registerType("axios-response",AxiosHTTPOut);
};
