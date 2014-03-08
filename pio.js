
require("require.async")(require);

const ASSERT = require("assert");
const PATH = require("path");
const EVENTS = require("events");
const FS = require("fs-extra");
const Q = require("q");
const URL = require("url");
const COMMANDER = require("commander");
const COLORS = require("colors");
const UUID = require("uuid");
const DNODE = require("dnode");
const DEEPCOPY = require("deepcopy");
const DEEPMERGE = require("deepmerge");
const CRYPTO = require("crypto");
const REQUEST = require("request");
const RSYNC = require("./lib/rsync");
const SSH = require("./lib/ssh");
const SPAWN = require("child_process").spawn;
const DIRSUM = require("dirsum");
const FSWALKER = require("./lib/fswalker");
const JSON_DIFF_PATCH = require("jsondiffpatch");
const EXEC = require("child_process").exec;

COLORS.setTheme({
    error: 'red'
});


var PIO = module.exports = function(seedPath) {
    var self = this;

    var dnodeClient = null;
    var dnodeRemote = null;
    var dnodeTimeout = null;
    var dnodeEvents = new EVENTS.EventEmitter();
    self._dnodeCanConnect = false;
    self._call = function(method, args) {
        if (!self._dnodeCanConnect && method !== "ping") {
            return Q.resolve(null);
        }
        // Close the connection one second after last response if no
        // more requests.
        function startTimeout() {
            if (dnodeTimeout) {
                clearTimeout(dnodeTimeout);
            }
            dnodeTimeout = setTimeout(function() {
                self.shutdown();
            }, 1 * 1000);
        }
        function callRemote() {
            var deferred = Q.defer();
            var stderr = [];
            // NOTE: This collects all errors that happen on all connections
            //       and broadcasts these to all connections. This could be considered a feature
            //       or a bug. We consider it a feature for now as ANY error should stop
            //       the provisioning run.
            var stderrListener = function(data) {
                stderr.push(data);
            }
            dnodeEvents.on("stderr", stderrListener);
            dnodeRemote[method](args, function (errStack, response) {
                dnodeEvents.removeListener("stderr", stderrListener);
                startTimeout();
                if (errStack) {
                    var err = new Error("Got remote error: " + stderr.join(""));
                    err.stack = errStack;
                    return deferred.reject(err);
                }
                return deferred.resolve(response);
            });
            return deferred.promise;
        }
        if (dnodeRemote) {
            if (dnodeTimeout) {
                clearTimeout(dnodeTimeout);
                dnodeTimeout = null;
            }
            return callRemote();
        }
        var deferred = Q.defer();
        dnodeClient = DNODE({
            stdout: function(data) {
                dnodeEvents.emit("stdout", new Buffer(data, "base64"));
                process.stdout.write(new Buffer(data, "base64"));
            },
            stderr: function(data) {
                dnodeEvents.emit("stderr", new Buffer(data, "base64"));
                process.stderr.write(new Buffer(data, "base64"));
            }
        });
        dnodeClient.on("error", function (err) {
            //console.error("dnode error", err.stack);
            return deferred.reject(err);
        });
        // TODO: Handle these failures better?
        dnodeClient.on("fail", function (err) {
            console.error("dnode fail", err.stack);
        });
        dnodeClient.on("remote", function (remote) {
            dnodeRemote = remote;
            return callRemote().then(deferred.resolve).fail(deferred.reject);
        });
        dnodeClient.connect(self._dnodePort, self._dnodeHostname);
        return deferred.promise;
    }
    self.shutdown = function() {
        if (dnodeTimeout) {
            clearTimeout(dnodeTimeout);
            dnodeTimeout = null;
        }
        dnodeRemote = null;
        if (dnodeClient) {
            dnodeClient.end();
            dnodeClient = null;
        }
        return Q.resolve();
    }

    // A hash that is affected by changes in `PIO_SEED_KEY` only.
    self._seedHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.seedId) {
            shasum.update([
                "seed-hash",
                self._config.config.pio.seedId
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (typeof process.env.PIO_SEED_KEY !== "string") {
                ok = false;
                console.error(("'PIO_SEED_KEY' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "seed-hash",
                process.env.PIO_SEED_KEY
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
    }

    // A hash that is affected by changes in `PIO_USER_ID` only.
    self._userHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.userId) {
            shasum.update([
                "user-hash",
                self._config.config.pio.userId
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (typeof process.env.PIO_USER_ID !== "string") {
                ok = false;
                console.error(("'PIO_USER_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "user-hash",
                process.env.PIO_USER_ID
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
    }

    // A hash that is affected by changes in `self._config.config.pio.namespace` only.
    self._codebaseHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.codebaseId) {
            shasum.update([
                "codebase-hash",
                self._config.config.pio.codebaseId
            ].concat(parts).join(":"));
        } else {
            shasum.update([
                "codebase-hash",
                self._config.config.pio.namespace
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
    }

    // A hash that is affected by all properties describing the specific instance
    // we are interacting with as well as `PIO_SEED_KEY`, `PIO_USER_ID` and `PIO_USER_SECRET`.
    self._instanceHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.deployId) {
            shasum.update([
                "instance-hash",
                self._config.config.pio.deployId,
                self._config.config.pio.domain,
                self._config.config.pio.namespace,
                self._config.config.pio.ip
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (typeof process.env.PIO_SEED_KEY !== "string") {
                ok = false;
                console.error(("'PIO_SEED_KEY' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (typeof process.env.PIO_USER_ID !== "string") {
                ok = false;
                console.error(("'PIO_USER_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (typeof process.env.PIO_USER_SECRET !== "string") {
                ok = false;
                console.error(("'PIO_USER_SECRET' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "instance-hash",
                process.env.PIO_SEED_KEY,
                process.env.PIO_USER_ID,
                process.env.PIO_USER_SECRET,
                self._config.config.pio.domain,
                self._config.config.pio.namespace,
                self._config.config.pio.ip
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
    }

    self._testDnodeConnect = function() {
        var self = this;
        if (!self._dnodeHostname || !self._dnodePort) {
            return Q.resolve(false);
        }
        var deferred = Q.defer();
        var timeout = setTimeout(function() {
            console.error("Timeout! Could not connect to: dnode://" + self._dnodeHostname + ":" + self._dnodePort);
            self._dnodeCanConnect = false;
            return deferred.resolve(false);
        }, 1000);
        var req = {
            timeClient: Date.now()
        }
        self._call("ping", req).then(function(res) {
            try {
                ASSERT.equal(req.timeClient, res.timeClient);
                // TODO: Track time offset.
                clearTimeout(timeout);
                self._dnodeCanConnect = true;
                return deferred.resolve(true);
            } catch(err) {
                clearTimeout(timeout);
                self._dnodeCanConnect = false;
                return deferred.resolve(false);
            }
        }).fail(function(err) {
            clearTimeout(timeout);
            self._dnodeCanConnect = false;
            return deferred.resolve(false);
        });
        return deferred.promise;
    }

    self._load = function() {
        return Q.fcall(function() {

            try {
                if (!FS.existsSync("/etc/machine-id")) {
                    var machineId = UUID.v4();
                    FS.outputFileSync("/etc/machine-id", machineId);
                    console.log(("Setting '/etc/machine-id' to '" + machineId + "'").magenta);
                } else {
                    // TODO: Load /etc/machine-id for insertion into RT info.
                }
            } catch(err) {
                if (err.code === "EACCES") {
                    // We ignore the absence of /etc/machine-id here as we cannot silently fix it.
                } else {
                    throw err;
                }
            }

            function resolveUri(uri) {
                var deferred = Q.defer();
                try {

                    ASSERT.equal(typeof uri, "string");

                    var uriParsed = URL.parse(uri);

                    if (/^dnodes?:$/.test(uriParsed.protocol)) {

                        self._dnodeHostname = uriParsed.hostname;
                        self._dnodePort = parseInt(uriParsed.port) || 8066;

                        return  self._testDnodeConnect().then(deferred.resolve).fail(deferred.reject);
    /*
    // TODO: Refine this.
                    } else
                    if (/^https?:$/.test(uriParsed.protocol)) {
                        REQUEST({
                            uri: uriParsed,
                            method: "GET",
                            json: true
                        }, function(err, res, body) {
                            if (err) return deferred.reject(err);
                            if (body.$schema === "http://schema.pinf.org/strawman/well-known.schema") {

                                ASSERT.equal(typeof body.services, "object");
                                ASSERT.equal(typeof body.services.pio, "string");

                                return resolveUri(body.services.pio).then(deferred.resolve, deferred.reject);
                            } else {
                                throw new Error("Unsupported schema '" + body.$schema + "'!");
                            }
                        });
    */
                    } else {
                        throw new Error("Unsupported protocol '" + uriParsed.protocol + "'!");
                    }
                } catch(err) {
                    return deferred.reject(err);
                }
                return deferred.promise;
            }
            function loadConfig(path) {
                // TODO: Use more generic PINF-based config loader here.
//                console.log("Using config:", path);
                return Q.denodeify(FS.readJson)(path).then(function(config) {
                    self._configPath = path;
                    self._config = config;

                    function verify() {
                        ASSERT.equal(typeof self._config.uuid, "string", "'uuid' must be set in '" + path + "' Here is a new one if you need one: " + UUID.v4());
                        ASSERT.equal(typeof self._config.config.pio.domain, "string", "'config.pio.domain' must be set in: " + path);
                        ASSERT.equal(typeof self._config.config.pio.namespace, "string", "'config.pio.namespace' must be set in: " + path);
                        ASSERT.equal(typeof self._config.config.pio.ip, "string", "'config.pio.ip' must be set in: " + path);
                    }

                    if (/\/\.pio\.json$/.test(path)) {
                        console.log("Skip loading profile as we are using a consolidated pio descriptor (" + path + ").");
                        verify();
                        ASSERT.equal(typeof self._config.config.pio.seedId, "string", "'config.pio.seedId' must be set in: " + path);
                        ASSERT.equal(typeof self._config.config.pio.dataId, "string", "'config.pio.dataId' must be set in: " + path);
                        ASSERT.equal(typeof self._config.config.pio.codebaseId, "string", "'config.pio.codebaseId' must be set in: " + path);
                        ASSERT.equal(typeof self._config.config.pio.userId, "string", "'config.pio.userId' must be set in: " + path);
                        ASSERT.equal(typeof self._config.config.pio.deployId, "string", "'config.pio.deployId' must be set in: " + path);
                        ASSERT.equal(typeof self._config.config.pio.hostname, "string", "'config.pio.hostname' must be set in: " + path);
                        return;
                    }
                    path = PATH.join(path, "..", "pio." + self._config.config.pio.profile + ".json");
//                    console.log("Using profile:", path);
                    return Q.denodeify(FS.readJson)(path).then(function(profile) {

                        self._config = DEEPMERGE(self._config, profile);
    /*
                        for (var key in self._config) {
                            if (/^config\[cloud=.+\]$/.test(key)) {
                                delete self._config[key];
                            }
                        }
    */
                        verify();

                        self._config.config.pio.seedIdSegmentPrefix = self._config.config.pio.seedIdSegmentPrefix || "s";
                        self._config.config.pio.codebaseIdSegmentPrefix = self._config.config.pio.codebaseIdSegmentPrefix || "c";
                        self._config.config.pio.userIdSegmentPrefix = self._config.config.pio.userIdSegmentPrefix || "u";
                        self._config.config.pio.deployIdSegmentPrefix = self._config.config.pio.deployIdSegmentPrefix || "d";
                        self._config.config.pio.glimpseLength = self._config.config.pio.glimpseLength || 7;

                        // WARNING: DO NOT MODIFY THIS! IF MODIFIED IT WILL BREAK COMPATIBILITY WITH ADDRESSING
                        //          EXISTING DEPLOYMENTS!
                        self._config.config.pio.seedId = self._seedHash(["seed-id"]);
                        var seedIdSegment =
                            self._config.config.pio.seedIdSegmentPrefix +
                            self._config.config.pio.seedId.substring(
                                0,
                                0 + self._config.config.pio.glimpseLength
                            );
                        self._config.config.pio.seedId = [
                            seedIdSegment,
                            self._config.config.pio.seedId.substring(
                                seedIdSegment.length
                            )
                        ].join("-").substring(0, 40);

                        // Use this to derive data namespaces. They will survive multiple deployments.
                        self._config.config.pio.dataId = [
                            // We prefix the seedId so we can group multiple data IDs per seed ID.
                            seedIdSegment,
                            self._seedHash(["data-id", self._config.config.pio.seedId]).substring(
                                seedIdSegment.length
                            )
                        ].join("-");

                        // Use this to derive orchestration and tooling namespaces. They are tied to the codebase uuid.
                        self._config.config.pio.codebaseId = self._codebaseHash([
                            "codebase-id",
                            self._config.uuid
                        ]);
                        var codebaseSegment =
                            self._config.config.pio.codebaseIdSegmentPrefix +
                            self._config.config.pio.codebaseId.substring(
                                seedIdSegment.length,
                                seedIdSegment.length + self._config.config.pio.glimpseLength
                            );
                        self._config.config.pio.codebaseId = [
                            // We prefix the seedIdSegment so we can group multiple codebase IDs per seed ID.
                            seedIdSegment,
                            codebaseSegment,
                            self._config.config.pio.codebaseId.substring(
                                seedIdSegment.length + codebaseSegment.length
                            )
                        ].join("-").substring(0, 40);

                        // Use this to derive data namespaces for users of the codebase that can create multiple instances.
                        self._config.config.pio.userId = self._userHash(["user-id"]);
                        var userSegment = 
                            self._config.config.pio.userIdSegmentPrefix +
                            self._config.config.pio.userId.substring(
                                seedIdSegment.length + codebaseSegment.length,
                                seedIdSegment.length + codebaseSegment.length + self._config.config.pio.glimpseLength
                            );
                        self._config.config.pio.userId = [
                            // We prefix the seedIdSegment so we can group multiple user IDs per seed ID.
                            seedIdSegment,
                            // We insert the codebaseSegment so we can group multiple user IDs per codebase ID.
                            codebaseSegment,
                            userSegment,
                            self._config.config.pio.userId.substring(
                                seedIdSegment.length + codebaseSegment.length
                            )
                        ].join("-").substring(0, 40);

                        // Use this to derive provisioning and runtime namespaces. They will change with every new IP.
                        self._config.config.pio.deployId = self._instanceHash([
                            "deployment-id",
                            self._config.config.pio.dataId,
                            self._config.config.pio.codebaseId,
                            self._config.config.pio.userId
                        ]);
                        var deploySegment =
                            self._config.config.pio.deployIdSegmentPrefix +
                            self._config.config.pio.deployId.substring(
                                seedIdSegment.length + codebaseSegment.length,
                                seedIdSegment.length + codebaseSegment.length + self._config.config.pio.glimpseLength
                        );
                        self._config.config.pio.deployId = [
                            // We prefix the seedIdSegment so we can group multiple deploy IDs per seed ID.
                            seedIdSegment,
                            // We insert the codebaseSegment so we can group multiple deploy IDs per codebase ID.
                            codebaseSegment,
                            deploySegment,
                            self._config.config.pio.deployId.substring(
                                seedIdSegment.length + codebaseSegment.length + deploySegment.length
                            )
                        ].join("-").substring(0, 40);


                        self._config.config.pio.hostname = [
                            self._config.config.pio.namespace,
                            "-",
                            deploySegment,
                            ".",
                            self._config.config.pio.domain
                        ].join("");

// TODO: Use `dnodes://`
                        return resolveUri("dnode://" + self._config.config.pio.ip + ":8066");
                    });
                });
            }
            return Q.denodeify(function(callback) {
                if (process.env.PIO_CONFIG_PATH) {
                    return loadConfig(process.env.PIO_CONFIG_PATH).then(function() {
                        return callback(null);
                    }).fail(callback);
                }
                return FS.exists(PATH.join(seedPath, "pio.json"), function(exists) {
                    if (exists) {
                        return loadConfig(PATH.join(seedPath, "pio.json")).then(function() {
                            return callback(null);
                        }).fail(callback);
                    }
                    return loadConfig(PATH.join(seedPath, ".pio.json")).then(function() {
                        return callback(null);
                    }).fail(callback);
                });
            })();
        });
    }

    self._ready = self._load();
}

PIO.prototype.ready = function() {
    return this._ready;
}

PIO.prototype.getConfig = function(selector) {
    if (typeof selector === "string") {
        return this._config[selector];
    }
    throw new Error("NYI");
}

PIO.prototype.updateConfig = function(selector, value) {
    var self = this;
    if (selector === "config.pio.ip") {
        return Q.denodeify(FS.readJson)(self._configPath).then(function(config) {
            config.config.pio.ip = value;
            return Q.denodeify(FS.outputFile)(self._configPath, JSON.stringify(config, null, 4));
        }).then(function() {
            return self._ready = self._load();
        });
    }
    throw new Error("NYI");
}

PIO.prototype.status = function() {
    var self = this;
    return self._ready.then(function() {
        return self._call("status", {});
    });
}

PIO.prototype.list = function() {
    var self = this;
    return self._ready.then(function() {
        var services = [];
        for (var serviceAlias in self._config.provides) {
            services.push({
                alias: serviceAlias
            });
        }
        return services;
//        return self._call("list", {});
    });
}

PIO.prototype._provisionPrerequisites = function(options) {
    var self = this;
    options = options || {};
    console.log("Provisioning PIO prerequisites on VM".magenta);
    // We also re-try a few times in case SSH is not yet available.
    function attempt(count) {
        count += 1;
        var hostname = options.ip || self._config.config.pio.ip || options.hostname || self._config.config.pio.hostname;
        return SSH.runRemoteCommands({
            targetUser: self._config.config.pio.user,
            targetHostname: hostname,
            commands: [
                // Make sure our user can write to the default install directory.
                "sudo chown -f " + self._config.config.pio.user + ":" + self._config.config.pio.user + " /opt",
                // Make sure some default directories exist
                'if [ ! -d "/opt/bin" ]; then mkdir /opt/bin; fi',
                'if [ ! -d "/opt/cache" ]; then mkdir /opt/cache; fi',
                'if [ ! -d "/opt/log" ]; then mkdir /opt/log; fi',
                // Put `/opt/bin` onto system-wide PATH.
                'sudo touch /etc/profile.d/pio.sh',
                "sudo chown -f " + self._config.config.pio.user + ":" + self._config.config.pio.user + " /etc/profile.d/pio.sh",
                'echo "export PATH=/opt/bin:\\$PATH" > /etc/profile.d/pio.sh',
                'sudo chown root:root /etc/profile.d/pio.sh',
                'if [ ! -f "/opt/bin/activate.sh" ]; then',
                '  echo "#!/bin/sh -e\nexport PATH=/opt/bin:$PATH\n" > /opt/bin/activate.sh',
                'fi'
            ],
            workingDirectory: "/",
            keyPath: self._config.config.pio.keyPath
        }).fail(function(err) {
            if (
                /Connection refused/.test(err.message) ||
                /Operation timed out/.test(err.message)
            ) {
                if (count >= 30) {
                    throw new Error("Stopping after " + count + " attempts! Cannot connect to IP: " + hostname);
                }
                console.log("Trying again in 3 seconds ...");
                var deferred = Q.defer();
                setTimeout(function() {
                    return attempt(count).then(deferred.resolve).fail(deferred.reject);
                }, 3000);
                return deferred.promise;
            }
            throw err;
        });
    }
    return attempt(0);
}

PIO.prototype._deployBootServices = function(options) {
    var self = this;
    console.log(("VM login:", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=" + self._config.config.pio.keyPath + " " + self._config.config.pio.user + "@" + self._config.config.pio.ip).bold);
    console.log("Deploying services sequentially according to 'boot' order:".cyan);
    var done = Q.resolve();
    self._config.boot.forEach(function(serviceAlias) {
        done = Q.when(done, function() {
            return self.deploy(serviceAlias, options).then(function() {
                if (!self._dnodeCanConnect) {
                    return self._testDnodeConnect().then(function(canConnect) {
                        if (canConnect) {
                            console.log("Switching to using dnode transport where possible!".green);
                        }
                    });
                }
            });
        });
    });
    return done;
}

PIO.prototype._normalizeServiceConfig = function(serviceAlias) {
    var self = this;
    return self._ready.then(function() {
        if (!self._config.provides || !self._config.provides[serviceAlias]) {
            throw ("Service with alias '" + serviceAlias + "' not found in 'pio.json ~ provides[" + serviceAlias + "]'!");
        }
        var serviceConfig = DEEPCOPY(self._config.provides[serviceAlias]);

        serviceConfig.config = serviceConfig.config || {};
        // We only carry forward our OWN config. We should not carry forward the config of other services.
        serviceConfig.config.pio = DEEPMERGE(self._config.config.pio, serviceConfig.config.pio || {});

        serviceConfig.config.pio.alias = serviceAlias;

        if (!serviceConfig.env) {
            serviceConfig.env = serviceConfig.env || {};
        }
        // TODO: Pass these along in a backchannel unless declared in config.
        // TODO: Make env propagation more generic using new config module.
        if (serviceConfig.env.AWS_ACCESS_KEY === "$AWS_ACCESS_KEY") {
            serviceConfig.env.AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY;
        }
        if (serviceConfig.env.AWS_SECRET_KEY === "$AWS_SECRET_KEY") {
            serviceConfig.env.AWS_SECRET_KEY = process.env.AWS_SECRET_KEY;
        }
        serviceConfig.env.PATH = serviceConfig.env.PATH || "/opt/bin:$PATH";

        serviceConfig.env.PIO_ALIAS = serviceConfig.config.pio.alias;
        serviceConfig.env.PIO_LOG_BASE_PATH = PATH.join(serviceConfig.config.pio.deployBasePath, "log", serviceConfig.env.PIO_ALIAS);
        serviceConfig.env.PIO_RUN_BASE_PATH = PATH.join("/var/run", serviceConfig.env.PIO_ALIAS);


        ASSERT.equal(typeof serviceConfig.config.pio.alias, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.hostname, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.ip, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.keyPath, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.user, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.projectsPath, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.deployBasePath, "string");

        // Update service config to be relevant in new context.
        var serviceConfigStr = JSON.stringify(serviceConfig);
        serviceConfigStr = serviceConfigStr.replace(/\{\{config.pio\.hostname\}\}/g, serviceConfig.config.pio.hostname);
//        serviceConfigStr = serviceConfigStr.replace(/\{\{config.pio\.glimpse\}\}/g, serviceConfig.config.pio.glimpse);
        serviceConfig = JSON.parse(serviceConfigStr);

        //-----
        // WARNING: This is something that is going to impact a lot once decided upon.
        // TODO: Not to sure about this. Should use JS expressions that operate on JSON above itself?
        //       If so only with restricted capabilities. But config for different environments
        //       should come from *profiles* and config inheritance and package mappings and mapping overlays
        //       should be used to eliminate different content sections.
        serviceConfig.config = DEEPMERGE(serviceConfig.config || {}, serviceConfig["config[live]"] || {});
        delete serviceConfig["config[live]"];
        serviceConfig.config = DEEPMERGE(serviceConfig.config || {}, serviceConfig["config[cloud=" + self._config.cloud + "]"] || {});
        for (var key in serviceConfig.config) {
            if (/^config\[cloud=.+\]$/.test(key)) {
                delete serviceConfig[key];
            }
        }
        serviceConfig.config = DEEPMERGE(serviceConfig.config || {}, serviceConfig["config[" + self._config.config.pio.hostname + "]"] || {});
        delete serviceConfig["config[" + self._config.config.pio.hostname + "]"];
        //-----

        if (serviceConfig.config.pio.seedPath) {
            serviceConfig.config.pio.seedPath = PATH.join(self._configPath, "..", serviceConfig.config.pio.seedPath);
        } else {
            serviceConfig.config.pio.seedPath = PATH.join(self._configPath, "..", serviceConfig.config.pio.projectsPath, serviceAlias);
        }
        if (!FS.existsSync(serviceConfig.config.pio.seedPath)) throw new Error("Source path '" + serviceConfig.config.pio.seedPath + "' does not exist!");
        delete serviceConfig.config.pio.projectsPath;

        if (serviceConfig.config.pio.deployPath) {
            serviceConfig.config.pio.deployPath = serviceConfig.config.pio.deployPath;
        } else {
            serviceConfig.config.pio.deployPath = PATH.join(serviceConfig.config.pio.deployBasePath, serviceAlias);
        }

        // The unique universal identifier for the service (codebase + instance)
        // POLICY: The same `uuid` must be used for the same service on each vm in a cluster.
        serviceConfig.uuid = self._instanceHash(["uuid", serviceAlias]);

        return serviceConfig;
    });
}


PIO.prototype.deploy = function(serviceAlias, options) {
    var self = this;

    if (!serviceAlias) {
        // Deploy all services.

        return self._ready.then(function() {

            var services = Object.keys(self._config.provides);

            return Q.when(self._deployBootServices(options), function() {

                // TODO: Deploy in parallel by default if nothing has changed.
                console.log("Deploying remaining services sequentially:".cyan);

                var done = Q.resolve();
                Object.keys(self._config.provides).forEach(function(serviceAlias) {
                    if (self._config.boot.indexOf(serviceAlias) !== -1) {
                        return;
                    }
                    done = Q.when(done, function() {
                        return self.deploy(serviceAlias, options);
                    });
                });
                return done;
            });
        });
    }

    // TODO: Only deploy if source has changed (call server to check hash)
    //       or if force is set.
    return self._normalizeServiceConfig(serviceAlias).then(function(serviceConfig) {

        if (serviceConfig.enabled === false) {
            console.log(("Skip deploy service '" + serviceAlias + "'. It is disabled!").yellow);
            return;
        }

        var previoussyncFiletreeInfoPath = PATH.join(serviceConfig.config.pio.seedPath, ".pio.sync");
        var syncFiletreeInfo = null;
        function hasChanged() {
//            console.log("Check if changed");
            function loadPreviousSyncFiletreeInfo() {
                var deferred = Q.defer();
                FS.exists(previoussyncFiletreeInfoPath, function(exists) {
                    if (!exists) return deferred.resolve(null);
                    return FS.readJson(previoussyncFiletreeInfoPath, function(err, json) {
                        if (err) return deferred.reject(err);
                        return deferred.resolve(json);
                    });
                });
                return deferred.promise;
            }
            return loadPreviousSyncFiletreeInfo().then(function(previousSyncFiletreeInfo) {
                var walker = new FSWALKER.Walker(serviceConfig.config.pio.seedPath);
                var opts = {};
                opts.returnIgnoredFiles = true;
                opts.includeDependencies = false;
                opts.respectDistignore = false;
                opts.respectNestedIgnore = true;
                return Q.nbind(walker.walk, walker)(opts).then(function(list) {
                    syncFiletreeInfo = list;
                    var shasum = CRYPTO.createHash("sha1");
                    shasum.update(JSON.stringify(syncFiletreeInfo[0]));
                    var seedHash = shasum.digest("hex");
                    serviceConfig.config.pio.seedHash = seedHash;
//                    console.log("Our seed hash: " + serviceConfig.config.pio.seedHash);
                    return self._call("status", {
                        deployPath: serviceConfig.config.pio.deployPath
                    }).then(function(status) {
                        if (!status || !status.config || !status.config.pio || !status.config.pio.seedHash) {
                            console.log("No remote seed hash!");
                            return seedHash;
                        }
//                        console.log("Remote seed hash: " + status.config.pio.seedHash);
                        if (status.config.pio.seedHash !== seedHash) {
                            console.log("Seed hash has changed!".cyan);
                            if (previousSyncFiletreeInfo) {
                                console.log(
                                    JSON_DIFF_PATCH.formatters.console.format(
                                        JSON_DIFF_PATCH.create({
                                            // @source https://github.com/benjamine/jsondiffpatch/issues/21#issuecomment-23892647
                                            objectHash: function(obj) {
                                                var hash = [];
                                                for (var prop in obj) {
                                                    if (obj.hasOwnProperty(prop)) {
                                                        hash.push(prop);
                                                    }
                                                }
                                                return hash.sort().join('');
                                            }
                                        }).diff(list, previousSyncFiletreeInfo)
                                    )
                                );
                            }
                            return seedHash;
                        }
                        return false;
                    }).fail(function(err) {
                        console.error("Ignoring status check error:", err.stack);
                        return seedHash;
                    });
                });
            });
        }

        return hasChanged().then(function(deploy) {
            if (!deploy) {
                if (options.force) {
                    console.log(("Skip deploy service '" + serviceAlias + "'. It has not changed. BUT CONTINUE due to FORCE").yellow);
                } else {
                    console.log(("Skip deploy service '" + serviceAlias + "'. It has not changed.").yellow);
                    return;
                }
            }
            function readDescriptor() {
                var path = PATH.join(serviceConfig.config.pio.seedPath, "package.json");
                return Q.denodeify(function(callback) {
                    return FS.exists(path, function(exists) {
                        if (!exists) return callback(null, null);
                        return FS.readJson(path, callback);
                    });
                })();
            }
            return readDescriptor().then(function(descriptor) {
                if (descriptor) {
                     serviceConfig = DEEPMERGE(DEEPCOPY(descriptor), DEEPCOPY(serviceConfig));
                }

                console.log(("Deploy service '" + serviceAlias + "' with config: " + JSON.stringify(serviceConfig, null, 4)).cyan);

                return Q.denodeify(FS.outputFile)(PATH.join(serviceConfig.config.pio.seedPath, ".pio.json"), JSON.stringify(serviceConfig, null, 4)).then(function() {

                    return Q.fcall(function() {
                        if (serviceConfig.config && serviceConfig.config["pio.deploy.converter"]) {
                            return Q.denodeify(function(callback) {                        
                                return require.async("../pio.deploy.converter", function(api) {
                                    try {
                                        return api.convert(self, serviceConfig).then(function(serviceConfig) {
                                            return callback(null, serviceConfig);
                                        }).fail(callback);
                                    } catch(err) {
                                        return callback(err);
                                    }
                                }, callback);
                            })();
                        }
                        return serviceConfig;
                    }).then(function(serviceConfig) {

                        var deployScriptPath = PATH.join(serviceConfig.config.pio.seedPath, "deploy.sh");

                        function callDeployScript() {
                            return Q.denodeify(function(callback) {
                                var env = {
                                    PATH: process.env.PATH,
                                    HOME: process.env.HOME
                                };
                                if (options.force) {
                                    env.PIO_FORCE = options.force;
                                }
                                var proc = SPAWN("sh", [
                                    deployScriptPath
                                ], {
                                    cwd: serviceConfig.config.pio.seedPath,
                                    env: env
                                });
                                proc.stdout.on('data', function (data) {
                                    process.stdout.write(data);
                                });
                                var stderr = [];
                                proc.stderr.on('data', function (data) {
                                    stderr.push(data.toString());
                                    process.stderr.write(data);
                                });
                                proc.on('close', function (code) {
                                    if (code !== 0) {
                                        console.error("ERROR: Deploy script exited with code '" + code + "'");
                                        return callback(new Error("Deploy script exited with code '" + code + "' and stderr: " + stderr.join("")));
                                    }
                                    return callback(null);
                                });
                            })();
                        }

                        return Q.denodeify(function(callback) {
                            return FS.exists(deployScriptPath, function(exists) {
                                if (exists) {
                                    return callDeployScript().then(function() {
                                        return callback(null);
                                    }).fail(callback);
                                }

                                function defaultDeployPlugin(pio, serviceConfig) {

                                    function uploadSource(targetPath, source) {
                                        return self._call("_putFile", {
                                            path: targetPath,
                                            body: source
                                        }).then(function(response) {
                                            if (response === true) return;
                                            return SSH.uploadFile({
                                                targetUser: serviceConfig.config.pio.user,
                                                targetHostname: serviceConfig.config.pio.ip,
                                                source: source,
                                                targetPath: targetPath,
                                                keyPath: serviceConfig.config.pio.keyPath
                                            });
                                        });
                                    }

                                    function runRemoteCommands(commands, workingDirectory) {
                                        function sshUpload() {
                                            return SSH.runRemoteCommands({
                                                targetUser: serviceConfig.config.pio.user,
                                                targetHostname: serviceConfig.config.pio.ip,
                                                commands: commands,
                                                workingDirectory: workingDirectory,
                                                keyPath: serviceConfig.config.pio.keyPath
                                            });
                                        }
                                        // NOTE: If deploying the `pio.deploy.server` which handles
                                        //       the `_runCommands` call we always use SSH to run the commands.
                                        //       If we do not do that our commands will exit early as the
                                        //       `pio.deploy.server` restarts.
                                        if (serviceAlias === "pio.deploy.server") {
                                            return sshUpload();
                                        }
                                        return self._call("_runCommands", {
                                            commands: commands,
                                            cwd: workingDirectory
                                        }).then(function(code) {
                                            if (code !== null) {
                                                if (code === 0) return;
                                                throw new Error("Remote commands exited with code: " + code);
                                            }
                                            return sshUpload();
                                        });
                                    }

                                    var ignoreRulesPath = PATH.join(serviceConfig.config.pio.seedPath, ".deployignore");

                                    return RSYNC.sync({
                                        sourcePath: serviceConfig.config.pio.seedPath,
                                        targetUser: serviceConfig.config.pio.user,
                                        targetHostname: serviceConfig.config.pio.ip,
                                        targetPath: serviceConfig.config.pio.deployPath,
                                        keyPath: serviceConfig.config.pio.keyPath,
                                        excludeFromPath: FS.existsSync(ignoreRulesPath) ? ignoreRulesPath : null
                                    }).then(function() {
                                        return uploadSource(
                                            PATH.join(serviceConfig.config.pio.deployPath, ".pio.json"),
                                            JSON.stringify(serviceConfig, null, 4)
                                        ).then(function() {

                                            if (!FS.existsSync(PATH.join(serviceConfig.config.pio.seedPath, "postdeploy.sh"))) {
                                                console.log("Skipping postdeploy. No postdeploy.sh file found!".yellow);
                                                return;
                                            }

                                            var commands = [];
                                            for (var name in serviceConfig.env) {
                                                commands.push('echo "Setting \'"' + name + '"\' to \'"' + serviceConfig.env[name] + '"\'"');
                                                if (options.force) {
                                                    commands.push('export PIO_FORCE=' + options.force);
                                                }
                                                commands.push('export ' + name + '=' + serviceConfig.env[name]);
                                            }
                                            commands.push('echo "Calling postdeploy script:"');
                                            commands.push("sh postdeploy.sh");
                                            return runRemoteCommands(commands, serviceConfig.config.pio.deployPath);
                                        });
                                    }).fail(function(err) {
                                        if (/Operation timed out/.test(err.message)) {
                                            throw new Error("Looks like we cannot connect to IP: " + serviceConfig.config.pio.ip);
                                        }
                                        throw err;
                                    });;
                                }

                                return defaultDeployPlugin(self, serviceConfig).then(function() {
                                    return callback(null);
                                }).fail(callback);
                            });
                        })();
                    });
                }).fail(function(err) {
                    if (/\/opt\/bin\/activate\.sh: No such file or directory/.test(err.message)) {
                        console.log(("Looks like /opt/bin/activate.sh does not exist on instance. Let's create it along with other prerequisites.").magenta);
                        if (options._repeatAfterProvisionPrerequisites) {
                            console.error(err.stack);
                            throw new Error("We already tried to provision the prerequisites but that failed. You need to resolve manually!");
                        }
                        return self._provisionPrerequisites().then(function() {
                            var opts = {};
                            for (var name in options) {
                                opts[name] = options[name];
                            }
                            opts._repeatAfterProvisionPrerequisites = true;
                            return self.deploy(serviceAlias, opts);
                        });
                    }
                    throw err;
                }).then(function() {

                    return Q.denodeify(FS.outputFile)(previoussyncFiletreeInfoPath, JSON.stringify(syncFiletreeInfo, null, 4));

                });
            });
        });
    });
}

PIO.prototype.test = function(serviceAlias) {
    var self = this;
    return self._normalizeServiceConfig(serviceAlias).then(function(serviceConfig) {

        console.log(("Calling 'test.sh' at: " + serviceConfig.config.pio.seedPath).magenta);

        return Q.denodeify(function(callback) {
            var proc = SPAWN("sh", [
                "test.sh"
            ], {
                cwd: serviceConfig.config.pio.seedPath,
                env: {
                    PATH: process.env.PATH,
                    PIO_PUBLIC_IP: serviceConfig.config.pio.ip,
                    PORT: serviceConfig.env.PORT
                }
            });
            proc.stdout.on('data', function (data) {
                process.stdout.write(data);
            });
            proc.stderr.on('data', function (data) {
                process.stderr.write(data);
            });
            proc.on('close', function (code) {
                if (code !== 0) {
                    console.error("ERROR: Script exited with code '" + code + "'");
                    return callback(new Error("Script exited with code '" + code + "'"));
                }
                return callback(null);
            });
        })();
    });
}

PIO.prototype.status = function(serviceAlias) {
    var self = this;
    return self._normalizeServiceConfig(serviceAlias).then(function(serviceConfig) {

        console.log(("Calling 'status.sh' at: " + serviceConfig.config.pio.seedPath).magenta);

        return Q.denodeify(function(callback) {
            var proc = SPAWN("sh", [
                "status.sh"
            ], {
                cwd: serviceConfig.config.pio.seedPath,
                env: {
                    PATH: process.env.PATH,
                    PIO_PUBLIC_IP: serviceConfig.config.pio.ip,
                    PORT: serviceConfig.env.PORT
                }
            });
            proc.stdout.on('data', function (data) {
                process.stdout.write(data);
            });
            proc.stderr.on('data', function (data) {
                process.stderr.write(data);
            });
            proc.on('close', function (code) {
                if (code !== 0) {
                    console.error("ERROR: Script exited with code '" + code + "'");
                    return callback(new Error("Script exited with code '" + code + "'"));
                }
                return callback(null);
            });
        })();
    });
}

module.exports.API = {
    RSYNC: RSYNC,
    SSH: SSH
};


if (require.main === module) {

    function error(err) {
        if (typeof err === "string") {
            console.error((""+err).red);
        } else
        if (typeof err === "object" && err.stack) {
            console.error((""+err.stack).red);
        }
        process.exit(1);
    }

    try {

        var pio = new PIO(process.cwd());

        return pio.ready().then(function() {

            return Q.denodeify(function(callback) {

                var program = new COMMANDER.Command();

                program
                    .version(JSON.parse(FS.readFileSync(PATH.join(__dirname, "package.json"))).version)
                    .option("-v, --verbose", "Show verbose progress")
                    .option("--debug", "Show debug output")
                    .option("-f, --force", "Force an operation when it would normally be skipped");

                var acted = false;
            /*
                program
                    .command("list [filter]")
                    .description("List services")
                    .action(function(path) {
                        acted = true;
                        return pio().list().then(function(list) {
                            list.forEach(function(service) {
                                console.log(service.alias);
                            });
                        }).fail(error);
                    });
            */
                program
                    .command("deploy [service alias]")
                    .description("Deploy a service")
                    .action(function(alias, options) {
                        acted = true;
                        return pio.deploy(alias, {
                            force: program.force || false
                        }).then(function() {
                            return callback(null);
                        }).fail(callback);
                    });

                program
                    .command("test <service alias>")
                    .description("Test a service")
                    .action(function(alias) {
                        acted = true;
                        return pio.test(alias).then(function() {
                            return callback(null);
                        }).fail(callback);
                    });

                program
                    .command("status <service alias>")
                    .description("Get the status of a service")
                    .action(function(alias) {
                        acted = true;
                        return pio.status(alias).then(function() {
                            return callback(null);
                        }).fail(callback);
                    });

                program
                    .command("clean")
                    .description("Clean all cache information forcing a fresh fetch on next run")
                    .action(function(alias) {
                        acted = true;
                        return EXEC([
                            'rm -Rf .pio.*',
                            'rm -Rf */.pio.*',
                            'rm -Rf */*/.pio.*',
                            'rm -Rf */*/*/.pio.*',
                            'rm -Rf */*/*/*/.pio.*'
                        ].join("; "), {
                            cwd: PATH.dirname(pio._configPath)
                        }, function(err, stdout, stderr) {
                            if (err) {
                                console.error(stdout);
                                console.error(stderr);
                                return callback(err);
                            }
                            console.log("All cache files cleaned!".green);
                            return callback(null);
                        });
                    });

                program.parse(process.argv);

                if (!acted) {
                    var command = process.argv.slice(2).join(" ");
                    if (command) {
                        console.error(("ERROR: Command '" + process.argv.slice(2).join(" ") + "' not found!").error);
                    }
                    program.outputHelp();
                    return callback(null);
                }
            })();

        }).then(function() {
            return pio.shutdown().then(function() {

                // NOTE: We force an exit here as for some reason it hangs when there is no server.
                // TODO: Try and do low-level connect to IP first.

                return process.exit(0);
            });
        }).fail(error);
    } catch(err) {
        return error(err);
    }
}
