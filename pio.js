
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
const NET = require("net");

COLORS.setTheme({
    error: 'red'
});


var PIO = module.exports = function(seedPath) {
    var self = this;

    self.API = {
        Q: Q,
        DEEPCOPY: DEEPCOPY,
        DEEPMERGE: DEEPMERGE,
        SSH: SSH,
        RSYNC: RSYNC,
        FSWALKER: FSWALKER
    };

    // A hash that is affected by changes in `PIO_SEED_SALT` and `PIO_SEED_KEY` only.
    self._seedHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.seedId) {
            shasum.update([
                "seed-hash",
                self._config.config.pio.seedId
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (!process.env.PIO_SEED_SALT) {
                ok = false;
                console.error(("'PIO_SEED_SALT' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!process.env.PIO_SEED_KEY) {
                ok = false;
                console.error(("'PIO_SEED_KEY' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "seed-hash",
                process.env.PIO_SEED_SALT,
                process.env.PIO_SEED_KEY
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
    }

    // A hash that is affected by changes in `PIO_EPOCH_ID` only.
    self._epochHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.epochId) {
            shasum.update([
                "user-hash",
                self._config.config.pio.epochId
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (!process.env.PIO_EPOCH_ID) {
                ok = false;
                console.error(("'PIO_EPOCH_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "epoch-hash",
                process.env.PIO_EPOCH_ID
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
    }

    // A hash that is affected by changes in `PIO_EPOCH_ID` and `PIO_USER_ID` only.
    self._userHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.userId) {
            shasum.update([
                "user-hash",
                self._config.config.pio.userId
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (!process.env.PIO_EPOCH_ID) {
                ok = false;
                console.error(("'PIO_EPOCH_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!process.env.PIO_USER_ID) {
                ok = false;
                console.error(("'PIO_USER_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "user-hash",
                process.env.PIO_EPOCH_ID,
                process.env.PIO_USER_ID
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
    }

    // A hash that is affected by changes in `PIO_EPOCH_ID`, `PIO_USER_ID` and `PIO_USER_SECRET` only.
    self._userSecretHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.userSecret) {
            shasum.update([
                "user-secret-hash",
                self._config.config.pio.userSecret
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (!process.env.PIO_EPOCH_ID) {
                ok = false;
                console.error(("'PIO_EPOCH_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!process.env.PIO_USER_ID) {
                ok = false;
                console.error(("'PIO_USER_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!process.env.PIO_USER_SECRET) {
                ok = false;
                console.error(("'PIO_USER_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "user-secret-hash",
                process.env.PIO_EPOCH_ID,
                process.env.PIO_USER_ID,
                process.env.PIO_USER_SECRET
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
    // we are interacting with as well as `PIO_SEED_SALT`, `PIO_SEED_KEY`, `PIO_USER_ID` and `PIO_USER_SECRET`.
    // It is not tied to a specific VM (i.e. IP).
    self._instanceHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        if (self._config.config.pio.instanceId) {
            shasum.update([
                "instance-hash",
                self._config.config.pio.instanceId,
                self._config.config.pio.domain,
                self._config.config.pio.namespace,
                self._config.config["pio.vm"].ip
            ].concat(parts).join(":"));
        } else {
            var ok = true;
            if (!process.env.PIO_SEED_SALT) {
                ok = false;
                console.error(("'PIO_SEED_SALT' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!process.env.PIO_SEED_KEY) {
                ok = false;
                console.error(("'PIO_SEED_KEY' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!process.env.PIO_USER_ID) {
                ok = false;
                console.error(("'PIO_USER_ID' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!process.env.PIO_USER_SECRET) {
                ok = false;
                console.error(("'PIO_USER_SECRET' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
            }
            if (!ok) {
                throw true;
            }            
            shasum.update([
                "instance-hash",
                process.env.PIO_SEED_SALT,
                process.env.PIO_SEED_KEY,
                process.env.PIO_USER_ID,
                process.env.PIO_USER_SECRET,
                self._config.config.pio.domain,
                self._config.config.pio.namespace
            ].concat(parts).join(":"));
        }
        return shasum.digest("hex");
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

            function loadConfig(path) {
                // TODO: Use more generic PINF-based config loader here.
//                console.log("Using config:", path);
                return Q.denodeify(FS.readJson)(path).then(function(config) {
                    self._configPath = path;
                    self._rtConfigPath = path.replace(/\.json$/, ".rt.json");
                    self._config = config;

                    function unlock() {
                        if (
                            !self._config.config ||
                            !self._config.config["pio.cli.local"] ||
                            !self._config.config["pio.cli.local"].plugins ||
                            !self._config.config["pio.cli.local"].plugins.unlock
                        ) return Q.resolve(null);
                        var deferred = Q.defer();
                        try {
                            ASSERT.equal(/^\.\/.*\.js$/.test(self._config.config["pio.cli.local"].plugins.unlock), true, "'config[pio.cli.local].plugins.unlock' value must be a relative path to a nodejs module (e.g. './plugin.js')");
                            var path = PATH.join(self._configPath, "..", self._config.config["pio.cli.local"].plugins.unlock);
                            require.async(path, function (api) {
                                ASSERT.equal(typeof api.unlock, "function", "Plugin at '" + path + "' does not export method 'unlock'!");
                                return api.unlock(self).then(deferred.resolve).fail(deferred.reject);
                            }, deferred.reject);
                        } catch(err) {
                            deferred.reject(err);
                        }
                        return deferred.promise;
                    }

                    return unlock().then(function(unlockInfo) {

                        // TODO: Use `unlockInfo` below.
                        if (unlockInfo) {
                            throw new Error("TODO: Use `unlockInfo`");
                        }

                        function verify() {
                            ASSERT.equal(typeof self._config.uuid, "string", "'uuid' must be set in '" + self._configPath + "' Here is a new one if you need one: " + UUID.v4());
                            ASSERT.equal(typeof self._config.config.pio.domain, "string", "'config.pio.domain' must be set in: " + self._configPath);
                            ASSERT.equal(/^[a-z0-9-\.]+$/.test(self._config.config.pio.domain), true, "'config.pio.domain' must only contain '[a-z0-9-\.]' in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.namespace, "string", "'config.pio.namespace' must be set in: " + self._configPath);
                            ASSERT.equal(/^[a-z0-9-]+$/.test(self._config.config.pio.namespace), true, "'config.pio.namespace' must only contain '[a-z0-9-]' in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config["pio.vm"].ip, "string", "'config[pio.vm].ip' must be set in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.keyPath, "string", "'config.pio.keyPath' must be set in '" + self._configPath + "'");
                        }

                        if (/\/\.pio\.json$/.test(self._configPath)) {
                            console.log("Skip loading profile as we are using a consolidated pio descriptor (" + self._configPath + ").");
                            verify();
                            ASSERT.equal(typeof self._config.config.pio.epochId, "string", "'config.pio.epochId' must be set in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.seedId, "string", "'config.pio.seedId' must be set in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.dataId, "string", "'config.pio.dataId' must be set in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.codebaseId, "string", "'config.pio.codebaseId' must be set in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.userId, "string", "'config.pio.userId' must be set in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.instanceId, "string", "'config.pio.instanceId' must be set in: " + self._configPath);
                            ASSERT.equal(typeof self._config.config.pio.hostname, "string", "'config.pio.hostname' must be set in: " + self._configPath);
                            return;
                        }
                        path = PATH.join(self._configPath, "..", "pio." + self._config.config.pio.profile + ".json");
    //                    console.log("Using profile:", path);
                        return Q.denodeify(FS.readJson)(path).then(function(profile) {
                            self._profilePath = path;
                            self._config = DEEPMERGE(self._config, profile);

                            function loadRuntimeConfig() {
                                return Q.denodeify(function(callback) {
                                    return FS.exists(self._rtConfigPath, function(exists) {
                                        return callback(null, exists);
                                    });
                                })().then(function(exists) {
                                    if (!exists) return {};
                                    return Q.denodeify(FS.readJson)(self._rtConfigPath);
                                });
                            }

                            return loadRuntimeConfig().then(function (runtimeConfig) {

                                if (runtimeConfig && runtimeConfig.config) {
                                    if (runtimeConfig.config["pio.vm"]) {
                                        if (runtimeConfig.config["pio.vm"].ip) {
                                            self._config.config["pio.vm"].ip = runtimeConfig.config["pio.vm"].ip;
                                        }
                                    }
                                }

                                // TODO: Remvoe this when we use dynamic config system.
                                var configStr = JSON.stringify(self._config.config);
                                configStr = configStr.replace(/\{\{env\.DNSIMPLE_EMAIL\}\}/g, process.env.DNSIMPLE_EMAIL);
                                configStr = configStr.replace(/\{\{env\.DNSIMPLE_TOKEN\}\}/g, process.env.DNSIMPLE_TOKEN);
                                configStr = configStr.replace(/\{\{env\.AWS_ACCESS_KEY\}\}/g, process.env.AWS_ACCESS_KEY);
                                configStr = configStr.replace(/\{\{env\.AWS_SECRET_KEY\}\}/g, process.env.AWS_SECRET_KEY);
                                configStr = configStr.replace(/\{\{env\.DIGIO_CLIENT_ID\}\}/g, process.env.DIGIO_CLIENT_ID);
                                configStr = configStr.replace(/\{\{env\.DIGIO_API_KEY\}\}/g, process.env.DIGIO_API_KEY);
                                self._config.config = JSON.parse(configStr);

            /*
                                for (var key in self._config) {
                                    if (/^config\[cloud=.+\]$/.test(key)) {
                                        delete self._config[key];
                                    }
                                }
            */
                                verify();

                                var c = self._config.config.pio;

                                c.idSegmentLength = c.idSegmentLength || 4;
                                c.epochIdSegmentPrefix = c.epochIdSegmentPrefix || "e";
                                c.seedIdSegmentPrefix = c.seedIdSegmentPrefix || "s";
                                c.codebaseIdSegmentPrefix = c.codebaseIdSegmentPrefix || "c";
                                c.userIdSegmentPrefix = c.userIdSegmentPrefix || "u";
                                c.instanceIdSegmentPrefix = c.instanceIdSegmentPrefix || "i";

                                // WARNING: DO NOT MODIFY THIS! IF MODIFIED IT WILL BREAK COMPATIBILITY WITH ADDRESSING
                                //          EXISTING DEPLOYMENTS!

                                c.epochId = self._epochHash(["epoch-id"]);
                                var epochIdSegment = c.epochIdSegmentPrefix + c.epochId.substring(0, c.idSegmentLength);
                                c.epochId = [epochIdSegment, c.namespace, c.epochId.substring(c.idSegmentLength)].join("_");

                                c.seedId = self._seedHash(["seed-id", c.epochId]);
                                var seedIdSegment = c.seedIdSegmentPrefix + c.seedId.substring(0, c.idSegmentLength);
                                c.seedId = [epochIdSegment, c.namespace, seedIdSegment, c.seedId.substring(c.idSegmentLength)].join("_");

                                // Use this to derive data namespaces. They will survive multiple deployments.
                                c.dataId = [epochIdSegment, c.namespace, seedIdSegment, self._seedHash(["data-id", c.epochId, c.seedId])].join("_");

                                // Use this to derive orchestration and tooling namespaces. They are tied to the codebase uuid.
                                c.codebaseId = self._codebaseHash(["codebase-id", c.epochId, self._config.uuid]);
                                var codebaseSegment = c.codebaseIdSegmentPrefix + c.codebaseId.substring(0, c.idSegmentLength);
                                c.codebaseId = [epochIdSegment, c.namespace, seedIdSegment, codebaseSegment, c.codebaseId.substring(c.idSegmentLength)].join("_");

                                // Use this to derive data namespaces for users of the codebase that can create multiple instances.
                                c.userId = self._userHash(["user-id", c.epochId]);
                                c.userSecret = self._userSecretHash(["user-secret", c.epochId, c.userId]);
                                var userSegment = c.userIdSegmentPrefix + c.userId.substring(0, c.idSegmentLength);
                                c.userId = [epochIdSegment, c.namespace, seedIdSegment, codebaseSegment, userSegment, c.userId.substring(c.idSegmentLength)].join("_");

                                // Use this to derive provisioning and runtime namespaces. They will change with every new IP.
                                c.instanceId = self._instanceHash(["deployment-id", c.epochId, c.seedId, c.dataId, c.codebaseId, c.userId]);
                                c.instanceSecret = self._instanceHash(["instance-secret", c.epochId, c.seedId, c.dataId, c.codebaseId, c.userId, c.instanceId]);
                                var deploySegment = c.instanceIdSegmentPrefix + c.instanceId.substring(0, c.idSegmentLength);
                                c.instanceId = [epochIdSegment, c.namespace, seedIdSegment, codebaseSegment, userSegment, deploySegment, c.instanceId.substring(c.idSegmentLength)].join("_");

                                c.hostname = [c.namespace, "-", deploySegment, ".", c.domain].join("");

                                function getPublicKey() {
                                    var deferred = Q.defer();
                                    var pubKeyPath = c.keyPath + ".pub";
                                    FS.exists(pubKeyPath, function(exists) {
                                        if (exists) {
                                            return FS.readFile(pubKeyPath, "utf8", function(err, data) {
                                                if (err) return deferred.reject(err);
                                                return deferred.resolve(data.match(/^(\S+\s+\S+)(\s+\S+)?\n?$/)[1]);
                                            });
                                        }
                                        return deferred.reject(new Error("Use 'ssh-keygen -y -f PRIVATE_KEY_PATH' to get public key from private key"));

                                    });
                                    return deferred.promise;
                                }

                                return getPublicKey().then(function(publicKey) {
                                    c.keyPub = publicKey;

                                    var configStr = JSON.stringify(self._config.config);
                                    configStr = configStr.replace(/\{\{config\.pio\.hostname\}\}/g, c.hostname);
                                    configStr = configStr.replace(/\{\{config\.pio\.domain\}\}/g, c.domain);
                                    configStr = configStr.replace(/\{\{config\['pio\.vm'\]\.ip\}\}/g, self._config.config['pio.vm'].ip);
                                    configStr = configStr.replace(/\{\{config\.pio\.keyPub\}\}/g, c.keyPub);
                                    configStr = configStr.replace(/\{\{env.USER\}\}/g, process.env.USER);
                                    self._config.config = JSON.parse(configStr);
                                });
                            });
                        });
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

    self._ensureInfo = null;
}

PIO.prototype = Object.create(EVENTS.EventEmitter.prototype);

PIO.prototype.ready = function() {
    return this._ready;
}

PIO.prototype.shutdown = function() {
    this.emit("shutdown");
    return Q.resolve();
}

PIO.prototype.getConfig = function(selector) {
    if (typeof selector === "string") {
        return this._config[selector];
    }
    throw new Error("NYI");
}

PIO.prototype._setRuntimeConfig = function(config) {
    var self = this;
    return Q.denodeify(FS.outputFile)(self._rtConfigPath, JSON.stringify(config, null, 4)).then(function() {
        return (self._ready = self._load());
    });

/*    
    if (selector === "config["pio.vm"].ip") {
        return Q.denodeify(FS.readJson)(self._configPath).then(function(config) {
            config.config["pio.vm"].ip = value;
            return Q.denodeify(FS.outputFile)(self._configPath, JSON.stringify(config, null, 4));
        }).then(function() {
            return (self._ready = self._load());
        });
    }
*/
}


function callPlugins(pio, method, state) {
    function callPlugin(plugin, state) {
        var deferred = Q.defer();
        try {
            ASSERT.equal(/^\.\/.*\.js$/.test(plugin), true, "'config[pio.cli.local].plugins." + method + "' value must be a relative path to a nodejs module (e.g. './plugin.js')");
            var path = PATH.join(pio._configPath, "..", plugin);
            require.async(path, function (api) {
                ASSERT.equal(typeof api[method], "function", "Plugin at '" + path + "' does not export method '" + method + "'!");
                return api[method](pio, DEEPCOPY(state)).then(deferred.resolve).fail(deferred.reject);
            }, deferred.reject);
        } catch(err) {
            deferred.reject(err);
        }
        return deferred.promise;
    }
    if (
        !pio._config.config ||
        !pio._config.config["pio.vm"] ||
        !pio._config.config["pio.vm"].ip ||
        !pio._config.config["pio.cli.local"] ||
        !pio._config.config["pio.cli.local"].plugins ||
        !pio._config.config["pio.cli.local"].plugins[method]
    ) {
        return Q.reject(new Error("No plugins found at 'config[pio.cli.local].plugins["+method+"]'"));
    }
    var plugins = pio._config.config["pio.cli.local"].plugins[method];
    if (!Array.isArray(plugins)) {
        plugins = [ plugins ];
    }
    var done = Q.resolve();
    plugins.forEach(function(plugin) {
        done = Q.when(done, function() {
            return callPlugin(plugin, state).then(function(_state) {
                state = DEEPMERGE(state, _state);
            });
        });
    });
    return done.then(function() {
        return state;
    });
}

PIO.prototype.ensure = function() {
    var self = this;
    if (self._state) {
        return Q.resolve(self._state);
    }
    if (
        !self._config.config ||
        !self._config.config["pio.vm"] ||
        !self._config.config["pio.vm"].ip ||
        !self._config.config["pio.cli.local"] ||
        !self._config.config["pio.cli.local"].plugins ||
        !self._config.config["pio.cli.local"].plugins.ensure
    ) {
        return Q.resolve(null);
    }
    return callPlugins(self, "ensure", {
        "pio.cli.local": {
            status: "ready"            
        },
        "pio": {
            hostname: self._config.config["pio"].hostname,
            keyPath: self._config.config["pio"].keyPath,
            servicesPath: self._config.config["pio"].servicesPath,
            status: "ready"
        },
        "pio.vm": {
            ip: self._config.config["pio.vm"].ip,
            user: self._config.config["pio.vm"].user,
            prefixPath: self._config.config["pio.vm"].prefixPath
        }
    }).then(function(state) {

        // We can proceed if everything is ready or we are not waiting
        // on required services.

        for (var alias in state) {
            if (
                state[alias].status !== "ready" &&
                (
                    state[alias].required === true ||
                    state[alias].required !== false
                )
            ) {
                throw ("Service not ready: " + JSON.stringify(alias, state[alias], null, 4));
            }
        }

        self._state = state;
    });
}

PIO.prototype.status = function() {
    var self = this;
    return self._ready.then(function() {
        return self._state["pio.deploy"]._call("status", {});
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

PIO.prototype.deploy = function(serviceAlias, options) {
    var self = this;

    if (!serviceAlias) {
        // Deploy all services.

        return self._ready.then(function() {

            var services = Object.keys(self._config.provides);

            console.log("Deploying services sequentially according to 'boot' order:".cyan);

            var done = Q.resolve();
            self._config.boot.forEach(function(serviceAlias) {
                done = Q.when(done, function() {
                    return self.deploy(serviceAlias, options).then(function() {
                        return self._state["pio.deploy"]._ensure().then(function(_response) {
                            if (_response.status === "ready") {
                                console.log("Switching to using dnode transport where possible!".green);
                            }
                            return;
                        });
                    });
                });
            });
            return Q.when(done, function() {

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

    if (self._config.provides[serviceAlias].enabled === false) {
        console.log(("Skip deploy service '" + serviceAlias + "'. It is disabled!").yellow);
        return;
    }

    self._state["pio.cli.local"].force = options.force || false;

    self._state["pio.service"] = {
        alias: serviceAlias
    };

    console.log(("VM login:", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=" + self._config.config.pio.keyPath + " " + self._config.config["pio.vm"].user + "@" + self._config.config["pio.vm"].ip).bold);

    return callPlugins(self, "deploy", self._state).then(function(state) {

        console.log(("Deploy of '" + serviceAlias + "' done!").green);

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
                    PIO_PUBLIC_IP: serviceConfig.config["pio.vm"].ip,
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
                    PIO_PUBLIC_IP: serviceConfig.config["pio.vm"].ip,
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

            return pio.ensure().then(function() {

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
                        .command("info")
                        .description("Overall stack config info")
                        .action(function() {
                            acted = true;
                            console.log(JSON.stringify(pio._config.config, null, 4));
                            return callback(null);
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
            });

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
