
require("require.async")(require);

const ASSERT = require("assert");
const PATH = require("path");
const EVENTS = require("events");
const FS = require("fs-extra");
const Q = require("q");
const URL = require("url");
const UUID = require("uuid");
const DEEPCOPY = require("deepcopy");
const DEEPMERGE = require("deepmerge");
const CRYPTO = require("crypto");
const REQUEST = require("request");
const RSYNC = require("./lib/rsync");
const SSH = require("./lib/ssh");
const SPAWN = require("child_process").spawn;
const DIRSUM = require("dirsum");
const FSWALKER = require("./lib/fswalker");
const EXEC = require("child_process").exec;
const NET = require("net");
const WAITFOR = require("waitfor");
const GLOB = require("glob");
const SMI = require("smi.cli");


var PIO = module.exports = function(seedPath) {
    var self = this;

    self.API = {
        Q: Q,
        FS: FS,
        DEEPCOPY: DEEPCOPY,
        DEEPMERGE: DEEPMERGE,
        SSH: SSH,
        RSYNC: RSYNC,
        FSWALKER: FSWALKER,
        WAITFOR: WAITFOR,
        UUID: UUID
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
                console.error(("'PIO_USER_SECRET' environment variable not set. Here is a new one in case you need one: " + UUID.v4()).red);
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

            function ensureUpstream() {

                var upstreamBasePath = PATH.join(self._configPath, "../_upstream");

                function ensureCatalog(catalogId, info) {
                    var catalogBasePath = upstreamBasePath;

                    function ensureCatalogDescriptor(verify) {
                        var catalogDescriptorPath = PATH.join(catalogBasePath, catalogId + ".catalog.json");
                        return Q.denodeify(function(callback) {
                            return SMI.readDescriptor(catalogDescriptorPath, {
                                basePath: PATH.join(self._configPath, "..")
                            }, function(err, descriptor) {
                                if (err) return callback(err);
                                return callback(null, descriptor);
                            });
                        })();
                    }

                    // TODO: Use `smi` to install these packages.
                    return ensureCatalogDescriptor().then(function(catalogDescriptor) {
                        return catalogDescriptor;
                    });
                }

                var combinedDescriptor = {};
                var done = Q.resolve();
                if (self._config.upstream && self._config.upstream.catalogs) {
                    Object.keys(self._config.upstream.catalogs).forEach(function(alias) {
                        done = Q.when(done, function() {
                            return ensureCatalog(alias, self._config.upstream.catalogs[alias]).then(function(catalogDescriptor) {
                                combinedDescriptor = DEEPMERGE(combinedDescriptor, catalogDescriptor);
                            });
                        });
                    });
                }
                return done.then(function() {
                    return combinedDescriptor;
                });
            }


            function loadConfig(path) {
                // TODO: Use more generic PINF-based config loader here.
//                console.log("Using config:", path);

                function load(path) {
                    return Q.denodeify(function(callback) {
                        return SMI.readDescriptor(path, {
                            basePath: PATH.join(path, "..")
                        }, function(err, config) {
                            if (err) return callback(err);

                            self._config = config;
                            self._configOriginal = DEEPCOPY(self._config);

                            path = path.replace(/\.json$/, ".1.json");
                            return FS.exists(path, function(exists) {
                                if (!exists) {
                                    return callback(null);
                                }
                                return SMI.readDescriptor(path, {
                                    basePath: PATH.join(path, "..")
                                }, function(err, _config) {
                                    if (err) return callback(err);
                                    
                                    self._config = DEEPMERGE(self._config, _config);
                                    return callback(null);
                                });
/*
                                return FS.readJson(path, function(err, _config) {
                                    if (err) return callback(err);
                                    self._config = DEEPMERGE(self._config, _config);
                                    return callback(null);
                                });
*/
                            });
                        });
                    })();
                }

                return load(path).then(function() {
                    self._configPath = path;
                    self._rtConfigPath = path.replace(/\.json$/, ".rt.json");

                    function mergeCatalogDescriptors() {
                        if (!self._config.upstream) {
                            return Q.resolve();
                        }
                        return ensureUpstream().then(function(catalogDescriptor) {
                            delete catalogDescriptor.name;
                            delete catalogDescriptor.uuid;
                            delete catalogDescriptor.revision;
                            delete catalogDescriptor.packages;
                            self._config = DEEPMERGE(catalogDescriptor, self._config);
                        });
                    }

                    return mergeCatalogDescriptors().then(function() {
                        var services = {};
                        var basePath = PATH.join(self._configPath, "..", self._config.config["pio"].servicesPath);
                        return Q.denodeify(GLOB)("*/*", {
                            cwd: basePath
                        }).then(function(files) {
                            files.forEach(function(filepath) {
                                services[filepath.split("/").pop()] = PATH.join(basePath, filepath);
                            });
                            basePath = PATH.join(self._configPath, "..", "_upstream");
                            return Q.denodeify(GLOB)("*/*", {
                                cwd: basePath
                            }).then(function(files) {
                                files.forEach(function(filepath) {
                                    services[filepath.split("/").pop()] = PATH.join(basePath, filepath);
                                });
                                self._locatedServices = services;
                                return;
                            });
                        }).then(function() {

                            function unlock() {
                                if (
                                    !self._config.config ||
                                    !self._config.config["pio.cli.local"] ||
                                    !self._config.config["pio.cli.local"].plugins ||
                                    !self._config.config["pio.cli.local"].plugins.unlock
                                ) return Q.resolve(null);
                                var deferred = Q.defer();
                                try {
                                    var path = resolvePluginPath(self, self._config.config["pio.cli.local"].plugins.unlock);
                                    require.async(path, function (api) {
                                        ASSERT.equal(typeof api.unlock, "function", "Plugin at '" + path + "' does not export method 'unlock'!");
                                        return api.unlock(self).then(deferred.resolve).fail(deferred.reject);
                                    }, deferred.reject);
                                } catch(err) {
                                    deferred.reject(err);
                                }
                                return deferred.promise.fail(function(err) {
                                    if (/Cannot find module/.test(err.message)) {
// Silently fail for now if plugin not found.
// TODO: Fix this by loading a *service* profile which unlocks using agent call vs cli config that asks user.
                                        return;
                                    }
                                    throw err;
                                });
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
                                    //ASSERT.equal(typeof self._config.config["pio.vm"].ip, "string", "'config[pio.vm].ip' must be set in: " + self._configPath);
                                    ASSERT.equal(typeof self._config.config["pio.vm"].prefixPath, "string", "'config[pio.vm].prefixPath' must be set in: " + self._configPath);
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


                                        self._config.env.PATH = [
                                            self._config.config["pio.vm"].prefixPath + "/bin",
                                            self._config.env.PATH
                                        ].filter(function(path) { return !!path; }).join(":");


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

                                        c.keyPath = c.keyPath.replace(/^~\//, ((process.env.HOME || "/home/ubuntu") + "/"));

                                        function getPublicKey(verify) {
                                            var deferred = Q.defer();
                                            var pubKeyPath = c.keyPath + ".pub";
                                            FS.exists(pubKeyPath, function(exists) {
                                                if (exists) {
                                                    return FS.readFile(pubKeyPath, "utf8", function(err, data) {
                                                        if (err) return deferred.reject(err);
                                                        return deferred.resolve(data.match(/^(\S+\s+\S+)(\s+\S+)?\n?$/)[1]);
                                                    });
                                                }
                                                if (verify) {
                                                    return deferred.reject(new Error("Still no public key after export!"));
                                                }
                                                console.log(("Generating public key from private key '" + c.keyPath + "' and store at: " + pubKeyPath).magenta);
                                                return SSH.exportPublicKeyFromPrivateKey(c.keyPath, pubKeyPath).then(function() {
                                                    return getPublicKey(true);
                                                }).then(deferred.resolve).fail(deferred.reject);
                                            });
                                            return deferred.promise;
                                        }

                                        return getPublicKey().then(function(publicKey) {
                                            c.keyPub = publicKey;

                                            var configStr = JSON.stringify(self._config.config);
                                            configStr = configStr.replace(/\{\{config\.pio\.hostname\}\}/g, c.hostname);
                                            configStr = configStr.replace(/\{\{config\.pio\.domain\}\}/g, c.domain);
                                            configStr = configStr.replace(/\{\{config\['pio\.vm'\]\.ip\}\}/g, self._config.config['pio.vm'].ip);
                                            configStr = configStr.replace(/\{\{config.pio.namespace\}\}/g, self._config.config['pio'].namespace);
                                            configStr = configStr.replace(/\{\{config\.pio\.keyPub\}\}/g, c.keyPub);
                                            configStr = configStr.replace(/\{\{env.USER\}\}/g, process.env.USER);
                                            self._config.config = JSON.parse(configStr);
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            }

            // TODO: Allow different config loading profiles based on environment.
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
                    return FS.exists(PATH.join(seedPath, "pio.json"), function(exists) {
                        if (exists) {
                            return loadConfig(PATH.join(seedPath, ".pio.json")).then(function() {
                                return callback(null);
                            }).fail(callback);
                        }

                        // Locate parent config and select service assuming we are loading config
                        // for a dev package.
                        return loadConfig(PATH.join(seedPath, "../../../pio.json")).then(function() {

                            self._config.config["pio.cli.local"].plugins = {
                                "ensure": [
                                    "service:pio.service/module:pio.cli.local.ensure.plugin"
                                ]
                            };

                            return self.ensure(PATH.basename(seedPath));
                        }).then(function() {
                            return callback(null);
                        }).fail(callback);
                    });
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


function resolvePluginPath(pio, plugin) {
    var path = plugin;
    var m = null;
    if ((m = plugin.match(/^service:([^\/:]+)\/module:([^\/:]+)$/))) {
        if (pio._locatedServices[m[1]]) {
            path = PATH.join(pio._locatedServices[m[1]], "source", m[2] + ".js");
            if (!FS.existsSync(path)) {
                path = PATH.join(pio._locatedServices[m[1]], m[2] + ".js");
            }
        }
    } else
    if (/^\./.test(plugin)) {
        path = PATH.join(pio._configPath, "..", path);
    }
    return path;
}


function callPlugins(pio, method, state, options) {
    function callPlugin(plugin, state) {
        var deferred = Q.defer();
        try {
            var path = resolvePluginPath(pio, plugin);
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
                if (_state !== null) {
                    if (typeof _state !== "object") {
                        throw new Error("Plugin '" + plugin + "' must return an object!");
                    }
                    for (var alias in _state) {
                        if (state[alias]) {
                            for (var name in _state[alias]) {
                                state[alias][name] = _state[alias][name];
                            }
                        } else {
                            state[alias] = _state[alias];
                        }
                    }
                }
            });
        });
    });
    return done.then(function() {
        return state;
    }).fail(function(err) {
        // TODO: Remove this once pio can install usign slim setup without requiring plugins.
        //       i.e. when using `smi` to install dependencies.
        if (err.ignorePluginFailures) {
            // Ignore error module require errors.
            return;
        }
        throw err;
    });
}

PIO.prototype.ensure = function(serviceSelector, options) {
    var self = this;
    if (self._state && self._state["pio.cli.local"].serviceSelector === serviceSelector) {
        return Q.resolve(self._state);
    }
    options = options || {
        force: (self._state && self._state["pio.cli.local"] && self._state["pio.cli.local"].force) || false
    }
    var services = {};
    var serviceGroups = {};
    for (var serviceGroup in self._config.services) {
        Object.keys(self._config.services[serviceGroup]).forEach(function(serviceId) {
            if (self._config.services[serviceGroup][serviceId] === null) {
                return;
            }
            if (serviceGroups[serviceId]) {
                throw new Error("Cannot redeclare service '" + serviceId + "' in group '" + serviceId + "'. It is already declared in '" + serviceConfig[serviceId] + "'");
            }
            serviceGroups[serviceId] = serviceGroup;
        });
    }
    for (var serviceId in self._locatedServices) {
        if (serviceGroups[serviceId]) {
            services[serviceId] = {
                group: serviceGroups[serviceId],
                path: self._locatedServices[serviceId],
                descriptor: DEEPCOPY(self._config.services[serviceGroups[serviceId]][serviceId])
            };
            if (typeof services[serviceId].descriptor.enabled === "undefined") {
                services[serviceId].enabled = true;
            } else {
                services[serviceId].enabled = services[serviceId].descriptor.enabled;
            }
        }
    }
    return callPlugins(self, "ensure", {
        "pio.cli.local": {
            serviceSelector: serviceSelector || null,
            force: options.force || false
        },
        "pio": DEEPMERGE(DEEPCOPY(self._config.config["pio"]), {}),
        "pio.vm": DEEPCOPY(self._config.config["pio.vm"]),
        "pio.services": {
            "services": services
        }
    }, options).then(function(state) {

        // We can proceed if everything is ready or we are not waiting
        // on required services.
        var repeat = false;
        for (var alias in state) {
            if (typeof state[alias].status !== "undefined") {
                if (state[alias].status === "repeat") {
                    console.log(("Service is asking for ensure to repeat: " + JSON.stringify({
                        "alias": alias,
                        "state": state[alias]
                    }, null, 4)).cyan);
                    repeat = true;
                } else
                if (state[alias].status !== "ready" &&
                    (
                        state[alias].required === true ||
                        state[alias].required !== false
                    )
                ) {
                    throw ("Service not ready: " + JSON.stringify({
                        "alias": alias,
                        "state": state[alias]
                    }, null, 4));
                }
            }
        }

        if (repeat) {
            return self._load().then(function() {
                return self.ensure(serviceSelector, options);
            });
        }

        self._state = state;
    });
}

PIO.prototype.list = function() {
    var self = this;
    return self._ready.then(function() {
        var services = [];
        for (var serviceId in self._state["pio.services"].services) {
            services.push({
                group: self._state["pio.services"].services[serviceId].group,
                id: serviceId,
                path: self._state["pio.services"].services[serviceId].path,
                pathReal: FS.realpathSync(self._state["pio.services"].services[serviceId].path),
                enabled: self._state["pio.services"].services[serviceId].enabled
            });
        }
        return services;
    });
}

function repeat(worker, failIsGood) {
    function check() {
        function again() {
            console.log("Warning: Attempt failed: " + err.stack);
            console.log("Waiting for 3 seconds and trying again ...");
            return Q.delay(3 * 1000).then(function() {
                return check();
            });
        }
        if (failIsGood) {
            return worker().then(function() {
                return again();
            }).fail(function(err) {
                // Ignore error. We are good!
            });
        } else {
            return worker().fail(function(err) {
                return again();
            });
        }
    }
    return Q.timeout(check(), 120 * 1000);
}

PIO.prototype.deploy = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        // Deploy all services.

        return self._ready.then(function() {
            var done = Q.resolve();
            if (self._config.config["pio.vm"].provision) {
                console.log("Deploying services sequentially according to 'boot' order:".cyan);
                self._config.config["pio.vm"].provision.forEach(function(serviceId) {
                    done = Q.when(done, function() {
                        return self.ensure(serviceId).then(function() {
                            return self.deploy().then(function() {
                                return self._state["pio.deploy"]._ensure().then(function(_response) {
                                    if (_response.status === "ready") {
                                        console.log("Switching to using dnode transport where possible!".green);
                                    }
                                    return;
                                });
                            });
                        });
                    });
                });
            }
            return Q.when(done, function() {

                // TODO: Deploy in parallel by default if nothing has changed.
                console.log("Deploying remaining services sequentially:".cyan);

                var done = Q.resolve();
                Object.keys(self._state["pio.services"].services).forEach(function(serviceId) {
                    if (
                        self._config.config["pio.vm"].provision &&
                        self._config.config["pio.vm"].provision.indexOf(serviceId) !== -1
                    ) {
                        return;
                    }
                    done = Q.when(done, function() {
                        return self.ensure(serviceId).then(function() {
                            return self.deploy();
                        });
                    });
                });
                return done;
            });
        });
    }

    if (self._state["pio.service"].enabled === false) {
        console.log(("Skip deploy for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        return Q.resolve(null);
    }

    console.log(("VM login:", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=" + self._config.config.pio.keyPath + " " + self._config.config["pio.vm"].user + "@" + self._config.config["pio.vm"].ip).bold);

    console.log(("Deploy '" + self._state["pio.service"].id + "' ...").magenta);

    return callPlugins(self, "deploy", self._state).then(function(state) {

        console.log(("Deploy '" + self._state["pio.service"].id + "' done!").green);

        return state;
    }).then(function(state) {

        if (state["pio.deploy"].status !== "done") {
            console.log(("Skip confirming service is working using status call as we did not deploy service.").yellow);
            return;
        }

        console.log(("Confirming service is working using status call ...").cyan);

        return Q.delay(1 * 1000).then(function() {
            return repeat(function() {
                return self.status();
            }).then(function() {

                console.log(("Service confirmed working using status call!").green);

            });
        });
    });
}

PIO.prototype.info = function() {
    var self = this;

    console.log(("VM login:", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=" + self._config.config.pio.keyPath + " " + self._config.config["pio.vm"].user + "@" + self._config.config["pio.vm"].ip).bold);

    if (!self._state["pio.cli.local"].serviceSelector) {
        return Q.resolve(self._config);
    }

    return self._state["pio.deploy"]._call("info", {
        servicePath: self._state["pio.service.deployment"].path
    }).then(function(res) {
        // NOTE: This format is going to change.
        return {
            remote: res,
            local: {
                service: self._state["pio.service"]
            }
        };
    });
}

PIO.prototype.status = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        // Deploy all services.

        return self._ready.then(function() {

            console.log("Getting status for all services:".cyan);

            var states = {};
            var done = Q.resolve();
            Object.keys(self._state["pio.services"].services).forEach(function(serviceId) {
                done = Q.when(done, function() {
                    return self.ensure(serviceId).then(function() {
                        return self.status().then(function(state) {
                            if (state !== null) {
                                states[serviceId] = state;
                            }
                            return;
                        });
                    });
                });
            });

            return done.then(function() {
                return states;
            });
        });
    }

    if (self._state["pio.service"].enabled === false) {
        console.log(("Skip status for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        return Q.resolve(null);
    }

    return callPlugins(self, "status", self._state).then(function(state) {
        return (state["pio.service.status"] && state["pio.service.status"].response) || {};
    });   
}

PIO.prototype.start = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        return Q.reject("Service must be selected!");
    }

    var commands = [];
    commands.push('. /opt/bin/activate.sh');
    for (var name in self._state["pio.service.deployment"].env) {
        commands.push('export ' + name + '="' + self._state["pio.service.deployment"].env[name] + '"');
    }
    commands.push('export PIO_SCRIPTS_PATH="' + PATH.join(self._state["pio.service.deployment"].path, "live/scripts") + '"');
    commands.push('echo "Calling \'start.sh\' on VM (cwd: ' + self._state["pio.service.deployment"].path + '):"');
    commands.push('sh $PIO_SCRIPTS_PATH/start.sh');

    return self._state["pio.deploy"]._call("_runCommands", {
        commands: commands,
        cwd: PATH.join(self._state["pio.service.deployment"].path, "live/install")
    }).then(function(response) {
        if (!response) {
            throw new Error("Remote commands exited with no response");
        }
        if (response.code !== 0)  {
            throw new Error("Remote commands exited with code: " + response.code);
        }

        console.log(("Confirming service is working using status call ...").cyan);

        return Q.delay(1 * 1000).then(function() {
            return repeat(function() {
                return self.status();
            }).then(function() {

                console.log(("Service confirmed working using status call!").green);

            });
        });
    });
}

PIO.prototype.stop = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        return Q.reject("Service must be selected!");
    }

    var commands = [];
    commands.push('. /opt/bin/activate.sh');
    for (var name in self._state["pio.service.deployment"].env) {
        commands.push('export ' + name + '="' + self._state["pio.service.deployment"].env[name] + '"');
    }
    commands.push('export PIO_SCRIPTS_PATH="' + PATH.join(self._state["pio.service.deployment"].path, "live/scripts") + '"');
    commands.push('echo "Calling \'stop.sh\' on VM (cwd: ' + self._state["pio.service.deployment"].path + '):"');
    commands.push('sh $PIO_SCRIPTS_PATH/stop.sh');

    return self._state["pio.deploy"]._call("_runCommands", {
        commands: commands,
        cwd: PATH.join(self._state["pio.service.deployment"].path, "live/install")
    }).then(function(response) {
        if (!response) {
            throw new Error("Remote commands exited with no response");
        }
        if (response.code !== 0)  {
            throw new Error("Remote commands exited with code: " + response.code);
        }

        console.log(("Confirming service is working using status call ...").cyan);

        return Q.delay(1 * 1000).then(function() {
            return repeat(function() {
                return self.status();
            }, true).then(function() {

                console.log(("Service confirmed working using status call!").green);

            });
        });
    });
}

PIO.prototype.restart = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        return Q.reject("Service must be selected!");
    }

    var commands = [];
    commands.push('. /opt/bin/activate.sh');
    for (var name in self._state["pio.service.deployment"].env) {
        commands.push('export ' + name + '="' + self._state["pio.service.deployment"].env[name] + '"');
    }
    commands.push('export PIO_SCRIPTS_PATH="' + PATH.join(self._state["pio.service.deployment"].path, "live/scripts") + '"');
    commands.push('echo "Calling \'restart.sh\' on VM (cwd: ' + self._state["pio.service.deployment"].path + '):"');
    commands.push('sh $PIO_SCRIPTS_PATH/restart.sh');

    return self._state["pio.deploy"]._call("_runCommands", {
        commands: commands,
        cwd: PATH.join(self._state["pio.service.deployment"].path, "live/install")
    }).then(function(response) {
        if (!response) {
            throw new Error("Remote commands exited with no response");
        }
        if (response.code !== 0)  {
            throw new Error("Remote commands exited with code: " + response.code);
        }

        console.log(("Confirming service is working using status call ...").cyan);

        return Q.delay(1 * 1000).then(function() {
            return repeat(function() {
                return self.status();
            }).then(function() {

                console.log(("Service confirmed working using status call!").green);

            });
        });
    });
}

PIO.prototype.test = function() {
    var self = this;


    if (!self._state["pio.cli.local"].serviceSelector) {
        // Deploy all services.

        return self._ready.then(function() {

            console.log("Testing all services:".cyan);

            var states = {};
            var done = Q.resolve();
            Object.keys(self._state["pio.services"].services).forEach(function(serviceId) {
                done = Q.when(done, function() {
                    return self.ensure(serviceId).then(function() {
                        return self.test().then(function(state) {
                            if (state !== null) {
                                states[serviceId] = state;
                            }
                            return;
                        });
                    });
                });
            });

            return done.then(function() {
                return states;
            });
        });
    }

    if (self._state["pio.service"].enabled === false) {
        console.log(("Skip test for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        return Q.resolve(null);
    }

    return callPlugins(self, "test", self._state).then(function(state) {

        return (state["pio.service.test"] && state["pio.service.test"].result) || {};
    });
}

PIO.prototype.publish = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        // Deploy all services.

        return self._ready.then(function() {

            console.log("Publishing all services:".cyan);

            var states = [];
            var done = Q.resolve();
            Object.keys(self._state["pio.services"].services).forEach(function(serviceId) {
                done = Q.when(done, function() {
                    return self.ensure(serviceId).then(function() {
                        return self.publish().then(function(state) {
                            if (state !== null) {
                                states.push(state);
                            }
                            return;
                        });
                    });
                });
            });

            return done.then(function() {
                return callPlugins(self, "publish.finalize", states).then(function(state) {

                    console.log(("Publish done!").green);
                    return;
                });                
            });
        });
    }

    if (self._state["pio.service"].enabled === false) {
        console.log(("Skip publish for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        return Q.resolve(null);
    }

    return callPlugins(self, "publish", self._state).then(function(state) {

        console.log(("Publish of '" + self._state["pio.service"].id + "' done!").green);

        return state;
    });
}

