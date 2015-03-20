
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
const OPENSSL = require("./lib/openssl");
const SPAWN = require("child_process").spawn;
const DIRSUM = require("dirsum");
const FSWALKER = require("./lib/fswalker");
const EXEC = require("child_process").exec;
const NET = require("net");
const WAITFOR = require("waitfor");
const GLOB = require("glob");
const SMI = require("smi.cli");
const ESCAPE_REGEXP_COMPONENT = require("escape-regexp-component");



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


    // A hash that is affected by all properties describing the specific instance
    // we are interacting with as well as `PIO_SEED_SALT`, `PIO_SEED_KEY`, `PIO_USER_ID` and `PIO_USER_SECRET`.
    // It is NOT tied to a specific VM (i.e. IP).
    self._makeInstanceId = function () {
        var shasum = CRYPTO.createHash("sha1");
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
            console.error(("You probably forgot to run 'source bin/activate.sh' if you have configured the instance already?").red);
            throw true;
        }            
        shasum.update([
            "instance-id",
            process.env.PIO_SEED_SALT,
            process.env.PIO_SEED_KEY,
            process.env.PIO_USER_ID,
            process.env.PIO_USER_SECRET,
            self._config.config.pio.domain,
            self._config.config.pio.namespace
        ].join(":"));
        return shasum.digest("hex");
    }

    // A hash that is affected by all properties describing the specific instance
    // we are interacting with as well as `PIO_SEED_SALT`, `PIO_SEED_KEY`, `PIO_USER_ID` and `PIO_USER_SECRET`.
    // It is NOT tied to a specific VM (i.e. IP).
    self._instanceHash = function (parts) {
        var shasum = CRYPTO.createHash("sha1");
        shasum.update([
            "instance-hash",
            self._config.config.pio.instanceId
        ].concat(parts).join(":"));
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
                                basePath: PATH.join(self._configPath, ".."),
                                resolve: true
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
                                combinedDescriptor = DEEPMERGE(combinedDescriptor, catalogDescriptor || {});
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
                            basePath: PATH.join(path, ".."),
                            resolve: false
                        }, function(err, config) {
                            if (err) return callback(err);

                            self._configOriginal = config;

                            return SMI.readDescriptor(path, {
                                basePath: PATH.join(path, ".."),
                                resolve: true
                            }, function(err, config) {
                                if (err) return callback(err);

                                self._config = config;

                                return callback(null);
                            });

/*
                            path = path.replace(/\.json$/, ".1.json");
                            return FS.exists(path, function(exists) {
                                if (!exists) {
                                    return callback(null);
                                }
                                return SMI.readDescriptor(path, {
                                    basePath: PATH.join(path, ".."),
                                    resolve: true
                                }, function(err, _config) {
                                    if (err) return callback(err);
                                    
                                    self._config = DEEPMERGE(self._config, _config);
                                    return callback(null);
                                });
*/
/*
                                return FS.readJson(path, function(err, _config) {
                                    if (err) return callback(err);
                                    self._config = DEEPMERGE(self._config, _config);
                                    return callback(null);
                                });
*/
//                            });
                        });
                    })();
                }

                return load(path).then(function() {
                    self._configPath = path;
                    self._rtConfigPath = path.replace(/\.json$/, ".rt.json");
                    self._workspaceProfilePath = process.env.PIO_PROFILE_PATH || null;

                    if (!self._config) return Q.resolve(null);

                    function mergeCatalogDescriptors() {
                        if (!self._config || !self._config.upstream) {
                            return Q.resolve();
                        }
                        return ensureUpstream().then(function(catalogDescriptor) {
                            delete catalogDescriptor.name;
                            delete catalogDescriptor.uuid;
                            delete catalogDescriptor.revision;
                            delete catalogDescriptor.packages;
                            for (var name in catalogDescriptor) {
                                self._config[name] = DEEPMERGE(catalogDescriptor[name], self._config[name] || {});
                            }
                        });
                    }

                    return mergeCatalogDescriptors().then(function() {
                        var services = {};

                        function locateServices() {
                            if (!self._config) return Q.resolve(null);
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
                                        var serviceId = filepath.split("/").pop();
                                        if (
                                            services[serviceId] &&
                                            serviceId === PATH.basename(PATH.join(basePath, filepath))
                                        ) return;
                                        services[serviceId] = PATH.join(basePath, filepath);
                                    });
//console.log("services", services);                                    
                                    self._locatedServices = services;
                                    return;
                                });
                            });
                        }

                        return locateServices().then(function() {

                            function unlock() {
                                if (
                                    !self._config ||
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
                                    //console.log("Skip loading profile as we are using a consolidated pio descriptor (" + self._configPath + ").");
                                    verify();
//                                    ASSERT.equal(typeof self._config.config.pio.epochId, "string", "'config.pio.epochId' must be set in: " + self._configPath);
//                                    ASSERT.equal(typeof self._config.config.pio.seedId, "string", "'config.pio.seedId' must be set in: " + self._configPath);
//                                    ASSERT.equal(typeof self._config.config.pio.dataId, "string", "'config.pio.dataId' must be set in: " + self._configPath);
//                                    ASSERT.equal(typeof self._config.config.pio.codebaseId, "string", "'config.pio.codebaseId' must be set in: " + self._configPath);
//                                    ASSERT.equal(typeof self._config.config.pio.userId, "string", "'config.pio.userId' must be set in: " + self._configPath);
                                    ASSERT.equal(typeof self._config.config.pio.instanceId, "string", "'config.pio.instanceId' must be set in: " + self._configPath);
                                    ASSERT.equal(typeof self._config.config.pio.hostname, "string", "'config.pio.hostname' must be set in: " + self._configPath);
                                    return;
                                }

                                function loadProfile() {
                                    return Q.resolve();
/*
NOTE: No longer used.                                    
                                    if (!self._config.config.pio.profile) {
                                        return Q.resolve();
                                    }
                                    var path = PATH.join(self._configPath, "..", "pio." + self._config.config.pio.profile + ".json");
//                                  console.log("Using profile:", path);
                                    return Q.denodeify(FS.readJson)(path).then(function(profile) {
                                        self._profilePath = path;
                                        self._config = DEEPMERGE(self._config, profile);
                                    });
*/
                                }

                                return loadProfile().then(function() {

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

                                        // TODO: Inherit more runtime values to set defaults if available.
                                        if (runtimeConfig && runtimeConfig.config) {
                                            if (runtimeConfig.config["pio.vm"]) {
                                                if (runtimeConfig.config["pio.vm"].ip) {
                                                    self._config.config["pio.vm"].ip = runtimeConfig.config["pio.vm"].ip;
                                                }
                                            }
                                        }

                                        // TODO: Remvoe this when we use dynamic config system.
                                        var configStr = JSON.stringify(self._config.config);
                                        var finalConfigString = configStr;
                                        var re = /\{\{env\.([^\}]+)\}\}/g;
                                        var m = null;
                                        while (m = re.exec(configStr)) {
                                            if (typeof process.env[m[1]] === "string") {
                                                finalConfigString = finalConfigString.replace(new RegExp(ESCAPE_REGEXP_COMPONENT(m[0]), "g"), process.env[m[1]]);
                                            }
                                        }
                                        configStr = finalConfigString;

                                        /*
                                        configStr = configStr.replace(/\{\{env\.DNSIMPLE_EMAIL\}\}/g, process.env.DNSIMPLE_EMAIL);
                                        configStr = configStr.replace(/\{\{env\.DNSIMPLE_TOKEN\}\}/g, process.env.DNSIMPLE_TOKEN);
                                        configStr = configStr.replace(/\{\{env\.AWS_ACCESS_KEY\}\}/g, process.env.AWS_ACCESS_KEY);
                                        configStr = configStr.replace(/\{\{env\.AWS_SECRET_KEY\}\}/g, process.env.AWS_SECRET_KEY);
                                        configStr = configStr.replace(/\{\{env\.LEGACY_AWS_ACCESS_KEY\}\}/g, process.env.LEGACY_AWS_ACCESS_KEY);
                                        configStr = configStr.replace(/\{\{env\.LEGACY_AWS_SECRET_KEY\}\}/g, process.env.LEGACY_AWS_SECRET_KEY);
                                        configStr = configStr.replace(/\{\{env\.DIGIO_CLIENT_ID\}\}/g, process.env.DIGIO_CLIENT_ID);
                                        configStr = configStr.replace(/\{\{env\.DIGIO_API_KEY\}\}/g, process.env.DIGIO_API_KEY);
                                        configStr = configStr.replace(/\{\{env\.PIO_PROFILE_KEY\}\}/g, process.env.PIO_PROFILE_KEY);                                        
                                        configStr = configStr.replace(/\{\{env\.PIO_PROFILE_SECRET\}\}/g, process.env.PIO_PROFILE_SECRET);
                                        */
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

                                        c.instance = c.instance || "0";

                                        c.instanceId = c.instanceId || self._makeInstanceId();

                                        c.hostname = c.hostname || [c.namespace, "-", "i" + c.instanceId.substring(0, 7), "-", c.instance, ".", c.domain].join("");

                                        var keyFilename = null;
                                        if (c.keyPath && typeof c.keyPath === "string") {
                                            // TODO: Add fingerprint to key id?
                                            self._config.config["pio.vm"].keyId = PATH.basename(c.keyPath);
                                        }

                                        c.keyPath = (
                                                        c.keyPath &&
                                                        c.keyPath.replace(/^~\//, ((process.env.HOME || "/home/ubuntu") + "/"))
                                                    ) ||
                                                    ((process.env.HOME || "/home/ubuntu") + "/.ssh/" + c.hostname);

                                        function getPublicKey(verify) {
                                            var deferred = Q.defer();
                                            function ensurePublicKey() {
                                                var pubKeyPath = c.keyPath + ".pub";
                                                return FS.exists(pubKeyPath, function(exists) {
                                                    if (exists) {
                                                        return FS.readFile(pubKeyPath, "utf8", function(err, data) {
                                                            if (err) return deferred.reject(err);
                                                            return deferred.resolve(data.match(/^(\S+\s+\S+)(\s+\S+)?\n?$/)[1]);
                                                        });
                                                    }
                                                    if (verify === "public") {
                                                        return deferred.reject(new Error("Still no public key after export!"));
                                                    }
                                                    console.log(("Generating public key from private key '" + c.keyPath + "' and store at: " + pubKeyPath).magenta);
                                                    return SSH.exportPublicKeyFromPrivateKey(c.keyPath, pubKeyPath).then(function() {
                                                        return getPublicKey("public");
                                                    }).then(deferred.resolve).fail(deferred.reject);
                                                });
                                            }
                                            function generateKeys () {
                                                return OPENSSL.generateKeys({
                                                    path: c.keyPath
                                                }).then(function() {
                                                    return getPublicKey("private");
                                                }).then(deferred.resolve).fail(deferred.reject);                                                
                                            }
                                            FS.exists(c.keyPath, function(keyExists) {
                                                if (keyExists) {
                                                    return ensurePublicKey();
                                                } else {
                                                    if (verify === "private") {
                                                        return deferred.reject(new Error("Still no private key after trying to create it!"));
                                                    }
                                                    if (!process.env.PIO_PROFILE_KEY) {
                                                        return generateKeys();
                                                    }
                                                    c.keyPath = (process.env.HOME || "/home/ubuntu") + "/.ssh/" + process.env.PIO_PROFILE_KEY;
                                                    return FS.exists(c.keyPath, function(keyExists) {
                                                        if (keyExists) {
                                                            return ensurePublicKey();
                                                        } else {
                                                            return generateKeys();
                                                        }
                                                    });
                                                }
                                            });
                                            return deferred.promise;
                                        }

                                        return getPublicKey().then(function(publicKey) {
                                            c.keyPub = publicKey;

                                            // TODO: Use parser that will always discard optional data.
                                            var privateKeySegment = FS.readFileSync(c.keyPath, "utf8").match(/---\n([\S\s]+)\n---/)[1].replace(/\n/g, "").substring(0, 256);
                                            var instanceSecret = CRYPTO.createHash("sha1");
                                            instanceSecret.update(["instance-secret", c.instanceId, privateKeySegment].join(":"));
                                            c.instanceSecret = instanceSecret.digest("hex");

                                            function replaceWithinProperty(name) {
                                                if (!self._config[name]) return;
                                                var configStr = JSON.stringify(self._config[name]);
                                                configStr = configStr.replace(/\{\{config\.pio\.hostname\}\}/g, c.hostname);
                                                configStr = configStr.replace(/\{\{config\.pio\.domain\}\}/g, c.domain);
                                                configStr = configStr.replace(/\{\{config\['pio\.vm'\]\.ip\}\}/g, self._config.config['pio.vm'].ip);
                                                configStr = configStr.replace(/\{\{config.pio.namespace\}\}/g, self._config.config['pio'].namespace);
                                                configStr = configStr.replace(/\{\{config\.pio\.keyPub\}\}/g, c.keyPub);
                                                configStr = configStr.replace(/\{\{env.USER\}\}/g, process.env.USER);
                                                self._config[name] = JSON.parse(configStr);
                                            }

                                            replaceWithinProperty("config");
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

                function determineDescriptorPath(callback) {
                    var packageDescriptorPath = PATH.join(seedPath, "package.json");
                    return FS.exists(packageDescriptorPath, function(exists) {
                        if (!exists) {
                            return callback(null, null);
                        }
                        return FS.readJson(packageDescriptorPath, function(err, descriptor) {
                            if (err) return callback(err);
                            if (
                                descriptor &&
                                descriptor.config &&
                                descriptor.config['pio'] &&
                                descriptor.config['pio'].descriptorPath
                            ) {
                                return callback(null, PATH.join(seedPath, descriptor.config['pio'].descriptorPath));
                            }
                            return callback(null, null);
                        });
                    });
                }

                return determineDescriptorPath(function(err, descriptorPath) {
                    if (err) return callback(err);

                    if (descriptorPath) {
                        return loadConfig(descriptorPath).then(function() {
                            return callback(null);
                        }).fail(callback);                        
                    } 

                    // TODO: We should be using meta data to resolve this path if we have some.
                    return FS.exists(PATH.join(seedPath, "pio.json"), function(exists) {
                        if (exists) {
                            return loadConfig(PATH.join(seedPath, "pio.json")).then(function() {
                                return callback(null);
                            }).fail(callback);
                        }
                        return FS.exists(PATH.join(seedPath, ".pio.json"), function(exists) {
                            if (exists) {
                                return loadConfig(PATH.join(seedPath, ".pio.json")).then(function() {
                                    return callback(null);
                                }).fail(callback);
                            }
                            return FS.exists(PATH.join(seedPath, "../.pio.json"), function(exists) {
                                if (exists) {
                                    return loadConfig(PATH.join(seedPath, "../.pio.json")).then(function() {
                                        return callback(null);
                                    }).fail(callback);
                                }

                                // Locate parent config and select service assuming we are loading config
                                // for a dev package.
                                function loadDevConfig(path, selector, callback) {
                                    return loadConfig(path).then(function() {

                                        if (!self._config) {
                                            return callback("You don't appear to be at the root of a pio system project. Your current path is: " + process.cwd());
                                        }

                                        self._config.config["pio.cli.local"].plugins = {
                                            "ensure": [
                                                "service:pio.service/module:pio.cli.local.ensure.plugin"
                                            ]
                                        };
                                        return self.ensure(selector);
                                    }).then(function() {
                                        return callback(null);
                                    }).fail(callback);
                                }

                                return loadDevConfig(PATH.join(seedPath, "../../../pio.json"), PATH.basename(seedPath), callback);
                            });
                        });
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

PIO.prototype._updateWorkspaceProfile = function(changes) {
    var self = this;
    if (!self._workspaceProfilePath) {
        console.log("Warning: Ignoring workspace profile update as 'self._workspaceProfilePath' not set!");
        return Q.resolve();
    }
    return Q.denodeify(FS.readJson)(self._workspaceProfilePath).then(function(profile) {
        // TODO: Display diff before writing. This could be implemented generically in an FS layer that shows diffs when overwiring JSON files.
        profile = DEEPMERGE(profile, changes);
        return Q.denodeify(FS.outputFile)(self._workspaceProfilePath, JSON.stringify(profile, null, 4)).then(function() {
            return (self._ready = self._load());
        });
    });
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


function locateServices(pio, options) {
    var services = {};
    var serviceGroups = {};
    for (var serviceGroup in pio._config.services) {
        Object.keys(pio._config.services[serviceGroup]).forEach(function(serviceId) {
            if (pio._config.services[serviceGroup][serviceId] === null) {
                return;
            }
            if (serviceGroups[serviceId]) {
                throw new Error("Cannot redeclare service '" + serviceId + "' in group '" + serviceId + "'. It is already declared in '" + serviceGroups[serviceId] + "'");
            }
            serviceGroups[serviceId] = serviceGroup;
        });
    }
    return Q.denodeify(function(callback) {
        var waitfor = WAITFOR.parallel(function(err) {
            if (err) return callback(err);
            return callback(null, services);
        });
        for (var serviceId in pio._locatedServices) {
            if (serviceGroups[serviceId]) {
                services[serviceId] = {
                    group: serviceGroups[serviceId],
                    path: pio._locatedServices[serviceId],
                    descriptor: DEEPCOPY(pio._config.services[serviceGroups[serviceId]][serviceId])
                };
                if (typeof services[serviceId].descriptor.enabled === "undefined") {
                    services[serviceId].enabled = true;
                } else {
                    services[serviceId].enabled = services[serviceId].descriptor.enabled;
                }
                waitfor(serviceId, function(serviceId, callback) {

                    return SMI.readDescriptor(PATH.join(pio._locatedServices[serviceId], "package.json"), {
                        basePath: pio._locatedServices[serviceId],
                        resolve: true
                    }, function(err, _descriptor) {
                        if (err) return callback(err);
                        if (!_descriptor) return callback(null);

                        services[serviceId].descriptor = DEEPMERGE(_descriptor, services[serviceId].descriptor);
                        if (
                            serviceGroups[serviceId] &&
                            pio._configOriginal &&
                            pio._configOriginal.services &&
                            pio._configOriginal.services[serviceGroups[serviceId]] &&
                            pio._configOriginal.services[serviceGroups[serviceId]][serviceId]
                        ) {
                            services[serviceId].descriptor._raw = DEEPMERGE(_descriptor, pio._configOriginal.services[serviceGroups[serviceId]][serviceId]);
                        } else {
                            // TODO: This needs to come from the catalog instead of using the resolved info here!
                            services[serviceId].descriptor._raw = DEEPMERGE(_descriptor, services[serviceId].descriptor);
                        }

                        return callback(null);
                    });
                });
            }
        }
        return waitfor();
    })();
}

// @source https://github.com/c9/architect/blob/567b7c034d7644a2cc0405817493b451b01975fa/architect.js#L332
function orderServices(services) {
    var plugins = [];
    var pluginsById = {};
    for (var serviceId in services) {
        pluginsById[serviceId] = {
            packagePath: services[serviceId].path,
            provides: [ serviceId ],
            consumes: (services[serviceId].descriptor && services[serviceId].descriptor.depends) || [],
            id: serviceId
        }
        plugins.push(JSON.parse(JSON.stringify(pluginsById[serviceId])));
    }
    var resolved = {};
    var changed = true;
    var sorted = [];

    while(plugins.length && changed) {
        changed = false;

        plugins.concat().forEach(function(plugin) {
            var consumes = plugin.consumes.concat();

            var resolvedAll = true;
            for (var i=0; i<consumes.length; i++) {
                var service = consumes[i];
                if (!resolved[service]) {
                    resolvedAll = false;
                } else {
                    plugin.consumes.splice(plugin.consumes.indexOf(service), 1);
                }
            }

            if (!resolvedAll)
                return;

            plugins.splice(plugins.indexOf(plugin), 1);
            plugin.provides.forEach(function(service) {
                resolved[service] = true;
            });
            sorted.push(plugin.id);
            changed = true;
        });
    }

    if (plugins.length) {
        var unresolved = {};
        plugins.forEach(function(plugin) {
            delete plugin.config;
            plugin.consumes.forEach(function(name) {
                if (unresolved[name] == false) {
                    return;
                }
                if (!unresolved[name]) {
console.log("unresolved", name, "for", plugin);
                    unresolved[name] = [];
                }
                unresolved[name].push(plugin.packagePath);
            });
            plugin.provides.forEach(function(name) {
                unresolved[name] = false;
            });
        });

        Object.keys(unresolved).forEach(function(name) {
            if (unresolved[name] == false)
                delete unresolved[name];
        });

        console.error("services", Object.keys(services).length, services);
        console.error("Could not resolve dependencies of these plugins:", plugins);
        console.error("Resolved services:", Object.keys(resolved));
        console.error("Missing services:", unresolved);
        console.log("NOTICE: Did you declare '" + Object.keys(unresolved) + "' in 'services' config?");

        function showChildHierarchy (pkgId, pkg, level) {
            if (!level) level = 0;
            if (!pkg) {
                console.log("Package '" + pkgId + "' not found!");
                return;
            }
            var prefix = [];
            for (var i=0 ; i<level ; i++) {
                prefix.push("  ");
            }
            console.log(prefix.join("") + pkg.id);
            if (!pkg.consumes) return;
            pkg.consumes.forEach(function (pkgId) {
                return showChildHierarchy(pkgId, pluginsById[pkgId], level + 1);
            });
        }
        console.log("Service hierarchy:");
        Object.keys(unresolved).forEach(function (pkgId) {
            showChildHierarchy(pkgId, pluginsById[pkgId]);
        });

        throw new Error("Could not resolve dependencies");
    }
    return sorted;
}

PIO.prototype.locate = function(serviceSelector) {
    var self = this;
    return Q.denodeify(function(callback) {
        return SMI.locateUpstreamPackages(self._config, function(err, packages) {
            if (err) return callback(err);
            if (!serviceSelector) {
                return callback(null, packages);
            }
            if (!packages[serviceSelector]) {
                return callback(null, null);
            }
            return callback(null, packages[serviceSelector]);
        });
    })();
}

PIO.prototype.ensure = function(serviceSelector, options) {
    var self = this;
    if (self._state && self._state["pio.cli.local"].serviceSelector === serviceSelector) {
        return Q.resolve(self._state);
    }
    options = options || {
        force: (self._state && self._state["pio.cli.local"] && self._state["pio.cli.local"].force) || false,
        debug: (self._state && self._state["pio.cli.local"] && self._state["pio.cli.local"].debug) || false,
        verbose: (self._state && self._state["pio.cli.local"] && (self._state["pio.cli.local"].verbose || self._state["pio.cli.local"].debug)) || false,
        silent: (self._state && self._state["pio.cli.local"] && self._state["pio.cli.local"].silent) || false
    }
    return locateServices(self, options).then(function(services) {
        var state = options.state || {};
        delete options.state;
        state = DEEPMERGE({
            "pio.cli.local": {
                serviceSelector: serviceSelector || null,
                force: options.force,
                debug: options.debug,
                verbose: options.verbose,
                silent: options.silent
            },
            "pio": DEEPMERGE(DEEPCOPY(self._config.config["pio"]), {}),
            "pio.vm": DEEPCOPY(self._config.config["pio.vm"]),
            "pio.services": {
                "services": services,
                "order": orderServices(services)
            }
        }, state);
        return callPlugins(self, "ensure", state, options).then(function(state) {
            // We can proceed if everything is ready or we are not waiting
            // on required services.
            var repeat = false;
            for (var alias in state) {
                if (
                    state[alias] &&
                    typeof state[alias] === "object" &&
                    typeof state[alias][".status"] !== "undefined"
                ) {
                    if (state[alias][".status"] === "repeat") {
                        console.log(("Service is asking for ensure to repeat: " + JSON.stringify({
                            "alias": alias,
                            "state": state[alias]
                        }, null, 4)).cyan);
                        repeat = true;
                    } else
                    if (state[alias][".status"] !== "ready" &&
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
    });
}

PIO.prototype.list = function() {
    var self = this;
    return self._ready.then(function() {
        var services = [];
        self._state["pio.services"].order.forEach(function(serviceId) {
            services.push({
                group: self._state["pio.services"].services[serviceId].group,
                id: serviceId,
                path: self._state["pio.services"].services[serviceId].path,
                pathReal: FS.realpathSync(self._state["pio.services"].services[serviceId].path),
                enabled: self._state["pio.services"].services[serviceId].enabled
            });
        });
        return services;
    });
}

function repeat(worker, failIsGood) {
    function check() {
        function again() {
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

PIO.prototype.deploy = function(options) {
    var self = this;

    options = options || {};

    if (!self._state["pio.cli.local"].serviceSelector) {
        // Deploy all services.
        return self._ready.then(function() {
            if (self._state["pio.cli.local"].verbose) {
                console.log("Deploying services sequentially according to 'depends' order:".cyan);
            }
            var done = Q.resolve();
            self._state["pio.services"].order.forEach(function(serviceId, serviceIndex) {
                done = Q.when(done, function() {
                    return self.ensure(serviceId).then(function() {
                        var opts = {};
                        for (var name in options) {
                            opts[name] = options[name];
                        }
                        opts.index = serviceIndex + 1;
                        opts.count = self._state["pio.services"].order.length;
                        return self.deploy(opts).then(function() {
                            return self._state["pio.deploy"]._ensure().then(function(_response) {
                                if (_response[".status"] === "ready") {
                                    if (self._state["pio.cli.local"].verbose) {
                                        console.log("Switching to using dnode transport where possible!".green);
                                    }
                                }
                                return;
                            });
                        });
                    });
                });
            });
            return done;
        });
    }

    if (self._state["pio.service"].enabled === false) {
        if (self._state["pio.cli.local"].verbose) {
            console.log(("Skip deploy for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        }
        return Q.resolve(null);
    }

    if (self._state["pio.cli.local"].verbose) {
        console.log(("VM login:", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=" + self._state["pio"].keyPath + " " + self._state["pio.vm"].user + "@" + self._state["pio.vm"].ip).bold);
    }

    if (options.buildCache === false) {
        self._state["pio.cli.local"].buildCache = false;
    } else {
        self._state["pio.cli.local"].buildCache = true;
    }

    var optionalMessage = "";
    if (options.index) {
        optionalMessage = " (" + options.index + "/" + options.count + ")";
    }
    console.log(("[pio] ensure SYNCED".bold + " " + self._state["pio.service"].id + optionalMessage).cyan);

    return callPlugins(self, "deploy", self._state).then(function(state) {

        if (state["pio.cli.local"].verbose) {
            console.log(("Deploy '" + self._state["pio.service"].id + "' done!").green);
        }

        return state;
    }).then(function(state) {
        if (state["pio.deploy"][".status"] !== "done") {
            if (state["pio.cli.local"].verbose) {
                console.log(("Skip confirming service is working using status call as we did not deploy service.").yellow);
            }
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

PIO.prototype.config = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        return Q.resolve(self._config);
    }

    return self._state["pio.deploy"]._call("config", {
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

PIO.prototype.info = function() {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {

        // TODO: Encode IP into auth code so it is not usable by others.
        var authCode = CRYPTO.createHash("sha1");
        authCode.update(["auth-code", self._state.pio.instanceId, self._state.pio.instanceSecret].join(":"));

        var env = Object.create({
        });
        env.PATH = process.env.PATH;
        env.PIO_PROFILE_PATH = process.env.PIO_PROFILE_PATH;

        var paths = Object.create({
        });
        paths.workspaceRoot = PATH.dirname(self._configPath);
        paths.activationFile = PATH.join(paths.workspaceRoot, "../", PATH.basename(paths.workspaceRoot) + ".activate.sh");
        paths.profileFile = process.env.PIO_PROFILE_PATH;
        paths.configFile = self._configPath;
        paths.keyPath = self._state["pio"].keyPath;

        var variables = Object.create({
            adminAuthCode: authCode.digest("hex")
        });
        variables.hostname = self._state["pio"].hostname;
        variables.ip = self._config.config["pio.vm"].ip;

        var commands = Object.create({
            open: null
        });
        commands.login = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=" + self._state["pio"].keyPath + " " + self._state["pio.vm"].user + "@" + self._state["pio.vm"].ip
        var urls = Object.create({
            admin: null
        });
        urls.server = "http://" + variables.hostname;
        if (
            self._state['pio.dns'] &&
            self._state['pio.dns'][".status"] === "ready"
        ) {
//            console.log("Using hostname '" + variables.hostname + "' to open admin as DNS is resolving to ip '" + variables.ip + "'.");
            urls.__proto__.admin = 'http://' + variables.hostname + ':' + self._config.services["0-pio"]["pio.server"].env.PORT + '?auth-code=' + variables.adminAuthCode;
        } else {
//            console.log("Using ip '" + variables.ip + "' to open admin as DNS hostname '" + variables.hostname + "' is NOT resolving.");
            urls.__proto__.admin = 'http://' + variables.ip + ':' + self._config.services["0-pio"]["pio.server"].env.PORT + '?auth-code=' + variables.adminAuthCode;
        }
        commands.__proto__.open = 'open "' + urls.admin + '"';

        // NOTE: This format is going to change.
        return Q.resolve({
            env: env,
            paths: paths,
            variables: variables,
            commands: commands,
            urls: urls
        });
    }

    return Q.reject(new Error("'info' for service not yet implemented"));
}

PIO.prototype.open = function() {
    var self = this;
    return self.info().then(function(info) {
        var deferred = Q.defer();
        console.log(("Calling command: " + info.commands.open).magenta);
        console.log("NOTE: If this does not exit it needs to be fixed for your OS.");
        return EXEC(info.commands.open, function(err, stdout, stderr) {
            if (err) {
                console.error(stdout);
                console.error(stderr);
                return deferred.reject(err);
            }
            console.log("Browser opened!");
            return deferred.resolve();
        });
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

PIO.prototype.run = function (options) {
    var self = this;

    if (!self._state["pio.cli.local"].serviceSelector) {
        return Q.reject(new Error("Service must be set!"));
    }

    if (self._state["pio.service"].enabled === false && !(self._state["pio.cli.local"].serviceSelector && options.local)) {
        console.log(("Skip run for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        return Q.resolve(null);
    }

    if (options.local) {

        // TODO: Detect how tests should be run and don't always assume npm.

        function npmRun(callback) {
            var basePath = self._state["pio.service"].originalPath;

            var command = "npm start";
            if (self._state["pio.service"].scripts.run) {
                command = "npm run-script run";
            }

            var env = {};
            for (var name in process.env) {
                env[name] = process.env[name];
            }
            for (var name in self._state["pio.service"].env) {
                env[name] = self._state["pio.service"].env[name];
            }

            if (options.dev) {
                // POLICY: Setting `DEV` environment variable (initially to `1`) enables
                //         debug mode which enables debugging and loads original sources just in time.
                env.DEV = "1";
            }

            if (options.deeperArgs && options.deeperArgs.length > 0) {
                command += " -- " + options.deeperArgs.join(" ");
            }

            console.log(("Calling `" + command + "` (cwd: " + basePath + ")").magenta);

            var proc = SPAWN(command.split(" ").shift(), command.split(" ").slice(1), {
                cwd: basePath,
                env: env,
                stdio: "inherit"
            });
            return proc.on('close', function (code) {
                if (code !== 0) {
                    console.error("ERROR: `" + command + "` exited with code '" + code + "'");
                    return callback(new Error("`" + command + "` script exited with code '" + code + "'"));
                }
                console.log(("`" + command + "` for '" + basePath + "' done!").green);
                return callback(null, {success: true});
            });
        }

        function runCycle (count) {

            // TODO: Instead of scheduling window to open on timer we should be listening
            //       for output from NPM and open browser once server is announced started.
            function openBrowser () {
                if (count > 0) return Q.resolve();
                if (!options.open) return Q.resolve();
                var deferred = Q.defer();
                setTimeout(function () {
                    // TODO: Only open if not already open.
                    // TODO: Optionally close browser when `run` call ends.
                    ASSERT.notEqual(typeof self._state["pio.service"].env.PORT, "undefined", "self._state['pio.service'].env.PORT' must be set");
                    var command = "open http://localhost:" + self._state["pio.service"].env.PORT + "/";
                    console.log(("Calling command: " + command).magenta);
                    console.log("NOTE: If this does not exit it needs to be fixed for your OS.");
                    return EXEC(command, function(err, stdout, stderr) {
                        if (err) {
                            console.error(stdout);
                            console.error(stderr);
                            return deferred.reject(err);
                        }
                        console.log("Browser opened!");
                        return deferred.resolve();
                    });
                }, 1000);
                return deferred.promise;
            }

            return openBrowser().then(function () {
                return Q.denodeify(npmRun)().fail(function (err) {
                    if (!options.cycle) throw err;
                    console.error(("Ignoring error due to cycle: " + err.stack).red);
                }).then(function() {
                    if (!options.cycle) return;
                    console.log("Running tests again in '" + options.cycle + "' seconds ...");
                    return Q.delay(options.cycle * 1000).then(function () {
                        return runCycle(count + 1);
                    });
                });
            });
        }

        return runCycle(0);
    }

    return callPlugins(self, "run", self._state).then(function(state) {

        console.log(("Run of '" + self._state["pio.service"].id + "' done!").green);

        return state;
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
    }, {
        transport: ((self._state["pio.cli.local"].serviceSelector === "pio.server") ? "ssh" : null ),
        pio: self
    }).then(function(response) {
        if (!response) {
            throw new Error("Remote commands exited with no response");
        }
        if (response.code !== 0)  {
            throw new Error("Remote commands exited with code: " + response.code);
        }

        if (self._state["pio.cli.local"].serviceSelector === "pio.server") {
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
    }, {
        transport: ((self._state["pio.cli.local"].serviceSelector === "pio.server") ? "ssh" : null ),
        pio: self
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

PIO.prototype.restart = function(options) {
    var self = this;

    options = options || {};

    if (!self._state["pio.cli.local"].serviceSelector) {
        // Restart all services.
        return self._ready.then(function() {
            if (self._state["pio.cli.local"].verbose) {
                console.log("Restarting services sequentially according to 'depends' order:".cyan);
            }
            var done = Q.resolve();
            self._state["pio.services"].order.forEach(function(serviceId, serviceIndex) {
                done = Q.when(done, function() {
                    return self.ensure(serviceId).then(function() {
                        var opts = {};
                        for (var name in options) {
                            opts[name] = options[name];
                        }
                        opts.index = serviceIndex + 1;
                        opts.count = self._state["pio.services"].order.length;
                        return self.restart(opts).then(function() {
/*                            
                            return self._state["pio.deploy"]._ensure().then(function(_response) {
                                if (_response[".status"] === "ready") {
                                    if (self._state["pio.cli.local"].verbose) {
                                        console.log("Switching to using dnode transport where possible!".green);
                                    }
                                }
                                return;
                            });
*/                            
                        });
                    });
                });
            });
            return done;
        });
    }

    if (self._state["pio.service"].enabled === false) {
        if (self._state["pio.cli.local"].verbose) {
            console.log(("Skip restart for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        }
        return Q.resolve(null);
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
    }, {
        transport: ((self._state["pio.cli.local"].serviceSelector === "pio.server") ? "ssh" : null ),
        pio: self
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

PIO.prototype.test = function(options) {
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

    if (self._state["pio.service"].enabled === false && !(self._state["pio.cli.local"].serviceSelector && options.local)) {
        console.log(("Skip test for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        return Q.resolve(null);
    }

    if (options.local) {
        // TODO: Instead of checking for local option here the declared plugin should already be swapped
        //       out so we don't need to do anything here.
        // TODO: Detect how tests should be run and don't always assume npm.

        function npmTest(callback) {
            var basePath = self._state["pio.service"].originalPath;
            console.log(("Calling `npm test` for: " + basePath).magenta);
            var proc = SPAWN("npm", [
                "test"
            ], {
                cwd: basePath
            });
            proc.stdout.on('data', function (data) {
                process.stdout.write(data);
            });
            proc.stderr.on('data', function (data) {
                process.stderr.write(data);
            });
            return proc.on('close', function (code) {
                if (code !== 0) {
                    console.error("ERROR: `npm test` exited with code '" + code + "'");
                    return callback(new Error("`npm test` script exited with code '" + code + "'"));
                }
                console.log(("`npm test` for '" + basePath + "' done!").green);
                return callback(null, {success: true});
            });
        }

        function runTestCycle() {
            return Q.denodeify(npmTest)().fail(function (err) {
                if (!options.cycle) throw err;
                console.error(("Ignoring error due to cycle: " + err.stack).red);
            }).then(function() {
                if (!options.cycle) return;
                console.log("Running tests again in '" + options.cycle + "' seconds ...");
                return Q.delay(options.cycle * 1000).then(runTestCycle);
            });
        }

        return runTestCycle();
    }

    return callPlugins(self, "test", self._state).then(function(state) {

        return (state["pio.service.test"] && state["pio.service.test"].result) || {};
    });
}

PIO.prototype.publish = function (options) {
    var self = this;

    options = options || {};

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

    if (options.local) {

        // TODO: Instead of checking for local option here the declared plugin should already be swapped
        //       out (through config) so we don't need to do anything here.
        // TODO: Detect how publish should be run and don't always assume npm.

        function npmPublish (callback) {
            var basePath = self._state["pio.service"].originalPath;
            console.log(("Calling `npm run-script publish` for: " + basePath).magenta);
            var proc = SPAWN("npm", [
                "run-script",
                "publish"
            ].concat(options.args || []), {
                cwd: basePath
            });
            proc.stdout.on('data', function (data) {
                process.stdout.write(data);
            });
            proc.stderr.on('data', function (data) {
                process.stderr.write(data);
            });
            return proc.on('close', function (code) {
                if (code !== 0) {
                    console.error("ERROR: `npm run-script publish` exited with code '" + code + "'");
                    return callback(new Error("`npm run-script publish` script exited with code '" + code + "'"));
                }
                console.log(("`npm run-script publish` for '" + basePath + "' done!").green);
                return callback(null, {success: true});
            });
        }

        function runLocalPublish() {
            return Q.denodeify(npmPublish)();
        }

        return runLocalPublish();
    }

    return callPlugins(self, "publish", self._state).then(function(state) {

        console.log(("Publish of '" + self._state["pio.service"].id + "' done!").green);

        return state;
    });
}

PIO.prototype.bundle = function (options) {
    var self = this;

    options = options || {};

    if (!self._state["pio.cli.local"].serviceSelector) {
        // Deploy all services.

        return self._ready.then(function() {

            console.log("Bundling all services:".cyan);

            var states = [];
            var done = Q.resolve();
            Object.keys(self._state["pio.services"].services).forEach(function(serviceId) {
                done = Q.when(done, function() {
                    return self.ensure(serviceId).then(function() {
                        return self.bundle().then(function(state) {
                            if (state !== null) {
                                states.push(state);
                            }
                            return;
                        });
                    });
                });
            });

            return done;
        });
    }

    if (self._state["pio.service"].enabled === false) {
        console.log(("Skip bundle for service '" + self._state["pio.service"].id + "' from group '" + self._state["pio.service"].group + "'. It is disabled!").yellow);
        return Q.resolve(null);
    }

    if (options.local) {

        // TODO: Instead of checking for local option here the declared plugin should already be swapped
        //       out (through config) so we don't need to do anything here.
        // TODO: Detect how bundle should be run and don't always assume npm.

        function npmBundle (callback) {
            var basePath = self._state["pio.service"].originalPath;
            console.log(("Calling `npm run-script bundle` for: " + basePath).magenta);
            var proc = SPAWN("npm", [
                "run-script",
                "bundle"
            ].concat(options.args || []), {
                cwd: basePath
            });
            proc.stdout.on('data', function (data) {
                process.stdout.write(data);
            });
            proc.stderr.on('data', function (data) {
                process.stderr.write(data);
            });
            return proc.on('close', function (code) {
                if (code !== 0) {
                    console.error("ERROR: `npm run-script bundle` exited with code '" + code + "'");
                    return callback(new Error("`npm run-script bundle` script exited with code '" + code + "'"));
                }
                console.log(("`npm run-script bundle` for '" + basePath + "' done!").green);
                return callback(null, {success: true});
            });
        }

        function runLocalBundle() {
            return Q.denodeify(npmBundle)();
        }

        return runLocalBundle();
    }

    return callPlugins(self, "bundle", self._state).then(function(state) {

        console.log(("Bundle of '" + self._state["pio.service"].id + "' done!").green);

        return state;
    });
}

PIO.prototype.terminate = function(ip) {
    var self = this;

    self._state["pio.cli.local"].ip = ip;

    // Cache values now as they may change after termination completes.
    var message = "Termination of " + self._state["pio.vm"].ip + " (" + self._state["pio"].hostname + ") done!";

    return callPlugins(self, "terminate", self._state).then(function(state) {

        console.log((message).green);

        return state;
    });
}


PIO.forPackage = function(basePath) {
    if (PATH.basename(basePath) === "live") {
        basePath = PATH.dirname(basePath);
    }
    var pio = new PIO(basePath);
    return pio.ready().then(function() {
        return pio;
    });
}

