
require("require.async")(require);

const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs-extra");
const Q = require("q");
const URL = require("url");
const COMMANDER = require("commander");
const COLORS = require("colors");
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

COLORS.setTheme({
    error: 'red'
});


var PIO = module.exports = function(seedPath) {
    var self = this;

    var dnodeClient = null;
    var dnodeRemote = null;
    var dnodeTimeout = null;
    self._call = function(method, args, progress) {
        if (!self._dnodePort || !self._dnodeHostname) {
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
            dnodeRemote[method](args, function (errStack, response) {
                startTimeout();
                if (errStack) {
                    var err = new Error("Got remote error");
                    err.stack = errStack;
                    return deferred.reject(err);
                }
                return deferred.resolve(response);
            });
            return deferred.promise;
        }
        if (dnodeRemote) {
            return callRemote();
        }
        var deferred = Q.defer();
        dnodeClient = DNODE(progress || {});
        dnodeClient.on("error", deferred.reject);
        // TODO: Handle these failures better?
        dnodeClient.on("fail", console.error);
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

    self._ready = Q.fcall(function() {

        function resolveUri(uri) {
            var deferred = Q.defer();
            try {

                ASSERT.equal(typeof uri, "string");

                var uriParsed = URL.parse(uri);

                if (/^dnodes?:$/.test(uriParsed.protocol)) {

                    self._dnodeHostname = uriParsed.hostname;
                    self._dnodePort = parseInt(uriParsed.port) || 8066;

                    function testConnect() {
                        var deferred = Q.defer();
                        var timeout = setTimeout(function() {
                            return deferred.reject(new Error("Timeout! Could not connect to: " + uri));
                        }, 1000);
                        var req = {
                            timeClient: Date.now()
                        }
                        self._call("ping", req).then(function(res) {
                            try {
                                ASSERT.equal(req.timeClient, res.timeClient);
                                // TODO: Track time offset.
                                clearTimeout(timeout);
                                return deferred.resolve();
                            } catch(err) {
                                return deferred.reject(err);
                            }
                        }).fail(function(err) {
                            clearTimeout(timeout);
                            return deferred.reject(err);
                        });
                        return deferred.promise;
                    }

                    return testConnect().then(deferred.resolve).fail(function(err) {
                        self._dnodeHostname = null;
                        self._dnodePort = null;
                    });
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
            console.log("Using config:", path);
            return Q.denodeify(FS.readJson)(path).then(function(config) {
                self._configPath = path;
                self._config = config;
                if (/\/\.pio\.json$/.test(path)) {
                    console.log("Skip loading profile as we are using a consolidated pio descriptor (" + path + ").");
                    return;
                }
                path = PATH.join(path, "..", "pio." + self._config.config.pio.profile + ".json");
                console.log("Using profile:", path);
                return Q.denodeify(FS.readJson)(path).then(function(profile) {

                    self._config = DEEPMERGE(self._config, profile);
/*
                    for (var key in self._config) {
                        if (/^config\[cloud=.+\]$/.test(key)) {
                            delete self._config[key];
                        }
                    }
*/

// TODO: Use `dnodes://`
                    return resolveUri("dnode://" + self._config.config.pio.publicIP + ":8066");
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

//        return loadConfig(PATH.join(seedPath, "pio.json")).then(function() {
//        return resolveUri(targetUri).then(function() {
//            ASSERT.equal(typeof self._dnodeHostname, "string");
//            ASSERT.equal(typeof self._dnodePort, "number");            
//        });
    });
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

PIO.prototype.ensure = function(desiredConfig) {
    var self = this;
    return self._ready.then(function() {
        return self._call("ensure", desiredConfig);
    });
}

PIO.prototype._provisionPrerequisites = function(options) {
    var self = this;
    options = options || {};
    // We also re-try a few times in case SSH is not yet available.
    function attempt(count) {
        count += 1;
        return SSH.runRemoteCommands({
            targetUser: self._config.config.pio.user,
            targetHostname: options.hostname || self._config.config.pio.hostname,
            commands: [
                // Make sure our user can write to the default install directory.
                "sudo chown -f " + self._config.config.pio.user + ":" + self._config.config.pio.user + " /opt",
                // Make sure some default directories exist
                'if [ ! -d "/opt/bin" ]; then mkdir /opt/bin; fi',
                'if [ ! -d "/opt/cache" ]; then mkdir /opt/cache; fi',
                'if [ ! -d "/opt/logs" ]; then mkdir /opt/logs; fi',
                // Put `/opt/bin` onto system-wide PATH.
                'sudo touch /etc/profile.d/pio.sh',
                "sudo chown -f " + self._config.config.pio.user + ":" + self._config.config.pio.user + " /etc/profile.d/pio.sh",
                'echo "export PATH=/opt/bin:\\$PATH" > /etc/profile.d/pio.sh',
                'sudo chown root:root /etc/profile.d/pio.sh'
            ],
            workingDirectory: "/",
            keyPath: self._config.config.pio.keyPath
        }).fail(function(err) {
console.log("MATCH ERROR MESSAGE [", err.message, "]");
            // TODO: Match if fails due to SSH not being up yet.
            if (/rsync exited with code '255'/.test(err.message)) {
                if (count >=5) {
                    throw new Error("Stopping after " + count + " attempts!");
                }                
                return attempt(count);
            }
            throw err;
        });
    }
    return attempt(0);
}

PIO.prototype._deployBootServices = function(options) {
    var self = this;
    var done = Q.resolve();
    self.getConfig("boot").forEach(function(service) {
        done = Q.when(done, function() {
            return self.deploy(service, options);
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

        ASSERT.equal(typeof serviceConfig.config.pio.alias, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.hostname, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.publicIP, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.keyPath, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.user, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.seedRepositories, "string");
        ASSERT.equal(typeof serviceConfig.config.pio.plantBasePath, "string");

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
            serviceConfig.config.pio.seedPath = PATH.join(self._configPath, "..", serviceConfig.config.pio.seedRepositories, serviceAlias);
        }
        if (!FS.existsSync(serviceConfig.config.pio.seedPath)) throw new Error("Source path '" + serviceConfig.config.pio.seedPath + "' does not exist!");

        if (serviceConfig.config.pio.plantPath) {
            serviceConfig.config.pio.plantPath = serviceConfig.config.pio.plantPath;
        } else {
            serviceConfig.config.pio.plantPath = PATH.join(serviceConfig.config.pio.plantBasePath, serviceAlias);
        }

        return serviceConfig;
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
                    return self.deploy(serviceAlias, options);
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
            console.log("Check if changed");
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
                var options = {};
                options.returnIgnoredFiles = true;
                options.includeDependencies = false;
                options.respectDistignore = false;
                options.respectNestedIgnore = true;
                return Q.nbind(walker.walk, walker)(options).then(function(list) {
                    syncFiletreeInfo = list;
                    var shasum = CRYPTO.createHash("sha1");
                    shasum.update(JSON.stringify(syncFiletreeInfo[0]));
                    var seedHash = shasum.digest("hex");
                    serviceConfig.config.pio.seedHash = seedHash;
                    console.log("Our seed hash: " + serviceConfig.config.pio.seedHash);
                    return self._call("status", {
                        plantPath: serviceConfig.config.pio.plantPath
                    }).then(function(status) {
                        if (!status || !status.config || !status.config.pio || !status.config.pio.seedHash) {
                            console.log("No remote seed hash!");
                            return seedHash;
                        }
                        console.log("Remote seed hash: " + status.config.pio.seedHash);
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
                                proc.stderr.on('data', function (data) {
                                    process.stderr.write(data);
                                });
                                proc.on('close', function (code) {
                                    if (code !== 0) {
                                        console.error("ERROR: Deploy script exited with code '" + code + "'");
                                        return callback(new Error("Deploy script exited with code '" + code + "'"));
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

                                    var ignoreRulesPath = PATH.join(serviceConfig.config.pio.seedPath, ".deployignore");

                                    return RSYNC.sync({
                                        sourcePath: serviceConfig.config.pio.seedPath,
                                        targetUser: serviceConfig.config.pio.user,
                                        targetHostname: serviceConfig.config.pio.publicIP,
                                        targetPath: serviceConfig.config.pio.plantPath,
                                        keyPath: serviceConfig.config.pio.keyPath,
                                        excludeFromPath: FS.existsSync(ignoreRulesPath) ? ignoreRulesPath : null
                                    }).then(function() {
                                        return SSH.uploadFile({
                                            targetUser: serviceConfig.config.pio.user,
                                            targetHostname: serviceConfig.config.pio.publicIP,
                                            source: JSON.stringify(serviceConfig, null, 4),
                                            targetPath: PATH.join(serviceConfig.config.pio.plantPath, ".pio.json"),
                                            keyPath: serviceConfig.config.pio.keyPath
                                        }).then(function() {
                                            var commands = [];
                                            for (var name in serviceConfig.env) {
                                                commands.push('echo "Setting \'"' + name + '"\' to \'"' + serviceConfig.env[name] + '"\'"');
                                                if (options.force) {
                                                    commands.push('export PIO_FORCE=' + options.force);
                                                }
                                                commands.push('export ' + name + '=' + serviceConfig.env[name]);
                                            }
                                            commands.push('echo "Calling postdeploy script:"');
                                            if (FS.existsSync(PATH.join(serviceConfig.config.pio.seedPath, "postdeploy.sh"))) {
                                                commands.push("sh postdeploy.sh");
                                            }
                                            return SSH.runRemoteCommands({
                                                targetUser: serviceConfig.config.pio.user,
                                                targetHostname: serviceConfig.config.pio.publicIP,
                                                commands: commands,
                                                workingDirectory: serviceConfig.config.pio.plantPath,
                                                keyPath: serviceConfig.config.pio.keyPath
                                            });
                                        });
                                    });
                                }

                                return defaultDeployPlugin(self, serviceConfig).then(function() {
                                    return callback(null);
                                }).fail(callback);
                            });
                        })();
                    });
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
                    PIO_PUBLIC_IP: serviceConfig.config.pio.publicIP,
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
                    PIO_PUBLIC_IP: serviceConfig.config.pio.publicIP,
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

    var pio = new PIO(process.cwd());

    function error(err) {
        if (typeof err === "string") {
            console.error((""+err).red);
        } else {
            console.error((""+err.stack).red);
        }
        process.exit(1);
    }

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
        return pio.shutdown();
    }).fail(error);
}
