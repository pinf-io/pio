
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
const REQUEST = require("request");
const RSYNC = require("./lib/rsync");
const SSH = require("./lib/ssh");

COLORS.setTheme({
    error: 'red'
});


var PIO = module.exports = function(sourcePath, targetUri) {
    var self = this;

    self._call = function(method, args, progress) {
        var deferred = Q.defer();
        var client = DNODE(progress || {});
        client.on("error", deferred.reject);
        // TODO: Handle these failures better?
        client.on("fail", console.error);
        client.on("remote", function (remote) {
            return remote[method](args, function (errStack, response) {
                if (errStack) {
                    var err = new Error("Got remote error");
                    err.stack = errStack;
                    return deferred.reject(err);
                }
                return deferred.resolve(response);
            });
        });
        client.connect(self._dnodePort, self._dnodeHostname);
        return deferred.promise;
    }

    self._ready = Q.fcall(function() {
        function resolveUri(uri) {
            var deferred = Q.defer();
            try {

                ASSERT.equal(typeof uri, "string");

                var uriParsed = URL.parse(uri);

                if (/^dnode:$/.test(uriParsed.protocol)) {

                    self._dnodeHostname = uriParsed.hostname;
                    self._dnodePort = parseInt(uriParsed.port) || 80;

                    deferred.resolve();
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
            return Q.denodeify(FS.readJson)(path).then(function(config) {
                self._configPath = path;
                self._config = config;
                self._config.config = DEEPMERGE(self._config.config || {}, self._config["config[cloud=" + self._config.cloud + "]"] || {});
                for (var key in self._config) {
                    if (/^config\[cloud=.+\]$/.test(key)) {
                        delete self._config[key];
                    }
                }
            });
        }
        return loadConfig(PATH.join(sourcePath, "pio.json")).then(function() {
//        return resolveUri(targetUri).then(function() {
//            ASSERT.equal(typeof self._dnodeHostname, "string");
//            ASSERT.equal(typeof self._dnodePort, "number");            
        });
    });
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

PIO.prototype.deploy = function(serviceAlias, options) {
    var self = this;
     options = options || {};
    // TODO: Only deploy if source has changed (call server to check hash)
    //       or if force is set.
    return self._ready.then(function() {
        if (!self._config.provides || !self._config.provides[serviceAlias]) {
            throw ("Service with alias '" + serviceAlias + "' not found in 'pio.json ~ provides[" + serviceAlias + "]'!");
        }
        var serviceConfig = self._config.provides[serviceAlias];

        ASSERT.equal(typeof self._config.config.pio.hostname, "string");
        ASSERT.equal(typeof self._config.config.pio.keyPath, "string");
        ASSERT.equal(typeof self._config.config.pio.user, "string");
        ASSERT.equal(typeof self._config.config.pio.servicesPath, "string");
        ASSERT.equal(typeof self._config.config.pio.targetBasePath, "string");

        var sourcePath = null;
        if (serviceConfig.sourcePath) {
            sourcePath = PATH.join(self._configPath, "..", serviceConfig.sourcePath);
        } else {
            sourcePath = PATH.join(self._configPath, "..", self._config.config.pio.servicesPath, serviceAlias);
        }
        if (!FS.existsSync(sourcePath)) throw new Error("Source path '" + sourcePath + "' does not exist!");

        var targetPath = null;
        if (serviceConfig.targetPath) {
            targetPath = serviceConfig.targetPath;
        } else {
            targetPath = PATH.join(self._config.config.pio.targetBasePath, serviceAlias);
        }
        var ignoreRulesPath = PATH.join(sourcePath, ".deployignore");

        serviceConfig = DEEPCOPY(serviceConfig);
        // Update service config to be relevant in new context.
        serviceConfig = JSON.stringify(serviceConfig);
        serviceConfig = serviceConfig.replace(/\{\{config.pio\.hostname\}\}/g, self._config.config.pio.hostname);
        serviceConfig = serviceConfig.replace(/\{\{config.pio\.glimpse\}\}/g, self._config.config.pio.glimpse);
        serviceConfig = JSON.parse(serviceConfig);
        delete serviceConfig.source;
        delete serviceConfig.target;
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

        console.log(("Staring service with config: " + JSON.stringify(serviceConfig, null, 4)).cyan);

        return RSYNC.sync({
            sourcePath: sourcePath,
            targetUser: self._config.config.pio.user,
            targetHostname: options.hostname || self._config.config.pio.hostname,
            targetPath: targetPath,
            keyPath: self._config.config.pio.keyPath,
            excludeFromPath: FS.existsSync(ignoreRulesPath) ? ignoreRulesPath : null
        }).then(function() {
            return SSH.uploadFile({
                targetUser: self._config.config.pio.user,
                targetHostname: options.hostname || self._config.config.pio.hostname,
                source: JSON.stringify(serviceConfig, null, 4),
                targetPath: PATH.join(targetPath, "pio.json"),
                keyPath: self._config.config.pio.keyPath
            }).then(function() {
                var commands = [];
                for (var name in self._config.env) {
                    commands.push('echo "Setting \'"' + name + '"\' to \'"' + self._config.env[name] + '"\'"');
                    commands.push('export ' + name + '=' + self._config.env[name]);
                }
                for (var name in serviceConfig.env) {
                    commands.push('echo "Setting \'"' + name + '"\' to \'"' + serviceConfig.env[name] + '"\'"');
                    commands.push('export ' + name + '=' + serviceConfig.env[name]);
                }
                commands.push('echo "Calling postdeploy script:"');
                commands.push(serviceConfig.postdeploy);
                return SSH.runRemoteCommands({
                    targetUser: self._config.config.pio.user,
                    targetHostname: options.hostname || self._config.config.pio.hostname,
                    commands: commands,
                    workingDirectory: targetPath,
                    keyPath: self._config.config.pio.keyPath
                });
            });
        });
    });
}


var pio = module.exports.pio = function() {
    return new PIO(
        process.cwd(),
        process.env.PIO_API || "http://pio.pinf.io/.well-known/pinf"
    );
}

if (require.main === module) {

    var program = new COMMANDER.Command();

    function error(err) {
        if (typeof err === "string") {
            console.error((""+err).red);
        } else {
            console.error((""+err.stack).red);
        }
        process.exit(1);
    }

    program
        .version(JSON.parse(FS.readFileSync(PATH.join(__dirname, "package.json"))).version)
        .option("-v, --verbose", "Show verbose progress")
        .option("--debug", "Show debug output");

    var acted = false;

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

    program
        .command("deploy <service alias>")
        .description("Deploy a service")
        .action(function(alias) {
            acted = true;
            return pio().deploy(alias).fail(error);
        });

    program.parse(process.argv);

    if (!acted) {
        var command = process.argv.slice(2).join(" ");
        if (command) {
            console.error(("ERROR: Command '" + process.argv.slice(2).join(" ") + "' not found!").error);
        }
        program.outputHelp();
    }
}
