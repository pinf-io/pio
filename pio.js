
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs");
const Q = require("q");
const URL = require("url");
const COMMANDER = require("commander");
const COLORS = require("colors");
const DNODE = require("dnode");
const REQUEST = require("request");

COLORS.setTheme({
    error: 'red'
});


var PIO = module.exports = function(uri) {
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
        return resolveUri(uri).then(function() {
            ASSERT.equal(typeof self._dnodeHostname, "string");
            ASSERT.equal(typeof self._dnodePort, "number");            
        });
    });
}

PIO.prototype.status = function() {
    var self = this;
    return self._ready.then(function() {
        return self._call("status", {});
    });
}

PIO.prototype.list = function(callback) {
    var self = this;
    return self._ready.then(function() {
        return self._call("list", {});
    });
}

PIO.prototype.ensure = function(desiredConfig, callback) {
    var self = this;
    return self._ready.then(function() {
        return self._call("ensure", desiredConfig);
    });
}


var pio = module.exports.pio = function() {
    return new PIO(process.env.PIO_API || "http://pio.pinf.io/.well-known/pinf");
}

if (require.main === module) {

    var program = new COMMANDER.Command();

    function error(err) {
        console.error((""+err.stack).red);
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

console.log("LIST SERVICES!", list);

            }).fail(error);
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
