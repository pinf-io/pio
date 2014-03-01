
const ASSERT = require("assert");
const Q = require("q");
const PATH = require("path");
const FS = require("fs-extra");
const SPAWN = require("child_process").spawn;


exports.sync = function (options) {
	return Q.denodeify(function (callback) {

		ASSERT.equal(typeof options, "object");
		ASSERT.equal(typeof options.sourcePath, "string");
		ASSERT.equal(typeof options.targetUser, "string");
		ASSERT.equal(typeof options.targetHostname, "string");
		ASSERT.equal(typeof options.targetPath, "string");
		ASSERT.equal(typeof options.keyPath, "string");

		console.log(("Sync source '" + options.sourcePath + "' to vm at '" + options.targetPath + "'").magenta);

		var args = [
			'-avz', '--compress',		
			'-e', 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentityFile=' + options.keyPath		
		];
		if (options.delete) {
			args.push("--delete");
		}
		if (options.exclude) {
			options.exclude.forEach(function(exclude) {
				args.push("--exclude", exclude);
			});
		}
		if (options.excludeFromPath) {
			args.push("--exclude-from", options.excludeFromPath);
		}

		var proc = SPAWN("/usr/bin/rsync", args.concat([
			options.sourcePath + '/',
			options.targetUser + '@' + options.targetHostname + ':' + options.targetPath
		]), {
			cwd: options.sourcePath
		});
		proc.on('error', callback);
		proc.stdout.on('data', function (data) {
			process.stdout.write(data);
		});
		proc.stderr.on('data', function (data) {
			process.stderr.write(data);
		});
		return proc.on('close', function (code) {
			if (code !== 0) {
				console.error("ERROR: rsync exited with code '" + code + "'");
				return callback(new Error("rsync exited with code '" + code + "'"));
			}
			return callback(null);
		});
	})();
}
