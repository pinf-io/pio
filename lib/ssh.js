
const ASSERT = require("assert");
const Q = require("q");
const PATH = require("path");
const FS = require("fs-extra");
const SPAWN = require("child_process").spawn;


exports.callRemoteCommand = function (options, callback) {
	return Q.denodeify(function (callback) {

		ASSERT.equal(typeof options, "object");
		ASSERT.equal(typeof options.targetUser, "string");
		ASSERT.equal(typeof options.targetHostname, "string");
		ASSERT.equal(typeof options.commandPath, "string");
		ASSERT.equal(typeof options.keyPath, "string");

		console.log(("Calling command '" + options.commandPath + "' on vm '" + options.targetHostname + "'").magenta);
		var proc = SPAWN("/usr/bin/ssh", [
			'-o', 'ConnectTimeout=5',
			'-o', 'ConnectionAttempts=1',
			'-o', 'StrictHostKeyChecking=no',
			'-o', 'UserKnownHostsFile=/dev/null',
			'-o', 'IdentityFile=' + options.keyPath,
			options.targetUser + '@' + options.targetHostname,
			'cd ' + PATH.dirname(options.commandPath) + '; sh ' + PATH.basename(options.commandPath)
		], {
	/*							
			env: self._settings.sshkey.addSshAskpassEnvVars({
				PATH: process.env.PATH
			})
	*/
			env: {
				PATH: process.env.PATH
			}
		});
		proc.stdout.on('data', function (data) {
			process.stdout.write(data);
		});
		var stderr = [];
		proc.stderr.on('data', function (data) {
			stderr.push(data.toString());
			process.stderr.write(data);
		});
		return proc.on('close', function (code) {
			if (code !== 0) {
				console.error("ERROR: Remote command exited with code '" + code + "'");
				return callback(new Error("Remote command exited with code '" + code + "' and stderr: " + stderr.join("")));
			}
			return callback(null);
		});
	})();
}

exports.runRemoteCommands = function (options, callback) {
	return Q.denodeify(function (callback) {

		ASSERT.equal(typeof options, "object");
		ASSERT.equal(typeof options.targetUser, "string");
		ASSERT.equal(typeof options.targetHostname, "string");
		ASSERT.equal(Array.isArray(options.commands), true);
		ASSERT.equal(typeof options.keyPath, "string");
		ASSERT.equal(typeof options.workingDirectory, "string");

		console.log(("Calling commands '" + options.commands.join("; ") + "' (identity: " + options.targetUser + " / " + options.keyPath + ") on vm '" + options.targetHostname + "' at path '" + options.workingDirectory + "'").magenta);

		var proc = SPAWN("/usr/bin/ssh", [
			'-o', 'ConnectTimeout=5',
			'-o', 'ConnectionAttempts=1',
			'-o', 'UserKnownHostsFile=/dev/null',
			'-o', 'StrictHostKeyChecking=no',
			'-o', 'UserKnownHostsFile=/dev/null',
			'-o', 'IdentityFile=' + options.keyPath,
			options.targetUser + '@' + options.targetHostname,
			'cd ' + options.workingDirectory + '; bash -e -s'
		], {
	/*							
			env: self._settings.sshkey.addSshAskpassEnvVars({
				PATH: process.env.PATH
			})
	*/
			env: {
				PATH: process.env.PATH
			}
		});
		var stdout = [];
		proc.stdout.on('data', function (data) {
			stdout.push(data.toString());
			process.stdout.write(data);
		});
		var stderr = [];
		proc.stderr.on('data', function (data) {
			stderr.push(data.toString());
			process.stderr.write(data);
		});
		proc.on('close', function (code) {
			if (code !== 0) {
				console.error("ERROR: Remote command exited with code '" + code + "'");
				return callback(new Error("Remote command exited with code '" + code + "' and stderr: " + stderr.join("")));
			}
			return callback(null, {
				code: code,
				stdout: stdout.join(""),
				stderr: stderr.join("")
			});
		});
		proc.stdin.write(options.commands.join("\n"));
		return proc.stdin.end();
	})();
}

exports.uploadFile = function (options, callback) {
	return Q.denodeify(function (callback) {

		ASSERT.equal(typeof options, "object");
		ASSERT.equal(typeof options.source, "string");
		ASSERT.equal(typeof options.targetUser, "string");
		ASSERT.equal(typeof options.targetHostname, "string");
		ASSERT.equal(typeof options.targetPath, "string");
		ASSERT.equal(typeof options.keyPath, "string");

		console.log(("Uploading file to '" + options.targetPath + "' on vm '" + options.targetHostname + "'").magenta);
		var proc = SPAWN("/usr/bin/ssh", [
			'-o', 'ConnectTimeout=5',
			'-o', 'ConnectionAttempts=1',
			'-o', 'StrictHostKeyChecking=no',
			'-o', 'UserKnownHostsFile=/dev/null',
			'-o', 'IdentityFile=' + options.keyPath,
			options.targetUser + '@' + options.targetHostname,
			'cat > ' + options.targetPath
		], {
	/*							
			env: self._settings.sshkey.addSshAskpassEnvVars({
				PATH: process.env.PATH
			})
	*/
			env: {
				PATH: process.env.PATH
			}
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
				console.error("ERROR: File upload exited with code '" + code + "'");
				return callback(new Error("File upload exited with code '" + code + "' and stderr: " + stderr.join("")));
			}
			return callback(null);
		});
		proc.stdin.write(options.source);
		return proc.stdin.end();
	})();
}


exports.exportPublicKeyFromPrivateKey = function(privateKeyPath, publicKeyPath) {
	return Q.denodeify(function(callback) {
		return FS.exists(publicKeyPath, function(exists) {
			if (exists) {
				return callback(null);
			}
			var pubKey = [];
			var proc = SPAWN("/usr/bin/ssh-keygen", [
				'-y',
				'-f', PATH.basename(privateKeyPath)
			], {
				cwd: PATH.dirname(privateKeyPath)
			});
			proc.stdout.on('data', function (data) {
				pubKey.push(data.toString());
			});
			proc.stderr.on('data', function (data) {
				process.stderr.write(data);
			});
			proc.on('close', function (code) {
				if (code !== 0) {
					console.error("ERROR: Key export exited with code '" + code + "'");
					return callback(new Error("Key export exited with code '" + code + "'"));
				}
				return FS.outputFile(publicKeyPath, pubKey.join(""), callback);
			});
		});
	})();
}

