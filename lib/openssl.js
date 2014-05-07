
const ASSERT = require("assert");
const PATH = require("path");
const FS = require("fs-extra");
const SPAWN = require("child_process").spawn;
const NEXPECT = require("nexpect");
const Q = require("q");
const UUID = require("uuid");




exports.generateKeys = function (options) {
	return Q.denodeify(function(callback) {

		ASSERT.equal(typeof options, "object");
		ASSERT.equal(typeof options.path, "string");

		console.log(("Generating private key at path: " + options.path).magenta);
		var proc = SPAWN("openssl", [
			"genrsa",
			"-out", options.path,
			1024
		]);
		proc.stdout.on("data", function (data) {
			error.push(data.toString());
		});
		var error = [];
		proc.stderr.on("data", function(data) {
			error.push(data.toString());
		});
		return proc.on('close', function (code) {
			if (code !== 0) {
				return callback(new Error("`openssl` exited with `code != 0` while generating private key: " + error.join("")));
			}
			return FS.chmod(options.path, 0400, callback);
		});
	})();
}


exports.generateCerts = function (options) {

	ASSERT.equal(typeof options, "object");
	ASSERT.equal(typeof options.CommonName, "string");
	ASSERT.equal(typeof options.EmailAddress, "string");

	function generateRootAuthorityKey(callback) {
		console.log("Generating root authority private key".magenta);
		var proc = SPAWN("openssl", [
			"genrsa",
			4096
		]);
		var key = [];
		proc.stdout.on("data", function (data) {
			key.push(data.toString());
		});
		var error = [];
		proc.stderr.on("data", function(data) {
			error.push(data.toString());
		});
		return proc.on('close', function (code) {
			if (code !== 0) {
				return callback(new Error("`openssl` exited with `code != 0` while generating root authority private key: " + error.join("")));
			}
			return callback(null, key.join(""));
		});
	}

	function generateRootAuthorityCertificate(rootAuthorityPrivateKey, callback) {
		console.log("Generating root authority certificate".magenta);
		var buffer = [];
		var proc = NEXPECT.spawn("openssl req -x509 -new -nodes -key /dev/stdin -days 36500", {
			stream: "stderr",
			verbose: false
		})
		.wait("Country Name (2 letter code) [AU]:")
		.sendline("CA")
		.wait("State or Province Name (full name) [Some-State]:")
		.sendline("Alberta")
		.wait("Locality Name (eg, city) []:")
		.sendline("Calgary")
		.wait("Organization Name (eg, company) [Internet Widgits Pty Ltd]:")
		.sendline("Organic Software")
		.wait("Organizational Unit Name (eg, section) []:")
		.sendline("os-inception")
		.wait("Common Name (e.g. server FQDN or YOUR name) []:")
		.sendline(options.CommonName)
		.wait("Email Address []:")
		.sendline(options.EmailAddress)
		.run(function (err, stderr, exitcode) {
			if (err) {
				return callback(err);
			}
			if (exitcode !== 0) {
				return callback(new Error("`openssl` exited with `code != 0` while generating root authority certificate"));
			}
			buffer = buffer.join("");
			if (/^-----BEGIN CERTIFICATE-----\n[\s\S]+?\n-----END CERTIFICATE-----\n$/.test(buffer)) {
				return callback(null, buffer);
/*
				var proc = SPAWN("openssl", [
					"x509",
					"-outform", "der",
					"-in", "/dev/stdin"
				]);
				var cert = [];
				proc.stdout.on("data", function (data) {
					cert.push(data.toString());
				});
				var error = [];
				proc.stderr.on("data", function(data) {
					error.push(data.toString());
				});
				proc.on('close', function (code) {
					if (code !== 0) {
						return callback(new Error("`openssl` exited with `code != 0` while concerting pem to crt: " + error.join("")));
					}
					return callback(null, {
						pem: buffer,
						crt: new Buffer(cert.join("")).toString("base64")
					});
				});
				return proc.stdin.write(buffer);
*/
			}
			return callback(new Error("`openssl` exited with stdout that does not include a root authority certificate: " + buffer));
		});
		proc.stdout.on("data", function(data) {
			buffer.push(data.toString());
		});
		return proc.stdin.write(rootAuthorityPrivateKey);
	}

	function generateKey(callback) {
		console.log("Generating private key".magenta);
		var proc = SPAWN("openssl", [
			"genrsa",
			1024
		]);
		var key = [];
		proc.stdout.on("data", function (data) {
			key.push(data.toString());
		});
		var error = [];
		proc.stderr.on("data", function(data) {
			error.push(data.toString());
		});
		return proc.on('close', function (code) {
			if (code !== 0) {
				return callback(new Error("`openssl` exited with `code != 0` while generating private key: " + error.join("")));
			}
			return callback(null, key.join(""));
		});
	}

	function generateCSR(privateKey, callback) {
		console.log("Generating csr".magenta);
		var csr = [];
		var proc = NEXPECT.spawn("openssl req -new -key /dev/stdin", {
			stream: "stderr",
			verbose: false
		})
		.wait("Country Name (2 letter code) [AU]:")
		.sendline("CA")
		.wait("State or Province Name (full name) [Some-State]:")
		.sendline("Alberta")
		.wait("Locality Name (eg, city) []:")
		.sendline("Calgary")
		.wait("Organization Name (eg, company) [Internet Widgits Pty Ltd]:")
		.sendline("Organic Software")
		.wait("Organizational Unit Name (eg, section) []:")
		.sendline("os-inception")
		.wait("Common Name (e.g. server FQDN or YOUR name) []:")
		.sendline(options.CommonName)
		.wait("Email Address []:")
		.sendline(options.EmailAddress)
		.wait("A challenge password []:")
		// TODO: Add a password.
		.sendline("")
		.wait("An optional company name []:")
		.sendline("Organic Software")		
		.run(function (err, stderr, exitcode) {
			if (err) {
				return callback(err);
			}
			if (exitcode !== 0) {
				return callback(new Error("`openssl` exited with `code != 0` while generating csr"));
			}
			csr = csr.join("");
			if (/^-----BEGIN CERTIFICATE REQUEST-----\n[\s\S]+?\n-----END CERTIFICATE REQUEST-----\n$/.test(csr)) {
				return callback(null, csr);
			}
			return callback(new Error("`openssl` exited with stdout that does not include a csr: " + csr));
		});
		proc.stdout.on("data", function(data) {
			csr.push(data.toString());
		});
		return proc.stdin.write(privateKey);
	}

	function signCsr(csr, rootAuthorityCertificate, rootAuthorityPrivateKey, done) {
		console.log("Signing csr".magenta);
		// TODO: See if we can do this without writing files.
		var tmpPath = PATH.join(__dirname, ".tmp", UUID.v4());
		FS.outputFileSync(PATH.join(tmpPath, "csr"), csr);
		FS.outputFileSync(PATH.join(tmpPath, "ca.pem"), rootAuthorityCertificate);
		function callback() {
			FS.removeSync(tmpPath);
			return done.apply(null, arguments);
		}
		var proc = SPAWN("openssl", "x509 -req -in csr -CA ca.pem -CAkey /dev/stdin -CAcreateserial -days 36500".split(" "), {
			cwd: tmpPath
		});
		var certificate = [];
		proc.stdout.on("data", function (data) {
			certificate.push(data.toString());
		});
		var error = [];
		proc.stderr.on("data", function(data) {
			error.push(data.toString());
		});
		proc.on('close', function (code) {
			if (code !== 0) {
				return callback(new Error("`openssl` exited with `code != 0` while signing csr: " + error.join("")));
			}
			certificate = certificate.join("");
			var m = certificate.match(/(-----BEGIN CERTIFICATE-----\n[\s\S]+?\n-----END CERTIFICATE-----\n)/);
			if (m && m[1]) {
				return callback(null, m[1]);
			}
			return callback(new Error("`openssl` exited with stdout that does not include a certificate: " + certificate));
		});
		return proc.stdin.write(rootAuthorityPrivateKey);
	}

	return Q.denodeify(function(callback) {
		return generateRootAuthorityKey(function(err, rootAuthorityPrivateKey) {
			if (err) return callback(err);
			return generateRootAuthorityCertificate(rootAuthorityPrivateKey, function(err, rootAuthorityCertificate) {
				if (err) return callback(err);
				return generateKey(function(err, privateKey) {
					if (err) return callback(err);
					return generateCSR(privateKey, function(err, csr) {
						if (err) return callback(err);
						return signCsr(csr, rootAuthorityCertificate, rootAuthorityPrivateKey, function(err, certificate) {
							if (err) return callback(err);
							return callback(null, {
								ca: {
									privateKey: rootAuthorityPrivateKey,
									certificate: rootAuthorityCertificate
								},
								privateKey: privateKey,
								csr: csr,
								certificate: certificate
							});
						});
					});
				});
			});
		});
	})();
}
