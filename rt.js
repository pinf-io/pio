
const PATH = require("path");
const FS = require("fs-extra");
const Q = require("q");
const PIO = require("./pio");


exports.forModule = function (module) {

	function loadLocalOnServer (systemBasePath) {
		var pio = new PIO(systemBasePath);
	    return pio.ready().then(function() {

			var serviceConfig = pio._config.config["pio.service"];

			serviceConfig._config_plugin = pio._config.config['pio.service.deployment']['config.plugin'];

			return serviceConfig;
	    });
	}

	function fetchFromServer (systemBasePath, serviceId) {
		var pio = new PIO(systemBasePath);
	    return pio.ready().then(function() {
			return pio.ensure(serviceId, {}).then(function () {

				var serviceConfig = pio._state['pio.service'];

				serviceConfig._config_plugin = pio._state['pio.service.deployment']['config.plugin'];

				return serviceConfig;
			});
	    });
	}

	var path = PATH.join(module.filename, "../");
	if (FS.existsSync(PATH.join(path, "../../../_upstream"))) {
		return fetchFromServer(PATH.join(path, "../../.."), PATH.basename(path));
	} else
	if (FS.existsSync(PATH.join(path, "../.pio.json"))) {
		return loadLocalOnServer(PATH.join(path, ".."));
	} else {
		return Q.reject(new Error("Could not find system config for service module '" + module.filename + "' while trying to determine serviceId."));
	}
}
