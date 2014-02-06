
const PATH = require("path");
const FS = require("fs");
const COMMANDER = require("commander");
const COLORS = require("colors");

COLORS.setTheme({
    error: 'red'
});



if (require.main === module) {

    var program = new COMMANDER.Command();

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

    console.log("LIST SERVICES!");

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
