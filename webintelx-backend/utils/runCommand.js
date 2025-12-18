const { exec } = require("child_process");

function runCommand(command) {
  return new Promise((resolve) => {
    exec(command, { timeout: 15000 }, (error, stdout, stderr) => {
      if (error) {
        resolve(
          stdout ||
          stderr ||
          `Command failed but scan continued`
        );
      } else {
        resolve(stdout);
      }
    });
  });
}

module.exports = runCommand;
