#!/usr/bin/env node
const command = process.argv[2];

switch (command) {
  case undefined:
  case "--help":
  case "-h":
    console.log("pact <command>\n\ncommands:\n  init     create a workspace\n  login    sign in\n  whoami   print current identity\n");
    break;
  default:
    console.error(`unknown command: ${command}`);
    process.exit(1);
}
