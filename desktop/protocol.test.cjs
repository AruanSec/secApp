const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execArgument, linuxDesktopEntry } = require("./protocol.cjs");

test("protocol launch command uses fixed local paths and no incoming URL", () => {
  const entry = linuxDesktopEntry("/opt/Electron App/electron", "/home/user/Scan App/");
  assert.match(entry, /MimeType=x-scheme-handler\/sentinel-scan;/);
  assert.match(entry, /Exec=env -u ELECTRON_RUN_AS_NODE/);
  assert.ok(entry.includes('"/opt/Electron App/electron"'));
  assert.ok(!entry.includes("%u") && !entry.includes("%U"));
});

test("desktop paths cannot inject fields or Exec field codes", () => {
  for (const value of ["/app\nExec=evil", "/app\rHidden=true", "/app\0"]) assert.throws(() => execArgument(value));
  assert.ok(execArgument('/app/%u').includes('%%u'));
  assert.ok(execArgument('/app/"quoted"').includes('\\\\"'));
  assert.ok(execArgument('/app/$value').includes('\\\\$'));
});
