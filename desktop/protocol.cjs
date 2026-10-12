const SCHEME = "sentinel-scan";

function execArgument(value) {
  if (/[\r\n\0]/.test(value)) throw new Error("Invalid desktop launcher path");
  // Bare safe paths also work with xdg-open’s generic desktop-file parser.
  if (/^[a-zA-Z0-9_./:-]+$/.test(value)) return value;
  // Desktop Entry string decoding precedes Exec quoting; percent is a field-code escape.
  const quoted = value.replace(/[\\"`$]/g, "\\$&").replace(/%/g, "%%");
  return `"${quoted.replace(/\\/g, "\\\\")}"`;
}

function linuxDesktopEntry(electronPath, appPath) {
  return `[Desktop Entry]\nType=Application\nName=Sentinel Scan\nComment=Open the Sentinel Scan desktop frontend\nExec=env -u ELECTRON_RUN_AS_NODE ${execArgument(electronPath)} ${execArgument(appPath)}\nTerminal=false\nMimeType=x-scheme-handler/${SCHEME};\nCategories=Utility;Security;\n`;
}

module.exports = { SCHEME, execArgument, linuxDesktopEntry };
