import { useState } from "react";
import { Icon } from "./ui";

export default function DesktopLaunch() {
  const [attempted, setAttempted] = useState(false);
  if (/Electron\//i.test(navigator.userAgent)) return null;
  return <div className="desktop-launch">
    <a className="button button-secondary" href="sentinel-scan://open" onClick={() => setAttempted(true)}><Icon name="arrow" size={16} />Launch desktop app</a>
    <details open={attempted}>
      <summary onClick={event => { event.preventDefault(); setAttempted(value => !value); }}>Desktop setup</summary>
      <p>Your browser may ask permission to open Sentinel Scan. If it does not open, install and register the desktop app on this computer from the project folder:</p>
      <pre>npm ci --prefix desktop<br />npm run register:desktop</pre>
      <p>Registration supports Linux. On Windows, launch Electron once to register the link. This source checkout on macOS uses the command below.</p>
      <p>You can always launch it directly:</p><pre>npm run start:electron</pre>
      <p>Keep the app services running. Sign in separately in the desktop window.</p>
      <button type="button" className="text-button" onClick={() => setAttempted(false)}>Close instructions</button>
    </details>
  </div>;
}
