"""Query OSV using lockfile package names and versions, without installing packages."""

import json
import sys
import tomllib
from pathlib import Path
from urllib.request import Request, urlopen

root = Path(__file__).resolve().parents[1]
lock = tomllib.loads((root / "backend/uv.lock").read_text())
packages = [p for p in lock["package"] if p.get("source", {}).get("registry")]
body = {
    "queries": [
        {"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]}
        for p in packages
    ]
}
request = Request(
    "https://api.osv.dev/v1/querybatch",
    data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json"},
)
with urlopen(request, timeout=30) as response:
    results = json.load(response)["results"]
findings = []
for package, result in zip(packages, results, strict=True):
    for vuln in result.get("vulns", []):
        with urlopen(
            f"https://api.osv.dev/v1/vulns/{vuln['id']}", timeout=30
        ) as response:
            details = json.load(response)
        findings.append(
            {
                "package": package["name"],
                "version": package["version"],
                "id": vuln["id"],
                "aliases": details.get("aliases", []),
                "summary": details.get("summary"),
                "affected": details.get("affected"),
                "references": details.get("references"),
                "severity": details.get("severity"),
            }
        )
output = {
    "packages_checked": len(packages),
    "source": "https://api.osv.dev",
    "findings": findings,
}
(root / "security/python-dependency-audit.json").write_text(
    json.dumps(output, indent=2) + "\n"
)
print(
    json.dumps(
        {
            "packages_checked": len(packages),
            "findings": [
                {
                    k: v
                    for k, v in f.items()
                    if k in {"package", "version", "id", "summary", "aliases"}
                }
                for f in findings
            ],
        },
        indent=2,
    )
)
sys.exit(bool(findings))
