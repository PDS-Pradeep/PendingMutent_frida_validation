#!/usr/bin/env python3
"""
inventory.py — Phase 0: freeze and hash the PendingMutent corpus.
Scans APK repositories, extracts identity + manifest facts, writes corpus_manifest.csv.

Setup:
    pip install androguard
Usage:
    python inventory.py
"""

import csv
import hashlib
from pathlib import Path

from androguard.core.apk import APK   # androguard >= 4.x
# for androguard 3.x use:  from androguard.core.bytecodes.apk import APK

# ---- configure your repos here -------------------------------------------
REPOS = {
    "fdroid":     r"android_repositories\fdroid_main",
    "izzyondroid": r"android_repositories\izzyondroid",
}
OUT_CSV = "corpus_manifest.csv"
# --------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_apk(path: Path) -> dict:
    """Pull the identity facts we need for the manifest."""
    try:
        a = APK(str(path))
        return {
            "package":       a.get_package(),
            "versionName":   a.get_androidversion_name(),
            "versionCode":   a.get_androidversion_code(),
            "minSdk":        a.get_min_sdk_version(),
            "targetSdk":     a.get_target_sdk_version(),
            "parse_ok":      "Y",
            "error":         "",
        }
    except Exception as e:
        return {
            "package": "", "versionName": "", "versionCode": "",
            "minSdk": "", "targetSdk": "",
            "parse_ok": "N", "error": str(e)[:120],
        }


def main():
    rows = []
    for repo_label, repo_dir in REPOS.items():
        root = Path(repo_dir)
        if not root.exists():
            print(f"[WARN] repo path not found: {root}")
            continue
        apks = sorted(root.rglob("*.apk"))
        print(f"[{repo_label}] found {len(apks)} apk(s) under {root}")
        for apk in apks:
            info = parse_apk(apk)
            info.update({
                "repo":     repo_label,
                "filename": apk.name,
                "relpath":  str(apk.relative_to(root)),
                "size_mb":  round(apk.stat().st_size / 1e6, 2),
                "sha256":   sha256_of(apk),
                "bucket":   "",   # fill in v1/v2/v3 manually after review
                "installs": "",   # fill in Y/N after adb install step
                "keep":     "",   # your final in-corpus decision
            })
            rows.append(info)
            print(f"  {info['parse_ok']}  {info['package'] or apk.name}"
                  f"  vCode={info['versionCode']}  tSdk={info['targetSdk']}")

    if not rows:
        print("No APKs found. Check REPOS paths.")
        return

    cols = ["repo", "filename", "relpath", "package", "versionName",
            "versionCode", "minSdk", "targetSdk", "size_mb", "sha256",
            "bucket", "installs", "keep", "parse_ok", "error"]

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    total = len(rows)
    ok = sum(1 for r in rows if r["parse_ok"] == "Y")
    dupes = total - len({r["sha256"] for r in rows})
    print(f"\nWrote {OUT_CSV}: {total} apk(s), {ok} parsed cleanly, "
          f"{total - ok} failed, {dupes} duplicate hash(es).")


if __name__ == "__main__":
    main()