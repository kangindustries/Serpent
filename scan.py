import argparse
import json
import os
from datetime import datetime
from pathlib import Path

import yara  # type: ignore
import base64
from typing import Any

def _bytes_preview(b: bytes | bytearray | None, max_len: int = 64) -> dict[str, Any]:
    if b is None:
        return {"len": 0, "b64": "", "truncated": False}
    raw = bytes(b[:max_len])  # type: ignore
    return {
        "len": len(b),
        "b64": base64.b64encode(raw).decode("ascii"),
        "truncated": len(b) > max_len,
    }

def compile_rules(rules_dir: Path) -> yara.Rules:
    rule_files = list(rules_dir.rglob("*.yar")) + list(rules_dir.rglob("*.yara"))
    if not rule_files:
        raise FileNotFoundError(f"No .yar/.yara files found under: {rules_dir}")

    filepaths = {str(p.relative_to(rules_dir)).replace("\\", "/"): str(p) for p in rule_files}
    return yara.compile(filepaths=filepaths)

def _string_matches_to_list(m: yara.Match) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    strings = getattr(m, "strings", None)
    if not strings:
        return out

    for s in strings:

        if isinstance(s, tuple) and len(s) >= 3:
            offset, ident, data = s[0], s[1], s[2]
            out.append({
                "offset": int(offset),
                "identifier": str(ident),
                "data": _bytes_preview(data),
            })
            continue

        offset = getattr(s, "offset", None)
        ident = getattr(s, "identifier", None)
        data = getattr(s, "data", None)

        instances = getattr(s, "instances", None)
        if instances:
            for inst in instances:
                out.append({
                    "offset": int(getattr(inst, "offset", -1)),
                    "identifier": str(getattr(s, "identifier", ident)),
                    "data": _bytes_preview(getattr(inst, "data", data)),
                })
        else:
            out.append({
                "offset": int(offset) if offset is not None else -1,
                "identifier": str(ident) if ident is not None else None,
                "data": _bytes_preview(data) if isinstance(data, (bytes, bytearray)) else None,
            })

    return out


def match_to_dict(m: yara.Match) -> dict:
    return {
        "rule": m.rule,
        "tags": list(m.tags),
        "meta": dict(m.meta),
        "strings": _string_matches_to_list(m),
    }


def scan_one(rules: yara.Rules, path: Path, timeout: int) -> dict:
    try:
        matches = rules.match(filepath=str(path), timeout=timeout)
        if matches:
            return {
                "path": str(path),
                "status": "MATCH",
                "matches": [match_to_dict(m) for m in matches],
            }
        return {"path": str(path), "status": "OK", "matches": []}

    except yara.TimeoutError:
        return {"path": str(path), "status": "TIMEOUT", "matches": []}
    except Exception as e:
        return {"path": str(path), "status": "ERROR", "error": str(e), "matches": []}


def iter_files(target: Path):
    if target.is_file():
        yield target
        return

    for root, _, files in os.walk(target):
        for fn in files:
            yield Path(root) / fn


def main():
    ap = argparse.ArgumentParser(description="Simple YARA scanner (targeted) with JSON report output")
    ap.add_argument("target", help="File or folder to scan")
    ap.add_argument("--rules", default="rules", help="Directory containing YARA rules")
    ap.add_argument("--timeout", type=int, default=10, help="Per-file YARA timeout (seconds)")
    ap.add_argument("--out", default="results.json", help="Output report file (JSON)")
    args = ap.parse_args()

    target = Path(args.target)
    rules_dir = Path(args.rules)
    out_path = Path(args.out)

    if not target.exists():
        raise SystemExit(f"Target not found: {target}")
    if not rules_dir.exists():
        raise SystemExit(f"Rules directory not found: {rules_dir}")

    rules = compile_rules(rules_dir)

    results: list[dict[str, Any]] = []
    scanned: int = 0
    match_files: int = 0

    print(f"Scanning: {target}")
    print(f"Rules: {rules_dir.resolve()}")
    print("----")

    for p in iter_files(target):
        scanned += 1  # type: ignore
        r = scan_one(rules, p, args.timeout)

        if r["status"] == "MATCH":
            match_files += 1  # type: ignore
            print(f"[MATCH] {r['path']}")
            for md in r["matches"]:
                print(f"  - rule={md['rule']} tags={md['tags']} meta={md['meta']}")
                for s in md.get("strings", [])[:3]:
                    print(f"    * {s.get('identifier')} @ {s.get('offset')} len={s.get('data', {}).get('len')}")
        elif r["status"] == "OK":
            pass
        else:
            print(f"[{r['status']}] {r['path']}")

        results.append(r)

    report = {
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "target": str(target),
        "rules_dir": str(rules_dir),
        "files_scanned": scanned,
        "files_with_matches": match_files,
        "results": results,
    }

    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("----")
    print(f"Done. files_scanned={scanned}, files_with_matches={match_files}")
    print(f"Report written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()