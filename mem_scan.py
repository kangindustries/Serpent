import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import psutil  # type: ignore
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


def scan_pid(rules: yara.Rules, pid: int, timeout: int) -> dict:
    try:
        matches = rules.match(pid=pid, timeout=timeout)  
        if matches:
            return {"pid": pid, "status": "MATCH", "matches": [match_to_dict(m) for m in matches]}
        return {"pid": pid, "status": "OK", "matches": []}
    except yara.TimeoutError:
        return {"pid": pid, "status": "TIMEOUT", "matches": []}
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"pid": pid, "status": "SKIP", "reason": type(e).__name__, "matches": []}
    except Exception as e:
        return {"pid": pid, "status": "ERROR", "error": str(e), "matches": []}


def pid_context(pid: int) -> dict:
    try:
        p = psutil.Process(pid)
        info = {"name": p.name()}
        try:
            info["exe"] = p.exe()
        except Exception:
            info["exe"] = None
        try:
            info["username"] = p.username()
        except Exception:
            info["username"] = None
        return info
    except Exception:
        return {"name": None, "exe": None, "username": None}


def main():
    ap = argparse.ArgumentParser(description="YARA memory scanner (process scanning by PID)")
    ap.add_argument("--rules", default="rules", help="Directory containing YARA rules")
    ap.add_argument("--pid", type=int, help="Scan a single process ID")
    ap.add_argument("--all", action="store_true", help="Scan all running processes")
    ap.add_argument("--timeout", type=int, default=10, help="Per-process YARA timeout (seconds)")
    ap.add_argument("--out", default="mem_results.json", help="Output JSON report filename")
    args = ap.parse_args()

    if not args.pid and not args.all:
        ap.error("Choose either --pid <PID> or --all")

    rules_dir = Path(args.rules)

    if not rules_dir.exists():
        raise SystemExit(f"Rules directory not found: {rules_dir}")
    if not rules_dir.is_dir():
        raise SystemExit(f"--rules must point to a directory: {rules_dir}")

    rules = compile_rules(rules_dir)

    if args.pid:
        pids = [args.pid]
    else:
        pids = [p.pid for p in psutil.process_iter(attrs=[])]  # quick enumeration

    results: list[dict[str, Any]] = []
    match_procs: int = 0
    scanned: int = 0

    print(f"Rules: {rules_dir.resolve()}")
    print("Starting memory scan... (you may need to run terminal as Administrator)\n")

    for pid in pids:
        scanned += 1  # type: ignore
        ctx = pid_context(pid)
        r = scan_pid(rules, pid, args.timeout)
        r.update(ctx)

        if r["status"] == "MATCH":
            match_procs += 1  # type: ignore
            print(f"[MATCH] PID={pid} name={r.get('name')} exe={r.get('exe')}")
            for md in r["matches"]:  # md is a dict from match_to_dict()
                print(f"  - rule={md['rule']} tags={md['tags']} meta={md['meta']}")
                for s in md.get("strings", [])[:3]:
                    print(f"    * {s.get('identifier')} @ {s.get('offset')} len={s.get('data', {}).get('len')}")
        elif r["status"] in ("SKIP", "ERROR", "TIMEOUT"):
            print(f"[{r['status']}] PID={pid} name={ctx.get('name')}")
        
        results.append(r)

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "rules_dir": str(rules_dir),
        "mode": "pid" if args.pid else "all",
        "files_scanned": None,  # not a file scan
        "processes_scanned": scanned,
        "processes_with_matches": match_procs,
        "results": results,
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nDone.")
    print(f"processes_scanned={scanned}, processes_with_matches={match_procs}")
    print(f"Report written to: {out_path.resolve()}")


if __name__ == "__main__":
    main()