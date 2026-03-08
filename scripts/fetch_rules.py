import argparse
import io
import shutil
import zipfile
from pathlib import Path
from urllib.request import urlopen, Request

DEFAULT_REPO = "Yara-Rules/rules"

ALLOWED_TOP_LEVEL = {
    "email", "exploit_kits", "maldocs", "malware",
    "mobile_malware", "packers", "webshells"
}


def download_github_zip(repo: str, ref: str) -> bytes:
    url = f"https://api.github.com/repos/{repo}/zipball/{ref}"
    req = Request(
        url,
        headers={
            "User-Agent": "yara-fetcher",
            "Accept": "application/vnd.github+json",
        },
    )
    with urlopen(req) as resp:
        return resp.read()


def safe_rmtree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def copy_yara_files(extracted_root: Path, dest_dir: Path, categories: list[str]) -> int:
    cats = [c.strip().replace("\\", "/").strip("/") for c in categories if c.strip()]
    cats_set = set(cats)

    if cats_set:
        unknown = cats_set - ALLOWED_TOP_LEVEL
        if unknown:
            raise SystemExit(
                f"Unknown category(s): {sorted(unknown)}. Allowed: {sorted(ALLOWED_TOP_LEVEL)}"
            )

    count = 0
    for p in extracted_root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".yar", ".yara"):
            continue

        rel = p.relative_to(extracted_root)
        top = rel.parts[0] if rel.parts else ""

        if cats_set and top not in cats_set:
            continue

        out_path = dest_dir / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, out_path)
        count += 1

    return count


def copy_license_and_readme(extracted_root: Path, dest_dir: Path) -> None:
    for name in ("LICENSE", "LICENSE.txt", "COPYING", "README.md"):
        src = extracted_root / name
        if src.exists() and src.is_file():
            shutil.copy2(src, dest_dir / name)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fetch third-party YARA rules into ./rules/third_party/"
    )
    ap.add_argument("--repo", default=DEFAULT_REPO, help='GitHub repo in "OWNER/REPO" form')
    ap.add_argument("--ref", default="master", help='Branch/tag/commit (e.g. "main", "master", "v1.2.3")')
    ap.add_argument("--dest", default="rules/third_party/yara-rules", help="Destination folder for rules")
    ap.add_argument("--clean", action="store_true", help="Delete destination folder before copying")

    ap.add_argument(
        "--categories",
        nargs="*",
        default=[],
        help="Only import these top-level folders (e.g. malware webshells maldocs). If omitted, imports all."
    )

    ap.add_argument("--list-categories", action="store_true", help="List available categories and exit")

    args = ap.parse_args()

    if args.list_categories:
        print("Available categories:")
        for c in sorted(ALLOWED_TOP_LEVEL):
            print(" -", c)
        return 0

    dest_dir = Path(args.dest)
    if args.clean:
        safe_rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    print(f"Downloading {args.repo}@{args.ref} ...")
    try:
        zip_bytes = download_github_zip(args.repo, args.ref)
    except Exception as e:
        print(f"ERROR: Failed to download repo zip: {e}")
        return 1

    tmp_dir = dest_dir.parent / "._tmp_extract"
    safe_rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(tmp_dir)

        top = next(tmp_dir.iterdir())
        if not top.is_dir():
            print("ERROR: Unexpected zip structure")
            return 1

        copied = copy_yara_files(top, dest_dir, args.categories)
        copy_license_and_readme(top, dest_dir)

    finally:
        safe_rmtree(tmp_dir)

    imported = args.categories if args.categories else ["ALL"]
    print(f"Done. Copied {copied} rule files into: {dest_dir.resolve()}")
    print(f"Imported categories: {imported}")

    print("\nNext steps:")
    print(f'  python scan.py <TARGET_PATH> --rules "{dest_dir.as_posix()}"')
    print(f'  python mem_scan.py --all --rules "{dest_dir.as_posix()}"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())