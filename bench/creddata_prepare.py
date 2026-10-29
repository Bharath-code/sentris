#!/usr/bin/env python3
"""Run CredData's own download/move/obfuscate steps, but tolerate repos whose pinned commit can no longer be fetched.

The stock download_data.py aborts on the first unreachable commit and asserts no repo is missing. Here a failed repo is
skipped; move_files then drops its metadata (renamed *.csv.bak) so it does not count, and the dropped repos are listed.
Usage: python3 bench/creddata_prepare.py   (needs bench/work/creddata with its venv: pip install pybase62)
"""
import json, os, sys
from multiprocessing import Pool
from pathlib import Path

CD = Path(__file__).resolve().parent / "work" / "creddata"
os.chdir(CD)
sys.path.insert(0, str(CD))
os.environ.setdefault("GIT_LFS_SKIP_SMUDGE", "1")
import download_data as dd  # noqa: E402

failed = []


def safe_download(repo_data):
    try:
        dd.download_and_check(repo_data)
        return None
    except Exception as e:  # noqa: BLE001 - any git failure means "skip this repo"
        return (repo_data[0], repo_data[1], str(e)[:120])


def main():
    snapshot = json.load(open("snapshot.json", encoding="utf-8"))
    os.makedirs(dd.TMP_DIR, exist_ok=True)
    with Pool(processes=8) as pool:
        failed.extend(r for r in pool.map(safe_download, list(snapshot.items())) if r)
    dd.shutil.rmtree("data", ignore_errors=True)
    missing = dd.move_files(snapshot, "data")
    dd.obfuscate_creds("meta", "data", 0)
    Path("dropped_repos.json").write_text(json.dumps({"fetch_failed": failed, "metadata_dropped": missing}, indent=2))
    print(f"repos total {len(snapshot)}, fetch failed {len(failed)}, metadata dropped {len(missing)}")


if __name__ == "__main__":
    main()
