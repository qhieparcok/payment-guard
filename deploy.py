#!/usr/bin/env python3
"""Deploy payment-guard with its KV binding.

Builds dist/ with tsc, then uploads dist/worker.js to Cloudflare with
the ARENA_KV binding in the metadata. Always deploy through this
script — a plain `cf.py deploy` sends metadata without bindings and
would drop the KV binding (the worker then falls back to in-memory
state only, which is safe but loses cross-isolate reuse detection).

Usage: python3 deploy.py
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ACCOUNT_ID = "dcccfa423c5a775786ea7820ef65c30b"
WORKER_NAME = "payment-guard"
KV_NAMESPACE_ID = "01a7bd04c56749feb4f104904ad63df2"

spec = importlib.util.spec_from_file_location(
    "cf", "/home/hatch/workspace/custom-connectors/custom.cloudflare/bin/cf.py"
)
cf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cf)


def main() -> int:
    build = subprocess.run(
        ["npx", "-y", "tsc"], cwd=HERE, capture_output=True, text=True
    )
    if build.returncode != 0:
        print(build.stdout)
        print(build.stderr, file=sys.stderr)
        print("tsc build failed", file=sys.stderr)
        return 1
    # Bundle into a single module for upload: the API takes one main
    # module, and dist/worker.js from tsc still imports ./engine.js
    # etc. (esbuild is the project's `npm run build` step).
    bundle = subprocess.run(
        [
            "npx", "-y", "esbuild", "src/worker.ts",
            "--bundle", "--format=esm",
            "--outfile=dist/worker.js", "--minify",
        ],
        cwd=HERE, capture_output=True, text=True,
    )
    if bundle.returncode != 0:
        print(bundle.stdout)
        print(bundle.stderr, file=sys.stderr)
        print("esbuild bundle failed", file=sys.stderr)
        return 1
    code = (HERE / "dist" / "worker.js").read_text(encoding="utf-8")
    metadata = {
        "main_module": "worker.js",
        "compatibility_date": "2026-11-14",
        "bindings": [
            {
                "type": "kv_namespace",
                "name": "ARENA_KV",
                "namespace_id": KV_NAMESPACE_ID,
            }
        ],
    }
    body, ctype = cf.build_multipart(metadata, "worker.js", code)
    status, payload = cf.call(
        "PUT",
        f"/accounts/{ACCOUNT_ID}/workers/scripts/{WORKER_NAME}",
        body=body,
        headers={"Content-Type": ctype},
    )
    print(json.dumps({"http": status, **payload}, indent=2))
    return 0 if payload.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
