#!/usr/bin/env python3
"""
Batch scan all Python files in a repository using TOTAL Analyzer.
Merges individual SARIF reports into a single SARIF file.

Usage:
    python scripts/batch_scan.py [--path /repo] [--sarif output.sarif] [--exclude dir1 dir2]
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

def collect_py_files(root_path: Path, exclude_dirs: List[str]) -> List[Path]:
    """Recursively collect all .py files, skipping excluded directories."""
    py_files = []
    exclude_set = set(exclude_dirs)
    for path in root_path.rglob("*.py"):
        # Skip if any part of the path matches an excluded directory
        if any(part in exclude_set for part in path.parts):
            continue
        py_files.append(path)
    return py_files

def run_analyzer(file_path: Path, sarif_mode: bool = True) -> Dict[str, Any] | None:
    """Run TOTAL Analyzer on a single file and return parsed JSON/SARIF output."""
    cmd = ["./target/release/total-analyzer", str(file_path)]
    if sarif_mode:
        cmd.append("--sarif")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = json.loads(result.stdout)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error scanning {file_path}: {e.stderr}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Invalid JSON from {file_path}: {e}", file=sys.stderr)
        return None

def merge_sarif_reports(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge multiple SARIF reports into a single SARIF report.
    Strategy: take the first report's tool/driver/rules, then concatenate results from all.
    """
    if not reports:
        return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []}
    
    # Use the first report as base
    merged = reports[0].copy()
    merged_runs = []

    # Collect all results across runs
    all_results = []
    unique_rules = set()
    for report in reports:
        for run in report.get("runs", []):
            all_results.extend(run.get("results", []))
            # Collect rule ids from results (we don't need full rule objects if they are same)
            for res in run.get("results", []):
                unique_rules.add(res.get("ruleId"))

    # Build a single run with all results
    if merged["runs"]:
        base_run = merged["runs"][0].copy()
        base_run["results"] = all_results
        merged_runs = [base_run]
    else:
        merged_runs = [{"tool": {"driver": {"name": "total-analyzer", "rules": []}}, "results": all_results}]
    
    merged["runs"] = merged_runs
    return merged

def main():
    parser = argparse.ArgumentParser(description="Batch scan Python files with TOTAL Analyzer")
    parser.add_argument("--path", default=".", help="Root path to scan (default: current directory)")
    parser.add_argument("--sarif", default="total-report.sarif", help="Output SARIF file (default: total-report.sarif)")
    parser.add_argument("--exclude", nargs="+", default=["venv", ".env", ".git", "__pycache__", "node_modules"],
                        help="Directories to exclude (default: venv .env .git __pycache__ node_modules)")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers (default: 4)")
    parser.add_argument("--local-bin", default="./target/release/total-analyzer", help="Path to analyzer binary")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path '{root}' does not exist", file=sys.stderr)
        sys.exit(1)

    # Check binary
    binary = Path(args.local_bin)
    if not binary.exists():
        # Try to build it
        print("Binary not found, running 'cargo build --release'...")
        subprocess.run(["cargo", "build", "--release"], cwd=root, check=True)
        if not binary.exists():
            print("Build failed or binary not in expected location.", file=sys.stderr)
            sys.exit(1)

    # Collect all Python files
    print("Collecting Python files...")
    py_files = collect_py_files(root, args.exclude)
    print(f"Found {len(py_files)} Python files.")

    # Run analyzer in parallel
    reports = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_file = {executor.submit(run_analyzer, f): f for f in py_files}
        for future in as_completed(future_to_file):
            file = future_to_file[future]
            try:
                report = future.result()
                if report:
                    reports.append(report)
                    print(f"✓ {file.relative_to(root)}")
                else:
                    print(f"✗ {file.relative_to(root)} (failed)")
            except Exception as e:
                print(f"Exception scanning {file}: {e}")

    if not reports:
        print("No valid reports generated. Exiting.")
        sys.exit(1)

    # Merge reports
    print(f"Merging {len(reports)} reports...")
    merged = merge_sarif_reports(reports)

    # Write output
    output_path = Path(args.sarif)
    with open(output_path, "w") as f:
        json.dump(merged, f, indent=2)
    print(f"Merged SARIF report written to {output_path}")

if __name__ == "__main__":
    main()
