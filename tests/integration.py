#!/usr/bin/env python3
"""
Integration tests for TOTAL Analyzer.
Run with: python tests/integration.py
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to path if needed
PROJECT_ROOT = Path(__file__).parent.parent
ANALYZER_BIN = PROJECT_ROOT / "target" / "release" / "total-analyzer"
VULNERABLE_APP = PROJECT_ROOT / "examples" / "vulnerable_app.py"

class TestTotalAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Ensure binary exists"""
        if not ANALYZER_BIN.exists():
            # Try to build it
            subprocess.run(["cargo", "build", "--release"], cwd=PROJECT_ROOT, check=True)

    def run_analyzer(self, file_path: Path, sarif: bool = False) -> dict | list:
        """Run analyzer and parse JSON output"""
        cmd = [str(ANALYZER_BIN), str(file_path)]
        if sarif:
            cmd.append("--sarif")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_sql_injection_detected_fstring(self):
        """Test that f-string SQL injection is detected"""
        findings = self.run_analyzer(VULNERABLE_APP)
        # Look for TOTAL-SQL-001 on line ~25 (user_fstring function)
        sql_findings = [f for f in findings if f["id"] == "TOTAL-SQL-001"]
        self.assertGreater(len(sql_findings), 0, "No SQL injection findings")
        # Check if the vulnerable line is reported (approx line 42 in example)
        lines = [f["line"] for f in sql_findings]
        self.assertTrue(any(40 <= l <= 50 for l in lines), f"Expected line ~42, got {lines}")

    def test_sql_injection_detected_concat(self):
        """Test that string concatenation injection is detected"""
        findings = self.run_analyzer(VULNERABLE_APP)
        sql_findings = [f for f in findings if f["id"] == "TOTAL-SQL-001"]
        # The concat example is around line 55
        lines = [f["line"] for f in sql_findings]
        self.assertTrue(any(50 <= l <= 60 for l in lines), f"Concat line not found, got {lines}")

    def test_sentinel_guard_detects_crypto(self):
        """Test that crypto operations are detected"""
        findings = self.run_analyzer(VULNERABLE_APP)
        crypto_findings = [f for f in findings if f["id"] == "SENTINEL-HSM-001"]
        self.assertGreater(len(crypto_findings), 0, "No crypto findings")
        # Should detect hmac and Fernet (around line 90+)
        lines = [f["line"] for f in crypto_findings]
        self.assertTrue(any(l > 80 for l in lines), f"Crypto lines not found, got {lines}")

    def test_safe_code_no_false_positive(self):
        """Test that safe patterns are not flagged (or flagged only as info)"""
        # Create a temporary safe file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
from flask import Flask, request
app = Flask(__name__)

@app.route("/safe")
def safe():
    uid = request.args.get("id")
    clean = int(uid)
    db.execute("SELECT * FROM users WHERE id = ?", (clean,))
    return "ok"
""")
            temp_path = Path(f.name)

        try:
            findings = self.run_analyzer(temp_path)
            critical = [f for f in findings if f["severity"] == "CRITICAL"]
            # No CRITICAL should be reported
            self.assertEqual(len(critical), 0, f"Unexpected critical findings: {critical}")
        finally:
            temp_path.unlink()

    def test_sarif_output_valid(self):
        """Test that SARIF output is valid and contains expected fields"""
        sarif_report = self.run_analyzer(VULNERABLE_APP, sarif=True)
        # Check required SARIF structure
        self.assertIn("version", sarif_report)
        self.assertEqual(sarif_report["version"], "2.1.0")
        self.assertIn("runs", sarif_report)
        runs = sarif_report["runs"]
        self.assertIsInstance(runs, list)
        self.assertGreater(len(runs), 0)
        run = runs[0]
        self.assertIn("tool", run)
        self.assertIn("results", run)
        # Check that at least one result has locations
        results = run["results"]
        if results:
            self.assertIn("locations", results[0])

if __name__ == "__main__":
    unittest.main()
