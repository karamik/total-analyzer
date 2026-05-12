
# TOTAL Protocol Analyzer — v1.0-beta

**SAST + Hardware Security Advisor**  
*By International Group of Developers*

TOTAL Analyzer is a static analysis tool that:
- Finds **SQL injections** (taint tracking) in Python code (Flask/FastAPI)
- Detects **software cryptography** that should be offloaded to hardware (Sentinel Guard)
- Outputs **SARIF** for native GitHub Code Scanning integration

> ⚠️ **Beta limitations** – see [LIMITATIONS.md](./LIMITINGS.md). No cross‑function taint yet.

---

## 🚀 Quick start (Docker)

1. **Pull the image**  
   ```bash
   docker pull ghcr.io/total-protocol/total-analyzer:v1.0-beta
   ```

2. **Run on your project**  
   ```bash
   docker run --rm -v $(pwd):/src ghcr.io/total-protocol/total-analyzer:v1.0-beta /src --sarif > results.sarif
   ```

3. **Upload SARIF to GitHub** (optional)  
   - Go to your repo → Security → Code scanning alerts  
   - Upload `results.sarif` manually or use GitHub Actions

---

## 🔍 Example output (SQL injection)

```json
{
  "id": "TOTAL-SQL-001",
  "severity": "CRITICAL",
  "message": "SQL Injection: tainted data in DB sink",
  "line": 42,
  "recommendation": "Use parameterized queries or Sentinel Shield"
}
```

---

## 📋 Supported patterns

### ✅ Taint sources (auto‑detected)
- Flask: `@app.route` function arguments
- FastAPI: `@app.get`, `@app.post`, etc.

### ✅ Taint propagation
- Assignment: `x = user_input`
- f‑strings: `f"SELECT ... {x}"`
- String concatenation: `"..." + x`
- Passing tainted values as function arguments

### ✅ DB sinks (dangerous calls)
- `.execute()`, `.executemany()`, `.raw()`, `.run_sql()`
- Direct `execute(...)` calls  
  (works for SQLAlchemy, psycopg2, sqlite3, Django cursor)

### ✅ Sanitizers (stop taint)
- `int()`, `float()`  
- SQLAlchemy `bindparam()`  

### ✅ Sentinel Guard – crypto detection
- `.encrypt()`, `.sign()`, `.PBKDF2()`, `.hash()`  
- Advises moving to hardware (HSM/FPGA) for performance & compliance

---

## 🐳 Building from source

```bash
git clone https://github.com/total-protocol/total-analyzer
cd total-analyzer
make build         # compiles Rust binary
make test          # runs on vulnerable_app.py
make docker        # builds Docker image locally
```

---

## 📮 Beta feedback

We need your help to improve. Please fill out [`SURVEY.md`](./SURVEY.md) and send to `beta@total-protocol.com`.

---

## ⚠️ Known limitations

See [LIMITATIONS.md](./LIMITATIONS.md) – no cross‑function taint, Python only.

---

## 📄 License

Proprietary – beta access only. Contact us for commercial licensing.
```

