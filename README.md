
# TOTAL Protocol Analyzer — v1.0-beta

**SAST + Hardware Security Advisor**  
*By International Group of Developers*

TOTAL Analyzer is a static analysis tool that:
- Finds **SQL injections** (taint tracking) in Python code (Flask, FastAPI, Django ORM)
- Detects **software cryptography** that should be offloaded to hardware (Sentinel Guard)
- Outputs **SARIF** for native GitHub Code Scanning integration

> ⚠️ **Beta limitations** – see [LIMITATIONS.md](./LIMITINGS.md). No cross‑function taint yet.

---

## 🚀 Quick start (Docker)

```bash
# Pull the image
docker pull ghcr.io/karamik/total-analyzer:v1.0-beta

# Run on your project
cd your-python-project
docker run --rm -v $(pwd):/src ghcr.io/karamik/total-analyzer:v1.0-beta /src --sarif > results.sarif

# Upload results.sarif to GitHub Security → Code scanning alerts (manual upload)
```

---

## 🔍 Example output (SQL injection)

```json
{
  "id": "TOTAL-SQL-001",
  "severity": "CRITICAL",
  "message": "SQL injection: tainted data used in database sink",
  "line": 42,
  "recommendation": "Use parameterized queries (bindparam) or Sentinel Shield"
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
- `%`‑formatting: `"... %s" % x`  *(new!)*
- Passing tainted values as function arguments

### ✅ DB sinks (dangerous calls)
- SQLAlchemy: `.execute()`, `.executemany()`, `.raw()`
- Raw DB‑API: `cursor.execute()`, `executemany()`
- Django ORM: `Model.objects.raw()`  *(new!)*
- Any direct call named `execute` or `run_sql`

### ✅ Sanitizers (stop taint)
- `int()`, `float()`
- SQLAlchemy `bindparam()`

### ✅ Sentinel Guard – crypto detection
- `.encrypt()`, `.sign()`, `.PBKDF2()`, `.hash()`, `hmac`
- Advises moving to hardware (HSM/FPGA) for performance & compliance

---

## 🛡️ Safe Migration: From Software to Hardware

Enterprise‑grade migration is not just about moving code – it guarantees **no regression** and **unchanged business logic**.

### 1. Behavioral Consistency – No Logic Change
When we offload cryptography (e.g., `hashlib.pbkdf2_hmac`) to Sentinel Core hardware, we **redirect** calls to hardware accelerators. Inputs and outputs remain identical, but computation happens inside a silicon enclave.  
→ **Risk eliminated:** Implementation errors in crypto code.

### 2. Sandbox Migration – Credentials Stay in Hardware
We promote **sidecar / offload** migration: application code keeps running, but sensitive operations move outside software reach. Even if the Python server is compromised, private keys never leave the hardware module.  
→ **Risk eliminated:** Key extraction from memory.

### 3. Verifiable via SARIF + CI/CD
Migration becomes a controlled process:

| Phase | Action |
|-------|--------|
| **Before** | Scan legacy code → find tainted sinks & software crypto |
| **Transition** | Replace software calls with Sentinel API |
| **After** | Re‑scan → confirmed: no critical findings |

The SARIF report serves as **technical and legal proof** that the risk has been eliminated at hardware level.

✅ **Safe Migration Path** – moving from vulnerable scripts to hardware‑protected infrastructure **without business downtime**. Every variable is tracked, every sink is validated, and every cryptographic key is physically isolated.

---

## 💰 Why Hardware Migration Matters for Enterprise

### 🔻 Reduced audit costs
When security is guaranteed by hardware, compliance checks become faster and less expensive. Auditors can rely on physical attestation instead of manual code reviews.

### ✅ Guaranteed compliance
Proving data protection to regulators is easier when sensitive assets live inside an HSM rather than in a plain file on a server. Hardware boundaries provide undeniable evidence of segregation.

### 🛡️ Immunity to software Zero‑Days
A vulnerability in Python, your web framework, or any software layer **cannot compromise the Sentinel hardware enclave**. Even if the application server is fully breached, keys and critical operations remain safe.

### 🎯 Bottom line
Our migration is safe because it is **transparent** (every data flow is visible through AST analysis) and **physically separated** from the main attack surface. We don’t just fix software – we build a **bunker** for it.

---

## 🐳 Building from source

```bash
git clone https://github.com/karamik/total-analyzer
cd total-analyzer
make build         # compiles Rust binary
make test          # runs on example vulnerable app
make docker        # builds Docker image locally
```

---

## 🔗 Pre‑commit integration

Run TOTAL Analyzer automatically on every commit.

### 1. Install `pre-commit`
```bash
pip install pre-commit
```

### 2. Create `.pre-commit-config.yaml` in your repository:
```yaml
repos:
  - repo: local
    hooks:
      - id: total-analyzer-docker
        name: TOTAL Analyzer
        entry: bash -c 'docker run --rm -v $(pwd):/src ghcr.io/karamik/total-analyzer:latest /src --sarif > .sarif-tmp && if grep -q "\"level\":\"error\"" .sarif-tmp; then echo "❌ SQL injection found" && cat .sarif-tmp && exit 1; else echo "✅ No critical issues"; fi'
        language: system
        files: \.py$
        pass_filenames: false
        verbose: true
```

### 3. Install the hook
```bash
pre-commit install
```

Now every `git commit` will scan staged Python files.  
To skip the hook: `git commit --no-verify`.

---

## 📦 Usage examples

### Scan a single file
```bash
./target/release/total-analyzer app.py --sarif > report.sarif
```

### Scan whole project (batch)
```bash
make batch-scan
# or
python scripts/batch_scan.py --path . --sarif merged.sarif
```

### Run via Docker on a specific folder
```bash
docker run --rm -v /path/to/your/code:/src ghcr.io/karamik/total-analyzer:v1.0-beta /src --sarif
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

