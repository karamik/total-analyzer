# TOTAL Analyzer Beta – Feedback Survey

Thank you for participating in the beta test. Your answers will directly shape the roadmap of TOTAL Protocol Analyzer.

**Please return this survey** to `beta@total-protocol.com` (plain text or filled markdown is fine).

---

## 1. General information

**Company / project name (optional):**  
**Role (e.g., backend dev, security engineer, team lead):**  
**Python version(s) you use:**  
**Primary web framework(s):**  
- [ ] Flask  
- [ ] FastAPI  
- [ ] Django  
- [ ] Aiohttp  
- [ ] Other: ___________

**Primary database library (ORM/driver):**  
- [ ] SQLAlchemy  
- [ ] psycopg2 (raw)  
- [ ] sqlite3  
- [ ] asyncpg  
- [ ] Django ORM  
- [ ] Other: ___________

---

## 2. SQL Injection detection

**How many real SQL injections did the tool find?**  
Approximate number: _____

**How many false positives?** (code flagged as vulnerable but actually safe)  
Number: _____  

**If possible, attach or describe one typical false positive example:**  

**Were there any false negatives?** (obvious injection not detected)  
If yes, please describe the pattern:  

**What share of your database query patterns are:**  
- f‑strings: ___%  
- `+` concatenation: ___%  
- `%`-formatting: ___%  
- Parameterized (bindparam, `?`, `%s`): ___%  
- Raw strings / `text()`: ___%

---

## 3. Sentinel Guard (hardware crypto offload)

**Did the analyzer flag any crypto operations (encrypt, sign, PBKDF2, hash)?**  
- [ ] Yes  
- [ ] No  

**If yes, were those recommendations useful?**  
- [ ] Very useful – we would consider offloading  
- [ ] Somewhat useful  
- [ ] Not useful (explain why):  

**Would your company pay for a feature that automatically generates PKCS#11/HSM wrapper code?**  
- [ ] Yes  
- [ ] Maybe  
- [ ] No  

---

## 4. Performance & integration

**How long did scanning take on your largest file / module?**  
File size: ____ KB or LOC: ____  
Time: ____ seconds  

**Did you run the tool locally or in CI?**  
- [ ] Local  
- [ ] CI (GitHub Actions / GitLab / Jenkins)  

**Which output format did you use?**  
- [ ] JSON (default)  
- [ ] SARIF (GitHub Security)  

**If you used SARIF, did GitHub successfully ingest it?**  
- [ ] Yes  
- [ ] No – problem: _____

---

## 5. Limitations awareness (honest check)

We list limitations in [LIMITATIONS.md](./LIMITATIONS.md). Please rate how much each limitation affects your daily work (1 = not at all, 5 = critical):

| Limitation | Rating (1-5) |
|------------|--------------|
| No cross‑function taint | |
| No dynamic imports | |
| No async/await sinks | |
| Python only | |
| Limited ORM coverage (Django raw, etc.) | |

---

## 6. Future features – prioritize for you

**Rank from 1 (most wanted) to 6 (least wanted):**

- [ ] Inter‑procedural taint tracking  
- [ ] Django ORM injection detection  
- [ ] asyncpg / async database sinks  
- [ ] More crypto detectors (JWT, AWS KMS, etc.)  
- [ ] Automatic PR generation for parameterized queries  
- [ ] IDE plugin (VS Code / PyCharm)  

---

## 7. Final comments

**What is the single most frustrating thing about the tool in its current state?**  

**What is the single best thing about it?**  

**Would you recommend TOTAL Analyzer to a colleague in another enterprise?**  
- [ ] Yes  
- [ ] No – because: _____

**Your email (optional, if you want follow‑up):**  

---

**Thank you for your time!**  
The TOTAL Protocol Team
