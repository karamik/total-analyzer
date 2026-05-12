
# TOTAL Analyzer v1.0-beta – Known Limitations

Thank you for testing TOTAL Analyzer. To set the right expectations, we openly list what the tool **does not yet do**.

## 1. Intra‑procedural analysis only
- Taint tracking is limited to **single function scope**.
- If a tainted value is passed to another function, we do **not** track it inside that function.
- **Example (NOT detected):**
  ```python
  @app.route("/user")
  def get_user(id):
      return build_query(id)        # tainted `id` passed

  def build_query(uid):
      return f"SELECT * FROM users WHERE id = {uid}"  # No alert
  ```

## 2. No support for dynamic imports / reflection
- `__import__()`, `importlib.import_module()`, and `getattr()` are **ignored**.
- We resolve only static imports (`from module import ...`, `import module`).

## 3. Limited control flow analysis
- We do not understand conditionals that sanitize data in one branch but not another.
- **Example (false negative):**
  ```python
  if isinstance(user_id, int):
      query = f"SELECT * FROM users WHERE id = {user_id}"   # safe, but still flagged
  else:
      query = f"SELECT * FROM users WHERE id = {user_id}"   # unsafe
  ```

## 4. Only Python language support
- Currently Python 3.8+ only.
- Support for Rust, Go, Java may come in future versions (v2.0+).

## 5. No support for ORM methods that build queries indirectly
- We detect direct `.execute()`, `.raw()`, `executemany()`.
- We **do not** detect injections via Django `raw()` when the string is built in multiple steps across different functions.

## 6. Sentinel Guard – basic crypto detection only
- We detect function calls named `encrypt`, `sign`, `PBKDF2`, `hash`.
- We do **not** verify if the operation actually uses a secret key that requires HSM.
- The recommendation is a hint, not a definitive requirement.

## 7. No support for async/await sinks (e.g., `asyncpg`)
- Async database calls are not currently recognized as sinks.

## 8. Performance on large codebases
- On a single file >10,000 lines, analysis time may exceed 30 seconds.
- We do not yet support incremental scanning (scanning only changed files).

---

## We plan to address these in future releases:
| Feature | Planned version |
|---------|----------------|
| Inter‑procedural taint | v2.0 |
| Asyncio support | v1.1 |
| Django ORM `raw()` | v1.1 |
| Incremental scanning | v1.2 |
| Rust language support | v2.5 |

**You can help us prioritise** – please fill out the survey ([SURVEY.md](./SURVEY.md)) and tell us which limitations hurt you most.
```

