# TOTAL Protocol Analyzer – Architecture Overview

## High-level design

TOTAL Analyzer is a **static analysis tool** for Python that detects:
- SQL injections via taint tracking
- Software cryptography suitable for hardware offload (Sentinel Guard)

It is written in **Rust** for performance and memory safety, using the **Ruff** ecosystem for AST and semantic analysis.

```mermaid
flowchart LR
    A[Python source code] --> B[ruff_python_parser]
    B --> C[AST]
    C --> D[SemanticModelBuilder]
    D --> E[SemanticModel]
    C --> F[TotalChecker Visitor]
    E --> F
    F --> G[Tainted variables tracking]
    F --> H[SQL sink detection]
    F --> I[Crypto detection]
    G --> H
    H --> J[Vulnerability list]
    I --> J
    J --> K[SARIF/JSON output]
