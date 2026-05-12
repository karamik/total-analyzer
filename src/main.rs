use anyhow::Result;
use rustpython_parser::ast::{Stmt, Expr, ExprKind, Located};
use rustpython_parser::parser;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::fs;
use walkdir::WalkDir;

#[derive(Serialize, Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub message: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub recommendation: String,
}

fn is_db_sink(call: &Expr) -> bool {
    match &call.node {
        ExprKind::Call { func, .. } => {
            if let ExprKind::Attribute { attr, .. } = &func.node {
                return matches!(attr.as_str(), "execute" | "raw" | "executemany");
            }
            if let ExprKind::Name(name) = &func.node {
                return matches!(name.as_str(), "execute" | "run_sql");
            }
            false
        }
        _ => false,
    }
}

fn extract_line(stmt: &Located<Stmt>) -> usize {
    stmt.location.row() as usize
}

fn scan_file(path: &Path) -> Result<Vec<Vulnerability>> {
    let source = fs::read_to_string(path)?;
    let ast = parser::parse_program(&source, "<stdin>")
        .map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;
    let mut findings = Vec::new();
    for stmt in ast {
        match stmt.node {
            StmtType::Expr { value } => {
                if is_db_sink(&value) {
                    let line = extract_line(&stmt);
                    findings.push(Vulnerability {
                        id: "TOTAL-SQL-001".to_string(),
                        message: "Potential SQL injection detected".to_string(),
                        severity: "CRITICAL".to_string(),
                        file: path.to_string_lossy().to_string(),
                        line,
                        recommendation: "Use parameterized queries".to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(findings)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: total-analyzer <directory> [--sarif]");
        std::process::exit(1);
    }
    let dir = Path::new(&args[1]);
    let sarif_mode = args.contains(&"--sarif");

    let mut all_findings = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("py") {
            let findings = scan_file(path)?;
            all_findings.extend(findings);
        }
    }

    if sarif_mode {
        // Упрощённый SARIF вывод
        println!("{{ \"version\": \"2.1.0\", \"runs\": [] }}");
    } else {
        println!("{}", serde_json::to_string_pretty(&all_findings)?);
    }
    Ok(())
}
