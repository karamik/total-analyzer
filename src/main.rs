use anyhow::Result;
use ruff_python_ast as ast;
use ruff_python_ast::Visitor;
use ruff_python_parser::{parse_module, Mode};
use ruff_python_semantic::{BindingId, SemanticModel, SemanticModelBuilder};
use ruff_source_file::SourceFileBuilder;
use serde::Serialize;
use std::collections::HashSet;
use std::env;
use std::fs;

// ------------------------------------------------------------
// Data structures for findings & SARIF output
// ------------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct HardwareRecommendation {
    pub module: String,
    pub estimated_speedup: String,
    pub security_level: String,
}

#[derive(Serialize, Debug)]
pub struct Vulnerability {
    pub id: String,
    pub message: String,
    pub severity: String,
    pub line: usize,
    pub recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_recommendation: Option<HardwareRecommendation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReport {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    short_description: SarifMessage,
    default_configuration: SarifDefaultConfig,
    help_uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDefaultConfig {
    level: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
}

#[derive(Serialize, Clone)]
struct SarifMessage {
    text: String,
}

// ------------------------------------------------------------
// Taint analyser
// ------------------------------------------------------------

struct TotalChecker<'a> {
    model: &'a SemanticModel<'a>,
    tainted_bindings: HashSet<BindingId>,
    findings: Vec<Vulnerability>,
}

impl<'a> TotalChecker<'a> {
    fn is_web_route(&self, decorator: &ast::Decorator) -> bool {
        if let ast::Expr::Call(call) = &decorator.expression {
            if let ast::Expr::Attribute(attr) = call.func.as_ref() {
                return matches!(attr.attr.as_str(), "route" | "get" | "post" | "put" | "delete");
            }
        }
        false
    }

    fn is_expr_tainted(&self, expr: &ast::Expr) -> bool {
        match expr {
            ast::Expr::Name(name) => {
                if let Some(id) = self.model.scope().get(&name.id) {
                    return self.tainted_bindings.contains(&id);
                }
                false
            }
            ast::Expr::FString(fstring) => {
                for part in &fstring.values {
                    if let ast::FStringPart::Value(val) = part {
                        if self.is_expr_tainted(&val.expression) {
                            return true;
                        }
                    }
                }
                false
            }
            ast::Expr::BinOp(binop) => {
                (binop.op == ast::Operator::Add || binop.op == ast::Operator::Mod)
                    && (self.is_expr_tainted(&binop.left) || self.is_expr_tainted(&binop.right))
            }
            ast::Expr::Call(call) => {
                if self.is_sanitizer(call) {
                    false
                } else {
                    call.arguments.args.iter().any(|arg| self.is_expr_tainted(arg))
                }
            }
            _ => false,
        }
    }

    fn is_sanitizer(&self, call: &ast::ExprCall) -> bool {
        if let ast::Expr::Name(name) = call.func.as_ref() {
            matches!(name.id.as_str(), "int" | "float" | "bindparam")
        } else {
            false
        }
    }

    fn is_db_sink(&self, call: &ast::ExprCall) -> bool {
        let dangerous = ["execute", "executemany", "raw", "run_sql"];
        match call.func.as_ref() {
            ast::Expr::Attribute(attr) => dangerous.contains(&attr.attr.as_str()),
            ast::Expr::Name(name) => dangerous.contains(&name.id.as_str()),
            _ => false,
        }
    }

    fn resolve_line(&self, node: &ast::AnyNodeRef) -> usize {
        self.model.locator().compute_line_index(node.range().start()).get() + 1
    }
}

impl<'a> Visitor<'a> for TotalChecker<'a> {
    fn visit_stmt(&mut self, stmt: &'a ast::Stmt) {
        // 1. Sources: параметры функций с декораторами роутов
        if let ast::Stmt::FunctionDef(def) = stmt {
            if def.decorator_list.iter().any(|d| self.is_web_route(d)) {
                for arg in &def.parameters.args {
                    if let Some(id) = self.model.scope().get(&arg.parameter.name) {
                        self.tainted_bindings.insert(id);
                    }
                }
            }
        }

        // 2. Propagate taint via assignment
        if let ast::Stmt::Assign(assign) = stmt {
            if self.is_expr_tainted(&assign.value) {
                for target in &assign.targets {
                    if let ast::Expr::Name(name) = target {
                        if let Some(id) = self.model.scope().get(&name.id) {
                            self.tainted_bindings.insert(id);
                        }
                    }
                }
            }
        }

        ast::visitor::walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a ast::Expr) {
        if let ast::Expr::Call(call) = expr {
            // SQL injection sink
            if self.is_db_sink(call) {
                if call.arguments.args.iter().any(|arg| self.is_expr_tainted(arg)) {
                    let line = self.resolve_line(ast::AnyNodeRef::from(expr));
                    self.findings.push(Vulnerability {
                        id: "TOTAL-SQL-001".to_string(),
                        message: "SQL injection: tainted data used in database sink".to_string(),
                        severity: "CRITICAL".to_string(),
                        line,
                        recommendation: "Use parameterized queries (bindparam) or Sentinel Shield".to_string(),
                        hardware_recommendation: None,
                    });
                }
            }

            // Sentinel Guard: crypto detection
            let crypto_ops = ["encrypt", "sign", "PBKDF2", "hash", "hmac"];
            let is_crypto = match call.func.as_ref() {
                ast::Expr::Attribute(attr) => crypto_ops.contains(&attr.attr.as_str()),
                ast::Expr::Name(name) => crypto_ops.contains(&name.id.as_str()),
                _ => false,
            };
            if is_crypto {
                let line = self.resolve_line(ast::AnyNodeRef::from(expr));
                self.findings.push(Vulnerability {
                    id: "SENTINEL-HSM-001".to_string(),
                    message: "Software cryptography detected".to_string(),
                    severity: "LOW".to_string(),
                    line,
                    recommendation: "Offload to Sentinel Core for hardware-level security and performance".to_string(),
                    hardware_recommendation: Some(HardwareRecommendation {
                        module: "Sentinel-FPGA".to_string(),
                        estimated_speedup: "45x".to_string(),
                        security_level: "FIPS 140-3".to_string(),
                    }),
                });
            }
        }
        ast::visitor::walk_expr(self, expr);
    }
}

// ------------------------------------------------------------
// SARIF conversion
// ------------------------------------------------------------

fn build_sarif(findings: &[Vulnerability], file_uri: &str) -> SarifReport {
    let rules = vec![
        SarifRule {
            id: "TOTAL-SQL-001".to_string(),
            short_description: SarifMessage { text: "SQL injection via tainted data".to_string() },
            default_configuration: SarifDefaultConfig { level: "error".to_string() },
            help_uri: "https://total-protocol.com/docs/sql-injection".to_string(),
        },
        SarifRule {
            id: "SENTINEL-HSM-001".to_string(),
            short_description: SarifMessage { text: "Software crypto offload candidate".to_string() },
            default_configuration: SarifDefaultConfig { level: "warning".to_string() },
            help_uri: "https://total-protocol.com/docs/sentinel-guard".to_string(),
        },
    ];

    let results = findings
        .iter()
        .map(|v| {
            let level = match v.severity.as_str() {
                "CRITICAL" => "error",
                "HIGH" => "warning",
                _ => "note",
            };
            SarifResult {
                rule_id: v.id.clone(),
                level: level.to_string(),
                message: SarifMessage { text: v.message.clone() },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: file_uri.to_string() },
                        region: SarifRegion { start_line: v.line },
                    },
                }],
            }
        })
        .collect();

    SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "TOTAL-Protocol-Analyzer".to_string(),
                    information_uri: "https://total-protocol.com".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: total-analyzer <file.py> [--sarif]");
        std::process::exit(1);
    }

    let file_path = &args[1];
    let sarif_mode = args.contains(&"--sarif".to_string());

    let contents = fs::read_to_string(file_path)?;
    let source_file = SourceFileBuilder::new(file_path, contents).finish();

    let parsed_module = parse_module(source_file.source_text(), Mode::Module)?;
    let program = parsed_module.suite();

    let comment_ranges = ruff_python_index::CommentRanges::default();
    let semantic_model = SemanticModelBuilder::new(&source_file, &comment_ranges)
        .build(program);

    let mut checker = TotalChecker {
        model: &semantic_model,
        tainted_bindings: HashSet::new(),
        findings: Vec::new(),
    };

    checker.visit_program(program);

    if sarif_mode {
        let sarif = build_sarif(&checker.findings, file_path);
        println!("{}", serde_json::to_string_pretty(&sarif)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&checker.findings)?);
    }

    Ok(())
}
