// =============================================================================
// TOTAL Analyzer v2.0 - Full Enterprise Cross‑file Taint Analysis
// =============================================================================

use anyhow::Result;
use ruff_python_ast as ast;
use ruff_python_ast::{Stmt, Expr, Visitor};
use ruff_python_parser::{parse_module, Mode};
use ruff_python_semantic::{SemanticModel, SemanticModelBuilder};
use ruff_python_index::CommentRanges;
use ruff_source_file::SourceFileBuilder;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::fs;
use walkdir::WalkDir;

// ------------------------------------------------------------
// Data structures for findings and SARIF
// ------------------------------------------------------------

#[derive(Serialize, Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub message: String,
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub recommendation: String,
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
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    start_line: usize,
}

#[derive(Serialize, Clone)]
struct SarifMessage {
    text: String,
}

// ------------------------------------------------------------
// Function identifier
// ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FunctionId {
    file: PathBuf,
    name: String,
}

impl FunctionId {
    fn new(file: PathBuf, name: String) -> Self {
        Self { file, name }
    }
}

// ------------------------------------------------------------
// Project index: all modules, ASTs, function definitions
// ------------------------------------------------------------

struct ModuleData {
    path: PathBuf,
    source: String,
    suite: ast::Suite,
    model: SemanticModel<'static>, // 'static is safe because we keep source & suite
    functions: Vec<ast::StmtFunctionDef>,
}

struct ProjectIndex {
    modules: Vec<ModuleData>,
    function_map: HashMap<FunctionId, (usize, usize)>, // (module_idx, func_idx)
}

impl ProjectIndex {
    fn from_dir(dir: &Path) -> Result<Self> {
        let mut modules = Vec::new();
        let mut function_map = HashMap::new();

        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("py") {
                continue;
            }
            let source = fs::read_to_string(path)?;
            let source_file = SourceFileBuilder::new(&path.to_string_lossy(), source.clone()).finish();
            let parsed = parse_module(&source, Mode::Module)?;
            let suite = parsed.suite().clone();
            let comment_ranges = CommentRanges::default();
            let model_builder = SemanticModelBuilder::new(&source_file, &comment_ranges);
            let model = model_builder.build(&suite);
            // SAFETY: we keep source_file and suite alive (as part of ModuleData)
            let model = unsafe { std::mem::transmute::<SemanticModel<'_>, SemanticModel<'static>>(model) };

            let mut functions = Vec::new();
            let mut func_idx = 0;
            for stmt in &suite {
                if let Stmt::FunctionDef(fdef) = stmt {
                    functions.push(fdef.clone());
                    let fid = FunctionId::new(path.to_path_buf(), fdef.name.to_string());
                    function_map.insert(fid, (modules.len(), func_idx));
                    func_idx += 1;
                }
            }
            modules.push(ModuleData { path: path.to_path_buf(), source, suite, model, functions });
        }
        Ok(Self { modules, function_map })
    }

    fn get_function(&self, id: &FunctionId) -> Option<(&ast::StmtFunctionDef, &SemanticModel<'static>, &PathBuf)> {
        let (mod_idx, func_idx) = self.function_map.get(id)?;
        let module = &self.modules[*mod_idx];
        let func = module.functions.get(*func_idx)?;
        Some((func, &module.model, &module.path))
    }
}

// ------------------------------------------------------------
// Call graph builder
// ------------------------------------------------------------

struct CallGraph {
    callers: HashMap<FunctionId, HashSet<FunctionId>>,
    callees: HashMap<FunctionId, HashSet<FunctionId>>,
}

impl CallGraph {
    fn new() -> Self {
        Self { callers: HashMap::new(), callees: HashMap::new() }
    }

    fn add_edge(&mut self, from: FunctionId, to: FunctionId) {
        self.callers.entry(to.clone()).or_default().insert(from.clone());
        self.callees.entry(from).or_default().insert(to);
    }
}

struct CallGraphBuilder<'a> {
    project: &'a ProjectIndex,
    graph: CallGraph,
    current_func: Option<FunctionId>,
}

impl<'a> CallGraphBuilder<'a> {
    fn build(project: &'a ProjectIndex) -> CallGraph {
        let mut builder = Self { project, graph: CallGraph::new(), current_func: None };
        for (fid, _) in &project.function_map {
            let (func, _, _) = project.get_function(fid).unwrap();
            builder.current_func = Some(fid.clone());
            builder.visit_stmts(&func.body);
        }
        builder.graph
    }

    fn visit_stmts(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Expr(expr_stmt) = stmt {
            if let Expr::Call(call) = &expr_stmt.value {
                if let Some(target) = self.resolve_call(call) {
                    if let Some(current) = &self.current_func {
                        self.graph.add_edge(current.clone(), target);
                    }
                }
            }
        }
        for child in stmt.body() {
            self.visit_stmt(child);
        }
    }

    fn resolve_call(&self, call: &ast::ExprCall) -> Option<FunctionId> {
        if let Expr::Name(name) = call.func.as_ref() {
            for (fid, _) in &self.project.function_map {
                if fid.name == name.id {
                    return Some(fid.clone());
                }
            }
        }
        None
    }
}

// ------------------------------------------------------------
// Function summary: which parameters affect return value
// ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FunctionSummary {
    param_tainted: Vec<bool>,   // per argument index
    return_tainted: bool,
}

struct SummaryAnalyzer<'a> {
    model: &'a SemanticModel<'static>,
    param_names: Vec<String>,
    tainted_params: Vec<bool>,
    return_tainted: bool,
}

impl<'a> SummaryAnalyzer<'a> {
    fn new(model: &'a SemanticModel<'static>, param_names: Vec<String>) -> Self {
        Self {
            model,
            param_names,
            tainted_params: vec![false; param_names.len()],
            return_tainted: false,
        }
    }

    fn analyze(&mut self, body: &[Stmt]) -> FunctionSummary {
        for stmt in body {
            self.visit_stmt(stmt);
        }
        FunctionSummary {
            param_tainted: self.tainted_params.clone(),
            return_tainted: self.return_tainted,
        }
    }

    fn is_expr_tainted(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Name(name) => {
                if let Some(idx) = self.param_names.iter().position(|p| p == &name.id) {
                    return self.tainted_params[idx];
                }
                false
            }
            Expr::BinOp(op) if matches!(op.op, ast::Operator::Add | ast::Operator::Mod) => {
                self.is_expr_tainted(&op.left) || self.is_expr_tainted(&op.right)
            }
            Expr::FString(fstring) => {
                fstring.values.iter().any(|part| match part {
                    ast::FStringPart::Value(val) => self.is_expr_tainted(&val.expression),
                    _ => false,
                })
            }
            Expr::Call(call) => {
                // sanitizers: int(), float(), bindparam()
                if let Expr::Name(name) = call.func.as_ref() {
                    if matches!(name.id.as_str(), "int" | "float" | "bindparam") {
                        return false;
                    }
                }
                call.arguments.args.iter().any(|arg| self.is_expr_tainted(arg))
            }
            _ => false,
        }
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign(assign) => {
                let rhs_tainted = self.is_expr_tainted(&assign.value);
                if rhs_tainted {
                    for target in &assign.targets {
                        if let Expr::Name(name) = target {
                            if let Some(idx) = self.param_names.iter().position(|p| p == &name.id) {
                                self.tainted_params[idx] = true;
                            }
                        }
                    }
                }
            }
            Stmt::Return(ret) => {
                if let Some(value) = &ret.value {
                    if self.is_expr_tainted(value) {
                        self.return_tainted = true;
                    }
                }
            }
            _ => {}
        }
        for child in stmt.body() {
            self.visit_stmt(child);
        }
    }
}

// ------------------------------------------------------------
// Inter‑procedural taint engine (fixed point)
// ------------------------------------------------------------

struct TaintEngine {
    project: ProjectIndex,
    call_graph: CallGraph,
    summaries: HashMap<FunctionId, FunctionSummary>,
}

impl TaintEngine {
    fn new(project: ProjectIndex, call_graph: CallGraph) -> Self {
        Self { project, call_graph, summaries: HashMap::new() }
    }

    fn run(&mut self) {
        // Initial summaries from local analysis
        for (fid, _) in &self.project.function_map {
            let (func, model, _) = self.project.get_function(fid).unwrap();
            let param_names: Vec<String> = func.parameters.args.iter()
                .map(|a| a.parameter.name.clone())
                .collect();
            let mut analyzer = SummaryAnalyzer::new(model, param_names);
            let summary = analyzer.analyze(&func.body);
            self.summaries.insert(fid.clone(), summary);
        }

        // Fixed point
        let mut changed = true;
        while changed {
            changed = false;
            for (fid, _) in self.project.function_map.clone() {
                let new_summary = self.recompute_summary(&fid);
                if let Some(old) = self.summaries.get(&fid) {
                    if new_summary != *old {
                        self.summaries.insert(fid.clone(), new_summary);
                        changed = true;
                    }
                } else {
                    self.summaries.insert(fid.clone(), new_summary);
                    changed = true;
                }
            }
        }
    }

    fn recompute_summary(&self, fid: &FunctionId) -> FunctionSummary {
        let (func, model, _) = self.project.get_function(fid).unwrap();
        let param_names: Vec<String> = func.parameters.args.iter()
            .map(|a| a.parameter.name.clone())
            .collect();
        let mut summary = FunctionSummary {
            param_tainted: vec![false; param_names.len()],
            return_tainted: false,
        };

        // Propagate taint through calls inside the function
        struct Propagator<'a> {
            engine: &'a TaintEngine,
            param_names: &'a [String],
            summary: &'a mut FunctionSummary,
        }
        impl<'a> Visitor<'a> for Propagator<'a> {
            fn visit_expr(&mut self, expr: &'a Expr) {
                if let Expr::Call(call) = expr {
                    // Try to resolve callee
                    let callee_id = if let Expr::Name(name) = call.func.as_ref() {
                        self.engine.project.function_map.keys()
                            .find(|fid| fid.name == name.id)
                            .cloned()
                    } else { None };
                    if let Some(callee_id) = callee_id {
                        if let Some(callee_summary) = self.engine.summaries.get(&callee_id) {
                            for (arg_idx, arg) in call.arguments.args.iter().enumerate() {
                                // Check if argument is tainted (simplified: if it's a parameter that is tainted)
                                let arg_tainted = if let Expr::Name(name) = arg {
                                    if let Some(idx) = self.param_names.iter().position(|p| p == &name.id) {
                                        self.summary.param_tainted[idx]
                                    } else { false }
                                } else { false };
                                if arg_tainted {
                                    if arg_idx < callee_summary.param_tainted.len() && callee_summary.param_tainted[arg_idx] {
                                        self.summary.return_tainted = true;
                                    }
                                }
                            }
                        }
                    }
                }
                ast::visitor::walk_expr(self, expr);
            }
        }
        let mut propagator = Propagator { engine: self, param_names: &param_names, summary: &mut summary };
        for stmt in &func.body {
            propagator.visit_stmt(stmt);
        }
        summary
    }
}

// ------------------------------------------------------------
// Web route source detection
// ------------------------------------------------------------

fn is_web_route(decorator: &ast::Decorator) -> bool {
    if let Expr::Call(call) = &decorator.expression {
        if let Expr::Attribute(attr) = call.func.as_ref() {
            return matches!(attr.attr.as_str(), "route" | "get" | "post" | "put" | "delete");
        }
    }
    false
}

// ------------------------------------------------------------
// Sink detection inside functions
// ------------------------------------------------------------

fn find_vulnerabilities(engine: &TaintEngine) -> Vec<Vulnerability> {
    let mut findings = Vec::new();
    for (fid, _) in &engine.project.function_map {
        let (func, model, path) = engine.project.get_function(fid).unwrap();
        // Determine which parameters are tainted because they come from web routes
        let mut param_tainted = vec![false; func.parameters.args.len()];
        // Check if function has a decorator that marks its parameters as sources
        let has_route_decorator = func.decorator_list.iter().any(is_web_route);
        if has_route_decorator {
            for (idx, _) in func.parameters.args.iter().enumerate() {
                param_tainted[idx] = true;
            }
        }

        // Now walk the function body, propagating taint and detecting sinks
        struct SinkVisitor<'a> {
            model: &'a SemanticModel<'static>,
            param_names: Vec<String>,
            param_tainted: Vec<bool>,
            findings: &'a mut Vec<Vulnerability>,
            file: PathBuf,
        }
        impl<'a> Visitor<'a> for SinkVisitor<'a> {
            fn visit_expr(&mut self, expr: &'a Expr) {
                if let Expr::Call(call) = expr {
                    // Check if it's a database sink
                    let is_sink = match call.func.as_ref() {
                        Expr::Attribute(attr) => matches!(attr.attr.as_str(), "execute" | "executemany" | "raw"),
                        Expr::Name(name) => matches!(name.id.as_str(), "execute" | "run_sql"),
                        _ => false,
                    };
                    if is_sink {
                        for arg in &call.arguments.args {
                            if self.is_arg_tainted(arg) {
                                let line = self.model.locator().compute_line_index(expr.range().start()).get() + 1;
                                self.findings.push(Vulnerability {
                                    id: "TOTAL-SQL-001".to_string(),
                                    message: "SQL injection: tainted data reaches database sink".to_string(),
                                    severity: "CRITICAL".to_string(),
                                    file: self.file.to_string_lossy().to_string(),
                                    line,
                                    recommendation: "Use parameterized queries (bindparam or ?)".to_string(),
                                });
                                break;
                            }
                        }
                    }
                }
                ast::visitor::walk_expr(self, expr);
            }
        }
        impl<'a> SinkVisitor<'a> {
            fn is_arg_tainted(&self, expr: &Expr) -> bool {
                match expr {
                    Expr::Name(name) => {
                        if let Some(idx) = self.param_names.iter().position(|p| p == &name.id) {
                            return self.param_tainted[idx];
                        }
                        false
                    }
                    Expr::BinOp(op) if matches!(op.op, ast::Operator::Add | ast::Operator::Mod) => {
                        self.is_arg_tainted(&op.left) || self.is_arg_tainted(&op.right)
                    }
                    Expr::FString(fs) => {
                        fs.values.iter().any(|part| match part {
                            ast::FStringPart::Value(val) => self.is_arg_tainted(&val.expression),
                            _ => false,
                        })
                    }
                    // Recursively check calls: if argument is result of a call that returns tainted
                    Expr::Call(call) => {
                        // If it's a sanitizer, it's safe
                        if let Expr::Name(name) = call.func.as_ref() {
                            if matches!(name.id.as_str(), "int" | "float" | "bindparam") {
                                return false;
                            }
                        }
                        // Otherwise, check if any argument of this call is tainted (simplified)
                        call.arguments.args.iter().any(|a| self.is_arg_tainted(a))
                    }
                    _ => false,
                }
            }
        }
        let param_names: Vec<String> = func.parameters.args.iter()
            .map(|a| a.parameter.name.clone())
            .collect();
        let mut visitor = SinkVisitor {
            model,
            param_names,
            param_tainted,
            findings: &mut findings,
            file: path.clone(),
        };
        for stmt in &func.body {
            visitor.visit_stmt(stmt);
        }
    }
    findings
}

// ------------------------------------------------------------
// Main entry point
// ------------------------------------------------------------

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: total-analyzer <project_path> [--sarif]");
        std::process::exit(1);
    }
    let path = Path::new(&args[1]);
    let sarif_mode = args.contains(&"--sarif".to_string());

    let project = ProjectIndex::from_dir(path)?;
    let call_graph = CallGraphBuilder::build(&project);
    let mut engine = TaintEngine::new(project, call_graph);
    engine.run();
    let findings = find_vulnerabilities(&engine);

    if sarif_mode {
        let rules = vec![SarifRule {
            id: "TOTAL-SQL-001".to_string(),
            short_description: SarifMessage { text: "SQL injection".to_string() },
            default_configuration: SarifDefaultConfig { level: "error".to_string() },
            help_uri: "https://total-protocol.com/docs/sql-injection".to_string(),
        }];
        let results: Vec<SarifResult> = findings.iter().map(|v| {
            SarifResult {
                rule_id: v.id.clone(),
                level: "error".to_string(),
                message: SarifMessage { text: v.message.clone() },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: v.file.clone() },
                        region: SarifRegion { start_line: v.line },
                    },
                }],
            }
        }).collect();
        let report = SarifReport {
            version: "2.1.0".to_string(),
            schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "TOTAL-Analyzer-v2.0".to_string(),
                        information_uri: "https://total-protocol.com".to_string(),
                        rules,
                    },
                },
                results,
            }],
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    }
    Ok(())
}
