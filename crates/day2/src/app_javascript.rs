//! The JavaScript checks app CI runs on every regular `.js`, `.mjs` and `.cjs`
//! file of an app repository: a syntax check, with `.cjs` parsed as CommonJS
//! and the rest as modules, then three formatting rules with ESLint's
//! meanings: `eol-last` (always), `no-trailing-spaces` and `semi` (always).
//! One fixed configuration; apps cannot override it. Nothing is executed.
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AccessorProperty, Directive, ExportDefaultDeclarationKind, ForInStatement, ForOfStatement,
    ForStatement, ForStatementInit, ForStatementLeft, PropertyDefinition, Statement,
    TemplateLiteral, VariableDeclaration,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::{GetSpan, SourceType, Span};
use std::collections::BTreeSet;

/// The extensions the checks select.
pub const EXTENSIONS: [&str; 3] = [".js", ".mjs", ".cjs"];

/// Whether `path` names a JavaScript file the checks select.
pub fn selected(path: &str) -> bool {
    EXTENSIONS.iter().any(|extension| path.ends_with(extension))
}

/// Whether the file name marks minified output: the pinned linter never reads
/// a file whose name contains `.min.`, `-min.` or `_min.`, so the checks
/// refuse one rather than pass it unlinted. The platform lints only source.
pub fn minified(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    [".min.", "-min.", "_min."]
        .iter()
        .any(|marker| name.contains(marker))
}

/// One failed check, at a 1-based line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

/// Every finding for the file `path` with these bytes, in line order.
pub fn check(path: &str, bytes: &[u8]) -> Vec<Finding> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return vec![Finding {
            line: 1,
            rule: "syntax",
            message: "source is not UTF-8".into(),
        }];
    };
    // ESLint reads source text without its byte order mark.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let source_type = if path.ends_with(".cjs") {
        SourceType::cjs()
    } else {
        SourceType::mjs()
    };
    let allocator = Allocator::default();
    let parsed = oxc_parser::Parser::new(&allocator, text, source_type).parse();
    if parsed.panicked || !parsed.diagnostics.is_empty() {
        let mut findings: Vec<Finding> = parsed
            .diagnostics
            .iter()
            .map(|diagnostic| Finding {
                line: line_of(
                    text,
                    diagnostic
                        .labels
                        .first()
                        .map_or(0, |label| label.offset() as usize),
                ),
                rule: "syntax",
                message: diagnostic.message.to_string(),
            })
            .collect();
        if findings.is_empty() {
            findings.push(Finding {
                line: 1,
                rule: "syntax",
                message: "the parser stopped".into(),
            });
        }
        findings.sort_by_key(|finding| finding.line);
        return findings;
    }
    let mut rules = Rules {
        text,
        templates: Vec::new(),
        loop_heads: BTreeSet::new(),
        findings: Vec::new(),
    };
    rules.visit_program(&parsed.program);
    rules.eol_last();
    rules.trailing_spaces();
    let mut findings = rules.findings;
    findings.sort_by(|a, b| (a.line, a.rule).cmp(&(b.line, b.rule)));
    findings
}

fn line_of(text: &str, offset: usize) -> usize {
    let prefix = &text.as_bytes()[..offset.min(text.len())];
    let mut line = 1;
    let mut index = 0;
    while index < prefix.len() {
        match prefix[index] {
            b'\r' => {
                line += 1;
                if prefix.get(index + 1) == Some(&b'\n') {
                    index += 1;
                }
            }
            b'\n' => line += 1,
            // U+2028 and U+2029 are line terminators too.
            0xe2 if prefix.get(index + 1) == Some(&0x80)
                && matches!(prefix.get(index + 2), Some(0xa8 | 0xa9)) =>
            {
                line += 1;
                index += 2;
            }
            _ => {}
        }
        index += 1;
    }
    line
}

struct Rules<'s> {
    text: &'s str,
    /// Each template element's span and its template literal's span.
    templates: Vec<(Span, Span)>,
    /// The declarations that head a `for`, `for-in` or `for-of` loop.
    loop_heads: BTreeSet<(u32, u32)>,
    findings: Vec<Finding>,
}

impl Rules<'_> {
    fn report(&mut self, offset: usize, rule: &'static str, message: &str) {
        self.findings.push(Finding {
            line: line_of(self.text, offset),
            rule,
            message: message.into(),
        });
    }

    /// `semi` (always): the node's last token is a semicolon.
    fn semicolon(&mut self, span: Span) {
        let text = self.text[span.start as usize..span.end as usize].trim_end();
        if !text.ends_with(';') {
            self.report(span.end as usize, "semi", "Missing semicolon.");
        }
    }

    /// `eol-last` (always): nonempty source ends with a line feed.
    fn eol_last(&mut self) {
        if !self.text.is_empty() && !self.text.ends_with('\n') {
            self.report(
                self.text.len(),
                "eol-last",
                "Newline required at end of file but not found.",
            );
        }
    }

    /// `no-trailing-spaces`: no line ends in blanks, except inside a template
    /// literal's text, as ESLint exempts it.
    fn trailing_spaces(&mut self) {
        let text = self.text;
        let mut start = 0;
        let mut line = 1;
        while start <= text.len() {
            let rest = &text[start..];
            let (end, next) = match rest.find(['\r', '\n', '\u{2028}', '\u{2029}']) {
                Some(position) => {
                    let terminator = rest[position..].chars().next().unwrap_or('\n');
                    let width = if rest[position..].starts_with("\r\n") {
                        2
                    } else {
                        terminator.len_utf8()
                    };
                    (start + position, start + position + width)
                }
                None => (text.len(), text.len() + 1),
            };
            let content = &text[start..end];
            let trimmed = content.trim_end_matches(blank);
            if trimmed.len() < content.len() {
                let blank_start = start + trimmed.len();
                let exempt = self.templates.iter().any(|(element, literal)| {
                    (element.start as usize) <= blank_start
                        && blank_start < element.end as usize
                        && blank_start > literal.start as usize
                        && next.min(text.len()) < literal.end as usize
                });
                if !exempt {
                    self.findings.push(Finding {
                        line,
                        rule: "no-trailing-spaces",
                        message: "Trailing spaces not allowed.".into(),
                    });
                }
            }
            line += 1;
            start = next;
        }
    }
}

/// ESLint's blank class for trailing spaces.
fn blank(character: char) -> bool {
    matches!(
        character,
        ' ' | '\t' | '\u{a0}' | '\u{2000}'..='\u{200b}' | '\u{3000}'
    )
}

impl<'a> Visit<'a> for Rules<'_> {
    fn visit_statement(&mut self, statement: &Statement<'a>) {
        match statement {
            Statement::ExpressionStatement(node) => self.semicolon(node.span),
            Statement::ReturnStatement(node) => self.semicolon(node.span),
            Statement::ThrowStatement(node) => self.semicolon(node.span),
            Statement::DoWhileStatement(node) => self.semicolon(node.span),
            Statement::DebuggerStatement(node) => self.semicolon(node.span),
            Statement::BreakStatement(node) => self.semicolon(node.span),
            Statement::ContinueStatement(node) => self.semicolon(node.span),
            Statement::ImportDeclaration(node) => self.semicolon(node.span),
            Statement::ExportAllDeclaration(node) => self.semicolon(node.span),
            Statement::ExportNamedDeclaration(node) => self.semicolon(node.span),
            Statement::ExportFromDeclaration(node) => self.semicolon(node.span),
            // A default-exported function or class declaration needs none.
            Statement::ExportDefaultDeclaration(node)
                if !matches!(
                    node.declaration,
                    ExportDefaultDeclarationKind::FunctionDeclaration(_)
                        | ExportDefaultDeclarationKind::ClassDeclaration(_)
                ) =>
            {
                self.semicolon(node.span);
            }
            _ => {}
        }
        walk::walk_statement(self, statement);
    }

    fn visit_directive(&mut self, directive: &Directive<'a>) {
        self.semicolon(directive.span);
        walk::walk_directive(self, directive);
    }

    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
        let span = declaration.span;
        if !self.loop_heads.contains(&(span.start, span.end)) {
            self.semicolon(span);
        }
        walk::walk_variable_declaration(self, declaration);
    }

    fn visit_for_statement(&mut self, statement: &ForStatement<'a>) {
        if let Some(ForStatementInit::VariableDeclaration(head)) = &statement.init {
            self.loop_heads.insert((head.span.start, head.span.end));
        }
        walk::walk_for_statement(self, statement);
    }

    fn visit_for_in_statement(&mut self, statement: &ForInStatement<'a>) {
        if let ForStatementLeft::VariableDeclaration(head) = &statement.left {
            self.loop_heads.insert((head.span.start, head.span.end));
        }
        walk::walk_for_in_statement(self, statement);
    }

    fn visit_for_of_statement(&mut self, statement: &ForOfStatement<'a>) {
        if let ForStatementLeft::VariableDeclaration(head) = &statement.left {
            self.loop_heads.insert((head.span.start, head.span.end));
        }
        walk::walk_for_of_statement(self, statement);
    }

    fn visit_property_definition(&mut self, property: &PropertyDefinition<'a>) {
        self.semicolon(property.span);
        walk::walk_property_definition(self, property);
    }

    fn visit_accessor_property(&mut self, property: &AccessorProperty<'a>) {
        self.semicolon(property.span);
        walk::walk_accessor_property(self, property);
    }

    fn visit_template_literal(&mut self, literal: &TemplateLiteral<'a>) {
        for element in &literal.quasis {
            self.templates.push((element.span(), literal.span));
        }
        walk::walk_template_literal(self, literal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(path: &str, source: &str) -> Vec<(usize, &'static str)> {
        check(path, source.as_bytes())
            .into_iter()
            .map(|finding| (finding.line, finding.rule))
            .collect()
    }

    #[test]
    fn formatted_modules_and_scripts_pass() {
        let module = "import { a } from \"./a.js\";\nexport { a };\nexport const b = 1;\n\
            export default function c() {}\nfor (let i = 0; i < 1; i++) {}\n\
            for (const x of []) { break; }\nclass D { e = 1; static f; }\ndo {} while (false);\n";
        assert_eq!(rules("app/ui/app.js", module), []);
        let script = "\"use strict\";\nconst fs = require(\"fs\");\nreturn fs;\n";
        assert_eq!(rules("tools/tool.cjs", script), []);
        // A script cannot return at the top level of a module.
        assert_eq!(rules("tools/tool.mjs", script)[0].1, "syntax");
    }

    #[test]
    fn each_rule_reports_its_line() {
        assert_eq!(rules("a.js", "let a = 1"), [(1, "eol-last"), (1, "semi")]);
        assert_eq!(rules("a.js", "let a = 1; \n"), [(1, "no-trailing-spaces")]);
        assert_eq!(
            rules("a.js", "f()\nexport { f }\nthrow f\n"),
            [(1, "semi"), (2, "semi"), (3, "semi")]
        );
        assert_eq!(rules("a.js", "class A { b = 1 }\n"), [(1, "semi")]);
        assert_eq!(rules("a.js", "export default 1\n"), [(1, "semi")]);
        assert_eq!(rules("a.js", "\"use strict\"\n"), [(1, "semi")]);
        assert_eq!(rules("a.js", "do {} while (x)\n"), [(1, "semi")]);
        assert_eq!(rules("a.js", "let = ;\n")[0], (1, "syntax"));
        assert_eq!(check("a.js", b"\xff\n")[0].rule, "syntax");
    }

    #[test]
    fn minified_names_are_the_ones_the_linter_skips() {
        for name in [
            "ui/vendor.min.js",
            "b-min.mjs",
            "c_min.cjs",
            "tests/q-min.test.js",
            ".min.js",
        ] {
            assert!(minified(name), "{name}");
        }
        for name in [
            "ui/app.js",
            "min.js",
            "a.MIN.js",
            "x-min-y.js",
            "a.mini.js",
            "dir.min/inner.js",
        ] {
            assert!(!minified(name), "{name}");
        }
    }

    #[test]
    fn template_text_may_keep_trailing_spaces() {
        assert_eq!(rules("a.js", "const t = `a  \nb`;\n"), []);
        assert_eq!(
            rules("a.js", "const t = `${a}  \n${b}`; \n"),
            [(2, "no-trailing-spaces")]
        );
        assert_eq!(rules("a.js", "/* a  \n*/\n"), [(1, "no-trailing-spaces")]);
        assert_eq!(rules("a.js", ""), []);
    }
}
