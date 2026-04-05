//! Anti-pattern registry with 15 patterns for detecting common Rust quality issues.

use crate::errors::JrError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Severity levels for anti-pattern violations, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Minor style or preference issue
    Low,
    /// Potential maintenance or correctness concern
    Medium,
    /// Likely bug or significant design flaw
    High,
    /// Security vulnerability or guaranteed runtime failure
    Critical,
}

/// Categories of anti-patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    /// Error handling quality
    ErrorHandling,
    /// Ownership and lifetime design
    Ownership,
    /// Async correctness and safety
    AsyncSafety,
    /// Type system usage
    TypeSystem,
    /// Security vulnerabilities
    Security,
    /// Rust idiom adherence
    Idioms,
    /// Configuration management
    Configuration,
}

/// An anti-pattern definition in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiPattern {
    /// Unique identifier (e.g., "AP-001")
    pub id: &'static str,
    /// Human-readable name
    pub name: &'static str,
    /// Description of the anti-pattern
    pub description: &'static str,
    /// How severe this issue is
    pub severity: Severity,
    /// Which category this belongs to
    pub category: Category,
    /// Related clippy lint, if any
    pub clippy_lint: Option<&'static str>,
    /// Regex pattern for detection (None if AST-only or review-only)
    pub detection_pattern: Option<&'static str>,
    /// What to do instead
    pub correct_alternative: &'static str,
    /// Path to detailed documentation
    pub doc_path: &'static str,
}

/// A detected violation of an anti-pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Which anti-pattern was violated
    pub anti_pattern_id: &'static str,
    /// Severity of the violation
    pub severity: Severity,
    /// File where the violation was found
    pub file: String,
    /// Line number (1-based)
    pub line: usize,
    /// Column number (1-based)
    pub column: usize,
    /// Source context around the violation
    pub context: String,
    /// Suggested fix
    pub suggestion: String,
}

/// The complete anti-pattern registry.
pub static ANTI_PATTERNS: &[AntiPattern] = &[
    AntiPattern {
        id: "AP-001",
        name: "unwrap_in_handler",
        description: "Using .unwrap() in non-test code risks panics in production",
        severity: Severity::Critical,
        category: Category::ErrorHandling,
        clippy_lint: Some("clippy::unwrap_used"),
        detection_pattern: Some(r"\.unwrap\(\)"),
        correct_alternative: "Use `?` operator, `.ok_or()`, `.unwrap_or_default()`, or match",
        doc_path: "docs/patterns/AP-001-unwrap-in-handler.md",
    },
    AntiPattern {
        id: "AP-002",
        name: "clone_without_justification",
        description: "Calling .clone() without a comment explaining why ownership can't be restructured",
        severity: Severity::High,
        category: Category::Ownership,
        clippy_lint: None,
        detection_pattern: Some(r"\.clone\(\)"),
        correct_alternative: "Restructure ownership with references, Cow, or Arc. If clone is needed, add a comment",
        doc_path: "docs/patterns/AP-002-clone-without-justification.md",
    },
    AntiPattern {
        id: "AP-003",
        name: "lock_across_await",
        description: "Holding a MutexGuard across an .await point causes deadlocks",
        severity: Severity::Critical,
        category: Category::AsyncSafety,
        clippy_lint: Some("clippy::await_holding_lock"),
        detection_pattern: None,
        correct_alternative: "Scope the lock guard to drop before .await, or use tokio::sync::Mutex",
        doc_path: "docs/patterns/AP-003-lock-across-await.md",
    },
    AntiPattern {
        id: "AP-004",
        name: "string_typed_id",
        description: "Using raw String or Uuid instead of domain-specific newtype IDs",
        severity: Severity::Medium,
        category: Category::TypeSystem,
        clippy_lint: None,
        detection_pattern: Some(r"fn\s+\w+\([^)]*:\s*(?:&?\s*)?Uuid\b"),
        correct_alternative: "Use domain newtypes: CampaignId, UserId, DeviceId, etc.",
        doc_path: "docs/patterns/AP-004-string-typed-id.md",
    },
    AntiPattern {
        id: "AP-005",
        name: "box_dyn_error",
        description: "Using Box<dyn Error> erases error types and prevents structured handling",
        severity: Severity::Medium,
        category: Category::ErrorHandling,
        clippy_lint: None,
        detection_pattern: Some(r"Box<dyn\s+.*Error"),
        correct_alternative: "Use thiserror-derived enum with specific variants",
        doc_path: "docs/patterns/AP-005-box-dyn-error.md",
    },
    AntiPattern {
        id: "AP-006",
        name: "missing_zeroize",
        description: "Secrets stored without Zeroizing wrapper remain in memory after drop",
        severity: Severity::Critical,
        category: Category::Security,
        clippy_lint: None,
        detection_pattern: None,
        correct_alternative: "Wrap secrets with zeroize::Zeroizing<T>",
        doc_path: "docs/patterns/AP-006-missing-zeroize.md",
    },
    AntiPattern {
        id: "AP-007",
        name: "non_constant_time_compare",
        description: "Using == to compare tokens allows timing attacks",
        severity: Severity::Critical,
        category: Category::Security,
        clippy_lint: None,
        detection_pattern: Some(r#"(?:token|secret|key|password|hash)\s*==\s*"#),
        correct_alternative: "Use ring::constant_time::verify_slices_are_equal or similar",
        doc_path: "docs/patterns/AP-007-non-constant-time-compare.md",
    },
    AntiPattern {
        id: "AP-008",
        name: "manual_json_deser",
        description: "Manually calling serde_json::from_str in handlers instead of using typed extractors",
        severity: Severity::Low,
        category: Category::Idioms,
        clippy_lint: None,
        detection_pattern: Some(r"serde_json::from_str"),
        correct_alternative: "Use axum::Json<T> extractor or other typed extractors",
        doc_path: "docs/patterns/AP-008-manual-json-deser.md",
    },
    AntiPattern {
        id: "AP-009",
        name: "missing_tracing_span",
        description: "Async functions without #[tracing::instrument] lose context in logs",
        severity: Severity::Medium,
        category: Category::Idioms,
        clippy_lint: None,
        detection_pattern: None,
        correct_alternative: "Add #[tracing::instrument(skip(db, state))] to async functions",
        doc_path: "docs/patterns/AP-009-missing-tracing-span.md",
    },
    AntiPattern {
        id: "AP-010",
        name: "unbounded_channel",
        description: "Unbounded channels can consume unlimited memory under load",
        severity: Severity::High,
        category: Category::AsyncSafety,
        clippy_lint: None,
        detection_pattern: Some(r"unbounded_channel"),
        correct_alternative: "Use bounded channels: tokio::sync::mpsc::channel(capacity)",
        doc_path: "docs/patterns/AP-010-unbounded-channel.md",
    },
    AntiPattern {
        id: "AP-011",
        name: "missing_timeout",
        description: "Async operations without timeouts can hang indefinitely",
        severity: Severity::High,
        category: Category::AsyncSafety,
        clippy_lint: None,
        detection_pattern: Some(r"\.await"),
        correct_alternative: "Wrap with tokio::time::timeout(Duration::from_secs(N), future).await",
        doc_path: "docs/patterns/AP-011-missing-timeout.md",
    },
    AntiPattern {
        id: "AP-012",
        name: "panic_in_drop",
        description: "Panicking in Drop implementations causes double panics and aborts",
        severity: Severity::Critical,
        category: Category::ErrorHandling,
        clippy_lint: None,
        detection_pattern: Some(r"impl\s+Drop\s+for"),
        correct_alternative: "Log errors in Drop instead of panicking, or use a close() method",
        doc_path: "docs/patterns/AP-012-panic-in-drop.md",
    },
    AntiPattern {
        id: "AP-013",
        name: "reimplemented_middleware",
        description: "Reimplementing cross-cutting concerns that should be middleware",
        severity: Severity::Medium,
        category: Category::Idioms,
        clippy_lint: None,
        detection_pattern: None,
        correct_alternative: "Use tower middleware layers for auth, logging, rate limiting",
        doc_path: "docs/patterns/AP-013-reimplemented-middleware.md",
    },
    AntiPattern {
        id: "AP-014",
        name: "hardcoded_config",
        description: "Hardcoded numeric or string literals that should be configuration",
        severity: Severity::Low,
        category: Category::Configuration,
        clippy_lint: None,
        detection_pattern: Some(
            r#"(?:port|host|url|timeout|limit|max|min)\s*(?:=|:)\s*(?:\d+|"[^"]*")"#,
        ),
        correct_alternative: "Use environment variables, config files, or const declarations",
        doc_path: "docs/patterns/AP-014-hardcoded-config.md",
    },
    AntiPattern {
        id: "AP-015",
        name: "missing_must_use",
        description: "Public functions returning Result without #[must_use] allow silent error drops",
        severity: Severity::Low,
        category: Category::ErrorHandling,
        clippy_lint: Some("clippy::must_use_candidate"),
        detection_pattern: Some(r"pub\s+fn\s+\w+[^}]*->\s*Result"),
        correct_alternative: "Add #[must_use] attribute to public functions returning Result",
        doc_path: "docs/patterns/AP-015-missing-must-use.md",
    },
];

/// Look up an anti-pattern by its ID.
pub fn get_anti_pattern(id: &str) -> Option<&'static AntiPattern> {
    ANTI_PATTERNS.iter().find(|ap| ap.id == id)
}

/// Get all anti-patterns with the given severity level.
pub fn by_severity(severity: Severity) -> Vec<&'static AntiPattern> {
    ANTI_PATTERNS
        .iter()
        .filter(|ap| ap.severity == severity)
        .collect()
}

/// Get all anti-patterns in the given category.
pub fn by_category(category: Category) -> Vec<&'static AntiPattern> {
    ANTI_PATTERNS
        .iter()
        .filter(|ap| ap.category == category)
        .collect()
}

/// Scan a single file for anti-pattern violations using regex-based detection.
///
/// Skips patterns that require AST analysis (detection_pattern is None).
/// Excludes lines inside `#[cfg(test)]` modules.
#[must_use = "violations should be inspected"]
pub fn scan_file(path: &Path, excludes: &[&str]) -> Result<Vec<Violation>, JrError> {
    let content = std::fs::read_to_string(path).map_err(|e| JrError::Io(e.to_string()))?;
    let file_str = path.display().to_string();

    for exclude in excludes {
        if file_str.contains(exclude) {
            return Ok(Vec::new());
        }
    }

    let mut violations = Vec::new();
    let test_mod_ranges = find_test_module_ranges(&content);

    for ap in ANTI_PATTERNS.iter() {
        let Some(pattern_str) = ap.detection_pattern else {
            continue;
        };

        let re = regex::Regex::new(pattern_str).map_err(|e| JrError::Regex(e.to_string()))?;

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;

            if is_in_test_module(line_num, &test_mod_ranges) {
                continue;
            }

            if let Some(m) = re.find(line) {
                violations.push(Violation {
                    anti_pattern_id: ap.id,
                    severity: ap.severity,
                    file: file_str.clone(), // clone: shared across violations in same file
                    line: line_num,
                    column: m.start() + 1,
                    context: line.trim().to_string(),
                    suggestion: ap.correct_alternative.to_string(),
                });
            }
        }
    }

    Ok(violations)
}

/// Scan a directory recursively for anti-pattern violations.
#[must_use = "violations should be inspected"]
pub fn scan_directory(root: &Path, excludes: &[&str]) -> Result<Vec<Violation>, JrError> {
    let mut all_violations = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !name.starts_with('.') && name != "target"
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            let file_violations = scan_file(path, excludes)?;
            all_violations.extend(file_violations);
        }
    }

    Ok(all_violations)
}

struct TestModuleRange {
    start: usize,
    end: usize,
}

fn find_test_module_ranges(content: &str) -> Vec<TestModuleRange> {
    let mut ranges = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        if line == "#[cfg(test)]" {
            let start = i + 1;
            let mut brace_depth = 0;
            let mut found_open = false;
            let mut j = start;

            while j < lines.len() {
                for ch in lines[j].chars() {
                    if ch == '{' {
                        brace_depth += 1;
                        found_open = true;
                    } else if ch == '}' {
                        brace_depth -= 1;
                        if found_open && brace_depth == 0 {
                            ranges.push(TestModuleRange {
                                start: start + 1,
                                end: j + 1,
                            });
                            i = j;
                            break;
                        }
                    }
                }
                if found_open && brace_depth == 0 {
                    break;
                }
                j += 1;
            }
        }
        i += 1;
    }

    ranges
}

fn is_in_test_module(line: usize, ranges: &[TestModuleRange]) -> bool {
    ranges.iter().any(|r| line >= r.start && line <= r.end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_ids_unique() {
        let ids: Vec<&str> = ANTI_PATTERNS.iter().map(|ap| ap.id).collect();
        let unique: HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len(), "Duplicate AP IDs found");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn get_anti_pattern_found() {
        let ap = get_anti_pattern("AP-001").expect("AP-001 should exist");
        assert_eq!(ap.name, "unwrap_in_handler");
    }

    #[test]
    fn get_anti_pattern_not_found() {
        assert!(get_anti_pattern("AP-999").is_none());
    }

    #[test]
    fn fifteen_patterns_registered() {
        assert_eq!(ANTI_PATTERNS.len(), 15);
    }

    #[test]
    fn by_severity_returns_correct_patterns() {
        let critical = by_severity(Severity::Critical);
        assert!(critical.len() >= 4);
        for ap in &critical {
            assert_eq!(ap.severity, Severity::Critical);
        }
    }

    #[test]
    fn by_category_returns_correct_patterns() {
        let security = by_category(Category::Security);
        assert!(security.len() >= 2);
        for ap in &security {
            assert_eq!(ap.category, Category::Security);
        }
    }
}
