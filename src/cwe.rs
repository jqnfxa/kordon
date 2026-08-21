//! The curated tool-check -> CWE mapping table.
//!
//! This table is Kordon's own IP, analogous to what MISRA published for their
//! own rules. It exists because the engines disagree about what a CWE is:
//!
//!   * clang-tidy reports no CWE at all, so every check needs an entry here.
//!   * cppcheck reports one, but frequently the *parent* class -- it labels
//!     `operatorEqToSelf` as CWE-398 when the defect is a CWE-416 use after
//!     free. Trusting the tool there loses real findings.
//!   * One check id can cover several defect classes: `unix.Malloc` is leak,
//!     use-after-free, double-free and free-of-non-heap at once. Those are
//!     separated by matching the diagnostic message.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::finding::{Confidence, CweSource, Tool};

/// The table shipped inside the binary. `--cwe-map` overrides it.
const BUILTIN_TABLE: &str = include_str!("../data/cwe_map.toml");

#[derive(Debug, Clone, Deserialize)]
struct RawTable {
    #[serde(default)]
    cwe: Vec<CweEntry>,
    #[serde(default)]
    rule: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CweEntry {
    pub id: u32,
    pub name: String,
    /// 1 = in Kordon's scope. 2/3 = explicitly out of scope (injection,
    /// authorization). 0 = style indicator, not a defect class we claim.
    pub tier: u8,
}

#[derive(Debug, Clone, Deserialize)]
struct Rule {
    tool: String,
    check: String,
    /// Discriminates checks covering several defect classes. Rules carrying
    /// this are tried before the bare fallback rule for the same check.
    #[serde(default)]
    message_contains: Option<String>,
    cwe: u32,
    #[serde(default)]
    confidence: Option<Confidence>,
}

/// Resolved classification for one raw diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
    pub cwe: Option<u32>,
    pub source: CweSource,
    pub confidence: Confidence,
}

pub struct CweTable {
    catalog: HashMap<u32, CweEntry>,
    /// (tool, check) -> rules. Rules with `message_contains` sort first, so a
    /// linear scan naturally tries specific patterns before the fallback.
    rules: HashMap<(String, String), Vec<Rule>>,
    /// check -> rules, ignoring which tool declared them.
    ///
    /// Several runners surface the same engine: `clang-analyzer-core.*` checks
    /// arrive both from clang-tidy and from the direct CTU pass. Keying only on
    /// (tool, check) would mean re-declaring the entire table per runner, and
    /// getting that wrong is silent -- the findings simply come back unmapped
    /// and vanish from the in-scope report. Check ids do not collide across the
    /// engines Kordon drives (clang's are dotted/prefixed, cppcheck's are
    /// camelCase), so falling back to a tool-independent lookup is safe.
    by_check: HashMap<String, Vec<Rule>>,
}

impl CweTable {
    pub fn builtin() -> Result<Self> {
        Self::from_toml(BUILTIN_TABLE).context("built-in CWE table is malformed")
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        let raw: RawTable = toml::from_str(text)?;

        let catalog = raw.cwe.into_iter().map(|e| (e.id, e)).collect();

        let mut rules: HashMap<(String, String), Vec<Rule>> = HashMap::new();
        let mut by_check: HashMap<String, Vec<Rule>> = HashMap::new();
        for rule in raw.rule {
            by_check
                .entry(rule.check.clone())
                .or_default()
                .push(rule.clone());
            rules
                .entry((rule.tool.clone(), rule.check.clone()))
                .or_default()
                .push(rule);
        }
        for bucket in by_check.values_mut() {
            bucket.sort_by_key(|r| r.message_contains.is_none());
        }
        for bucket in rules.values_mut() {
            // Specific-before-fallback. `sort_by_key` is stable, so rules that
            // both carry a pattern keep their file order -- which is how the
            // table author expresses precedence between them.
            bucket.sort_by_key(|r| r.message_contains.is_none());
        }

        Ok(CweTable {
            catalog,
            rules,
            by_check,
        })
    }

    pub fn name_of(&self, cwe: u32) -> Option<&str> {
        self.catalog.get(&cwe).map(|e| e.name.as_str())
    }

    /// True if this CWE is one Kordon claims to target (tier 1).
    ///
    /// An unknown CWE is *not* in scope: the report must never imply coverage
    /// of a class nobody has classified.
    pub fn in_scope(&self, cwe: u32) -> bool {
        self.catalog.get(&cwe).is_some_and(|e| e.tier == 1)
    }

    /// Classify one raw diagnostic.
    ///
    /// `native_cwe` is whatever the tool reported itself, if anything. A
    /// matching table rule always wins over it -- see the module docs for why.
    pub fn classify(
        &self,
        tool: &Tool,
        check: &str,
        message: &str,
        native_cwe: Option<u32>,
        default_confidence: Confidence,
    ) -> Classification {
        let key = (tool.as_str().to_string(), check.to_string());

        // Exact (tool, check) first, then the tool-independent fallback.
        let bucket = self
            .rules
            .get(&key)
            .or_else(|| self.by_check.get(check));

        if let Some(bucket) = bucket {
            let hit = bucket.iter().find(|rule| match &rule.message_contains {
                Some(pattern) => message.contains(pattern.as_str()),
                None => true,
            });

            if let Some(rule) = hit {
                let source = match native_cwe {
                    Some(native) if native != rule.cwe => CweSource::Overridden,
                    _ => CweSource::Mapped,
                };
                return Classification {
                    cwe: Some(rule.cwe),
                    source,
                    confidence: rule.confidence.unwrap_or(default_confidence),
                };
            }
        }

        match native_cwe {
            Some(cwe) => Classification {
                cwe: Some(cwe),
                source: CweSource::Native,
                confidence: default_confidence,
            },
            None => Classification {
                cwe: None,
                source: CweSource::Unmapped,
                confidence: default_confidence,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> CweTable {
        CweTable::builtin().expect("built-in table must parse")
    }

    #[test]
    fn builtin_table_parses() {
        let t = table();
        assert_eq!(t.name_of(416), Some("Use After Free"));
        assert!(t.in_scope(416));
    }

    #[test]
    fn style_cwes_are_out_of_scope() {
        let t = table();
        // cppcheck labels a lot of real defects CWE-398; it must never count
        // as an in-scope finding on its own.
        assert!(!t.in_scope(398));
        assert!(!t.in_scope(561));
    }

    #[test]
    fn unknown_cwe_is_not_silently_in_scope() {
        assert!(!table().in_scope(99999));
    }

    #[test]
    fn dead_store_confidence_splits_on_what_the_store_cost() {
        let t = table();
        let tool = Tool::new("clang-tidy");
        // A value computed and thrown away is the shape with no benign
        // reading -- an accumulator nothing consumes, say.
        let discarded = t.classify(
            &tool,
            "clang-analyzer-deadcode.DeadStores",
            "Value stored to 'v' is never read",
            None,
            Confidence::Medium,
        );
        assert_eq!(discarded.confidence, Confidence::High);

        // A computed initializer replaced before it is read wasted a call, but
        // may be a deliberate default that a branch usually replaces.
        let initializer = t.classify(
            &tool,
            "clang-analyzer-deadcode.DeadStores",
            "Value stored to 'w' during its initialization is never read",
            None,
            Confidence::Medium,
        );
        assert_eq!(initializer.confidence, Confidence::Medium);
        assert_eq!(discarded.cwe, initializer.cwe);
    }

    #[test]
    fn message_pattern_beats_fallback() {
        let t = table();
        let tidy = Tool::new("clang-tidy");

        // One check id, three defect classes -- separated only by message.
        let uaf = t.classify(
            &tidy,
            "clang-analyzer-unix.Malloc",
            "Use of memory after it is freed",
            None,
            Confidence::Medium,
        );
        assert_eq!(uaf.cwe, Some(416));

        let double = t.classify(
            &tidy,
            "clang-analyzer-unix.Malloc",
            "Attempt to free released memory",
            None,
            Confidence::Medium,
        );
        assert_eq!(double.cwe, Some(415));

        // No pattern matches -> the bare fallback rule for the same check.
        let leak = t.classify(
            &tidy,
            "clang-analyzer-unix.Malloc",
            "Potential leak of memory pointed to by 'p'",
            None,
            Confidence::Medium,
        );
        assert_eq!(leak.cwe, Some(401));
    }

    #[test]
    fn table_overrides_wrong_native_cwe() {
        // cppcheck calls this CWE-398. It is a use after free.
        let c = table().classify(
            &Tool::new("cppcheck"),
            "operatorEqToSelf",
            "'operator=' should check for self-assignment",
            Some(398),
            Confidence::Medium,
        );
        assert_eq!(c.cwe, Some(416));
        assert_eq!(c.source, CweSource::Overridden);
    }

    #[test]
    fn native_cwe_passes_through_when_untabled() {
        let c = table().classify(
            &Tool::new("cppcheck"),
            "someCheckKordonHasNeverSeen",
            "whatever",
            Some(369),
            Confidence::Medium,
        );
        assert_eq!(c.cwe, Some(369));
        assert_eq!(c.source, CweSource::Native);
    }

    #[test]
    fn unmapped_is_reported_not_dropped() {
        let c = table().classify(
            &Tool::new("clang-tidy"),
            "modernize-use-nullptr",
            "use nullptr",
            None,
            Confidence::Low,
        );
        assert_eq!(c.cwe, None);
        assert_eq!(c.source, CweSource::Unmapped);
    }

    #[test]
    fn rule_confidence_overrides_tool_default() {
        // A Rule-of-Five violation is a *latent* double free, not an observed
        // one -- the table must be able to say so even though the tool is
        // otherwise trusted.
        let c = table().classify(
            &Tool::new("clang-tidy"),
            "cppcoreguidelines-special-member-functions",
            "class 'Foo' defines a destructor but does not define ...",
            None,
            Confidence::High,
        );
        assert_eq!(c.cwe, Some(415));
        assert_eq!(c.confidence, Confidence::Low);
    }
}
