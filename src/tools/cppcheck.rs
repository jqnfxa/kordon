//! cppcheck runner and `--xml --xml-version=2` parser.
//!
//! cppcheck is the cheap second opinion: a different engine with different
//! blind spots. It is invoked as a subprocess and never linked, so its GPL-3.0
//! licence does not reach Kordon's own Apache-2.0 code or the code it analyses.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;

use crate::cwe::CweTable;
use crate::finding::{Confidence, Event, Finding, Severity, Tool};
use crate::tools::{ToolOutcome, ToolRun};

pub fn tool() -> Tool {
    Tool::new("cppcheck")
}

/// Run cppcheck over either a compile database or a list of source files.
///
/// `--enable=warning,style,portability` rather than `all`: `all` adds
/// `information` and `unusedFunction`, which produce pure noise
/// (`missingIncludeSystem` for every standard header) and no defect signal.
pub fn run(
    binary: &str,
    sources: &[PathBuf],
    std: &str,
    jobs: usize,
    exhaustive: bool,
    table: &CweTable,
) -> ToolRun {
    let mut cmd = Command::new(binary);
    cmd.arg(format!("--std={std}"))
        .arg("--language=c++")
        .arg("--enable=warning,style,portability")
        .arg("--inline-suppr")
        .arg("--error-exitcode=0")
        .arg(format!("-j{jobs}"))
        .arg("--xml")
        .arg("--xml-version=2");

    if exhaustive {
        // --check-level appeared in cppcheck 2.11.
        cmd.arg("--check-level=exhaustive");
    }

    // Always an explicit file list rather than --project: the caller has
    // already decided which units are in scope, and pointing cppcheck at the
    // project would re-add the ones it excluded.
    for source in sources {
        cmd.arg(source);
    }

    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) => {
            return ToolRun::failed(tool(), format!("could not run `{binary}`: {err}"));
        }
    };

    // cppcheck writes its XML report to stderr, not stdout.
    let xml = String::from_utf8_lossy(&output.stderr).into_owned();

    match parse(&xml, table) {
        Ok(findings) => ToolRun {
            tool: tool(),
            outcome: ToolOutcome::Ran,
            findings,
            notes: Vec::new(),
        },
        Err(err) => ToolRun::failed(tool(), format!("could not parse cppcheck XML: {err}")),
    }
}

/// cppcheck's own severity vocabulary.
fn severity_of(raw: &str) -> Severity {
    match raw {
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "style" | "performance" | "portability" => Severity::Style,
        _ => Severity::Info,
    }
}

/// Default trust per severity, used when the mapping table has no opinion.
/// cppcheck `error` findings are value-flow conclusions; `style` findings are
/// pattern matches that frequently do not describe a defect at all.
fn default_confidence(severity: Severity) -> Confidence {
    match severity {
        Severity::Error => Confidence::High,
        Severity::Warning => Confidence::Medium,
        _ => Confidence::Low,
    }
}

/// Parse a cppcheck v2 XML report.
///
/// Shape:
/// ```xml
/// <results version="2">
///   <errors>
///     <error id="deallocuse" severity="error" msg="..." cwe="416">
///       <location file="a.cpp" line="26" column="6"/>   <!-- primary -->
///       <location file="a.cpp" line="24" column="1" info="allocated here"/>
///     </error>
///   </errors>
/// </results>
/// ```
/// The first `<location>` is the defect site; any further ones are the
/// value-flow path that justifies it.
pub fn parse(xml: &str, table: &CweTable) -> Result<Vec<Finding>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut findings = Vec::new();
    let mut current: Option<PartialError> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Eof) => break,

            // `<error>` with children. Closed by a matching End event.
            Ok(XmlEvent::Start(e)) if e.name().as_ref() == b"error" => {
                current = Some(PartialError::from_attrs(&e));
            }

            // `<error .../>` with no children, so no End event will arrive and
            // it can never have a location. Settle it immediately rather than
            // leaving it to be silently overwritten by the next error.
            Ok(XmlEvent::Empty(e)) if e.name().as_ref() == b"error" => {
                if let Some(finding) = PartialError::from_attrs(&e).finish(table) {
                    findings.push(finding);
                }
            }

            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e))
                if e.name().as_ref() == b"location" =>
            {
                if let Some(partial) = current.as_mut() {
                    partial.locations.push(RawLocation::from_attrs(&e));
                }
            }

            Ok(XmlEvent::End(e)) if e.name().as_ref() == b"error" => {
                if let Some(partial) = current.take() {
                    if let Some(finding) = partial.finish(table) {
                        findings.push(finding);
                    }
                }
            }

            Ok(_) => {}
            Err(err) => {
                return Err(err).context("malformed XML");
            }
        }
        buf.clear();
    }

    Ok(findings)
}

struct RawLocation {
    file: PathBuf,
    line: u32,
    column: u32,
    info: String,
}

impl RawLocation {
    fn from_attrs(e: &quick_xml::events::BytesStart<'_>) -> Self {
        let mut loc = RawLocation {
            file: PathBuf::new(),
            line: 0,
            column: 0,
            info: String::new(),
        };
        for attr in e.attributes().flatten() {
            let value = attr.unescape_value().unwrap_or_default().into_owned();
            match attr.key.as_ref() {
                b"file" => loc.file = PathBuf::from(value),
                b"line" => loc.line = value.parse().unwrap_or(0),
                b"column" => loc.column = value.parse().unwrap_or(0),
                b"info" => loc.info = value,
                _ => {}
            }
        }
        loc
    }
}

#[derive(Default)]
struct PartialError {
    id: String,
    severity: String,
    message: String,
    native_cwe: Option<u32>,
    locations: Vec<RawLocation>,
}

impl PartialError {
    fn from_attrs(e: &quick_xml::events::BytesStart<'_>) -> Self {
        let mut partial = PartialError::default();
        for attr in e.attributes().flatten() {
            let value = attr.unescape_value().unwrap_or_default().into_owned();
            match attr.key.as_ref() {
                b"id" => partial.id = value,
                b"severity" => partial.severity = value,
                b"msg" => partial.message = value,
                b"cwe" => partial.native_cwe = value.parse().ok(),
                _ => {}
            }
        }
        partial
    }

    fn finish(self, table: &CweTable) -> Option<Finding> {
        // A finding with no location cannot be deduped or acted on.
        let primary = self.locations.first()?;

        let severity = severity_of(&self.severity);
        let class = table.classify(
            &tool(),
            &self.id,
            &self.message,
            self.native_cwe,
            default_confidence(severity),
        );

        let events = self.locations[1..]
            .iter()
            .map(|loc| Event {
                file: loc.file.clone(),
                line: loc.line,
                column: loc.column,
                message: loc.info.clone(),
            })
            .collect();

        Some(Finding {
            tool: tool(),
            native_id: self.id,
            cwe: class.cwe,
            cwe_source: class.source,
            file: canonical(&primary.file),
            line: primary.line,
            column: primary.column,
            severity,
            confidence: class.confidence,
            message: self.message,
            events,
        })
    }
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::CweSource;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <cppcheck version="2.13.0"/>
  <errors>
    <error id="deallocuse" severity="error" msg="Dereferencing &apos;q&apos; after it is deallocated" cwe="416">
      <location file="probe.cpp" line="26" column="6"/>
      <symbol>q</symbol>
    </error>
    <error id="zerodiv" severity="error" msg="Division by zero." cwe="369">
      <location file="probe.cpp" line="16" column="14" info="Division by zero"/>
      <location file="probe.cpp" line="15" column="13" info="Assignment &apos;d=0&apos;"/>
    </error>
    <error id="operatorEqToSelf" severity="style" msg="no self-assignment check" cwe="398">
      <location file="probe.cpp" line="40" column="1"/>
    </error>
    <error id="noLocationHere" severity="information" msg="Cannot find include"/>
  </errors>
</results>"#;

    fn parsed() -> Vec<Finding> {
        let table = CweTable::builtin().unwrap();
        parse(SAMPLE, &table).expect("sample must parse")
    }

    #[test]
    fn parses_every_located_error() {
        // The location-less <error> is dropped; the other three survive.
        assert_eq!(parsed().len(), 3);
    }

    #[test]
    fn primary_location_is_the_defect_site() {
        let f = &parsed()[1];
        assert_eq!(f.native_id, "zerodiv");
        assert_eq!(f.line, 16); // the division, not the assignment
        assert_eq!(f.column, 14);
    }

    #[test]
    fn secondary_locations_become_the_event_path() {
        let f = &parsed()[1];
        assert_eq!(f.events.len(), 1);
        assert_eq!(f.events[0].line, 15);
        assert_eq!(f.events[0].message, "Assignment 'd=0'");
    }

    #[test]
    fn native_cwe_is_kept_when_the_table_agrees() {
        let f = &parsed()[1];
        assert_eq!(f.cwe, Some(369));
    }

    #[test]
    fn wrong_native_cwe_is_overridden() {
        // cppcheck says 398 "poor code quality"; it is a use after free.
        let f = &parsed()[2];
        assert_eq!(f.native_id, "operatorEqToSelf");
        assert_eq!(f.cwe, Some(416));
        assert_eq!(f.cwe_source, CweSource::Overridden);
    }

    #[test]
    fn severity_maps_to_kordon_vocabulary() {
        let all = parsed();
        assert_eq!(all[0].severity, Severity::Error);
        assert_eq!(all[2].severity, Severity::Style);
    }

    #[test]
    fn xml_entities_are_unescaped() {
        assert!(parsed()[0].message.contains("'q'"));
    }

    #[test]
    fn garbage_input_errors_rather_than_panicking() {
        let table = CweTable::builtin().unwrap();
        // An unclosed tag must surface as an error, not a crash.
        assert!(parse("<results><errors><error id=", &table).is_err());
    }
}
