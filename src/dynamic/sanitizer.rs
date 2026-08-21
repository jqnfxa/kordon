//! Parsing LLVM sanitizer output.
//!
//! Four sanitizers share one runner because they share one output shape, with
//! one exception. ASan, LSan and MSan all print a banner naming the engine and
//! the defect class, followed by a stack trace. UBSan does not: it prints a
//! single self-contained line per defect and no trace at all.
//!
//! Everything here is line-based and hand-written, matching the rest of the
//! codebase; the formats are stable enough across LLVM releases that a parser
//! is cheaper than a dependency.

use crate::dynamic::report::{Frame, RuntimeReport};

/// Parse one frame of a sanitizer stack trace.
///
///     #1 0x5f5151071b61 in leak() /tmp/dyn/lsan_probe.cpp:2:32
///
/// Split from the right, because the function name can contain spaces
/// (`void f(int, int)`) while the location never does. Frames with no source
/// location -- the allocator interceptor at #0, or any frame in a stripped
/// object -- return `None` and are dropped rather than guessed at.
fn parse_frame(line: &str) -> Option<Frame> {
    let rest = line.trim().strip_prefix('#')?;
    let rest = rest.split_once(' ')?.1; // drop the frame number
    let rest = rest.split_once(" in ")?.1; // drop the instruction pointer
    let (function, location) = rest.rsplit_once(' ')?;

    // FILE:LINE:COL *or* FILE:LINE -- both occur, and which one depends on the
    // optimisation level rather than on the sanitizer. At -O0 the column is
    // there; at -O1 it usually is not. Requiring three parts silently dropped
    // every ASan frame in an -O1 build, and a report whose frames are all
    // dropped is discarded as frameless, so the defect vanished entirely.
    //
    // The numeric parse is what decides, not the shape: `(BuildId: ...)`
    // contains a colon too.
    let (head, last) = location.rsplit_once(':')?;
    let last_num = last.parse::<u32>().ok()?;
    let (file, line_no, column) = match head.rsplit_once(':') {
        Some((file, mid)) => match mid.parse::<u32>() {
            Ok(line_no) => (file, line_no, last_num),
            // A colon in the path itself, not a line number.
            Err(_) => (head, last_num, 0),
        },
        None => (head, last_num, 0),
    };
    Some(Frame {
        function: function.trim().to_string(),
        file: file.into(),
        line: line_no,
        column,
    })
}

/// Turn a sanitizer's free-text defect description into a stable id.
///
/// `heap-use-after-free on address 0x60200000eff0 at pc ...` becomes
/// `heap-use-after-free`. The address and pc vary per run, so keeping them
/// would make every occurrence a distinct native id and defeat both dedup and
/// the mapping table.
fn class_of(description: &str) -> String {
    let mut words = description.split_whitespace();
    let first = words.next().unwrap_or("unknown");
    // ASan phrases the double-free report as `attempting double-free on 0x..`,
    // where every other class leads with its own name. Taking the first word
    // there would file every double free under `attempting`.
    let word = if first == "attempting" {
        words.next().unwrap_or(first)
    } else {
        first
    };
    word.trim_end_matches(':').to_string()
}

/// UBSan's defect phrasings, mapped to stable ids.
///
/// Curated rather than derived, for the same reason the cppcheck CWE overrides
/// are: the messages embed values that change every run. Deriving an id from
/// `load of address 0x502000000034 with insufficient space for an object of
/// type 'int'` yields a different id on every execution, so nothing dedups and
/// nothing ever matches the mapping table.
///
/// The list is UBSan's own vocabulary and is stable across LLVM releases.
/// Anything unrecognised falls through to a truncated form rather than being
/// dropped -- an unmapped finding is visible as a gap, a discarded one is not.
const UBSAN_PHRASES: &[(&str, &str)] = &[
    ("load of misaligned address", "misaligned-load"),
    ("store to misaligned address", "misaligned-store"),
    ("member access within misaligned address", "misaligned-member-access"),
    ("load of address", "insufficient-space-for-object"),
    ("store to address", "insufficient-space-for-object"),
    ("member access within null pointer", "member-access-within-null-pointer"),
    ("load of null pointer", "load-of-null-pointer"),
    ("call to null pointer", "call-of-null-pointer"),
    ("null pointer passed as argument", "null-pointer-passed-as-argument"),
    ("reference binding to null pointer", "reference-binding-to-null-pointer"),
    ("applying non-zero offset", "pointer-overflow"),
    ("pointer index expression", "pointer-overflow"),
    ("out of bounds for type", "index-out-of-bounds"),
    ("shift exponent", "shift-exponent-too-large"),
    ("left shift of negative value", "left-shift-of-negative"),
    ("variable length array bound", "vla-bound-not-positive"),
    ("downcast of address", "invalid-downcast"),
    ("execution reached", "unreachable-code-reached"),
];

fn ubsan_class(message: &str) -> String {
    // The overflow and division messages are already `kind: detail`, so the
    // text before the colon is exactly the id and needs no table.
    if let Some((head, _)) = message.split_once(':') {
        let head = head.trim();
        if !head.is_empty() && head.split_whitespace().count() <= 5 {
            return head.replace(' ', "-");
        }
    }
    for (phrase, id) in UBSAN_PHRASES {
        if message.contains(phrase) {
            return (*id).to_string();
        }
    }
    // Unrecognised: keep it stable by dropping the parts that vary.
    message
        .split_whitespace()
        .filter(|w| !w.starts_with("0x") && !w.starts_with('\'') && w.parse::<i64>().is_err())
        .take(5)
        .collect::<Vec<_>>()
        .join("-")
}

/// UBSan reports one line per defect, with no trace:
///
///     f.cpp:2:66: runtime error: signed integer overflow: 2147483647 + 1 ...
///
/// The class is the text before the first colon of the message, kebab-cased,
/// so `signed integer overflow` and `shift exponent too large` stay distinct
/// in the mapping table.
fn parse_ubsan_line(line: &str) -> Option<RuntimeReport> {
    let (location, message) = line.split_once(": runtime error: ")?;
    let (head, col) = location.rsplit_once(':')?;
    let (file, line_no) = head.rsplit_once(':')?;
    let frame = Frame {
        function: String::new(),
        file: file.into(),
        line: line_no.parse().ok()?,
        column: col.parse().ok()?,
    };
    let class = ubsan_class(message);
    Some(RuntimeReport {
        engine: "UndefinedBehaviorSanitizer".to_string(),
        class,
        message: message.trim().to_string(),
        frames: vec![frame],
    })
}

/// Extract every report from a run's stderr.
pub fn parse(text: &str) -> Vec<RuntimeReport> {
    let mut out: Vec<RuntimeReport> = Vec::new();
    let mut current: Option<RuntimeReport> = None;

    // A block ends when the next one starts or the run summarises. Closing it
    // drops blocks that never collected a frame, which is exactly what the
    // LeakSanitizer banner is -- it announces leaks, then each `Direct leak
    // of` block carries the actual trace.
    fn close(current: &mut Option<RuntimeReport>, out: &mut Vec<RuntimeReport>) {
        if let Some(report) = current.take() {
            if !report.frames.is_empty() {
                out.push(report);
            }
        }
    }

    for line in text.lines() {
        let trimmed = line.trim();

        if let Some(report) = parse_ubsan_line(trimmed) {
            close(&mut current, &mut out);
            out.push(report);
            continue;
        }

        // ==1234==ERROR: AddressSanitizer: heap-use-after-free on address ...
        if let Some(after) = trimmed
            .split_once("==ERROR: ")
            .or_else(|| trimmed.split_once("==WARNING: "))
            .map(|(_, rest)| rest)
        {
            if let Some((engine, description)) = after.split_once(": ") {
                close(&mut current, &mut out);
                current = Some(RuntimeReport {
                    engine: engine.to_string(),
                    class: class_of(description),
                    message: description.trim().to_string(),
                    frames: Vec::new(),
                });
                continue;
            }
        }

        // Each leak gets its own block and its own trace.
        if trimmed.starts_with("Direct leak of") || trimmed.starts_with("Indirect leak of") {
            close(&mut current, &mut out);
            let direct = trimmed.starts_with("Direct");
            current = Some(RuntimeReport {
                engine: "LeakSanitizer".to_string(),
                class: if direct { "direct-leak" } else { "indirect-leak" }.to_string(),
                message: trimmed.trim_end_matches(" allocated from:").to_string(),
                frames: Vec::new(),
            });
            continue;
        }

        if trimmed.starts_with("SUMMARY:") {
            close(&mut current, &mut out);
            continue;
        }

        if trimmed.starts_with('#') {
            if let (Some(report), Some(frame)) = (current.as_mut(), parse_frame(trimmed)) {
                report.frames.push(frame);
            }
        }
    }
    close(&mut current, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `clang++ -fsanitize=address -O0` on a lost malloc.
    const LSAN: &str = "\
=================================================================\n\
==52697==ERROR: LeakSanitizer: detected memory leaks\n\
\n\
Direct leak of 64 byte(s) in 1 object(s) allocated from:\n\
    #0 0x5f5151031193 in malloc (/tmp/dyn/lsan_probe+0xc7193) (BuildId: 839bccbe)\n\
    #1 0x5f5151071b61 in leak() /tmp/dyn/lsan_probe.cpp:2:32\n\
    #2 0x5f5151071b43 in main /tmp/dyn/lsan_probe.cpp:3:14\n";

    /// Verbatim from `clang++ -fsanitize=undefined`.
    const UBSAN: &str = "\
ubsan_probe.cpp:2:66: runtime error: signed integer overflow: 2147483647 + 1 \
cannot be represented in type 'int'\n\
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ubsan_probe.cpp:2:66\n";

    #[test]
    fn leak_banner_is_not_a_finding_but_each_leak_is() {
        let reports = parse(LSAN);
        // The `ERROR: LeakSanitizer` line announces leaks and carries no trace
        // of its own. Emitting it too would double every leak.
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].class, "direct-leak");
        assert_eq!(reports[0].engine, "LeakSanitizer");
    }

    #[test]
    fn allocator_frame_is_dropped_and_project_frame_kept() {
        let reports = parse(LSAN);
        let frames = &reports[0].frames;
        // `#0 ... in malloc (...)` has no source location; anchoring there
        // would report every leak against the sanitizer's own interceptor.
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].function, "leak()");
        assert_eq!(frames[0].line, 2);
        assert_eq!(frames[0].column, 32);
    }

    #[test]
    fn ubsan_line_is_self_contained() {
        let reports = parse(UBSAN);
        assert_eq!(reports.len(), 1, "SUMMARY must not become a second finding");
        assert_eq!(reports[0].class, "signed-integer-overflow");
        assert_eq!(reports[0].frames[0].line, 2);
        assert_eq!(reports[0].frames[0].column, 66);
    }

    /// Verbatim from an -O1 ASan build run under ctest: no columns.
    const ASAN_O1: &str = "\
==56696==ERROR: AddressSanitizer: heap-use-after-free on address 0x502000000010 at pc 0x5c1\n\
READ of size 4 at 0x502000000010 thread T0\n\
    #0 0x5c143c52c287 in main /k/testdata/dynamic/use_after_free.cpp:10\n\
    #1 0x7a538242a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58\n";

    #[test]
    fn ubsan_ids_do_not_embed_a_per_run_address() {
        // Real text from an -O1 build. Deriving the id from the message would
        // produce a new id every execution, so nothing would dedup or map.
        let m = "load of address 0x502000000034 with insufficient space for an object of type \'int\'";
        assert_eq!(ubsan_class(m), "insufficient-space-for-object");
        assert!(!ubsan_class(m).contains("0x"));
        // The `kind: detail` messages need no table.
        assert_eq!(
            ubsan_class("signed integer overflow: 1 + 2147483647 cannot be represented"),
            "signed-integer-overflow"
        );
    }

    #[test]
    fn frames_without_a_column_are_still_frames() {
        // -O1 emits FILE:LINE, -O0 emits FILE:LINE:COL. Requiring the column
        // dropped every frame here, and a report with no frames is discarded --
        // so the whole defect disappeared while the run looked clean.
        let reports = parse(ASAN_O1);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].class, "heap-use-after-free");
        assert_eq!(reports[0].frames[0].line, 10);
        assert_eq!(reports[0].frames[0].column, 0);
    }

    #[test]
    fn double_free_is_not_filed_under_attempting() {
        // Real ASan text: `attempting double-free on 0x502000000010 in thread T0:`
        assert_eq!(class_of("attempting double-free on 0x50 in thread T0:"), "double-free");
    }

    #[test]
    fn class_drops_the_varying_address() {
        // Keeping the address would make every occurrence a distinct native
        // id, so nothing would ever dedup or map to a CWE.
        assert_eq!(
            class_of("heap-use-after-free on address 0x60200000eff0 at pc 0x1"),
            "heap-use-after-free"
        );
    }

    #[test]
    fn frame_without_source_location_is_not_guessed_at() {
        assert!(parse_frame("    #0 0x1 in malloc (/bin/x+0xc7193) (BuildId: ab)").is_none());
        assert!(parse_frame("    #1 0x1 in f() /a/b.cpp:9:4").is_some());
    }
}
