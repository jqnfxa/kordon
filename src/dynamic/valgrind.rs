//! Parsing valgrind's memcheck XML.
//!
//! XML rather than the human-readable output, because the text form folds the
//! defect location and the allocation site into one indented blob that cannot
//! be split reliably. `--xml=yes` separates them into distinct `<stack>`
//! elements.
//!
//! Two shapes have to be handled: leaks carry their description in
//! `<xwhat><text>`, everything else in `<what>`.

use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;

use crate::dynamic::report::{Frame, RuntimeReport};

/// Errors valgrind reports that are not defects in the analyzed program.
///
/// `Leak_StillReachable` is memory alive at exit with a pointer still held --
/// the normal state of any program with a global cache or singleton, and not a
/// leak by any definition Kordon uses. Reporting it would bury the two leak
/// classes that are real.
fn is_defect(kind: &str) -> bool {
    !matches!(kind, "Leak_StillReachable" | "Leak_PossiblyLost")
}

/// Extract every error from a memcheck XML document.
///
/// Only the **first** `<stack>` of each error is kept. Later ones describe
/// where the memory was allocated or freed, which is context rather than the
/// defect's location; anchoring on them would report the leak against the
/// allocation site of an unrelated block.
pub fn parse(xml: &str) -> Vec<RuntimeReport> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut out = Vec::new();
    let mut buf = Vec::new();

    let mut in_error = false;
    let mut stack_index = 0usize;
    let mut in_frame = false;
    let mut kind = String::new();
    let mut what = String::new();
    let mut aux = String::new();
    let mut frames: Vec<Frame> = Vec::new();
    let (mut fun, mut dir, mut file, mut line) = (String::new(), String::new(), String::new(), 0u32);
    let mut field: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "error" => {
                        in_error = true;
                        stack_index = 0;
                        kind.clear();
                        what.clear();
                        aux.clear();
                        frames.clear();
                    }
                    "stack" if in_error => stack_index += 1,
                    "frame" if in_error && stack_index == 1 => {
                        in_frame = true;
                        fun.clear();
                        dir.clear();
                        file.clear();
                        line = 0;
                    }
                    _ => field = Some(name),
                }
            }
            Ok(XmlEvent::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                match field.as_deref() {
                    Some("kind") if in_error => kind = text,
                    // `what` for ordinary errors, `text` inside `xwhat` for leaks.
                    Some("what") | Some("text") if in_error && what.is_empty() => what = text,
                    // `InvalidRead` covers both an access past a live block and
                    // an access to a freed one -- CWE-125 and CWE-416, which are
                    // different defects. Only auxwhat says which, so it is
                    // carried into the message for the mapping table to
                    // discriminate on, exactly as cppcheck's are.
                    Some("auxwhat") if in_error && aux.is_empty() => aux = text,
                    Some("fn") if in_frame => fun = text,
                    Some("dir") if in_frame => dir = text,
                    Some("file") if in_frame => file = text,
                    Some("line") if in_frame => line = text.parse().unwrap_or(0),
                    _ => {}
                }
            }
            Ok(XmlEvent::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "frame" if in_frame => {
                        in_frame = false;
                        // Frames in stripped objects carry no file at all.
                        if !file.is_empty() {
                            let path = if dir.is_empty() {
                                std::path::PathBuf::from(&file)
                            } else {
                                std::path::Path::new(&dir).join(&file)
                            };
                            frames.push(Frame {
                                function: fun.clone(),
                                file: path,
                                line,
                                column: 0,
                            });
                        }
                    }
                    "error" if in_error => {
                        in_error = false;
                        if is_defect(&kind) && !frames.is_empty() {
                            let message = if aux.is_empty() {
                                what.clone()
                            } else {
                                format!("{what} — {aux}")
                            };
                            out.push(RuntimeReport {
                                engine: "valgrind".to_string(),
                                class: kind.clone(),
                                message,
                                frames: std::mem::take(&mut frames),
                            });
                        }
                    }
                    _ => {}
                }
                field = None;
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a real `valgrind --xml=yes` run. The second `<stack>` is
    /// the allocation site, which is exactly the trap this parser has to avoid.
    const XML: &str = r#"<valgrindoutput>
<error><unique>0x0</unique><kind>InvalidRead</kind>
<what>Invalid read of size 4</what>
<stack><frame><ip>0x109171</ip><fn>main</fn><dir>/tmp/dyn</dir><file>vg2.cpp</file><line>4</line></frame></stack>
<auxwhat>Address is 0 bytes inside a block of size 16 free'd</auxwhat>
<stack><frame><ip>0x484</ip><fn>malloc</fn></frame>
<frame><ip>0x109168</ip><fn>main</fn><dir>/tmp/dyn</dir><file>vg2.cpp</file><line>3</line></frame></stack>
</error>
<error><unique>0x1</unique><kind>Leak_DefinitelyLost</kind>
<xwhat><text>64 bytes in 1 blocks are definitely lost</text><leakedbytes>64</leakedbytes></xwhat>
<stack><frame><ip>0x484</ip><fn>malloc</fn></frame>
<frame><ip>0x109171</ip><fn>leak()</fn><dir>/tmp/dyn</dir><file>lsan_probe.cpp</file><line>2</line></frame></stack>
</error>
<error><unique>0x2</unique><kind>Leak_StillReachable</kind>
<xwhat><text>8 bytes still reachable</text></xwhat>
<stack><frame><ip>0x1</ip><fn>g()</fn><dir>/tmp</dir><file>x.cpp</file><line>1</line></frame></stack>
</error>
</valgrindoutput>"#;

    #[test]
    fn only_the_first_stack_locates_the_defect() {
        let reports = parse(XML);
        let read = &reports[0];
        assert_eq!(read.class, "InvalidRead");
        // Line 4 is the bad read; line 3 is where the block was allocated and
        // belongs to the second <stack>.
        assert_eq!(read.frames.len(), 1);
        assert_eq!(read.frames[0].line, 4);
    }

    #[test]
    fn auxwhat_rides_along_so_the_table_can_discriminate() {
        // InvalidRead is both CWE-125 and CWE-416; only the auxiliary text
        // says which. Dropping it would file every use-after-free as an
        // out-of-bounds read.
        let reports = parse(XML);
        assert!(reports[0].message.contains("free'd"));
    }

    #[test]
    fn leaks_carry_their_text_in_xwhat_not_what() {
        let reports = parse(XML);
        let leak = reports.iter().find(|r| r.class == "Leak_DefinitelyLost").unwrap();
        assert!(leak.message.contains("definitely lost"));
    }

    #[test]
    fn still_reachable_is_not_a_leak() {
        // Memory alive at exit with a pointer still held is the normal state
        // of any program with a singleton. Reporting it buries the real leaks.
        assert!(parse(XML).iter().all(|r| r.class != "Leak_StillReachable"));
    }
}
