//! Byte offset -> (line, column) resolution.
//!
//! clang-tidy has no SARIF output (checked against LLVM 18) and its only
//! structured export, `--export-fixes`, locates every diagnostic by a byte
//! offset into the file rather than by line and column. Kordon has to do the
//! conversion itself, which means reading each analyzed file once and keeping
//! a line-start index for it.
//!
//! Columns are counted in bytes, 1-based, which is what clang itself prints.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Line-start offsets for one file, plus the file length.
struct LineIndex {
    /// Byte offset of the start of each line. Always begins with 0.
    starts: Vec<usize>,
    len: usize,
}

impl LineIndex {
    fn build(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut starts = vec![0usize];
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'\n' {
                starts.push(i + 1);
            }
        }
        LineIndex {
            starts,
            len: bytes.len(),
        }
    }

    fn resolve(&self, offset: usize) -> (u32, u32) {
        // Clamp rather than fail: a stale offset (file edited between analysis
        // and reporting) should degrade to the last line, not lose the finding.
        let offset = offset.min(self.len);

        // Index of the last line whose start is <= offset.
        let line = match self.starts.binary_search(&offset) {
            Ok(exact) => exact,
            Err(insert) => insert.saturating_sub(1),
        };

        let column = offset - self.starts[line] + 1;
        (line as u32 + 1, column as u32)
    }
}

/// Caches line indices so a file with many findings is read once.
#[derive(Default)]
pub struct OffsetResolver {
    /// `None` marks a file that could not be read, so we do not retry it once
    /// per finding.
    cache: HashMap<PathBuf, Option<LineIndex>>,
}

impl OffsetResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a byte offset to 1-based line and column.
    ///
    /// Returns `(1, 1)` if the file cannot be read -- the finding is still
    /// worth reporting with a degraded location, since the check id and
    /// message carry most of the signal.
    pub fn resolve(&mut self, file: &Path, offset: usize) -> (u32, u32) {
        let entry = self.cache.entry(file.to_path_buf()).or_insert_with(|| {
            std::fs::read_to_string(file).ok().map(|t| LineIndex::build(&t))
        });

        match entry {
            Some(index) => index.resolve(offset),
            None => (1, 1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_byte_is_line_one_column_one() {
        let index = LineIndex::build("abc\ndef\n");
        assert_eq!(index.resolve(0), (1, 1));
    }

    #[test]
    fn resolves_within_and_across_lines() {
        //           0123 4567 8
        let index = LineIndex::build("abc\ndef\ng");
        assert_eq!(index.resolve(2), (1, 3)); // 'c'
        assert_eq!(index.resolve(3), (1, 4)); // the '\n' itself
        assert_eq!(index.resolve(4), (2, 1)); // 'd'
        assert_eq!(index.resolve(6), (2, 3)); // 'f'
        assert_eq!(index.resolve(8), (3, 1)); // 'g'
    }

    #[test]
    fn empty_lines_do_not_shift_the_index() {
        //           0 1 2345
        let index = LineIndex::build("\n\nabc");
        assert_eq!(index.resolve(0), (1, 1));
        assert_eq!(index.resolve(1), (2, 1));
        assert_eq!(index.resolve(2), (3, 1));
        assert_eq!(index.resolve(4), (3, 3));
    }

    #[test]
    fn offset_past_end_clamps_instead_of_panicking() {
        let index = LineIndex::build("abc\n");
        // A file edited between analysis and reporting must not crash the run.
        assert_eq!(index.resolve(9_999), (2, 1));
    }

    #[test]
    fn empty_file() {
        let index = LineIndex::build("");
        assert_eq!(index.resolve(0), (1, 1));
    }

    #[test]
    fn unreadable_file_degrades_to_line_one() {
        let mut resolver = OffsetResolver::new();
        let missing = Path::new("/nonexistent/kordon/does-not-exist.cpp");
        assert_eq!(resolver.resolve(missing, 42), (1, 1));
    }
}
