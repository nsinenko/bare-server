//! The boot banner.
//!
//! A courtesy for a human at a terminal, not output. It goes to stderr exactly
//! once, only when stderr is a TTY, and never under `--quiet`: a server that
//! deliberately has no request logging should not be the noisiest thing in a
//! systemd journal. Under systemd or Docker, stderr is a pipe, so nothing here
//! ever reaches the journal.
//!
//! The rendering is split from the printing so the output can be asserted in
//! tests without a terminal attached.

use std::io::{self, IsTerminal, Write};

use crate::config::Storage;

/// The mark, drawn on the same geometry as `assets/brand/mark.svg`: brackets
/// closed around a block split once into header and body. Every line is 11
/// columns wide so the side text lines up.
const MARK: [&str; 5] = [
    "\u{250c}\u{2500}\u{2500}     \u{2500}\u{2500}\u{2510}",
    "\u{2502}         \u{2502}",
    "\u{2502}  \u{2588}\u{2588} \u{2588}\u{2588}\u{2588} \u{2502}",
    "\u{2502}         \u{2502}",
    "\u{2514}\u{2500}\u{2500}     \u{2500}\u{2500}\u{2518}",
];

const BLOCK: char = '\u{2588}';

/// Tint one row of the mark: box drawing muted, the first block run (the
/// header) in ember, the second (the body) left at the terminal's own
/// foreground so it stays legible on a light or a dark profile alike.
///
/// Works on runs rather than byte offsets, because every glyph here is multi-byte, so
/// a column index is not a byte index.
fn tint(row: &str) -> String {
    let mut out = String::new();
    let mut blocks_seen = 0;
    let mut rest = row;
    while !rest.is_empty() {
        let head = rest.chars().next().unwrap();
        let class = |c: char| (c == BLOCK, c == ' ');
        let take: String = rest.chars().take_while(|c| class(*c) == class(head)).collect();
        rest = &rest[take.len()..];
        match head {
            BLOCK => {
                blocks_seen += 1;
                if blocks_seen == 1 {
                    out.push_str(&format!("{EMBER}{take}{RESET}"));
                } else {
                    out.push_str(&take);
                }
            }
            ' ' => out.push_str(&take),
            _ => out.push_str(&format!("{MUTED}{take}{RESET}")),
        }
    }
    out
}

/// The ember accent as an ANSI 256-colour code. One accent, on one element.
const EMBER: &str = "\x1b[38;5;166m";
/// The brackets are structure, not content, so the palette's muted tone (#8B857A)
/// is for exactly this, and dropping them back lets the blocks read as the
/// subject. Not an accent, so this does not spend the one-accent budget.
const MUTED: &str = "\x1b[38;5;245m";
const RESET: &str = "\x1b[0m";

/// Does this locale claim UTF-8? The box drawing is unreadable if not, so the
/// ASCII form is used instead rather than emitting mojibake.
fn locale_is_utf8(v: Option<String>) -> bool {
    v.map(|v| v.to_ascii_uppercase().contains("UTF-8")).unwrap_or(false)
}

fn locale_from_env() -> Option<String> {
    std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_CTYPE"))
        .or_else(|_| std::env::var("LANG"))
        .ok()
}

/// The side text. `storage` and the brotli quality are the two settings that
/// change what the process actually does at boot, so they are read from the
/// running config rather than hardcoded, because the banner should not claim a
/// configuration the server is not in.
fn sides(storage: Storage, brotli_quality: u32, compression: bool) -> [String; 5] {
    let codec = if compression {
        format!("brotli q{brotli_quality}")
    } else {
        "no compression".to_string()
    };
    let store = match storage {
        Storage::Memory => "memory",
        Storage::Disk => "disk",
    };
    [
        String::new(),
        format!("bare server {}", env!("CARGO_PKG_VERSION")),
        format!("rustls \u{b7} {codec} \u{b7} storage={store}"),
        "MIT \u{b7} github.com/nsinenko/bare-server".to_string(),
        String::new(),
    ]
}

/// The one-line form, for `--version`, logs and CI. Machine-readable, so it
/// uses the hyphenated crate name rather than the logotype.
pub(crate) fn one_line() -> String {
    format!("bare-server {} ({})", env!("CARGO_PKG_VERSION"), env!("BARE_SERVER_TARGET"))
}

/// Render the banner. `unicode` selects the box drawing over the ASCII form,
/// `colour` tints the header block.
fn render(unicode: bool, colour: bool, storage: Storage, brotli_quality: u32, compression: bool) -> String {
    if !unicode {
        return format!("[ ## ### ] bare server {}\n", env!("CARGO_PKG_VERSION"));
    }
    let sides = sides(storage, brotli_quality, compression);
    let mut out = String::from("\n");
    for (mark, side) in MARK.iter().zip(&sides) {
        let mark = if colour { tint(mark) } else { mark.to_string() };
        // Trailing space on the blank-side rows would be invisible but is still
        // noise in a captured log.
        out.push_str(format!(" {mark} {side}").trim_end());
        out.push('\n');
    }
    out.push('\n');
    out
}

/// Print the banner to stderr, if a human is there to read it.
pub(crate) fn print(quiet: bool, storage: Storage, brotli_quality: u32, compression: bool) {
    let err = io::stderr();
    if quiet || !err.is_terminal() {
        return;
    }
    // NO_COLOR is honoured at any value, including empty. See no-color.org.
    let colour = std::env::var_os("NO_COLOR").is_none();
    let text = render(locale_is_utf8(locale_from_env()), colour, storage, brotli_quality, compression);
    let mut w = err.lock();
    let _ = w.write_all(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_detection_only_accepts_utf8() {
        assert!(locale_is_utf8(Some("en_US.UTF-8".into())));
        assert!(locale_is_utf8(Some("C.utf-8".into())));
        assert!(!locale_is_utf8(Some("en_US.ISO-8859-1".into())));
        assert!(!locale_is_utf8(Some("C".into())));
        assert!(!locale_is_utf8(None));
    }

    #[test]
    fn ascii_form_is_one_line_and_has_no_box_drawing() {
        let s = render(false, false, Storage::Memory, 11, true);
        assert_eq!(s.lines().count(), 1);
        assert!(s.contains("bare server"), "{s}");
        assert!(s.is_ascii(), "the ASCII fallback must not emit non-ASCII: {s:?}");
    }

    #[test]
    fn unicode_form_is_the_mark_plus_side_text() {
        let s = render(true, false, Storage::Memory, 11, true);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 7, "blank, five mark rows, blank: {s:?}");
        assert_eq!(lines[0], "");
        assert_eq!(lines[6], "");
        assert!(lines[2].contains("bare server"), "{s}");
        assert!(lines[3].contains("storage=memory"), "{s}");
        assert!(lines[4].contains("MIT"), "{s}");
        // No stray escape when colour is off.
        assert!(!s.contains('\x1b'), "{s:?}");
    }

    #[test]
    fn the_mark_rows_are_all_the_same_width() {
        // The side text is appended after the mark, so a ragged mark would make
        // the whole banner ragged.
        let w: Vec<usize> = MARK.iter().map(|m| m.chars().count()).collect();
        assert!(w.iter().all(|n| *n == w[0]), "mark rows differ in width: {w:?}");
    }

    #[test]
    fn the_accent_lands_once_and_only_on_the_header_block() {
        let s = render(true, true, Storage::Memory, 11, true);
        // The one-accent-per-surface rule: ember appears exactly once, wrapping
        // the header block. The body block is left at the terminal foreground.
        assert_eq!(s.matches(EMBER).count(), 1, "the accent appears once: {s:?}");
        assert!(s.contains(&format!("{EMBER}\u{2588}\u{2588}{RESET}")), "{s:?}");
        assert!(!s.contains(&format!("{EMBER}\u{2588}\u{2588}\u{2588}")), "body must stay untinted: {s:?}");
    }

    #[test]
    fn brackets_are_muted_and_blocks_are_not() {
        let s = render(true, true, Storage::Memory, 11, true);
        assert!(s.contains(&format!("{MUTED}\u{250c}\u{2500}\u{2500}{RESET}")), "top arm muted: {s:?}");
        assert!(s.contains(&format!("{MUTED}\u{2502}{RESET}")), "stems muted: {s:?}");
        // Every escape opened is closed, or the colour bleeds into the log
        // lines the server prints next.
        let opens = s.matches(MUTED).count() + s.matches(EMBER).count();
        assert_eq!(opens, s.matches(RESET).count(), "unbalanced escapes: {s:?}");
    }

    #[test]
    fn tint_leaves_a_row_visually_unchanged() {
        // Stripping the escapes must give back the original row: the tinting
        // may not add, drop or reorder a single glyph.
        for row in MARK {
            let painted = tint(row);
            let stripped: String = painted
                .split('\u{1b}')
                .enumerate()
                .map(|(i, part)| if i == 0 { part } else { part.split_once('m').map(|(_, r)| r).unwrap_or("") })
                .collect();
            assert_eq!(stripped, row, "tint altered the row: {painted:?}");
        }
    }

    #[test]
    fn side_text_reports_the_running_configuration() {
        let disk = render(true, false, Storage::Disk, 5, true);
        assert!(disk.contains("storage=disk"), "{disk}");
        assert!(disk.contains("brotli q5"), "{disk}");
        let off = render(true, false, Storage::Memory, 11, false);
        assert!(off.contains("no compression"), "{off}");
    }

    #[test]
    fn one_line_form_is_machine_readable() {
        let s = one_line();
        assert!(s.starts_with("bare-server "), "hyphenated for machines: {s}");
        assert!(s.contains(env!("CARGO_PKG_VERSION")), "{s}");
        assert!(s.contains('(') && s.ends_with(')'), "carries the target triple: {s}");
    }
}
