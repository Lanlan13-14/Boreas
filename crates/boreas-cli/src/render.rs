//! Pure rendering layer for the Boreas console status screen.
//!
//! This module renders a [`StatusSnapshot`] value that the caller supplies;
//! it performs no I/O and never pretends to have contacted a daemon. The
//! live snapshot source will be the authorized Unix control socket
//! (`/run/boreas/control.sock`, master plan §10.4 and §10.5); that transport
//! is NOT part of this slice, so the only snapshot the current CLI builds is
//! [`StatusSnapshot::offline`].
//!
//! Box width basis: master plan §10.4.1 normatively fixes the standard
//! first screen at exactly 77 columns x 18 lines (example target on a
//! standard 80x24 PTY, East Asian Width with Ambiguous = 1, zero Emoji,
//! zero Ambiguous-width characters inside the box). The 18-line layout
//! belongs to the full interactive menu screen, which is out of scope for
//! this pure-render slice; the column count (77) and the
//! no-Emoji/no-Ambiguous rules are honored here for a 10-line status box.

use crate::i18n::{Lang, Msg, text};

/// Total box width in terminal columns (master plan §10.4.1).
pub(crate) const BOX_WIDTH: usize = 77;

/// Maximum display columns reserved for the version token. Every snapshot field
/// is untrusted; an unbounded version would otherwise push the title line past
/// `BOX_WIDTH` and make the frame ragged.
const VERSION_COLS: usize = 24;

/// Inner content width: total minus the two border columns and one padding
/// space on each side.
const INNER_WIDTH: usize = BOX_WIDTH - 4;

/// Security mode tokens from master plan §1.3. These strings are part of the
/// trust-model contract and are never translated. The current CLI only
/// constructs the `E2eRequired` offline placeholder; `HopOnly` is needed by
/// the renderer contract and is exercised by tests.
#[allow(
    dead_code,
    reason = "future control-socket snapshots can report hop-only; renderer supports it now"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityMode {
    HopOnly,
    E2eRequired,
}

impl SecurityMode {
    /// Canonical token, exactly as written in §1.3.
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityMode::HopOnly => "hop-only",
            SecurityMode::E2eRequired => "e2e-required",
        }
    }
}

/// Daemon connection state, as reported by the snapshot source. This slice
/// honestly constructs only `NotConnected`; `Connected` is part of the
/// renderer contract for the future authorized control socket.
#[allow(
    dead_code,
    reason = "future control-socket snapshots can report a connected daemon; this slice never fabricates one"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonState {
    Connected,
    NotConnected,
}

/// A pure snapshot of node status to render. Constructed by the caller
/// (offline placeholder today; the authorized control socket later).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusSnapshot {
    /// Node name (e.g. `hub-us-c`). Sanitized before display: control
    /// characters are replaced so a hostile name cannot inject terminal
    /// escapes or newlines (§10.4, log/terminal injection defense).
    pub node_name: String,
    pub version: String,
    pub inbound_on: bool,
    pub inbound_connections: u64,
    pub outbound_upstreams: u64,
    pub security_mode: SecurityMode,
    pub daemon: DaemonState,
}

impl StatusSnapshot {
    /// The honest offline placeholder used by this slice: nothing is
    /// running, nothing was connected to, all counters are zero. The
    /// security mode shows the default production policy (`e2e-required`,
    /// §1.3) as a display default only — it does not claim any live node
    /// is enforcing it.
    pub fn offline(version: &str) -> StatusSnapshot {
        StatusSnapshot {
            node_name: String::new(),
            version: version.to_string(),
            inbound_on: false,
            inbound_connections: 0,
            outbound_upstreams: 0,
            security_mode: SecurityMode::E2eRequired,
            daemon: DaemonState::NotConnected,
        }
    }

    /// Stable JSON representation used for non-TTY output and `--json`
    /// (§10.4: non-TTY output is JSON). Field order is fixed.
    pub fn to_json(&self, lang: Lang) -> String {
        let daemon = match self.daemon {
            DaemonState::Connected => "connected",
            DaemonState::NotConnected => "not_connected",
        };
        format!(
            concat!(
                "{{\"command\":\"status\",\"lang\":\"{}\",\"version\":\"{}\",",
                "\"node_name\":\"{}\",\"inbound_on\":{},\"inbound_connections\":{},",
                "\"outbound_upstreams\":{},\"security_mode\":\"{}\",\"daemon\":\"{}\"}}"
            ),
            lang.code(),
            json_escape(&self.version),
            json_escape(&sanitize(&self.node_name)),
            self.inbound_on,
            self.inbound_connections,
            self.outbound_upstreams,
            self.security_mode.as_str(),
            daemon,
        )
    }
}

/// Render the status screen as a fixed-width box (10 lines x 77 columns),
/// joined by `\n` with no trailing newline. Contains no ANSI escapes and no
/// Emoji; the `*` marker follows the §10.4.1 examples (active =
/// `*`, inactive = `x`).
pub fn render_status(snapshot: &StatusSnapshot, lang: Lang) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(10);

    // The version comes from the snapshot, i.e. eventually from the control
    // socket. It is exactly as untrusted as the node name, so it is sanitized
    // (no control characters/ESC/newlines) and truncated to its reserved
    // columns before it can reach the terminal.
    let version_display = truncate(&sanitize(&snapshot.version), VERSION_COLS);

    // Title line, following the §10.4.1 shape:
    //   ┌─ BOREAS CONSOLE ───── v<version> / [L] <lang> ┐
    let title_left = format!("─ {} ", text(lang, Msg::ConsoleTitle));
    let title_right = format!(" v{version_display} / [L] {} ", text(lang, Msg::LangLabel));
    let fill = BOX_WIDTH
        .saturating_sub(2)
        .saturating_sub(display_width(&title_left))
        .saturating_sub(display_width(&title_right));
    lines.push(format!("┌{title_left}{}{title_right}┐", "─".repeat(fill)));

    // Node line: "NODE  <name>" on the left, version pinned at the right.
    let node_display = if snapshot.node_name.is_empty() {
        text(lang, Msg::UnknownNode).to_string()
    } else {
        sanitize(&snapshot.node_name)
    };
    let node_left = format!("{}  {node_display}", text(lang, Msg::NodeLabel));
    let version_right = format!("v{version_display}");
    lines.push(row(&two_col(&node_left, &version_right)));

    // Security mode + daemon connection state.
    let mode_text = format!(
        "{}  {}",
        text(lang, Msg::ModeLabel),
        snapshot.security_mode.as_str()
    );
    lines.push(row(&mode_text));
    let daemon_text = text(
        lang,
        match snapshot.daemon {
            DaemonState::Connected => Msg::DaemonConnected,
            DaemonState::NotConnected => Msg::DaemonNotConnected,
        },
    );
    lines.push(row(daemon_text));

    lines.push(separator());

    // Inbound / outbound counters. Zero upstreams uses the `x` marker.
    let in_marker = if snapshot.inbound_on { '*' } else { 'x' };
    let in_state = text(
        lang,
        if snapshot.inbound_on {
            Msg::On
        } else {
            Msg::Off
        },
    );
    let in_text = format!(
        "{}  {in_marker} {in_state} / {} {}",
        text(lang, Msg::InboundLabel),
        snapshot.inbound_connections,
        text(lang, Msg::ConnectionsUnit)
    );
    lines.push(row(&in_text));
    let out_marker = if snapshot.outbound_upstreams > 0 {
        '*'
    } else {
        'x'
    };
    let out_text = format!(
        "{}  {out_marker} {} {}",
        text(lang, Msg::OutboundLabel),
        snapshot.outbound_upstreams,
        text(lang, Msg::UpstreamsUnit)
    );
    lines.push(row(&out_text));

    // Trust-boundary line. In hop-only mode §1.3 requires the literal
    // `PLAINTEXT AT CORE` marker to be displayed persistently; the full
    // line is a single line in every language so the box height is fixed.
    let trust_line = match snapshot.security_mode {
        SecurityMode::HopOnly => {
            format!("! PLAINTEXT AT CORE: {}", text(lang, Msg::PlaintextWarning))
        }
        SecurityMode::E2eRequired => format!("* {}", text(lang, Msg::E2eNote)),
    };
    lines.push(row(&trust_line));

    // Provenance line: never claim a live connection we did not make.
    let note = text(
        lang,
        match snapshot.daemon {
            DaemonState::Connected => Msg::LiveNote,
            DaemonState::NotConnected => Msg::OfflineNote,
        },
    );
    lines.push(row(note));

    lines.push(format!("└{}┘", "─".repeat(BOX_WIDTH - 2)));
    lines.join("\n")
}

/// True when a terminal measured `columns` wide can host the 77-column frame.
///
/// `None` means the width was never measured (stdout is not a terminal, or the
/// platform probe failed); the frame is kept rather than silently replacing
/// every screen with a degraded list. A measured width below [`BOX_WIDTH`]
/// fails here, so the console never claims 77 columns on a narrower terminal
/// (§10.4).
pub fn fits_boxed(columns: Option<usize>) -> bool {
    columns.is_none_or(|columns| columns >= BOX_WIDTH)
}

/// Render the status facts as plain lines for a terminal measured narrower
/// than [`BOX_WIDTH`]: one `KEY  value` line per fact, no box drawing, and
/// every line truncated to `columns` display columns so the degraded screen
/// cannot claim the 77-column frame (§10.4). Field order matches
/// [`render_status`], and untrusted fields are sanitized exactly as there.
pub fn render_status_narrow(snapshot: &StatusSnapshot, lang: Lang, columns: usize) -> String {
    let columns = columns.min(BOX_WIDTH);
    let version = truncate(&sanitize(&snapshot.version), VERSION_COLS);
    let node = if snapshot.node_name.is_empty() {
        text(lang, Msg::UnknownNode).to_string()
    } else {
        sanitize(&snapshot.node_name)
    };
    let daemon = text(
        lang,
        match snapshot.daemon {
            DaemonState::Connected => Msg::DaemonConnected,
            DaemonState::NotConnected => Msg::DaemonNotConnected,
        },
    );
    let trust = match snapshot.security_mode {
        SecurityMode::HopOnly => {
            format!("! PLAINTEXT AT CORE: {}", text(lang, Msg::PlaintextWarning))
        }
        SecurityMode::E2eRequired => format!("* {}", text(lang, Msg::E2eNote)),
    };
    let note = text(
        lang,
        match snapshot.daemon {
            DaemonState::Connected => Msg::LiveNote,
            DaemonState::NotConnected => Msg::OfflineNote,
        },
    );
    let lines = [
        format!(
            "{} v{version} / [L] {}",
            text(lang, Msg::ConsoleTitle),
            text(lang, Msg::LangLabel)
        ),
        format!("{}  {node}", text(lang, Msg::NodeLabel)),
        format!(
            "{}  {}",
            text(lang, Msg::ModeLabel),
            snapshot.security_mode.as_str()
        ),
        daemon.to_string(),
        format!(
            "{}  {} {} {}",
            text(lang, Msg::InboundLabel),
            text(
                lang,
                if snapshot.inbound_on {
                    Msg::On
                } else {
                    Msg::Off
                }
            ),
            snapshot.inbound_connections,
            text(lang, Msg::ConnectionsUnit)
        ),
        format!(
            "{}  {} {}",
            text(lang, Msg::OutboundLabel),
            snapshot.outbound_upstreams,
            text(lang, Msg::UpstreamsUnit)
        ),
        trust,
        note.to_string(),
    ];
    lines
        .iter()
        .map(|line| truncate(line, columns))
        .collect::<Vec<String>>()
        .join("\n")
}

/// Display width in terminal columns, simplified East Asian Width with
/// Ambiguous = 1 (§10.4.1): ASCII = 1, box-drawing = 1, CJK unified
/// ideographs and their fullwidth neighbours = 2, control characters = 0,
/// everything else = 1. Self-implemented; this crate takes no unicode-width
/// dependency.
pub fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    let cp = c as u32;
    if cp < 0x20 || (0x7F..=0x9F).contains(&cp) {
        0 // C0/C1 control characters never occupy a cell (and are sanitized out anyway).
    } else if is_wide(cp) {
        2
    } else {
        1 // ASCII, box drawing (U+2500..=U+257F), Ambiguous-width: all 1.
    }
}

/// Wide/Fullwidth ranges (display width 2), covering the scripts this
/// console can print: CJK unified ideographs and extensions, radicals and
/// compat ideographs, Hiragana/Katakana, Hangul, and fullwidth forms.
fn is_wide(cp: u32) -> bool {
    matches!(
        cp,
        0x1100..=0x115F // Hangul Jamo
            | 0x2E80..=0x303E // CJK radicals, Kangxi radicals, CJK symbols (excl. U+303F narrow)
            | 0x3041..=0x33FF // Hiragana, Katakana, Bopomofo, Kanbun, CJK compat
            | 0x3400..=0x4DBF // CJK Unified Ideographs Extension A
            | 0x4E00..=0x9FFF // CJK Unified Ideographs
            | 0xA000..=0xA4CF // Yi
            | 0xAC00..=0xD7A3 // Hangul syllables
            | 0xF900..=0xFAFF // CJK compat ideographs
            | 0xFE10..=0xFE19 // vertical forms
            | 0xFE30..=0xFE6F // CJK compat forms, small form variants
            | 0xFF00..=0xFF60 // fullwidth forms
            | 0xFFE0..=0xFFE6 // fullwidth signs
            | 0x16FE0..=0x16FE4
            | 0x17000..=0x187F7 // Tangut
            | 0x18800..=0x18CD5
            | 0x1B000..=0x1B152
            | 0x1B164..=0x1B167
            | 0x1B170..=0x1B2FB
            | 0x1F200..=0x1F2FF // enclosed ideographic supplement
            | 0x20000..=0x2FFFD // CJK Ext. B and later planes
            | 0x30000..=0x3FFFD
    )
}

/// Replace control characters (including ESC and newline) with `?` so
/// untrusted snapshot fields cannot inject terminal escapes or extra lines
/// (§10.4: node names and log fields must reject control characters,
/// newlines and terminal escapes).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Truncate `s` to at most `max_width` display columns without splitting a
/// wide character, then right-pad with spaces to exactly `max_width`.
fn fit(s: &str, max_width: usize) -> String {
    let mut out = String::new();
    let mut width = 0usize;
    for c in s.chars() {
        let w = char_width(c);
        if width + w > max_width {
            break;
        }
        out.push(c);
        width += w;
    }
    while width < max_width {
        out.push(' ');
        width += 1;
    }
    out
}

/// Truncate `s` to at most `max_width` display columns without splitting a wide
/// character. Unlike [`fit`] it never pads.
fn truncate(s: &str, max_width: usize) -> String {
    let mut out = String::new();
    let mut width = 0usize;
    for c in s.chars() {
        let w = char_width(c);
        if width + w > max_width {
            break;
        }
        out.push(c);
        width += w;
    }
    out
}

/// One content row: `│ <inner padded to INNER_WIDTH> │`.
fn row(inner: &str) -> String {
    format!("│ {} │", fit(inner, INNER_WIDTH))
}

fn separator() -> String {
    format!("├{}┤", "─".repeat(BOX_WIDTH - 2))
}

/// Left segment and right-pinned segment on one inner line. The left
/// segment is truncated first so the right one always survives.
fn two_col(left: &str, right: &str) -> String {
    let right_width = display_width(right);
    if right_width + 1 >= INNER_WIDTH {
        return fit(left, INNER_WIDTH);
    }
    let budget = INNER_WIDTH - right_width - 1;
    format!("{} {right}", fit(left, budget))
}

/// Minimal JSON string escaping for snapshot fields (quotes, backslash and
/// control characters). No serde dependency in this crate.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        BOX_WIDTH, DaemonState, SecurityMode, StatusSnapshot, display_width, fit, fits_boxed,
        render_status, render_status_narrow,
    };
    use crate::i18n::Lang;

    fn snapshot(inbound_on: bool, mode: SecurityMode) -> StatusSnapshot {
        StatusSnapshot {
            node_name: "hub-test".to_string(),
            version: "0.1.0".to_string(),
            inbound_on,
            inbound_connections: if inbound_on { 12 } else { 0 },
            outbound_upstreams: 2,
            security_mode: mode,
            daemon: DaemonState::NotConnected,
        }
    }

    /// Emoji and pictograph code points that must never appear inside the
    /// box (§10.4.1: 0 Emoji). Scans the pictographic blocks plus the
    /// common single-codepoint emoji remapped from symbol blocks.
    fn is_emoji_codepoint(cp: u32) -> bool {
        matches!(cp,
            0x00A9 | 0x00AE // (c) (r)
            | 0x203C | 0x2049 | 0x2122 | 0x2139
            | 0x2194..=0x21AA
            | 0x231A..=0x231B | 0x2328 | 0x23CF | 0x23E9..=0x23FA
            | 0x24C2 | 0x25AA..=0x25FE | 0x2600..=0x27BF
            | 0x2934..=0x2935 | 0x2B00..=0x2BFF | 0x3030 | 0x303D | 0x3297 | 0x3299
            | 0xFE0F // variation selector-16 (emoji presentation)
            | 0x1F000..=0x1FAFF // emoticons, transport, supplemental symbols, chess, ...
            | 0x200D) // zero-width joiner used by emoji sequences
    }

    #[test]
    fn display_width_counts_ascii_cjk_and_box_chars() {
        assert_eq!(display_width(""), 0);
        assert_eq!(display_width("BOREAS"), 6);
        assert_eq!(display_width("简中"), 4);
        assert_eq!(display_width("繁中"), 4);
        assert_eq!(display_width("┌─┐│├┤└┘"), 8);
        assert_eq!(display_width("a简b"), 4);
        assert_eq!(display_width("测"), 2); // CJK unified ideograph
        assert_eq!(display_width("\t"), 0); // control character
    }

    #[test]
    fn fit_pads_and_truncates_on_wide_boundaries() {
        assert_eq!(fit("ab", 5), "ab   ");
        assert_eq!(fit("简中", 5), "简中 ");
        assert_eq!(fit("简中简", 5), "简中 ");
        assert_eq!(fit("abcdef", 3), "abc");
        assert_eq!(display_width(&fit("简中简中简", 7)), 7);
    }

    #[test]
    fn three_languages_two_inbound_two_modes_all_equal_width() {
        // 3 languages x inbound on/off x 2 security modes = 12 combinations.
        let mut combinations = 0;
        for lang in Lang::ALL {
            for inbound_on in [false, true] {
                for mode in [SecurityMode::HopOnly, SecurityMode::E2eRequired] {
                    combinations += 1;
                    let rendered = render_status(&snapshot(inbound_on, mode), lang);
                    let lines: Vec<&str> = rendered.split('\n').collect();
                    assert_eq!(lines.len(), 10, "line count for {lang:?}");
                    for line in &lines {
                        assert_eq!(
                            display_width(line),
                            BOX_WIDTH,
                            "line width for {lang:?} inbound={inbound_on} {mode:?}: {line:?}"
                        );
                    }
                }
            }
        }
        assert_eq!(combinations, 12);
    }

    #[test]
    fn no_emoji_codepoints_in_any_rendering() {
        for lang in Lang::ALL {
            for mode in [SecurityMode::HopOnly, SecurityMode::E2eRequired] {
                let rendered = render_status(&snapshot(true, mode), lang);
                for c in rendered.chars() {
                    assert!(
                        !is_emoji_codepoint(c as u32),
                        "emoji code point U+{:04X} in {lang:?}/{mode:?} output",
                        c as u32
                    );
                }
            }
        }
    }

    #[test]
    fn no_ansi_escape_bytes_in_any_rendering() {
        // §10.4 requires NO_COLOR support; this slice emits no ANSI at all,
        // so NO_COLOR is honored by construction. Pin it with a byte scan.
        for lang in Lang::ALL {
            let rendered = render_status(&snapshot(true, SecurityMode::HopOnly), lang);
            assert!(
                !rendered.as_bytes().contains(&0x1B),
                "ANSI ESC byte in {lang:?} output"
            );
        }
    }

    #[test]
    fn hop_only_shows_plaintext_warning_e2e_does_not() {
        for lang in Lang::ALL {
            let hop = render_status(&snapshot(false, SecurityMode::HopOnly), lang);
            assert!(
                hop.contains("PLAINTEXT AT CORE"),
                "hop-only must show PLAINTEXT AT CORE ({lang:?})"
            );
            assert!(hop.contains("hop-only"));
            let e2e = render_status(&snapshot(false, SecurityMode::E2eRequired), lang);
            assert!(
                !e2e.contains("PLAINTEXT AT CORE"),
                "e2e-required must not show the hop-only warning ({lang:?})"
            );
            assert!(e2e.contains("e2e-required"));
        }
    }

    #[test]
    fn daemon_state_is_reported_honestly() {
        for lang in Lang::ALL {
            let offline = render_status(&snapshot(false, SecurityMode::E2eRequired), lang);
            assert!(
                offline.contains("daemon: not connected"),
                "offline snapshot must say not connected ({lang:?})"
            );
            assert!(!offline.contains("daemon: connected /"));

            let mut live = snapshot(true, SecurityMode::E2eRequired);
            live.daemon = DaemonState::Connected;
            let rendered = render_status(&live, lang);
            assert!(rendered.contains("daemon: connected"));
            assert!(!rendered.contains("not connected"));
            assert!(rendered.split('\n').all(|l| display_width(l) == BOX_WIDTH));
        }
    }

    #[test]
    fn offline_snapshot_is_all_zeros_and_honest() {
        let snap = StatusSnapshot::offline("0.1.0");
        assert!(!snap.inbound_on);
        assert_eq!(snap.inbound_connections, 0);
        assert_eq!(snap.outbound_upstreams, 0);
        assert_eq!(snap.daemon, DaemonState::NotConnected);
        assert_eq!(snap.security_mode, SecurityMode::E2eRequired);
        let rendered = render_status(&snap, Lang::En);
        assert!(rendered.contains("(unknown)"));
        assert!(rendered.contains("daemon: not connected"));
    }

    #[test]
    fn hostile_node_name_cannot_inject_escapes_or_lines() {
        let mut snap = snapshot(false, SecurityMode::E2eRequired);
        snap.node_name = "evil\u{1b}[31m\nline2\u{07}".to_string();
        let rendered = render_status(&snap, Lang::En);
        assert!(!rendered.as_bytes().contains(&0x1B));
        assert_eq!(rendered.split('\n').count(), 10);
        for line in rendered.split('\n') {
            assert_eq!(display_width(line), BOX_WIDTH, "line: {line:?}");
        }
        assert!(rendered.contains("evil?"));
    }

    #[test]
    fn very_long_node_name_is_truncated_to_box() {
        let mut snap = snapshot(true, SecurityMode::E2eRequired);
        snap.node_name = "测".repeat(200);
        let rendered = render_status(&snap, Lang::ZhCn);
        for line in rendered.split('\n') {
            assert_eq!(display_width(line), BOX_WIDTH, "line: {line:?}");
        }
    }

    #[test]
    fn fits_boxed_requires_a_measured_width_of_at_least_77() {
        assert!(fits_boxed(None), "an unmeasured width keeps the frame");
        assert!(fits_boxed(Some(77)));
        assert!(fits_boxed(Some(80)));
        assert!(fits_boxed(Some(200)));
        assert!(!fits_boxed(Some(76)));
        assert!(!fits_boxed(Some(40)));
        assert!(!fits_boxed(Some(1)));
        assert!(!fits_boxed(Some(0)));
    }

    #[test]
    fn narrow_status_has_no_box_and_fits_the_measured_width() {
        for lang in Lang::ALL {
            for columns in [40usize, 20, 8, 1] {
                let mut snap = snapshot(true, SecurityMode::HopOnly);
                snap.node_name = "测".repeat(60);
                let rendered = render_status_narrow(&snap, lang, columns);
                assert!(!rendered.contains('┌'), "{lang:?}/{columns}");
                assert!(!rendered.contains('│'), "{lang:?}/{columns}");
                assert!(!rendered.as_bytes().contains(&0x1B));
                for line in rendered.split('\n') {
                    assert!(
                        display_width(line) <= columns,
                        "{lang:?}/{columns}: {line:?} is {}",
                        display_width(line)
                    );
                }
            }
            // A width that still fits the whole title line keeps it readable.
            let rendered = render_status_narrow(&snapshot(true, SecurityMode::HopOnly), lang, 40);
            assert!(rendered.contains("BOREAS CONSOLE"), "{lang:?}");
            assert!(rendered.contains("PLAINTEXT AT CORE"), "{lang:?}");
        }
    }

    #[test]
    fn narrow_status_reports_the_same_facts_and_sanitizes_names() {
        let mut snap = snapshot(false, SecurityMode::E2eRequired);
        snap.node_name = "evil\u{1b}[31m\nline2".to_string();
        let rendered = render_status_narrow(&snap, Lang::En, 77);
        assert!(rendered.contains("Offline snapshot"), "{rendered}");
        assert!(rendered.contains("daemon: not connected"));
        assert!(rendered.contains("e2e-required"));
        assert!(!rendered.as_bytes().contains(&0x1B));
        assert_eq!(rendered.split('\n').count(), 8, "one line per status fact");
        assert!(rendered.contains("evil?"));
    }

    #[test]
    fn status_json_is_stable_and_escapes_strings() {
        let snap = StatusSnapshot::offline("0.1.0");
        assert_eq!(
            snap.to_json(Lang::En),
            concat!(
                "{\"command\":\"status\",\"lang\":\"en\",\"version\":\"0.1.0\",",
                "\"node_name\":\"\",\"inbound_on\":false,\"inbound_connections\":0,",
                "\"outbound_upstreams\":0,\"security_mode\":\"e2e-required\",",
                "\"daemon\":\"not_connected\"}"
            )
        );
        let mut tricky = snapshot(true, SecurityMode::HopOnly);
        tricky.node_name = "a\"b\\c".to_string();
        assert!(
            tricky
                .to_json(Lang::ZhTw)
                .contains("\"node_name\":\"a\\\"b\\\\c\"")
        );
        assert!(tricky.to_json(Lang::ZhTw).contains("\"lang\":\"zh-TW\""));
    }
}
