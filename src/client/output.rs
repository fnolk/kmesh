//! Plain-text output. Escape control characters before calculating column widths.

use std::fmt::Write;

use unicode_width::UnicodeWidthStr;

pub(super) fn cell(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control()
                || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

pub(super) fn state(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

pub(super) fn print_table(title: &str, headers: &[&str], rows: Vec<Vec<String>>) {
    print!("{}", render_table(title, headers, rows));
}

pub(super) fn render_table(title: &str, headers: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut output = format!("{} ({})\n", cell(title), rows.len());
    if rows.is_empty() {
        output.push_str("No records.\n");
        return output;
    }
    let mut rows = rows
        .into_iter()
        .map(|row| {
            row.into_iter()
                .map(|value| cell(&value))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    rows.insert(0, headers.iter().map(|header| cell(header)).collect());
    let widths = (0..headers.len())
        .map(|column| {
            rows.iter()
                .map(|row| row.get(column).map_or(0, |value| value.width()))
                .max()
                .unwrap_or(0)
        })
        .collect::<Vec<_>>();
    for (index, row) in rows.iter().enumerate() {
        for (column, width) in widths.iter().enumerate() {
            let value = row.get(column).map_or("", String::as_str);
            output.push_str(value);
            if column + 1 < widths.len() {
                let _ = write!(
                    output,
                    "{:padding$}",
                    "",
                    padding = width - value.width() + 2
                );
            }
        }
        output.push('\n');
        if index == 0 {
            output.push_str(
                &widths
                    .iter()
                    .map(|width| "-".repeat(*width))
                    .collect::<Vec<_>>()
                    .join("  "),
            );
            output.push('\n');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_have_headings_counts_and_no_tabs() {
        assert_eq!(
            render_table(
                "Users",
                &["USER", "STATE"],
                vec![
                    vec!["alice".into(), "enabled".into()],
                    vec!["bo".into(), "disabled".into()]
                ]
            ),
            "Users (2)\nUSER   STATE\n-----  --------\nalice  enabled\nbo     disabled\n"
        );
        assert_eq!(
            render_table("Users", &["USER"], vec![]),
            "Users (0)\nNo records.\n"
        );
    }

    #[test]
    fn untrusted_cells_cannot_insert_terminal_controls_or_rows() {
        let rendered = render_table(
            "Keys",
            &["LABEL"],
            vec![vec!["a\n\t\x1b[31m\u{202e}".into()]],
        );
        assert!(!rendered.contains('\t'));
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\u{202e}'));
        assert_eq!(rendered.lines().count(), 4);
        assert!(rendered.contains("a\\n\\t\\u{1b}[31m\\u{202e}"));
        assert_eq!(
            cell("\u{061c}\u{200e}\u{200f}\u{2028}\u{2029}"),
            "\\u{61c}\\u{200e}\\u{200f}\\u{2028}\\u{2029}"
        );
    }

    #[test]
    fn columns_use_terminal_width_and_keep_complete_ids() {
        let output = render_table(
            "Names",
            &["NAME", "ID"],
            vec![
                vec!["机器".into(), "full-id".into()],
                vec!["e\u{301}".into(), "other-id".into()],
            ],
        );
        assert!(output.contains("机器  full-id"));
        assert!(output.contains("e\u{301}     other-id"));
    }
}
