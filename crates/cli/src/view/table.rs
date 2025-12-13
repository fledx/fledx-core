pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(idx) {
                *width = (*width).max(cell.len());
            }
        }
    }

    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(format_row(headers, &widths));
    for row in rows {
        let cells = row.iter().map(|c| c.as_str()).collect::<Vec<_>>();
        lines.push(format_row(&cells, &widths));
    }

    lines.join("\n")
}

fn format_row(cells: &[&str], widths: &[usize]) -> String {
    cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| format!("{:<width$}", cell, width = widths[idx]))
        .collect::<Vec<_>>()
        .join("  ")
}
