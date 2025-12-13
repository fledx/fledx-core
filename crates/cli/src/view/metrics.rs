use ::common::api::MetricSample;

use super::{format::format_metric_count, table::render_table};

pub fn render_metrics_table(samples: &[MetricSample]) -> String {
    let headers = ["METHOD", "PATH", "STATUS", "COUNT"];
    let rows = samples
        .iter()
        .map(|sample| {
            vec![
                sample.method.clone(),
                sample.path.clone(),
                sample.status.clone(),
                format_metric_count(sample.count),
            ]
        })
        .collect::<Vec<_>>();
    render_table(&headers, &rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_metrics_table_rows() {
        let samples = vec![
            MetricSample {
                method: "GET".into(),
                path: "/api/v1".into(),
                status: "200".into(),
                count: 3.0,
            },
            MetricSample {
                method: "POST".into(),
                path: "/api/v1/items".into(),
                status: "500".into(),
                count: 1.25,
            },
        ];
        let output = render_metrics_table(&samples);
        assert!(output.contains("METHOD"));
        assert!(output.contains("GET"));
        assert!(output.contains("/api/v1/items"));
        assert!(output.contains("500"));
        assert!(output.contains("1.25"));
    }
}
