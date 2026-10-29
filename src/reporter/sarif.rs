use crate::model::{ScanReport, Severity};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub version: &'static str,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: &'static str,
    pub version: String,
    pub information_uri: &'static str,
    pub rules: Vec<SarifRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub default_configuration: SarifConfiguration,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifConfiguration {
    pub level: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: &'static str,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: usize,
    pub start_column: usize,
}

pub fn convert_to_sarif(report: &ScanReport) -> SarifLog {
    // Collect unique rules
    let mut rules = Vec::new();
    let mut seen_rule_ids = std::collections::HashSet::new();

    for finding in &report.findings {
        if seen_rule_ids.insert(finding.rule_id.clone()) {
            let level = match finding.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };

            rules.push(SarifRule {
                id: finding.rule_id.clone(),
                name: finding.rule_id.replace('-', " "),
                short_description: SarifMessage {
                    text: finding.description.clone(),
                },
                default_configuration: SarifConfiguration { level },
            });
        }
    }

    // Map findings to SARIF results
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };

            SarifResult {
                rule_id: f.rule_id.clone(),
                level,
                message: SarifMessage {
                    text: format!(
                        "Potential hardcoded secret detected: {} ({})",
                        f.description, f.redacted_match
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.file_path.clone(),
                        },
                        region: SarifRegion {
                            start_line: f.line_number,
                            start_column: f.column,
                        },
                    },
                }],
            }
        })
        .collect();

    SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sentris",
                    version: report.version.clone(),
                    information_uri: "https://github.com/Bharath-code/sentris",
                    rules,
                },
            },
            results,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, ScanStats, Severity};

    #[test]
    fn test_convert_to_sarif_structure() {
        let report = ScanReport {
            timestamp: "123456789".to_string(),
            version: "0.1.0".to_string(),
            stats: ScanStats::default(),
            findings: vec![Finding {
                rule_id: "stripe-secret-key".to_string(),
                description: "Live Stripe Secret Key".to_string(),
                severity: Severity::Critical,
                file_path: "config/billing.ts".to_string(),
                line_number: 42,
                column: 15,
                redacted_match: "sk_live_...1234".to_string(),
                entropy: 4.8,
                fingerprint: "abcdef123456".to_string(),
                commit_hash: None,
                commit_author: None,
                commit_date: None,
            }],
        };

        let sarif = convert_to_sarif(&report);
        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].tool.driver.name, "sentris");
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].rule_id, "stripe-secret-key");
        assert_eq!(sarif.runs[0].results[0].level, "error");
        assert_eq!(
            sarif.runs[0].results[0].locations[0]
                .physical_location
                .artifact_location
                .uri,
            "config/billing.ts"
        );
        assert_eq!(
            sarif.runs[0].results[0].locations[0]
                .physical_location
                .region
                .start_line,
            42
        );
    }
}
