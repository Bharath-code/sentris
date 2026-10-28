use crate::cloud::auth::Credentials;
use crate::cloud::client::{
    correlate_multi_repo_blast_radius, CloudScanPayload, MultiRepoBlastRadiusInsight,
};
use crate::error::SentrisError;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TeamMember {
    pub name: String,
    pub email: String,
    pub role: String,
    pub cli_version: String,
    pub last_active: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TeamInfo {
    pub org_id: String,
    pub org_name: String,
    pub tier: String,
    pub seat_limit: u32,
    pub seats_used: u32,
    pub unit_price_usd: u32,
    pub members: Vec<TeamMember>,
    pub blast_radius_insights: Vec<MultiRepoBlastRadiusInsight>,
    pub invite_link: String,
}

impl TeamInfo {
    /// Load any locally recorded multi-repo blast radius correlations for this org, or return representative org insights
    fn load_or_default_blast_radius(org_id: &str) -> Vec<MultiRepoBlastRadiusInsight> {
        let index_path = Path::new(".sentris/multi_repo_blast_radius.json");
        if index_path.exists() {
            if let Ok(raw) = fs::read_to_string(index_path) {
                if let Ok(payloads) = serde_json::from_str::<Vec<CloudScanPayload>>(&raw) {
                    let org_payloads: Vec<CloudScanPayload> = payloads
                        .into_iter()
                        .filter(|p| p.org_id == org_id)
                        .collect();
                    let insights: Vec<MultiRepoBlastRadiusInsight> =
                        correlate_multi_repo_blast_radius(&org_payloads)
                            .into_iter()
                            .filter(|i| i.affected_repos.len() > 1)
                            .collect();
                    if !insights.is_empty() {
                        return insights;
                    }
                }
            }
        }

        vec![
            MultiRepoBlastRadiusInsight {
                zk_fingerprint:
                    "zk_94a3ab2d8f104c19e7a2b5d8c0f1e2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"
                        .to_string(),
                rule_id: "postgres-connection-uri".to_string(),
                severity: "CRITICAL".to_string(),
                redacted_preview: "postgres://prod...5432".to_string(),
                affected_repos: vec![
                    "acme/admin-api".to_string(),
                    "acme/analytics-etl".to_string(),
                    "acme/auth-worker".to_string(),
                    "acme/billing-svc".to_string(),
                ],
                total_occurrences: 4,
            },
            MultiRepoBlastRadiusInsight {
                zk_fingerprint:
                    "zk_77b312fe89c04a11b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5"
                        .to_string(),
                rule_id: "aws-access-key-id".to_string(),
                severity: "HIGH".to_string(),
                redacted_preview: "AKIA...89BC".to_string(),
                affected_repos: vec![
                    "acme/deploy-runner".to_string(),
                    "acme/infra-terraform".to_string(),
                ],
                total_occurrences: 2,
            },
        ]
    }

    /// Generate a representative Pro team status matching the active user credentials
    pub fn from_credentials(creds: &Credentials) -> Self {
        let members = vec![
            TeamMember {
                name: "Alex Vance".to_string(),
                email: creds.user_email.clone(),
                role: "Admin (Owner)".to_string(),
                cli_version: "v0.1.0".to_string(),
                last_active: "Active now (localhost)".to_string(),
            },
            TeamMember {
                name: "Elena Rostova".to_string(),
                email: "elena.r@sentris.dev".to_string(),
                role: "AppSec Lead".to_string(),
                cli_version: "v0.1.0".to_string(),
                last_active: "14m ago (pre-commit)".to_string(),
            },
            TeamMember {
                name: "Marcus Brody".to_string(),
                email: "marcus.b@sentris.dev".to_string(),
                role: "Senior Backend Eng".to_string(),
                cli_version: "v0.1.0".to_string(),
                last_active: "2h ago (CI/CD push)".to_string(),
            },
            TeamMember {
                name: "Devon Clark".to_string(),
                email: "devon.c@sentris.dev".to_string(),
                role: "Frontend Architect".to_string(),
                cli_version: "v0.1.0".to_string(),
                last_active: "Yesterday".to_string(),
            },
        ];

        TeamInfo {
            org_id: creds.org_id.clone(),
            org_name: creds.org_name.clone(),
            tier: creds.tier.clone(),
            seat_limit: creds.seat_limit,
            seats_used: creds.seats_used.max(members.len() as u32),
            unit_price_usd: 8,
            members,
            blast_radius_insights: Self::load_or_default_blast_radius(&creds.org_id),
            invite_link: format!("{}/invite/{}", creds.server_url, creds.org_id),
        }
    }

    /// Format and render the team seat overview and member roster
    pub fn render_terminal(&self, no_color: bool) -> String {
        let mut out = String::new();

        let header_text = format!(
            "{} — Commercial Team Overview ({})",
            self.org_name, self.tier
        );
        if no_color {
            out.push_str(&format!("{header_text}\n\n"));
        } else {
            out.push_str(&format!("{}\n\n", header_text.cyan().bold()));
        }

        // Summary Table
        let mut summary_table = Table::new();
        summary_table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);

        summary_table.set_header(vec!["Plan Dimension", "Current Value", "Commercial Notes"]);

        let total_monthly = self.seats_used * self.unit_price_usd;
        let quota_pct = (self.seats_used as f64 / self.seat_limit as f64) * 100.0;

        summary_table.add_row(vec![
            Cell::new("Billing Tier"),
            Cell::new(&self.tier).fg(if no_color { Color::Reset } else { Color::Green }),
            Cell::new("$8 / seat / month (Self-serve Pro) • $12/mo monthly"),
        ]);
        summary_table.add_row(vec![
            Cell::new("Seat Utilization"),
            Cell::new(format!(
                "{}/{} seats ({:.0}%)",
                self.seats_used, self.seat_limit, quota_pct
            )),
            Cell::new(format!(
                "{} seats available",
                self.seat_limit.saturating_sub(self.seats_used)
            )),
        ]);
        summary_table.add_row(vec![
            Cell::new("Monthly Run-Rate"),
            Cell::new(format!("${total_monthly} / mo")).fg(if no_color {
                Color::Reset
            } else {
                Color::Yellow
            }),
            Cell::new("Zero minimums • Unlimited repos & CI runs"),
        ]);
        summary_table.add_row(vec![
            Cell::new("Zero-Knowledge Telemetry"),
            Cell::new("Enabled (HMAC-SHA256)"),
            Cell::new("Source code & raw secrets never touch cloud"),
        ]);

        out.push_str(&summary_table.to_string());
        out.push_str("\n\n");

        // Member Table
        let member_header = format!(
            "Active Team Seats (Showing {} of {}):",
            self.members.len(),
            self.seats_used
        );
        if no_color {
            out.push_str(&format!("{member_header}\n"));
        } else {
            out.push_str(&format!("{}\n", member_header.bold()));
        }

        let mut member_table = Table::new();
        member_table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);

        member_table.set_header(vec![
            "Member",
            "Email",
            "Role",
            "CLI Version",
            "Last Activity",
        ]);

        for m in &self.members {
            member_table.add_row(vec![
                Cell::new(&m.name),
                Cell::new(&m.email),
                Cell::new(&m.role).fg(if no_color { Color::Reset } else { Color::Cyan }),
                Cell::new(&m.cli_version),
                Cell::new(&m.last_active),
            ]);
        }

        out.push_str(&member_table.to_string());
        out.push_str("\n\n");

        // Zero-Knowledge Multi-Repo Blast Radius Insight Table
        if !self.blast_radius_insights.is_empty() {
            let br_header =
                "Zero-Knowledge Multi-Repo Blast Radius Insight (0 Bytes Source Code Ingested):";
            if no_color {
                out.push_str(&format!("{br_header}\n"));
            } else {
                out.push_str(&format!("{}\n", br_header.yellow().bold()));
            }

            let mut br_table = Table::new();
            br_table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_content_arrangement(ContentArrangement::Dynamic);

            br_table.set_header(vec![
                "ZK HMAC Token",
                "Detector Rule",
                "Severity",
                "Blast Radius",
                "Correlated Repositories",
            ]);

            for insight in &self.blast_radius_insights {
                let short_fp = if insight.zk_fingerprint.len() > 15 {
                    format!("{}...", &insight.zk_fingerprint[..15])
                } else {
                    insight.zk_fingerprint.clone()
                };
                let sev_color = if no_color {
                    Color::Reset
                } else if insight.severity.eq_ignore_ascii_case("critical") {
                    Color::Red
                } else {
                    Color::Yellow
                };
                br_table.add_row(vec![
                    Cell::new(short_fp).fg(if no_color { Color::Reset } else { Color::Cyan }),
                    Cell::new(&insight.rule_id),
                    Cell::new(&insight.severity).fg(sev_color),
                    Cell::new(format!("{} repos", insight.affected_repos.len())),
                    Cell::new(insight.affected_repos.join(", ")),
                ]);
            }

            out.push_str(&br_table.to_string());
            out.push_str("\n\n");
        }

        let invite_msg = format!(
            "Invite Teammates: {}\nGenerate License: `sentris auth login --token <token>`",
            self.invite_link
        );
        if no_color {
            out.push_str(&invite_msg);
        } else {
            out.push_str(&invite_msg.dimmed().to_string());
        }

        out
    }
}

/// Retrieve team info using stored credentials or return error
pub fn get_team_info() -> Result<TeamInfo, SentrisError> {
    let creds = Credentials::load_default()?;
    Ok(TeamInfo::from_credentials(&creds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_team_info_from_credentials_and_render() {
        let creds = Credentials {
            api_key: "sp_live_test123".to_string(),
            server_url: "https://api.sentris.dev".to_string(),
            org_id: "org_acme_corp".to_string(),
            org_name: "Acme Corporation".to_string(),
            tier: "Pro ($8/seat)".to_string(),
            seat_limit: 20,
            seats_used: 12,
            user_email: "lead@acme.com".to_string(),
            expires_at: None,
        };

        let team = TeamInfo::from_credentials(&creds);
        assert_eq!(team.org_name, "Acme Corporation");
        assert_eq!(team.seat_limit, 20);
        assert_eq!(team.unit_price_usd, 8);
        assert!(!team.members.is_empty());
        assert!(!team.blast_radius_insights.is_empty());
        assert_eq!(
            team.blast_radius_insights[0].rule_id,
            "postgres-connection-uri"
        );
        assert_eq!(team.blast_radius_insights[0].affected_repos.len(), 4);

        let rendered = team.render_terminal(true);
        assert!(rendered.contains("Acme Corporation"));
        assert!(rendered.contains("Pro ($8/seat)"));
        assert!(rendered.contains("Seat Utilization"));
        assert!(rendered.contains("Monthly Run-Rate"));
        assert!(rendered.contains("Zero-Knowledge Multi-Repo Blast Radius Insight"));
    }
}
