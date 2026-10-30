use std::collections::HashMap;

use cert_core::{
    Certificate, ChainValidationResult, ValidationOptions, ValidationStatus, validate_in_os_store,
};
use cert_infra::{load_os_store, trust_anchors_der};
use chrono::{DateTime, Datelike, Duration, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Detail,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    All,
    Valid,
    Expiring,
    Expired,
    Issues,
    OtherIssues,
    Ca,
}

impl Filter {
    pub const ALL: [Filter; 6] = [
        Filter::All,
        Filter::Valid,
        Filter::Expiring,
        Filter::Expired,
        Filter::Issues,
        Filter::Ca,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "All",
            Filter::Valid => "Valid",
            Filter::Expiring => "Expiring",
            Filter::Expired => "Expired",
            Filter::Issues => "Issues",
            Filter::OtherIssues => "Other issues",
            Filter::Ca => "CA",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertRow {
    pub certificate: Certificate,
    pub result: ChainValidationResult,
}

impl CertRow {
    pub fn status(&self) -> &ValidationStatus {
        &self.result.status
    }
}

pub struct AppState {
    pub rows: Vec<CertRow>,
    pub filter: Filter,
    pub view: View,
    pub selected: Option<String>,
    pub warn_days: i64,
    pub anchor_count: usize,
    pub parse_errors: Vec<String>,
    pub load_error: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        let mut state = Self {
            rows: Vec::new(),
            filter: Filter::All,
            view: View::Dashboard,
            selected: None,
            warn_days: 30,
            anchor_count: 0,
            parse_errors: Vec::new(),
            load_error: None,
        };
        state.reload();
        state
    }

    pub fn reload(&mut self) {
        let store = match load_os_store() {
            Ok(store) => store,
            Err(err) => {
                self.load_error = Some(err.to_string());
                self.rows.clear();
                return;
            }
        };

        let anchors = trust_anchors_der(&store.certificates);
        let options = ValidationOptions {
            now: Utc::now(),
            warn_days: self.warn_days,
        };

        self.rows = store
            .certificates
            .iter()
            .map(|certificate| CertRow {
                certificate: certificate.clone(),
                result: validate_in_os_store(certificate, &anchors, &options),
            })
            .collect();
        self.anchor_count = anchors.len();
        self.parse_errors = store.errors;
        self.load_error = None;

        if let Some(selected) = &self.selected {
            if !self
                .rows
                .iter()
                .any(|row| &row.certificate.fingerprint_sha256 == selected)
            {
                self.selected = None;
                self.view = View::Dashboard;
            }
        }
    }

    pub fn filtered_indices(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| match self.filter {
                Filter::All => true,
                Filter::Valid => matches!(row.status(), ValidationStatus::Valid),
                Filter::Expiring => matches!(row.status(), ValidationStatus::ExpiringSoon),
                Filter::Expired => matches!(row.status(), ValidationStatus::Expired),
                Filter::Issues => !row.status().is_healthy(),
                Filter::OtherIssues => {
                    !row.status().is_healthy() && !matches!(row.status(), ValidationStatus::Expired)
                }
                Filter::Ca => row.certificate.is_ca,
            })
            .map(|(index, _)| index)
            .collect()
    }

    pub fn selected_row(&self) -> Option<&CertRow> {
        let selected = self.selected.as_ref()?;
        self.rows
            .iter()
            .find(|row| &row.certificate.fingerprint_sha256 == selected)
    }

    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for row in &self.rows {
            counts.total += 1;
            match row.status() {
                ValidationStatus::Valid => counts.valid += 1,
                ValidationStatus::ExpiringSoon => counts.expiring += 1,
                ValidationStatus::Expired => counts.expired += 1,
                _ => {}
            }
            if row.certificate.is_ca {
                counts.ca += 1;
            }
        }
        counts.issues = counts.total.saturating_sub(counts.valid + counts.expiring);
        counts
    }

    /// Buckets upcoming expirations into the next 12 calendar months.
    /// Returns the buckets and the number of certificates expiring after them.
    pub fn expiry_buckets(&self, now: DateTime<Utc>, warn_days: i64) -> (Vec<ExpiryBucket>, usize) {
        let start_year = now.year();
        let start_month = now.month0() as i32;
        let warn_until = now + Duration::days(warn_days.max(0));

        let mut buckets: Vec<ExpiryBucket> = (0..12)
            .map(|offset| {
                let month_index = start_month + offset;
                let year = start_year + month_index.div_euclid(12);
                let month = month_index.rem_euclid(12) as u32 + 1;
                let label = chrono::NaiveDate::from_ymd_opt(year, month, 1)
                    .map(|date| date.format("%b").to_string())
                    .unwrap_or_default();
                ExpiryBucket {
                    label,
                    year,
                    count: 0,
                    urgent: false,
                }
            })
            .collect();

        let mut beyond = 0;
        for row in &self.rows {
            let expiry = row.certificate.not_after;
            if expiry < now {
                continue;
            }
            let index = (expiry.year() - start_year) * 12 + (expiry.month0() as i32 - start_month);
            if (0..12).contains(&index) {
                let bucket = &mut buckets[index as usize];
                bucket.count += 1;
                if expiry <= warn_until {
                    bucket.urgent = true;
                }
            } else if index >= 12 {
                beyond += 1;
            }
        }

        (buckets, beyond)
    }

    /// Most common issuers, with the remainder collapsed into "Other".
    pub fn top_issuers(&self, limit: usize) -> Vec<IssuerCount> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for row in &self.rows {
            *counts.entry(row.certificate.issuer.as_str()).or_default() += 1;
        }

        let mut items: Vec<IssuerCount> = counts
            .into_iter()
            .map(|(issuer, count)| IssuerCount {
                issuer: issuer.to_string(),
                count,
            })
            .collect();
        items.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.issuer.cmp(&right.issuer))
        });

        if items.len() > limit {
            let other = items[limit..].iter().map(|item| item.count).sum();
            items.truncate(limit);
            items.push(IssuerCount {
                issuer: "Other".to_string(),
                count: other,
            });
        }

        items
    }
}

#[derive(Debug, Clone)]
pub struct ExpiryBucket {
    pub label: String,
    pub year: i32,
    pub count: usize,
    pub urgent: bool,
}

#[derive(Debug, Clone)]
pub struct IssuerCount {
    pub issuer: String,
    pub count: usize,
}

#[derive(Debug, Default)]
pub struct Counts {
    pub total: usize,
    pub valid: usize,
    pub expiring: usize,
    pub expired: usize,
    pub issues: usize,
    pub ca: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cert_core::CertSource;
    use chrono::TimeZone;

    fn row(issuer: &str, not_after: DateTime<Utc>) -> CertRow {
        let certificate = Certificate {
            source: CertSource::OsTrustStore,
            subject: "CN=test".to_string(),
            issuer: issuer.to_string(),
            serial: "01".to_string(),
            not_before: not_after - Duration::days(365),
            not_after,
            san: Vec::new(),
            signature_algorithm: "1.2.840.113549.1.1.11".to_string(),
            key_algorithm: "1.2.840.113549.1.1.1".to_string(),
            is_ca: true,
            path_length: None,
            raw_der: Vec::new(),
            fingerprint_sha256: "00".to_string(),
        };
        let result = ChainValidationResult {
            target: certificate.clone(),
            intermediates: Vec::new(),
            trust_anchor: None,
            status: ValidationStatus::Valid,
            checked_at: not_after,
            errors: Vec::new(),
            warnings: Vec::new(),
        };
        CertRow {
            certificate,
            result,
        }
    }

    fn state(rows: Vec<CertRow>) -> AppState {
        AppState {
            rows,
            filter: Filter::All,
            view: View::Dashboard,
            selected: None,
            warn_days: 30,
            anchor_count: 0,
            parse_errors: Vec::new(),
            load_error: None,
        }
    }

    fn utc(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
            .single()
            .expect("valid date")
    }

    #[test]
    fn buckets_expirations_into_the_next_twelve_months() {
        let now = utc(2026, 11, 15);
        let state = state(vec![
            row("A", utc(2026, 11, 20)),
            row("A", utc(2027, 1, 10)),
            row("B", utc(2027, 10, 1)),
            row("B", utc(2028, 6, 1)),
            row("C", utc(2026, 1, 1)),
        ]);

        let (buckets, beyond) = state.expiry_buckets(now, 30);

        assert_eq!(buckets.len(), 12);
        assert_eq!(buckets[0].label, "Nov");
        assert!(buckets[0].urgent);
        assert_eq!(buckets[0].count, 1);
        assert_eq!(buckets[2].label, "Jan");
        assert_eq!(buckets[2].year, 2027);
        assert_eq!(buckets[2].count, 1);
        assert_eq!(buckets[11].count, 1);
        assert_eq!(beyond, 1);
        assert_eq!(
            buckets.iter().map(|bucket| bucket.count).sum::<usize>() + beyond,
            4
        );
    }

    #[test]
    fn collapses_issuers_beyond_the_limit() {
        let now = utc(2026, 11, 15);
        let state = state(vec![
            row("A", now + Duration::days(30)),
            row("A", now + Duration::days(30)),
            row("A", now + Duration::days(30)),
            row("B", now + Duration::days(30)),
            row("B", now + Duration::days(30)),
            row("C", now + Duration::days(30)),
        ]);

        let items = state.top_issuers(2);

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].issuer, "A");
        assert_eq!(items[0].count, 3);
        assert_eq!(items[1].issuer, "B");
        assert_eq!(items[1].count, 2);
        assert_eq!(items[2].issuer, "Other");
        assert_eq!(items[2].count, 1);
    }
}
