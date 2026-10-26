use cert_core::{
    Certificate, ChainValidationResult, ValidationOptions, ValidationStatus, validate_in_os_store,
};
use cert_infra::{load_os_store, trust_anchors_der};
use chrono::Utc;

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
