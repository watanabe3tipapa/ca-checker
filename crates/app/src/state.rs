use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use cert_core::{
    Certificate, ChainValidationResult, RevocationCheck, RevocationStatus, ValidationOptions,
    ValidationStatus, apply_revocation, find_issuer_certificate, validate, validate_in_os_store,
};
use cert_infra::{
    AppConfig, NotificationSummary, RevocationCache, RevocationMode, check_revocation, config_path,
    load_os_store, load_path, notify_summary, trust_anchors_der,
};
use chrono::{DateTime, Datelike, Duration, Utc};
use gpui::{AppContext, Context, Entity, Window};
use gpui_terminal::{ColorPalette, TerminalConfig, TerminalView};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Detail,
    Settings,
    Terminal,
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
    pub const ALL: [Filter; 7] = [
        Filter::All,
        Filter::Valid,
        Filter::Expiring,
        Filter::Expired,
        Filter::Issues,
        Filter::OtherIssues,
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
    pub config: AppConfig,
    pub config_path: PathBuf,
    pub config_message: Option<String>,
    pub notification_summary: Option<NotificationSummary>,
    pub notification_message: Option<String>,
    pub imported: Vec<Certificate>,
    pub import_message: Option<String>,
    pub revocation_message: Option<String>,
    pub revocation_cache: Arc<RevocationCache>,
    pub terminal: Option<Entity<TerminalView>>,
    pub terminal_error: Option<String>,
    terminal_child: Option<Box<dyn Child + Send>>,
    terminal_master: Option<Arc<parking_lot::Mutex<Box<dyn MasterPty + Send>>>>,
    trust_certificates: Vec<Certificate>,
}

impl AppState {
    pub fn new() -> Self {
        let path = config_path();
        let (config, config_error) = match AppConfig::load(&path) {
            Ok(config) => (config, None),
            Err(error) => (AppConfig::default(), Some(error.to_string())),
        };
        let warn_days = config.warn_days;

        let mut state = Self {
            rows: Vec::new(),
            filter: Filter::All,
            view: View::Dashboard,
            selected: None,
            warn_days,
            anchor_count: 0,
            parse_errors: Vec::new(),
            load_error: config_error,
            config,
            config_path: path,
            config_message: None,
            notification_summary: None,
            notification_message: None,
            imported: Vec::new(),
            import_message: None,
            revocation_message: None,
            revocation_cache: Arc::new(RevocationCache::new()),
            terminal: None,
            terminal_error: None,
            terminal_child: None,
            terminal_master: None,
            trust_certificates: Vec::new(),
        };
        state.reload();
        state.notify_on_startup();
        state
    }

    pub fn reload(&mut self) {
        let options = ValidationOptions {
            now: Utc::now(),
            warn_days: self.warn_days,
        };

        let mut rows = Vec::new();
        let mut seen = HashSet::new();
        let mut parse_errors = Vec::new();
        let mut load_error = None;
        let mut trust_certificates = Vec::new();
        let mut anchors = Vec::new();

        match load_os_store() {
            Ok(store) => {
                trust_certificates = store.certificates.clone();
                anchors = trust_anchors_der(&store.certificates);
                parse_errors = store.errors;
                for certificate in &store.certificates {
                    if seen.insert(certificate.fingerprint_sha256.clone()) {
                        rows.push(CertRow {
                            certificate: certificate.clone(),
                            result: validate_in_os_store(certificate, &anchors, &options),
                        });
                    }
                }
            }
            Err(error) => {
                load_error = Some(error.to_string());
            }
        }

        for (index, certificate) in self.imported.iter().enumerate() {
            if !seen.insert(certificate.fingerprint_sha256.clone()) {
                continue;
            }
            let intermediates: Vec<Certificate> = self
                .imported
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != index)
                .map(|(_, certificate)| certificate.clone())
                .collect();
            rows.push(CertRow {
                certificate: certificate.clone(),
                result: validate(certificate, &intermediates, &anchors, &options),
            });
        }

        self.rows = rows;
        self.anchor_count = anchors.len();
        self.parse_errors = parse_errors;
        self.load_error = load_error;
        self.trust_certificates = trust_certificates;

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

    fn notify_on_startup(&mut self) {
        let summary = NotificationSummary::from_statuses(self.rows.iter().map(|row| row.status()));
        self.notification_summary = Some(summary.clone());
        if !self.config.notifications.on_startup
            || !summary.should_notify(&self.config.notifications)
        {
            return;
        }
        self.notification_message = Some(match notify_summary(&summary) {
            Ok(()) => "Desktop notification sent".to_string(),
            Err(error) => format!("Desktop notification failed: {error}"),
        });
    }

    pub fn import_paths(&mut self, paths: Vec<PathBuf>) {
        let mut added = 0;
        let mut errors = Vec::new();
        for path in paths {
            match load_path(&path) {
                Ok(certificates) => {
                    for certificate in certificates {
                        if self.imported.iter().any(|existing| {
                            existing.fingerprint_sha256 == certificate.fingerprint_sha256
                        }) {
                            continue;
                        }
                        self.imported.push(certificate);
                        added += 1;
                    }
                }
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }
        self.reload();
        self.import_message = Some(if errors.is_empty() {
            format!("Imported {added} certificate(s)")
        } else {
            format!("Imported {added} certificate(s); {}", errors.join("; "))
        });
    }

    pub fn clear_imports(&mut self) {
        self.imported.clear();
        self.import_message = Some("Imported certificates cleared".to_string());
        self.reload();
    }

    pub fn set_warn_days(&mut self, days: i64) {
        self.warn_days = days;
        self.config.warn_days = days;
        self.reload();
    }

    pub fn set_revocation_mode(&mut self, mode: RevocationMode) {
        self.config.revocation.mode = mode;
        self.revocation_message = None;
    }

    pub fn toggle_notifications(&mut self) {
        self.config.notifications.enabled = !self.config.notifications.enabled;
    }

    pub fn save_config(&mut self) {
        self.config_message = Some(match self.config.save(&self.config_path) {
            Ok(()) => format!("Saved {}", self.config_path.display()),
            Err(error) => format!("Failed to save config: {error}"),
        });
    }

    pub fn start_revocation_check(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.selected_row().cloned() else {
            return;
        };
        let Some(issuer) =
            find_issuer_certificate(&row.certificate, &self.imported, &self.trust_certificates)
                .cloned()
        else {
            self.revocation_message =
                Some("Issuer certificate is not available for revocation checking".to_string());
            return;
        };

        let target = row.certificate.clone();
        let config = self.config.revocation.clone();
        let cache = self.revocation_cache.clone();
        self.revocation_message = Some(format!(
            "Checking revocation via {}...",
            config.mode.label()
        ));

        cx.spawn(async move |weak, cx| {
            let check = cx
                .background_executor()
                .spawn(async move { check_revocation(&target, Some(&issuer), &config, &cache) })
                .await;
            if let Some(entity) = weak.upgrade() {
                cx.update_entity(
                    &entity,
                    |this: &mut AppState, cx: &mut Context<AppState>| {
                        this.apply_revocation_check(&row.certificate.fingerprint_sha256, check);
                        cx.notify();
                    },
                )
                .ok();
            }
        })
        .detach();
    }

    fn apply_revocation_check(&mut self, fingerprint: &str, check: RevocationCheck) {
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|row| row.certificate.fingerprint_sha256 == fingerprint)
        {
            apply_revocation(&mut row.result, &check);
        }
        self.revocation_message = Some(match &check.status {
            RevocationStatus::Good => "Revocation status: good".to_string(),
            RevocationStatus::Revoked { reason, .. } => format!(
                "Revocation status: revoked{}",
                reason
                    .as_ref()
                    .map(|reason| format!(" ({reason})"))
                    .unwrap_or_default()
            ),
            RevocationStatus::Unknown { message } => {
                format!("Revocation status: unknown ({message})")
            }
        });
    }

    pub fn ensure_terminal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(terminal) = &self.terminal {
            terminal.read(cx).focus_handle().focus(window);
            return;
        }

        match spawn_shell() {
            Ok((writer, reader, child, master)) => {
                let resize_master = master.clone();
                let terminal = cx.new(|cx| {
                    let config = TerminalConfig {
                        cols: 100,
                        rows: 28,
                        font_family: "Menlo".into(),
                        font_size: gpui::px(13.0),
                        scrollback: 10_000,
                        line_height_multiplier: 1.2,
                        padding: gpui::Edges::all(gpui::px(8.0)),
                        colors: ColorPalette::default(),
                    };
                    TerminalView::new(writer, reader, config, cx).with_resize_callback(
                        move |cols, rows| {
                            let _ = resize_master.lock().resize(PtySize {
                                cols: cols as u16,
                                rows: rows as u16,
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        },
                    )
                });
                terminal.read(cx).focus_handle().focus(window);
                self.terminal = Some(terminal);
                self.terminal_child = Some(child);
                self.terminal_master = Some(master);
                self.terminal_error = None;
            }
            Err(error) => {
                self.terminal_error = Some(error);
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

type PtyWriter = Box<dyn Write + Send>;
type PtyReader = Box<dyn Read + Send>;
type PtyMaster = Arc<parking_lot::Mutex<Box<dyn MasterPty + Send>>>;

fn spawn_shell() -> Result<(PtyWriter, PtyReader, Box<dyn Child + Send>, PtyMaster), String> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 28,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| format!("Failed to open PTY: {error}"))?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let mut command = CommandBuilder::new(shell);
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    if let Ok(directory) = std::env::current_dir() {
        command.cwd(directory);
    }

    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("Failed to spawn shell: {error}"))?;
    drop(pair.slave);

    let writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("Failed to open terminal input: {error}"))?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("Failed to open terminal output: {error}"))?;
    let master = Arc::new(parking_lot::Mutex::new(pair.master));

    Ok((writer, reader, child, master))
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
            crl_distribution_points: Vec::new(),
            ocsp_responders: Vec::new(),
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
            revocation: None,
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
            config: AppConfig::default(),
            config_path: PathBuf::new(),
            config_message: None,
            notification_summary: None,
            notification_message: None,
            imported: Vec::new(),
            import_message: None,
            revocation_message: None,
            revocation_cache: Arc::new(RevocationCache::new()),
            terminal: None,
            terminal_error: None,
            terminal_child: None,
            terminal_master: None,
            trust_certificates: Vec::new(),
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
