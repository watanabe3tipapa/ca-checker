use std::collections::HashSet;
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
use chrono::Utc;
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
