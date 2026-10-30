use cert_core::ValidationStatus;
use serde::Serialize;

use crate::InfraError;
use crate::config::NotificationConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NotificationSummary {
    pub total: usize,
    pub valid: usize,
    pub expiring: usize,
    pub expired: usize,
    pub issues: usize,
}

impl NotificationSummary {
    pub fn from_statuses<'a>(statuses: impl IntoIterator<Item = &'a ValidationStatus>) -> Self {
        let mut summary = Self::default();
        for status in statuses {
            summary.total += 1;
            match status {
                ValidationStatus::Valid => summary.valid += 1,
                ValidationStatus::ExpiringSoon => summary.expiring += 1,
                ValidationStatus::Expired => summary.expired += 1,
                _ => {}
            }
        }
        summary.issues = summary
            .total
            .saturating_sub(summary.valid + summary.expiring);
        summary
    }

    pub fn should_notify(&self, config: &NotificationConfig) -> bool {
        if !config.enabled {
            return false;
        }
        (config.expiring && self.expiring > 0)
            || (config.expired && self.expired > 0)
            || (config.issues && self.issues > 0)
    }

    pub fn signature(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.total, self.valid, self.expiring, self.expired, self.issues
        )
    }

    pub fn title(&self) -> String {
        if self.expired > 0 {
            format!("ca-checker: {} certificate(s) expired", self.expired)
        } else if self.expiring > 0 {
            format!("ca-checker: {} certificate(s) expiring soon", self.expiring)
        } else {
            format!("ca-checker: {} certificate(s) need attention", self.issues)
        }
    }

    pub fn body(&self) -> String {
        format!(
            "{} certificates checked · {} valid · {} expiring · {} expired · {} issues",
            self.total, self.valid, self.expiring, self.expired, self.issues
        )
    }
}

pub fn send_desktop_notification(title: &str, body: &str) -> Result<(), InfraError> {
    notify_rust::Notification::new()
        .appname("ca-checker")
        .summary(title)
        .body(body)
        .show()
        .map(|_| ())
        .map_err(|err| InfraError::Notification(err.to_string()))
}

pub fn notify_summary(summary: &NotificationSummary) -> Result<(), InfraError> {
    send_desktop_notification(&summary.title(), &summary.body())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cert_core::ValidationStatus;

    #[test]
    fn summary_counts_statuses() {
        let statuses = [
            ValidationStatus::Valid,
            ValidationStatus::ExpiringSoon,
            ValidationStatus::Expired,
            ValidationStatus::UntrustedRoot,
        ];
        let summary = NotificationSummary::from_statuses(statuses.iter());
        assert_eq!(summary.total, 4);
        assert_eq!(summary.valid, 1);
        assert_eq!(summary.expiring, 1);
        assert_eq!(summary.expired, 1);
        assert_eq!(summary.issues, 2);
    }

    #[test]
    fn notifications_can_be_disabled() {
        let summary = NotificationSummary {
            total: 1,
            expired: 1,
            issues: 1,
            ..Default::default()
        };
        let mut config = NotificationConfig::default();
        assert!(summary.should_notify(&config));
        config.enabled = false;
        assert!(!summary.should_notify(&config));
    }
}
