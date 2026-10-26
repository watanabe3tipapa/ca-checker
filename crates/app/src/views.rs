use base64::{Engine, engine::general_purpose::STANDARD};
use cert_core::{Certificate, ValidationStatus};
use gpui::{
    AnyElement, App, Context, FontWeight, Hsla, IntoElement, Window, div, prelude::*, px, rgb,
    uniform_list,
};

use crate::state::{AppState, CertRow, Filter, View};

const BG: u32 = 0xffffff;
const FG: u32 = 0x0b0b0b;
const ACCENT: u32 = 0x00e5a8;
const MUTED: u32 = 0xf2f2f2;
const MUTED_TEXT: u32 = 0x525252;
const UI_FONT: &str = "Hiragino Sans";
const MONO_FONT: &str = "Menlo";

impl AppState {
    pub fn render_root(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        div().size_full().bg(rgb(MUTED)).p_3().child(
            div()
                .flex()
                .flex_col()
                .size_full()
                .bg(rgb(BG))
                .border_4()
                .border_color(rgb(FG))
                .rounded_xs()
                .overflow_hidden()
                .font_family(UI_FONT)
                .text_color(rgb(FG))
                .child(self.render_header(cx))
                .child(div().flex_1().min_h(px(0.)).child(self.render_content(cx))),
        )
    }

    fn render_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let entity = cx.entity();
        let reload_entity = entity.clone();

        div()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .px_6()
                    .pt_5()
                    .child(
                        div()
                            .border_3()
                            .border_color(rgb(FG))
                            .rounded_xs()
                            .px_3()
                            .py_1()
                            .font_weight(FontWeight::BOLD)
                            .child("ca-checker"),
                    )
                    .child(meta_tag(format!("v0.1.0 · {} certs", self.rows.len()))),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .px_6()
                    .pt_4()
                    .child(
                        div().flex().child(
                            div()
                                .border_3()
                                .border_color(rgb(FG))
                                .rounded_xs()
                                .bg(rgb(BG))
                                .px_4()
                                .py_2()
                                .text_3xl()
                                .font_weight(FontWeight::BOLD)
                                .child("CA Certificate Checker"),
                        ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED_TEXT))
                            .child("Verify X.509 certificates from the OS trust store."),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .border_b_4()
                    .border_color(rgb(FG))
                    .px_6()
                    .py_4()
                    .child(nav_button(
                        "Dashboard",
                        self.view == View::Dashboard,
                        entity.clone(),
                        View::Dashboard,
                    ))
                    .child(nav_button(
                        "Settings",
                        self.view == View::Settings,
                        entity,
                        View::Settings,
                    ))
                    .child(div().flex_1())
                    .child(action_button("Reload", true, move |_, cx| {
                        reload_entity.update(cx, |this, cx| {
                            this.reload();
                            cx.notify();
                        });
                    })),
            )
    }

    fn render_content(&mut self, cx: &mut Context<Self>) -> AnyElement {
        match self.view {
            View::Dashboard => self.render_dashboard(cx).into_any_element(),
            View::Detail => self.render_detail(cx).into_any_element(),
            View::Settings => self.render_settings(cx).into_any_element(),
        }
    }

    fn render_dashboard(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let counts = self.counts();
        let entity = cx.entity();
        let indices = self.filtered_indices();
        let item_count = indices.len();

        let list = uniform_list(
            "certificate-list",
            item_count,
            cx.processor(move |this, range: std::ops::Range<usize>, _window, _cx| {
                range
                    .map(|position| {
                        let row_index = indices[position];
                        render_row(position, &this.rows[row_index], entity.clone())
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .h_full();

        div()
            .flex()
            .flex_col()
            .size_full()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .px_6()
                    .pt_5()
                    .pb_4()
                    .child(section_title("Trust store"))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_3()
                            .child(stat_card("Total", counts.total, rgb(ACCENT).into()))
                            .child(stat_card("Valid", counts.valid, rgb(0x8ef0cf).into()))
                            .child(stat_card("Expiring", counts.expiring, rgb(0xffc857).into()))
                            .child(stat_card("Expired", counts.expired, rgb(0xff6b6b).into()))
                            .child(stat_card("Issues", counts.issues, rgb(0xff8fab).into()))
                            .child(stat_card("CA", counts.ca, rgb(0xc8b6ff).into())),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .children(Filter::ALL.into_iter().map(|filter| {
                                let active = self.filter == filter;
                                div()
                                    .id(filter.label())
                                    .border_2()
                                    .border_color(rgb(FG))
                                    .rounded_xs()
                                    .px_3()
                                    .py_1()
                                    .font_family(MONO_FONT)
                                    .text_xs()
                                    .font_weight(FontWeight::BOLD)
                                    .cursor_pointer()
                                    .bg(if active { rgb(ACCENT) } else { rgb(BG) })
                                    .hover(|this| this.bg(rgb(ACCENT)))
                                    .child(filter.label())
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.filter = filter;
                                        cx.notify();
                                    }))
                            })),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h(px(0.))
                    .border_t_4()
                    .border_color(rgb(FG))
                    .child(if item_count == 0 {
                        div()
                            .size_full()
                            .flex()
                            .items_center()
                            .justify_center()
                            .font_family(MONO_FONT)
                            .text_sm()
                            .text_color(rgb(MUTED_TEXT))
                            .child("No certificates match this filter")
                            .into_any_element()
                    } else {
                        list.into_any_element()
                    }),
            )
    }

    fn render_detail(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let entity = cx.entity();
        let Some(row) = self.selected_row().cloned() else {
            return div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .font_family(MONO_FONT)
                .text_sm()
                .text_color(rgb(MUTED_TEXT))
                .child("Select a certificate from the dashboard")
                .into_any_element();
        };

        let certificate = row.certificate.clone();
        let status = row.status().clone();
        let color = status_color(&status);
        let pem_lines = pem_lines(&certificate);

        div()
            .id("detail-scroll")
            .flex_1()
            .min_h(px(0.))
            .size_full()
            .overflow_scroll()
            .p_6()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(action_button("Back", false, move |_, cx| {
                        entity.update(cx, |this, cx| {
                            this.view = View::Dashboard;
                            cx.notify();
                        });
                    }))
                    .child(status_badge(status.label(), color)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .w_full()
                            .border_3()
                            .border_color(rgb(FG))
                            .rounded_xs()
                            .bg(rgb(BG))
                            .px_4()
                            .py_2()
                            .text_xl()
                            .font_weight(FontWeight::BOLD)
                            .child(certificate.subject.clone()),
                    )
                    .child(
                        div()
                            .font_family(MONO_FONT)
                            .text_xs()
                            .text_color(rgb(MUTED_TEXT))
                            .child(format!("ISSUED BY {}", certificate.issuer)),
                    ),
            )
            .child(section_title("Properties"))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(property("Serial", certificate.serial.clone()))
                    .child(property(
                        "Not before",
                        certificate
                            .not_before
                            .format("%Y-%m-%d %H:%M UTC")
                            .to_string(),
                    ))
                    .child(property(
                        "Not after",
                        certificate
                            .not_after
                            .format("%Y-%m-%d %H:%M UTC")
                            .to_string(),
                    ))
                    .child(property(
                        "Days remaining",
                        certificate
                            .days_until_expiry(chrono::Utc::now())
                            .to_string(),
                    ))
                    .child(property("CA", certificate.is_ca.to_string()))
                    .child(property(
                        "Path length",
                        certificate
                            .path_length
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    ))
                    .child(property(
                        "Signature algorithm",
                        algorithm_label(&certificate.signature_algorithm),
                    ))
                    .child(property(
                        "Key algorithm",
                        algorithm_label(&certificate.key_algorithm),
                    ))
                    .child(property("Source", certificate.source.label()))
                    .child(property("SHA-256", certificate.fingerprint_sha256.clone())),
            )
            .child(section(
                "Subject alternative names",
                if certificate.san.is_empty() {
                    vec!["-".to_string()]
                } else {
                    certificate.san.clone()
                },
            ))
            .child(section(
                "Validation",
                if row.result.errors.is_empty() && row.result.warnings.is_empty() {
                    vec!["No validation messages".to_string()]
                } else {
                    row.result
                        .errors
                        .iter()
                        .map(|message| format!("error: {message}"))
                        .chain(
                            row.result
                                .warnings
                                .iter()
                                .map(|message| format!("warning: {message}")),
                        )
                        .collect()
                },
            ))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(section_title("PEM"))
                    .child(
                        div()
                            .p_4()
                            .border_2()
                            .border_dashed()
                            .border_color(rgb(FG))
                            .rounded_xs()
                            .bg(rgb(BG))
                            .flex()
                            .flex_col()
                            .children(
                                pem_lines
                                    .into_iter()
                                    .map(|line| div().font_family(MONO_FONT).text_xs().child(line)),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_settings(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let count = self.rows.len();
        let anchor_count = self.anchor_count;
        let issue_count = self
            .rows
            .iter()
            .filter(|row| !row.status().is_healthy())
            .count();
        let parse_errors = self.parse_errors.clone();
        let load_error = self.load_error.clone();
        let warn_days = self.warn_days;
        let load_errors: Vec<String> = load_error
            .into_iter()
            .chain(parse_errors)
            .collect::<Vec<_>>();
        let load_errors = if load_errors.is_empty() {
            vec!["No load errors".to_string()]
        } else {
            load_errors
        };

        div()
            .id("settings-scroll")
            .size_full()
            .overflow_scroll()
            .p_6()
            .flex()
            .flex_col()
            .gap_5()
            .child(
                div().flex().child(
                    div()
                        .border_3()
                        .border_color(rgb(FG))
                        .rounded_xs()
                        .bg(rgb(BG))
                        .px_4()
                        .py_2()
                        .text_xl()
                        .font_weight(FontWeight::BOLD)
                        .child("Settings"),
                ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(section_title("Expiry warning window"))
                    .child(div().flex().flex_wrap().gap_2().children(
                        [7_i64, 30, 90, 180].into_iter().map(|days| {
                            let active = warn_days == days;
                            div()
                                .id(("warn-days", days as usize))
                                .border_2()
                                .border_color(rgb(FG))
                                .rounded_xs()
                                .px_3()
                                .py_1()
                                .font_family(MONO_FONT)
                                .text_xs()
                                .font_weight(FontWeight::BOLD)
                                .cursor_pointer()
                                .bg(if active { rgb(ACCENT) } else { rgb(BG) })
                                .hover(|this| this.bg(rgb(ACCENT)))
                                .child(format!("{days} days"))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.warn_days = days;
                                    this.reload();
                                    cx.notify();
                                }))
                        }),
                    )),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(section_title("Trust store"))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_3()
                            .child(property("Certificates loaded", count.to_string()))
                            .child(property("Trust anchors", anchor_count.to_string()))
                            .child(property(
                                "Certificates with issues",
                                issue_count.to_string(),
                            )),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(section_title("Diagnostics"))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_3()
                            .child(property(
                                "Network fetching",
                                "Not implemented in this build".to_string(),
                            ))
                            .child(property(
                                "Certificate import",
                                "Use cert-cli inspect/verify for files".to_string(),
                            )),
                    ),
            )
            .child(section("Load errors", load_errors))
    }
}

fn nav_button(
    label: &'static str,
    active: bool,
    entity: gpui::Entity<AppState>,
    view: View,
) -> impl IntoElement {
    div()
        .id(label)
        .border_3()
        .border_color(rgb(FG))
        .rounded_xs()
        .px_3()
        .py_1()
        .font_family(MONO_FONT)
        .text_xs()
        .font_weight(FontWeight::BOLD)
        .cursor_pointer()
        .bg(if active { rgb(ACCENT) } else { rgb(BG) })
        .hover(|this| this.bg(rgb(ACCENT)))
        .child(label)
        .on_click(move |_, _, cx| {
            entity.update(cx, |this, cx| {
                this.view = view;
                cx.notify();
            });
        })
}

fn action_button(
    label: &'static str,
    primary: bool,
    on_click: impl Fn(&mut Window, &mut App) + 'static,
) -> impl IntoElement {
    div()
        .id(label)
        .border_4()
        .border_color(rgb(FG))
        .rounded_xs()
        .px_3()
        .py_1()
        .font_family(MONO_FONT)
        .text_xs()
        .font_weight(FontWeight::BOLD)
        .cursor_pointer()
        .bg(if primary { rgb(ACCENT) } else { rgb(BG) })
        .hover(|this| this.bg(rgb(FG)).text_color(rgb(BG)))
        .child(label)
        .on_click(move |_, window, cx| on_click(window, cx))
}

fn meta_tag(label: String) -> impl IntoElement {
    div()
        .border_2()
        .border_color(rgb(FG))
        .rounded_xs()
        .bg(rgb(MUTED))
        .px_2()
        .py_1()
        .font_family(MONO_FONT)
        .text_xs()
        .child(label)
}

fn section_title(label: &'static str) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap_2()
        .child(
            div()
                .w(px(14.))
                .h(px(14.))
                .flex_none()
                .bg(rgb(ACCENT))
                .border_2()
                .border_color(rgb(FG)),
        )
        .child(
            div()
                .border_3()
                .border_color(rgb(FG))
                .rounded_xs()
                .bg(rgb(BG))
                .px_3()
                .py_1()
                .text_sm()
                .font_weight(FontWeight::BOLD)
                .child(label),
        )
}

fn stat_card(label: &'static str, value: usize, color: Hsla) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .min_w(px(128.))
        .p_4()
        .border_4()
        .border_color(rgb(FG))
        .rounded_xs()
        .bg(rgb(BG))
        .hover(|this| this.bg(rgb(ACCENT)))
        .child(
            div()
                .font_family(MONO_FONT)
                .text_3xl()
                .font_weight(FontWeight::BOLD)
                .text_color(color)
                .child(value.to_string()),
        )
        .child(
            div()
                .font_family(MONO_FONT)
                .text_xs()
                .font_weight(FontWeight::BOLD)
                .text_color(rgb(FG))
                .child(label),
        )
}

fn render_row(position: usize, row: &CertRow, entity: gpui::Entity<AppState>) -> AnyElement {
    let status = row.status().clone();
    let color = status_color(&status);
    let certificate = &row.certificate;
    let subject = certificate.subject.clone();
    let issuer = certificate.issuer.clone();
    let expires = certificate.not_after.format("%Y-%m-%d").to_string();
    let source = certificate.source.label();
    let fingerprint = certificate.fingerprint_sha256.clone();
    let status_label = status.label().to_string();

    div()
        .id(position)
        .h(px(66.))
        .px_6()
        .flex()
        .items_center()
        .gap_4()
        .border_b_2()
        .border_color(rgb(FG))
        .bg(rgb(BG))
        .cursor_pointer()
        .hover(|this| this.bg(rgb(ACCENT)))
        .on_click(move |_, _, cx| {
            entity.update(cx, |this, cx| {
                this.selected = Some(fingerprint.clone());
                this.view = View::Detail;
                cx.notify();
            });
        })
        .child(
            div()
                .w(px(12.))
                .h(px(12.))
                .flex_none()
                .border_2()
                .border_color(rgb(FG))
                .bg(color),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_0p5()
                .flex_1()
                .min_w(px(0.))
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::BOLD)
                        .truncate()
                        .child(subject),
                )
                .child(
                    div()
                        .font_family(MONO_FONT)
                        .text_xs()
                        .text_color(rgb(MUTED_TEXT))
                        .truncate()
                        .child(issuer),
                ),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap_0p5()
                .items_end()
                .w(px(160.))
                .child(
                    div()
                        .font_family(MONO_FONT)
                        .text_xs()
                        .font_weight(FontWeight::BOLD)
                        .child(expires),
                )
                .child(
                    div()
                        .font_family(MONO_FONT)
                        .text_xs()
                        .text_color(rgb(MUTED_TEXT))
                        .truncate()
                        .child(source),
                ),
        )
        .child(status_badge(&status_label, color))
        .into_any_element()
}

fn status_badge(label: &str, color: Hsla) -> impl IntoElement {
    div()
        .px_2()
        .py_1()
        .border_2()
        .border_color(rgb(FG))
        .rounded_xs()
        .flex_none()
        .bg(color)
        .font_family(MONO_FONT)
        .text_xs()
        .font_weight(FontWeight::BOLD)
        .text_color(rgb(FG))
        .child(label.to_string())
}

fn status_color(status: &ValidationStatus) -> Hsla {
    match status {
        ValidationStatus::Valid => rgb(0x8ef0cf).into(),
        ValidationStatus::ExpiringSoon => rgb(0xffc857).into(),
        ValidationStatus::Expired => rgb(0xff6b6b).into(),
        ValidationStatus::NotYetValid => rgb(0xffa94d).into(),
        ValidationStatus::UntrustedRoot => rgb(0xff8fab).into(),
        ValidationStatus::SelfSigned => rgb(0xc8b6ff).into(),
        ValidationStatus::WeakSignature => rgb(0xff9f9f).into(),
        ValidationStatus::RevocationUnknown => rgb(0xffe066).into(),
        ValidationStatus::Error(_) => rgb(0xff6b6b).into(),
    }
}

fn property(label: &'static str, value: String) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .min_w(px(210.))
        .p_3()
        .border_2()
        .border_color(rgb(FG))
        .rounded_xs()
        .bg(rgb(BG))
        .hover(|this| this.bg(rgb(ACCENT)))
        .child(
            div()
                .font_family(MONO_FONT)
                .text_xs()
                .text_color(rgb(MUTED_TEXT))
                .child(label),
        )
        .child(div().text_sm().child(value))
}

fn section(title: &'static str, values: Vec<String>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(section_title(title))
        .child(
            div()
                .border_2()
                .border_color(rgb(FG))
                .rounded_xs()
                .bg(rgb(BG))
                .children(values.into_iter().map(|value| {
                    div()
                        .px_3()
                        .py_2()
                        .border_b_2()
                        .border_color(rgb(MUTED))
                        .font_family(MONO_FONT)
                        .text_xs()
                        .child(value)
                })),
        )
}

fn algorithm_label(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA".to_string(),
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA".to_string(),
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA".to_string(),
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA".to_string(),
        "1.2.840.10045.2.1" => "EC".to_string(),
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256".to_string(),
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        other => other.to_string(),
    }
}

fn pem_lines(certificate: &Certificate) -> Vec<String> {
    let encoded = STANDARD.encode(&certificate.raw_der);
    let mut lines = Vec::with_capacity(encoded.len() / 64 + 3);
    lines.push("-----BEGIN CERTIFICATE-----".to_string());
    for chunk in encoded.as_bytes().chunks(64) {
        lines.push(String::from_utf8_lossy(chunk).into_owned());
    }
    lines.push("-----END CERTIFICATE-----".to_string());
    lines
}
