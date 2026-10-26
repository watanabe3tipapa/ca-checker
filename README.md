# ca-checker

**信頼の鎖は、確かめてから使う。**

ca-checker は、OS の信頼ストアにある **X.509 証明書**を、有効期限・署名アルゴリズム・信頼チェーンから検証する GPUI 製デスクトップダッシュボード兼 CLI ツールです。ルート CA の状態を一覧し、期限切れや弱い署名、未信頼の証明書をひと目で見つけられます。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v0.1.1-blue.svg)](https://github.com/watanabe3tipapa/ca-checker/releases)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-000000.svg?logo=rust)](https://www.rust-lang.org/)
[![GPUI](https://img.shields.io/badge/GPUI-0.2.2-00e5a8.svg)](https://crates.io/crates/gpui)
[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-site-00e5a8.svg)](https://watanabe3tipapa.github.io/ca-checker/)
[![GitHub issues](https://img.shields.io/github/issues/watanabe3tipapa/ca-checker.svg)](https://github.com/watanabe3tipapa/ca-checker/issues)

---

## 概要

ca-checker は、OS の信頼ストアを読み込み、証明書ごとの状態を **「有効 / 期限間近 / 期限切れ / 問題あり」** に分類します。GUI ではサマリー、フィルタ、証明書一覧、詳細、PEM 表示、期限警告日数の設定を提供します。CLI では同じ検証エンジンを使って、ファイルやディレクトリ、証明書チェーンを検証できます。

本リポジトリの根底にあるのは、**「信頼しているつもり」を、確認できる状態に変える**という考え方です。証明書は置いてあるだけでは安全ではありません。期限、署名、発行者とのつながりを確認して初めて、信頼の鎖として機能します。ca-checker は、その鎖を人間にも機械にも扱いやすい形で可視化します。

## コンセプト（なぜ「チェッカー」か）

証明書の信頼は、単一の証明書ではなく **連なり（チェーン）** で成立します。ca-checker は、日常的に見落としやすい次の視点を、ひとつの画面とひとつのコマンドにまとめます。

| 視点 | 確認する内容 |
|---|---|
| 期限 | 有効期間の開始前・期限切れ・期限間近を判定する |
| 署名 | MD5 / SHA-1 などの弱い署名アルゴリズムを検出する |
| 発行の連なり | ルート・中間・リーフのチェーンを `rustls-webpki` で検証する |
| 信頼の起点 | OS 信頼ストア、または指定したルート証明書と照合する |
| 基本制約 | CA フラグ、パス長制約、SAN の有無を確認する |
| 記録 | GUI、CLI、JSON で同じ結果を参照できる |

## 主な特徴

- OS の信頼ストア（macOS Keychain / Linux のネイティブストア）を読み込み
- PEM / DER 形式の証明書ファイルと、再帰的なディレクトリスキャンに対応
- `rustls-webpki` によるルート・中間・リーフのチェーン検証
- 有効期限、期限間近、弱い署名アルゴリズム（MD5 / SHA-1）の検出
- GPUI によるブルータリズム調のダッシュボード UI
- 状態サマリー、ステータスフィルタ、証明書一覧、詳細、PEM 表示
- 期限警告日数の設定（7 / 30 / 90 / 180 日）
- GUI からの PEM / DER ファイル・フォルダのインポート
- CRL / OCSP による失効確認（CRL 署名検証・OCSP レスポンス検証）
- 期限切れ・期限間近・問題のある証明書のデスクトップ通知
- GUI 内蔵ターミナル（ローカル PTY シェル）
- 設定ファイル（`~/.config/ca-checker/config.toml`）による通知・失効確認の制御
- CLI による一覧・詳細・検証・スキャン・通知・設定表示と JSON 出力
- 検証結果に応じた終了コード（CI に組み込み可能）

## 機能一覧

| 機能 | GUI | CLI | 説明 |
|---|---|---|---|
| OS 信頼ストアの一覧 | 対応 | `list-os` | 読み込んだ証明書とパースエラーを表示 |
| 証明書ファイルの詳細 | — | `inspect` | Subject / Issuer / SAN / アルゴリズム / SHA-256 を表示 |
| チェーン検証 | 対応 | `verify` | ルート・中間・リーフを検証し、状態とメッセージを出力 |
| ディレクトリスキャン | — | `scan` | `.pem` / `.crt` / `.cer` / `.der` を再帰的に読み込み |
| JSON 出力 | — | 対応 | 一覧・詳細・検証結果を JSON で出力 |
| 期限警告の変更 | 対応 | `--warn-days` | 期限間近と判定する日数を変更 |
| 証明書の PEM 表示 | 対応 | — | 詳細画面で PEM を表示 |
| ファイルインポート | 対応 | 対応 | GUI の Import、または CLI でファイル・フォルダを指定 |
| CRL / OCSP 失効確認 | 対応 | `--revocation` | CRL / OCSP の取得と署名検証、失効状態の判定 |
| デスクトップ通知 | 起動時 | `notify` | 期限切れ・期限間近・問題ありを OS 通知で知らせる |
| 設定ファイル | 対応 | `config` | 通知・失効確認モード・警告日数を TOML で管理 |
| 内蔵ターミナル | 対応 | — | Terminal タブからローカルシェルを起動 |

## 検証ステータス

| ステータス | 意味 | 正常扱い |
|---|---|---|
| `Valid` | 有効期限内で、チェーン検証に成功 | はい |
| `ExpiringSoon` | 警告日数以内に期限切れ（デフォルト 30 日） | はい |
| `Expired` | 有効期限が切れている | いいえ |
| `NotYetValid` | 有効期間開始前 | いいえ |
| `UntrustedRoot` | 信頼チェーンを構築できない | いいえ |
| `SelfSigned` | 自己署名かつ信頼ストアに未登録 | いいえ |
| `WeakSignature` | MD5 / SHA-1 など弱い署名アルゴリズム | いいえ |
| `Revoked` | CRL / OCSP により失効が確認された | いいえ |
| `RevocationUnknown` | 失効確認を実行したが、判定できなかった | いいえ |
| `Error` | その他の検証エラー | いいえ |

## 使い方

### GUI

```sh
cargo run -p app
```

起動すると OS の信頼ストアを読み込み、ダッシュボードを表示します。`Import` から証明書ファイルやフォルダを追加でき、行を選択すると詳細画面へ移動します。`Settings` では期限警告日数、通知、失効確認モードを変更して設定ファイルに保存できます。詳細画面の `Check revocation` で CRL / OCSP を確認でき、`Terminal` タブではローカルシェルを起動できます。

### CLI

```sh
# OS 信頼ストアの証明書一覧
cargo run -p cert_cli -- list-os
cargo run -p cert_cli -- list-os --json

# 証明書ファイルの詳細表示
cargo run -p cert_cli -- inspect certificate.pem
cargo run -p cert_cli -- inspect certificate.der --json

# 設定ファイルを初期化
cargo run -p cert_cli -- config --init

# 証明書チェーンの検証
cargo run -p cert_cli -- verify leaf.pem \
  --chain intermediate.pem \
  --trust root.pem

# OS 信頼ストアをルートとして検証
cargo run -p cert_cli -- verify leaf.pem --chain intermediate.pem

# CRL / OCSP による失効確認
cargo run -p cert_cli -- verify leaf.pem \
  --chain intermediate.pem \
  --trust root.pem \
  --revocation both

# 期限切れ・期限間近をデスクトップ通知
cargo run -p cert_cli -- notify

# ディレクトリ内の証明書を再帰スキャン
cargo run -p cert_cli -- scan /path/to/certs
cargo run -p cert_cli -- scan /path/to/certs --json
```

ビルド済みバイナリは `target/debug/cert-cli` に生成されます。

### `verify` の終了コード

| コード | 意味 |
|---|---|
| `0` | 検証成功（Valid / ExpiringSoon） |
| `1` | 検証失敗（期限切れ・未信頼など） |
| `2` | 実行エラー（ファイル読込失敗など） |

## 動作環境

- Rust 1.85 以上（現在の検証環境: Rust 1.88 / macOS x86_64）
- macOS で GPUI をビルドする場合は Xcode（Metal コンパイラ）が必要
- Linux は未検証（GPUI の X11 / Wayland 対応に依存）

macOS で `xcode-select` が Command Line Tools を指している場合は、ビルド時に `DEVELOPER_DIR` を指定してください。

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
```

## ビルド

```sh
git clone https://github.com/watanabe3tipapa/ca-checker.git
cd ca-checker
cargo build --workspace
```

GUI アプリのみ:

```sh
cargo build -p app
```

初回の GPUI ビルドは依存クレートが多く、数分から十数分かかります。

## リポジトリ構成

```text
.
├── README.md                    # このファイル（日本語）
├── LICENSE                      # MIT ライセンス
├── VERSION                      # リポジトリのバージョン（v0.1.1）
├── Cargo.toml                   # Cargo workspace
├── Cargo.lock                   # 再現可能なビルド用
├── crates/
│   ├── cert_core/               # ドメインモデル、パース、検証エンジン
│   │   ├── src/models.rs
│   │   ├── src/parser.rs
│   │   ├── src/revocation.rs
│   │   └── src/validator.rs
│   ├── cert_infra/              # 設定 / ファイル / OS 信頼ストア / 通知 / 失効確認
│   │   ├── src/config.rs
│   │   ├── src/file_loader.rs
│   │   ├── src/notify.rs
│   │   ├── src/os_store.rs
│   │   └── src/revocation.rs
│   ├── cert_cli/                # CLI バイナリ (cert-cli)
│   │   ├── src/main.rs
│   │   └── tests/cli.rs
│   └── app/                     # GPUI アプリケーション (ca-checker)
│       ├── src/main.rs
│       ├── src/state.rs
│       └── src/views.rs
├── docs/
│   └── index.html               # GitHub Pages ランディングページ
└── .github/
    └── workflows/
        └── pages.yml            # Pages デプロイ
```

## 開発

```sh
# フォーマット
cargo fmt --all

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# テスト
cargo test --workspace
```

テストでは `rcgen` を用いてルート CA・中間 CA・リーフ証明書を動的に生成し、正常系・期限切れ・未信頼ルート・自己署名・弱署名を検証しています。

## ランディングページ / GitHub Pages

`docs/index.html` は本プロジェクトのランディングページです。GitHub Actions（`.github/workflows/pages.yml`）で GitHub Pages に自動デプロイします。

初回のみ、リポジトリの **Settings → Pages → Build and deployment → Source** を **GitHub Actions** に設定してください。以降は `main` ブランチへの push で自動的に公開されます（手動実行は Actions タブの `workflow_dispatch`）。

- 公開 URL: [https://watanabe3tipapa.github.io/ca-checker/](https://watanabe3tipapa.github.io/ca-checker/)
- デプロイ対象: `docs/`

## 現在の制限

- ネットワーク経由の証明書取得（TLS ハンドシェイク）は未実装
- GUI のファイル選択は対応済みだが、ウィンドウへのドラッグ＆ドロップは未対応
- OCSP の nonce 検証は未対応
- Windows は未対応
- wterm は Web 専用のため、GUI 内では GPUI ネイティブの PTY ターミナルを使用
- GPUI は pre-1.0 のため、アップグレード時に API 変更が発生する可能性あり

## 使用クレート

- [gpui](https://crates.io/crates/gpui) — GUI
- [gpui-terminal](https://crates.io/crates/gpui-terminal) — 内蔵ターミナル
- [portable-pty](https://crates.io/crates/portable-pty) — PTY
- [x509-parser](https://crates.io/crates/x509-parser) — X.509 / CRL パース
- [x509-ocsp](https://crates.io/crates/x509-ocsp) — OCSP リクエスト / レスポンス
- [rustls-webpki](https://crates.io/crates/rustls-webpki) — チェーン検証
- [rustls-native-certs](https://crates.io/crates/rustls-native-certs) — OS 信頼ストア
- [ureq](https://crates.io/crates/ureq) — CRL / OCSP の HTTP 取得
- [notify-rust](https://crates.io/crates/notify-rust) — デスクトップ通知
- [clap](https://crates.io/crates/clap) — CLI
- [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) — JSON 出力
- [chrono](https://crates.io/crates/chrono) — 日時処理
- [rcgen](https://crates.io/crates/rcgen) — テスト用証明書生成

## コントリビューション

コントリビューションは歓迎します。不具合報告や改善案は、GitHub の Issue または Pull Request で共有してください。検証ロジック、UI、ドキュメントのいずれも対象です。

基本的なワークフロー:

1. リポジトリをフォーク
2. 機能ブランチを作成 (`git checkout -b feature/your-change`)
3. 変更をコミット (`git commit -m 'Add your change'`)
4. ブランチをプッシュし、Pull Request を作成

## 連絡先 / 公開サイト

- GitHub: [https://github.com/watanabe3tipapa/ca-checker](https://github.com/watanabe3tipapa/ca-checker)
- ランディングページ: [https://watanabe3tipapa.github.io/ca-checker/](https://watanabe3tipapa.github.io/ca-checker/)
- 関連プロジェクト: [skills-seedling](https://github.com/watanabe3tipapa/skills-seedling) — AI コーディング支援のための SKILLS.md コレクション

## ライセンス

MIT ライセンス — 詳細は [LICENSE](LICENSE) を参照してください。
