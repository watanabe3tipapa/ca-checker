# ca-checker

**信頼の鎖は、確かめてから使う。**

ca-checker は、OS の信頼ストアにある **X.509 証明書**を、有効期限・署名アルゴリズム・信頼チェーンから検証する GPUI 製デスクトップダッシュボード兼 CLI ツールです。ルート CA の状態を一覧し、期限切れや弱い署名、未信頼の証明書をひと目で見つけられます。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/watanabe3tipapa/ca-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/watanabe3tipapa/ca-checker/actions/workflows/ci.yml)
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
- TLS ハンドシェイクでリモートサーバーが提示する証明書チェーンを取得（`fetch`）
- `rustls-webpki` によるルート・中間・リーフのチェーン検証
- 有効期限、期限間近、弱い署名アルゴリズム（MD5 / SHA-1）の検出
- GPUI によるブルータリズム調のダッシュボード UI
- 状態分布・期限タイムライン・発行者分布の統計パネル（クリックでフィルタ）
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
| 統計の可視化 | 対応 | — | 状態分布・期限タイムライン・発行者分布を表示 |
| 証明書ファイルの詳細 | — | `inspect` | Subject / Issuer / SAN / アルゴリズム / SHA-256 を表示 |
| チェーン検証 | 対応 | `verify` | ルート・中間・リーフを検証。`--host` でリモート取得にも対応 |
| ディレクトリスキャン | — | `scan` | `.pem` / `.crt` / `.cer` / `.der` を再帰的に読み込み |
| ネットワーク証明書取得 | — | `fetch` | TLS ハンドシェイクで提示された証明書チェーンを取得 |
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
| `ExpiringSoon` | 警告日数以内に期限を迎える（既定 30 日） | はい |
| `Expired` | 有効期限が切れている | いいえ |
| `NotYetValid` | 有効期間開始前 | いいえ |
| `UntrustedRoot` | 信頼チェーンを構築できない | いいえ |
| `SelfSigned` | 自己署名かつ信頼ストアに未登録 | いいえ |
| `WeakSignature` | MD5 / SHA-1 など弱い署名アルゴリズム | いいえ |
| `Revoked` | CRL / OCSP により失効が確認された | いいえ |
| `RevocationUnknown` | 失効確認を実行したが、判定できなかった | いいえ |
| `Error` | その他の検証エラー | いいえ |

## 統計と可視化

ダッシュボードには **状態分布**（クリックでフィルタ）、**期限タイムライン**（今後 12 か月）、**発行者分布**（上位 5 件）を表示します。色はステータスバッジと共通で、GPUI のネイティブ要素だけで描画します。詳細と設計意図は [USAGE.md の統計パネル](USAGE.md#統計パネル) を参照してください。

ランディングページでは、同じ内容を Mermaid で図解しています。図の構成は [oh-my-mermaid](https://github.com/oh-my-mermaid/oh-my-mermaid) の「関心ごとに Mermaid で説明する」アプローチを参考にしています。

## 使い方

```sh
# GUI
cargo run -p app

# CLI: OS 信頼ストアの一覧
cargo run -p cert_cli -- list-os

# CLI: リモートサーバーのチェーンを検証
cargo run -p cert_cli -- verify --host example.com

# CLI: 失効確認とデスクトップ通知
cargo run -p cert_cli -- verify leaf.pem --chain intermediate.pem --revocation both
cargo run -p cert_cli -- notify
```

起動すると OS の信頼ストアを読み込み、ダッシュボードを表示します。`Import` から証明書ファイルやフォルダを追加でき、`Settings` では期限警告日数・通知・失効確認モードを変更できます。詳細画面の `Check revocation` で CRL / OCSP を確認でき、`Terminal` タブではローカルシェルを起動できます。

GUI の操作、全 CLI コマンド、`verify` の処理フロー、ネットワーク検証、失効確認、統計パネル、JSON 出力の仕様は **[USAGE.md](USAGE.md)** にまとめています。

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
├── USAGE.md                     # 使い方と技術的な解説
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
│   │   ├── src/network.rs
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

## 現在の制限

- `fetch` はサーバーが提示したチェーンを取得するのみで、その場では検証しない（`verify` で明示的に検証してください）
- GUI のファイル選択は対応済みだが、ウィンドウへのドラッグ＆ドロップは未対応
- OCSP の nonce 検証は未対応
- Windows は未対応
- wterm は Web 専用のため、GUI 内では GPUI ネイティブの PTY ターミナルを使用
- GPUI は pre-1.0 のため、アップグレード時に API 変更が発生する可能性あり

## 正直な見解

このツールは、証明書を「専門家に任せる前に、自分で一度確かめる」ための補助ツールです。GUI と CLI が同じ検証エンジンを使い、OS の信頼ストアをまとめて一覧できる点には実用上の価値があると考えています。一方で、次の点は率直に弱いと感じています。

| 向いていること | 向いていないこと |
|---|---|
| ローカル開発での TLS エラーの切り分け | 本番 PKI の監査・コンプライアンス対応 |
| 期限切れ・期限間近の証明書の早期発見 | 秘密鍵管理、証明書発行、HSM / スマートカード操作 |
| 証明書チェーンや CRL / OCSP の学習 | CT ログ照会や OCSP nonce 検証を含む完全な失効保証 |
| macOS 上での日常的な点検 | Windows / Linux での動作保証（Linux は未検証） |

- **検証はベストエフォートです。** 失効確認は CRL / OCSP エンドポイントの可用性に依存します。取得できない場合は「不明」として扱い、失効していないとは断定しません。
- **対応環境は限定的です。** 実際に検証しているのは macOS で、Linux は未検証、Windows は未対応です。GPUI も pre-1.0 のため、UI 周りは変更に弱い前提です。
- **個人開発の規模です。** 主要な検証経路のテストは用意していますが、大規模な信頼ストアや例外的な証明書に対する実績は十分ではありません。
- **最終判断は利用者に依存します。** セキュリティ上の判断や監査には、専用の PKI ツールや専門家の確認を併用してください。

それでも、信頼の鎖を自分で確認するための入口としては十分に役立つはずです。「万能な CA 監査ツール」ではなく、日々の点検を手早くする道具として使ってもらえると嬉しいです。

## 使用クレート

- [gpui](https://crates.io/crates/gpui) — GUI
- [gpui-terminal](https://crates.io/crates/gpui-terminal) — 内蔵ターミナル
- [portable-pty](https://crates.io/crates/portable-pty) — PTY
- [x509-parser](https://crates.io/crates/x509-parser) — X.509 / CRL パース
- [x509-ocsp](https://crates.io/crates/x509-ocsp) — OCSP リクエスト / レスポンス
- [rustls-webpki](https://crates.io/crates/rustls-webpki) — チェーン検証
- [rustls](https://crates.io/crates/rustls) — TLS ハンドシェイクによる証明書取得
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
