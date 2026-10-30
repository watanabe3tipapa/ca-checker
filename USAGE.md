# ca-checker の使い方

[README](README.md) に戻る

このドキュメントでは、GUI と CLI の使い方、`verify` の処理フロー、ネットワーク検証の仕組み、統計パネルの見方、JSON 出力の仕様を説明します。

## GUI

```sh
cargo run -p app
```

起動すると OS の信頼ストアを読み込み、ダッシュボードを表示します。

- **Dashboard**: 状態サマリー、統計パネル、ステータスフィルタ、証明書一覧を表示します。
- **Detail**: 一覧の行を選択すると移動します。Subject / Issuer / Serial / SAN / 有効期間 / 署名・鍵アルゴリズム / SHA-256 / PEM を確認できます。
- **Settings**: 期限警告日数を 7 / 30 / 90 / 180 日から選択できます。
- **Reload**: OS の信頼ストアを再読み込みします。

### 統計パネル

ダッシュボードでは、証明書の状態を数値と比率の両方で把握できるようにしています。

| パネル | 表示内容 | 操作 |
|---|---|---|
| 状態分布 | Valid / Expiring / Expired / その他の問題の比率を積み上げバーで表示 | セグメントまたは凡例をクリックしてフィルタ |
| 期限タイムライン | 今後 12 か月の月別期限切れ件数。警告日数以内の月はアンバー色 | 12 か月より先の件数をフッターに表示 |
| 発行者分布 | 件数の多い上位 5 発行者と `Other` | 発行者の集中度を確認 |

色はステータスバッジと共通です（緑 = Valid、黄 = 期限間近、赤 = 期限切れ、ピンク = その他の問題）。チャートは GPUI のネイティブ要素で描画するため、WebView や JS ランタイムは不要です。

ランディングページ（`docs/index.html`）には、同じ考え方を Mermaid で図解しています。状態分布・期限タイムラインのサンプルに加え、検証フローとコンポーネント構成を掲載しています。図の構成は [oh-my-mermaid](https://github.com/oh-my-mermaid/oh-my-mermaid) の「関心ごとに Mermaid で説明する」アプローチを参考にしています。

## CLI

```sh
# OS 信頼ストアの証明書一覧
cargo run -p cert_cli -- list-os
cargo run -p cert_cli -- list-os --json

# 証明書ファイルの詳細表示
cargo run -p cert_cli -- inspect certificate.pem
cargo run -p cert_cli -- inspect certificate.der --json

# 証明書チェーンの検証
cargo run -p cert_cli -- verify leaf.pem \
  --chain intermediate.pem \
  --trust root.pem

# OS 信頼ストアをルートとして検証
cargo run -p cert_cli -- verify leaf.pem --chain intermediate.pem

# リモートサーバーの証明書チェーンを検証（OS 信頼ストアをルートに使用）
cargo run -p cert_cli -- verify --host example.com

# リモートサーバーの証明書チェーンを明示したルートで検証
cargo run -p cert_cli -- verify --host example.com --trust root.pem

# ディレクトリ内の証明書を再帰スキャン
cargo run -p cert_cli -- scan /path/to/certs
cargo run -p cert_cli -- scan /path/to/certs --json

# リモートサーバーが提示する証明書チェーンを取得（検証は行わない）
cargo run -p cert_cli -- fetch example.com
cargo run -p cert_cli -- fetch example.com --port 443 --json
```

ビルド済みバイナリは `target/debug/cert-cli` に生成されます。

### コマンドの処理内容

| コマンド | 入力 | 内部処理 | 主な出力 |
|---|---|---|---|
| `list-os` | OS 信頼ストア | `rustls-native-certs` でネイティブストアを読み込み、各 DER を `x509-parser` でパース | 証明書一覧、パースエラー（stderr） |
| `inspect` | ファイル | PEM ブロックまたは DER を判定してパース | Subject / Issuer / 有効期間 / 署名・鍵アルゴリズム / CA フラグ / SAN / SHA-256 |
| `verify` | ファイルまたは `--host` | リーフと中間 CA を収集し、`rustls-webpki` で信頼アンカーまで検証 | ステータス、信頼アンカー、エラー、警告 |
| `scan` | ディレクトリ | `.pem` / `.crt` / `.cer` / `.der` を再帰的に列挙してパース | 証明書一覧、ファイル単位のエラー |
| `fetch` | `--host` / `--port` | TLS ハンドシェイクでサーバー提示のチェーンを取得 | 証明書一覧（取得のみで検証なし） |

## `verify` の技術解説

### 処理フロー

`verify` は「対象の決定 → 中間 CA の収集 → 信頼アンカーの決定 → 検証」の順に進みます。

1. **対象の決定**
   - ファイル指定: ファイル内の**最初の証明書**をリーフ、残りを中間 CA として扱います。
   - `--host` 指定: TLS ハンドシェイクで取得したチェーンの**先頭**をリーフ、残りを中間 CA として扱います。`--chain` を併用すると、サーバーが送らなかった中間 CA を補完できます。
2. **信頼アンカーの決定**
   - `--trust` 指定時: 指定ファイルに含まれる証明書だけをアンカーにします。
   - 未指定時: OS 信頼ストア全体をアンカーにします。
3. **検証（`cert_core::validate`）**
   - **有効期間**: `notBefore` より前なら `NotYetValid`、`notAfter` を過ぎていれば `Expired`。
   - **署名アルゴリズム**: MD5 / SHA-1 系の OID を `WeakSignature` として検出。
   - **信頼アンカーとの完全一致**: 対象 DER がアンカーと一致する場合はチェーン検証を省略。
   - **自己署名**: 対象が自己発行かつ信頼ストアにない場合は `SelfSigned`。
   - **チェーン検証**: `rustls-webpki` の `verify_for_usage` を現在時刻で実行。EKU が `serverAuth` で失敗した場合は `clientAuth` で再試行します。
   - **期限間近**: `Valid` でも残日数が `--warn-days`（既定 30 日）以内なら `ExpiringSoon`。

### 検証の優先順位

ステータスは上から順に評価され、最初に該当したものが採用されます。

1. `NotYetValid` — 有効期間開始前
2. `Expired` — 有効期限切れ
3. `WeakSignature` — MD5 / SHA-1 などの弱い署名
4. `Valid` / `ExpiringSoon` — 信頼アンカーと完全一致、またはチェーン検証に成功
5. `SelfSigned` — 自己発行かつ未信頼
6. `UntrustedRoot` — 信頼チェーンを構築できない
7. `Error` — その他の検証エラー

チェーン検証後も、CA 証明書のパス長制約がない場合や、リーフに SAN がない場合は警告として記録します。

### ネットワーク検証の仕組み

`fetch` と `verify --host` は [rustls](https://crates.io/crates/rustls) で TLS 1.2 / 1.3 のハンドシェイクを行い、サーバーが送信した証明書チェーンを取得します。

- 接続・読み書きのタイムアウトはそれぞれ 10 秒です。
- SNI には `--host` の値をそのまま使用します（IP リテラルの場合は SNI を送信しません）。
- **取得時点では証明書を検証しません。** 自己署名・期限切れ・未信頼の証明書でも取得できます。信頼判定は `verify` のチェーン検証で行います。
- サーバーが中間 CA を送らない場合は `--chain intermediate.pem` で補完できます。
- クライアント証明書、ALPN、CRL / OCSP による失効確認には未対応です。

```sh
# サーバーが提示したチェーンをそのまま表示（検証なし）
cargo run -p cert_cli -- fetch example.com --json

# 取得と検証を一度に実行
cargo run -p cert_cli -- verify --host example.com --json
```

### 終了コード

| コード | 意味 |
|---|---|
| `0` | 検証成功（Valid / ExpiringSoon） |
| `1` | 検証失敗（期限切れ・未信頼など） |
| `2` | 実行エラー（ファイル読込失敗・ネットワークエラーなど） |

### JSON 出力

`--json` を付けると、stdout に整形済みの JSON を出力します。

| コマンド | JSON の形 |
|---|---|
| `list-os` / `inspect` / `scan` / `fetch` | `Certificate` の配列。`source` で取得元（OS / ファイル / ネットワーク）を識別 |
| `verify` | `ChainValidationResult`（`target` / `intermediates` / `trust_anchor` / `status` / `checked_at` / `errors` / `warnings`） |

JSON 出力にはパース警告を含めません。警告を確認したい場合は `--json` を外して実行してください。エラー時は JSON ではなく stderr にメッセージを出し、終了コード `2` を返します。

## 関連リンク

- [README](README.md)
- [GitHub リポジトリ](https://github.com/watanabe3tipapa/ca-checker)
- [ランディングページ](https://watanabe3tipapa.github.io/ca-checker/)
