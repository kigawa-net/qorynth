# 技術スタック選定（実装言語）— Qorynth

> **状態:** 設計案（言語選定）
> **対象:** `qorynth-node` / `qorynth-seal` / `qorynth-signal` / `qorynth-approval` / `qorynth` CLI の実装言語とライブラリ
> **関連:** [設計概要](design-overview.md) / [アーキテクチャ](architecture.md)（§5 技術スタック候補） / [閾値暗号プロトコル選定](threshold-crypto.md) / [P2P通信層](p2p-transport.md) / [OpenBao連携](openbao-integration.md) / [Seal認証](seal-authentication.md) / [開発計画](development-plan.md)

本書は、architecture.md §5 と development-plan.md で「フェーズ1前に決定」とされている **実装言語** を選定する。実装コードは含まない。認証情報・秘密値も含まない。

> **裏取りの状況（重要）**
> 執筆環境では Web 検索を利用できなかった（権限未付与）。ライブラリの最新版・メンテナンス状況・機能サポートは執筆時点の知識に基づくため、**バージョン番号・サポート有無の断定には【要確認】を付けた**。フェーズ1冒頭のスパイク（§7）で一括して確認する。「チームの既存知見」も、リポジトリ上のワークスペース（Kotlin 製プロジェクトが多い）からの推測であり【要確認】。

---

## 0. 要約

| 項目 | 結論 |
|---|---|
| 推奨言語 | **Rust**（全コンポーネント単一言語、Cargo workspace） |
| 次点 | Go（運用・OpenBao 親和性・学習コストで優位。鍵素材のメモリ管理と閾値暗号ライブラリで劣後） |
| 不採用 | Kotlin/JVM（QUIC・TPM・鍵素材のメモリ消去・起動時の依存で要件との相性が最も悪い） |
| 決め手 | ①鍵Share・部分復号値を確実にゼロ化できる（GC なし） ②QUIC 実装（quinn）+ rustls で「クラスタ CA + Raft メンバーシップ照合」「TPM 非エクスポート鍵での署名」を低レベルで差し込める ③閾値暗号・HPKE・P-256 の実装資産（RustCrypto / ZF FROST） ④単一静的バイナリで K8s・VM どちらにも配布しやすい |
| 最大のリスク | 学習コストとチーム知見（【要確認】）。対処は §6 |

---

## 1. 目的・スコープ

- 対象は Qorynth 全コンポーネントの**実装言語**と、QUIC・暗号・TPM・OpenBao 連携・K8s・テストの**主要ライブラリ**の選定。
- 対象外: プロトコル設計そのもの（他の設計書で確定済み）、UI（承認端末のフロントエンド。WebAuthn クライアント側はブラウザ API であり、言語選定の対象外）。
- 決定時期は development-plan.md の「フェーズ1前」。以降のフェーズ（P2P → 認証 → 承認 → 状態管理 → 閾値暗号 → OpenBao 連携 → 復旧）の実装前提となる。

---

## 2. 選定要件（既存設計書からの抽出）

| # | 要件 | 出典 | 言語選定への含意 |
|---|---|---|---|
| T1 | データ経路は **QUIC（RFC 9000/9001）+ TLS 1.3 mTLS**。**0-RTT 不使用**。ALPN で用途分離 | p2p-transport.md §0, §3 | QUIC 実装が成熟し、ALPN・0-RTT 無効化・ストリーム多重化を制御できること |
| T2 | 証明書検証は「クラスタ CA 検証 + **Raft メンバーシップ照合**」。接続先 `node_id` を指定して dial | p2p-transport.md §0 | TLS の証明書検証フック（カスタム verifier）を差し込めること |
| T3 | UDP **hole punching** は Signaling 仲介で自前実装。QUIC 外で調整 | p2p-transport.md §0, §3 | QUIC が使う UDP ソケットを自前で管理・共有できること |
| T4 | ノード鍵は **TPM 2.0 の非エクスポート鍵**。TLS ハンドシェイク署名に使う | architecture.md §3, seal-authentication.md | TLS の署名操作を TPM に委譲でき、TPM 2.0（TSS）にアクセスできること |
| T5 | **(2,3) Shamir + Feldman VSS + 閾値 HPKE 復号（P-256）**、GJKR New-DKG、Share Refresh、VSR による再シェアリング。将来 FROST（RFC 9591, P-256/Ed25519） | threshold-crypto.md §0 | P-256 の群演算・スカラー演算・HPKE（RFC 9180）が利用でき、低レベルのプリミティブ上に自前プロトコルを組めること。FROST 実装資産があるとよい |
| T6 | 鍵 Share・部分復号値・root key 平文の**確実なメモリ消去**（実行時侵害の影響限定） | threshold-crypto.md §1.1, §6 | GC によるコピー残存が起きない、または制御できること |
| T7 | **Raft**（メンバーシップ・クラスタ状態）。Signaling は Raft を使わず LWW 収束 | architecture.md §1.1, §3 | 組込み可能な Raft ライブラリがあること |
| T8 | **Transit Seal 互換 API ファサード**（OpenBao は無改造。HTTP/2 + TLS 1.3） | openbao-integration.md §0 | HTTP サーバ（TLS 1.3、HTTP/2）と OpenBao 本体を使った統合テストができること |
| T9 | **WebAuthn / Passkey** 端末登録・承認（HTTPS/WSS の Signal 承認口） | architecture.md §1.4, §3 | サーバ側 WebAuthn 検証ライブラリ、WebSocket サーバ |
| T10 | K8s / VM 双方でのデプロイ（TPM は物理/vTPM が前提）。小さな実行物、再現可能ビルド | design-overview.md, architecture.md | 静的リンク・小イメージ・TPM デバイス（`/dev/tpmrm0`）へのアクセスが容易 |
| T11 | 単体・プロパティ・E2E（3 ノード障害注入、OpenBao との統合）テスト | development-plan.md 各フェーズ検証 | テストコンテナ、ネットワーク分断のシミュレーション、決定論的テストがしやすいこと |
| T12 | 小規模チームでの保守性（【要確認】チーム構成） | CLAUDE.md の workspace 傾向 | 学習コスト、既存資産（Kotlin 多数）との距離 |

---

## 3. 比較対象: Go / Rust / Kotlin

### 3.1 Go

| 観点 | 評価 |
|---|---|
| QUIC / mTLS | **quic-go**（実績が最も厚い。`tls.Config` で `VerifyPeerCertificate` / `GetClientCertificate` を差し込め、ALPN も標準。0-RTT は既定で無効化可能。`Transport` に自前の `net.PacketConn` を渡せるため hole punching 用のソケット共有が可能）。HTTP/3 も同系統 |
| 暗号（閾値・VSS・HPKE） | 標準 `crypto/ecdh`・`crypto/elliptic`（P-256 は高速）。HPKE は Go 1.26 で標準 `crypto/hpke` が入ったとの認識だが**【要確認】**。それ以前は `cloudflare/circl`（HPKE、FROST 実装あり）。Shamir/Feldman は `hashicorp/vault/shamir`（Shamir のみ）等があるが、Feldman VSS・GJKR・VSR は**自前実装が前提** |
| メモリ消去 | **弱い**。GC によるスタック拡張・ヒープ移動でコピーが残り、確実なゼロ化が保証されない（`runtime/secret` 相当の取り組みは進行中だが**【要確認】**）。T6 で最大の弱点 |
| TPM | `google/go-tpm`（TPM 2.0 コマンド）+ `go-tpm-keyfiles` 等。`crypto.Signer` を実装すれば `tls.Certificate.PrivateKey` に直接差し込めるため **TLS 署名の TPM 委譲が自然**。純 Go で C 依存なし |
| OpenBao 連携 | OpenBao 自体が Go 製。Transit Seal のクライアント側の挙動を同一言語のソースで読める利点（API の仕様確認が容易）。ただし連携は HTTP API 経由なので言語統一の必須性はない。`net/http` の HTTP/2 + TLS 1.3 標準対応 |
| K8s 運用 | 静的バイナリ、distroless イメージ、`client-go`（必要なら）、運用ツールの親和性は最良。クロスコンパイルが容易 |
| テスト基盤 | 標準 `testing`、`testify`、`testcontainers-go`、`-race`。fuzz 標準搭載。QUIC の障害注入は `net.PacketConn` ラッパで容易 |
| Raft | `hashicorp/raft`（OpenBao/Vault と同系統。実績最大）、`etcd-io/raft` |
| WebAuthn | `go-webauthn/webauthn`（成熟） |
| エコシステム・採用実績 | KMS/PKI/secret 管理（Vault、OpenBao、etcd、Consul）で最大。K8s エコシステムと同一 |
| 学習コスト・チーム知見 | 低（言語仕様が小さい）。ただしワークスペースの既存資産は Kotlin 中心で、Go の知見は【要確認】 |

### 3.2 Rust

| 観点 | 評価 |
|---|---|
| QUIC / mTLS | **quinn**（+ **rustls**）。`rustls` の `ServerCertVerifier` / `ClientCertVerifier` / `SigningKey` トレイトを実装することで「クラスタ CA + Raft メンバーシップ照合」（T2）と「TPM 委譲署名」（T4）を型安全に差し込める。ALPN、0-RTT 無効（`enable_early_data` を使わない）を明示制御可能。`AsyncUdpSocket` を差し替えれば hole punching 用のソケット共有も可能【要確認：現行の API 名・安定度】。参考実装として iroh（quinn ベースの P2P。hole punching 実装あり）があるが、依存はせず設計参考にとどめる【要確認】。代替に **s2n-quic**（AWS）、**quiche**（Cloudflare） |
| 暗号（閾値・VSS・HPKE） | **RustCrypto**: `p256`（定数時間群・スカラー演算）、`elliptic-curve`、`sha2`、`hkdf`、`aead`。HPKE は `hpke`（rozbb、RFC 9180）が複数の KEM/KDF/AEAD をサポート【要確認：P-256 KEM・版】。FROST は **ZcashFoundation `frost-p256` / `frost-ed25519`**（RFC 9591 対応、監査実績あり）【要確認】。Shamir/Feldman VSS は `vsss-rs` が候補【要確認】。GJKR・VSR は**自前実装**（Go と同じ） |
| メモリ消去 | **強い**。GC なし。`zeroize` / `secrecy` / `subtle`（定数時間比較）で Share・部分復号値をスコープ終了時にゼロ化。`mlock`（`memsec`/`region` 等）や core dump 抑止も OS レベルで素直に扱える。T6 で最大の強み |
| TPM | **tss-esapi**（Parallaxsecond / rust-tpm。TSS2 ESAPI の安全ラッパ）。実体は C ライブラリ `libtss2` へのリンクが必要（動的/静的リンクの管理が増える）【要確認：版・静的ビルド可否】。純 Rust の TPM コマンドクレートは未成熟。`TPM2_Sign` を `rustls::sign::SigningKey` に包むラッパを自作する（約 100 行規模の薄い層）。代替に PKCS#11 経由の `cryptoki` + `tpm2-pkcs11` |
| OpenBao 連携 | HTTP サーバに **axum**（hyper + rustls、HTTP/2、TLS 1.3）。Transit 互換 API のサブセット（encrypt/decrypt）の JSON を `serde` で型定義。OpenBao 本体は統合テストで外部プロセス/コンテナとして起動 |
| K8s 運用 | `musl` 静的ビルド + distroless / scratch で小イメージ。ただし `libtss2` 依存のため `qorynth-node` は glibc 動的リンク + 最小ベースが現実的な可能性【要確認】。`kube`（kube-rs）は必要になった場合のみ。コンパイル時間は長い（CI キャッシュ要） |
| テスト基盤 | `cargo test` / `nextest`、プロパティテスト `proptest`、fuzz `cargo-fuzz`、決定論的シミュレーション `turmoil`（Tokio 上のネットワーク分断・遅延）、`testcontainers`（OpenBao コンテナ）、TPM は `swtpm`（ソフトウェア TPM）。Raft の決定論テストが書きやすい |
| Raft | **openraft**（非同期。API が進化中で版固定が必須）【要確認：安定版到達状況】。代替に `raft-rs`（TiKV。ステートマシン側の実装量が多い） |
| WebAuthn | **webauthn-rs**（Passkey 対応。実績あり）【要確認】 |
| エコシステム・採用実績 | 暗号基盤・セキュリティ製品で採用拡大（rustls、AWS、Cloudflare 等）。KMS/シークレット管理では Go 製が多数派 |
| 学習コスト・チーム知見 | **高い**（所有権、async/Tokio）。ワークスペース上に Rust 資産は見当たらず【要確認】。一方、Kotlin 経験者は型システム面で親和性があるとされる |

### 3.3 Kotlin/JVM

| 観点 | 評価 |
|---|---|
| QUIC / mTLS | JVM 標準に QUIC なし。Netty `netty-incubator-codec-quic`（quiche の JNI ラッパ。incubator 段階）、**Kwik**（純 Java QUIC、成熟度は低い）【要確認】。証明書検証は `X509TrustManager`/`SSLEngine` で可能だが、QUIC スタックとの統合が不十分。UDP ソケット共有 hole punching は実装難度が高い |
| 暗号（閾値・VSS・HPKE） | **BouncyCastle**（P-256、HPKE は 1.7x 系で対応【要確認】）。FROST・Feldman VSS は定評ある実装が乏しく、**ほぼ全て自前**。プロトコルを JCA/BC の上に組むのは可能だが、定数時間性の保証はライブラリ依存 |
| メモリ消去 | **弱い**。`ByteArray` は明示ゼロ化できるが、JIT/GC によるコピー、`BigInteger`・`String` の不変オブジェクトに秘密が残る。BouncyCastle の内部状態も制御しづらい。T6 に最も不利 |
| TPM | JVM ネイティブ TPM 2.0 クライアントは乏しい（`tpm2-java` 系は小規模でメンテ状況が不明【要確認】）。JNI/Panama（FFI）で `libtss2` を叩くか、PKCS#11 プロバイダ（SunPKCS11 + `tpm2-pkcs11`）経由。TLS 署名の委譲は `Signature`/Provider 実装が必要で、他言語より手間が大きい |
| OpenBao 連携 | Ktor / Netty で HTTP/2 + TLS 1.3 のファサードは容易。Transit 互換 JSON の実装も問題なし |
| K8s 運用 | JVM のため起動が遅く、メモリフットプリントが大きい（3 台構成の鍵管理ノードでは過剰）。GraalVM native-image で緩和可能だが、リフレクション・暗号プロバイダ周りの設定が増える。既存の Keruta（Kotlin）とのビルド・運用知見は再利用可能 |
| テスト基盤 | JUnit5、Kotest、Testcontainers、プロパティテスト。ツール群は充実。ただし QUIC・TPM の統合テスト基盤は貧弱 |
| Raft | `Atomix`（保守状況【要確認】）、`Apache Ratis`（Java、実績あり） |
| WebAuthn | `webauthn4j`（成熟） |
| エコシステム・採用実績 | 業務アプリ・Android に強い。分散 KMS・ブロックチェーン系（Corda 等）でも JVM の採用例はあるが、低レベル暗号・P2P では少数派 |
| 学習コスト・チーム知見 | **最も低い**（ワークスペースの Kotlin/Gradle 資産、特に `kigawa-net/` が Kotlin 中心）【要確認】。ただし要件 T1・T4・T6 との適合の悪さを学習コストの低さで補うのは難しい |

---

## 4. 比較表

◎ = 要件に自然に適合 / ○ = 適合（実装・調整要） / △ = 懸念あり / ✕ = 実質的に不適

| 観点（要件） | Go | Rust | Kotlin/JVM |
|---|---|---|---|
| QUIC 実装の成熟度（T1） | ◎ quic-go | ◎ quinn / s2n-quic / quiche | △ Netty QUIC（incubator）/ Kwik |
| 証明書検証フック（T2） | ◎ `VerifyPeerCertificate` | ◎ rustls verifier トレイト | ○ `X509TrustManager` |
| hole punching 用ソケット共有（T3） | ○ `Transport` に `PacketConn` | ○ `AsyncUdpSocket`【要確認】 | △ |
| TPM 非エクスポート鍵での TLS 署名（T4） | ◎ `crypto.Signer` + go-tpm（純 Go） | ○ tss-esapi + 自作 `SigningKey`（C 依存） | △ JNI/PKCS#11 |
| 閾値暗号・HPKE の既存資産（T5） | ○ circl（HPKE/FROST）。VSS/GJKR/VSR は自前 | ◎ RustCrypto / frost-p256 / vsss-rs。GJKR/VSR は自前 | △ BC のみ。ほぼ自前 |
| 鍵素材のメモリ消去（T6） | △ GC により保証不可 | ◎ zeroize / secrecy / mlock | ✕〜△ |
| Raft（T7） | ◎ hashicorp/raft | ○ openraft（API 変動）【要確認】 | ○ Ratis |
| OpenBao 連携・同言語の参照性（T8） | ◎ 同一言語 | ○ HTTP 経由のみ | ○ HTTP 経由のみ |
| WebAuthn（T9） | ◎ go-webauthn | ○ webauthn-rs | ◎ webauthn4j |
| K8s/VM デプロイ（T10） | ◎ 静的バイナリ・小イメージ | ○ 静的バイナリ（libtss2 依存に注意） | △ JVM / native-image |
| 単体・E2E テスト性（T11） | ○ testcontainers, fuzz, `-race` | ◎ proptest, turmoil, swtpm, nextest | ○ JUnit/Kotest。QUIC/TPM テストは弱 |
| 学習コスト・チーム知見（T12）【要確認】 | ○ 低〜中 | △ 高 | ◎ 既存知見が最大 |
| **総合** | **次点** | **推奨** | 不採用 |

---

## 5. 推奨する言語と決定根拠

**推奨: Rust**（全コンポーネントを単一の Cargo workspace で実装）。

### 5.1 決定根拠

1. **鍵素材のメモリ衛生（T6）が本システムの存在意義に直結する。** threshold-crypto.md は「1 ノードの実行時侵害でも `d` が漏れない」ことを強い要求としている。Share・部分復号値・root key 平文を確実にゼロ化できるのは Rust のみ。Go・JVM は GC 管理下のコピーを完全には消せず、設計上の防御（再構成しない分散復号）を実装レベルで弱める。
2. **TLS の差し込みポイントが要件と一致する（T2・T4）。** rustls の verifier / `SigningKey` トレイトにより、「証明書検証 = クラスタ CA + Raft メンバーシップ照合」と「署名 = TPM」を TLS スタックの内側に型安全に実装できる。メンバーシップ照合を通らない証明書でハンドシェイクが完了しない構造にでき、p2p-transport.md の R3（Signaling を信頼しない相互認証）と整合する。
3. **閾値暗号の実装資産（T5）。** P-256 の定数時間演算（RustCrypto）、FROST（ZF の RFC 9591 実装）、Feldman/Shamir の候補（vsss-rs）、HPKE がある。Go も circl で近いが、メモリ消去（1）で劣後する。Kotlin は資産が乏しい。ただし GJKR New-DKG と VSR は**どの言語でも自前実装**であり、監査対象となるコード量は言語によらない。
4. **単一静的バイナリ（T10）。** JVM のような実行環境依存がなく、攻撃面と起動時依存が小さい。TPM 用の `libtss2` のみ native 依存として管理する。
5. **テスト性（T11）。** `turmoil` による決定論的なネットワーク分断・遅延の再現、`proptest` による Share・クォーラム条件のプロパティテスト、`swtpm` による TPM 自動テストが、フェーズごとの検証項目（「不正ノードが参加できない」「1 台では復号できない」等）と噛み合う。

### 5.2 Go を選ばなかった理由（次点との差）

Go は運用性（K8s、静的バイナリ）、OpenBao と同一言語、TPM の `crypto.Signer` 連携、チームの学習コストの低さで優位であり、**最も現実的な代替案**である。それでも選ばない理由は T6（メモリ消去）が言語仕様上解決できない点にある。メモリ衛生を設計要件に掲げる KMS で、実装言語がその保証を提供できない状態は許容しない。OpenBao との連携は HTTP API で閉じており（openbao-integration.md §0）、同一言語であることの利点は仕様確認の容易さに限られる。

> **覆る条件:** フェーズ1冒頭のスパイク（§7）で、Rust 側に致命的な欠落（rustls での TPM 委譲署名が実現できない、quinn で hole punching 用ソケット制御ができない、tss-esapi が配布要件を満たさない等）が見つかった場合は、Go に切り替える。その場合、メモリ消去は「秘密を扱う小さなコンポーネントを分離し、`mlock` + 明示ゼロ化 + 秘密値を持つ期間の短縮」で緩和する。

### 5.3 Kotlin を選ばなかった理由

QUIC・TPM・メモリ消去の 3 要件（T1・T4・T6）が同時に弱く、学習コストの低さでは補えない。Keruta 等の既存 Kotlin 資産との統合は、承認端末や管理 UI のバックエンドなど**データ経路外**のコンポーネントを別途作る際に再検討すればよい。

---

## 6. 採用ライブラリ一覧（Rust）

バージョン方針は共通して以下とする。**`Cargo.lock` をコミット、`cargo-deny`（ライセンス・脆弱性）と `cargo-vet` または `cargo-audit` を CI に組込む。暗号・TLS・QUIC クレートはマイナー版まで固定（`~x.y`）し、更新は変更履歴確認後に手動で行う。** 具体的な版番号は【要確認】とし、フェーズ1冒頭で最新の安定版を調査して固定する。

| 領域 | ライブラリ | 用途 | バージョン方針 |
|---|---|---|---|
| 言語・ツールチェーン | Rust stable（MSRV を明示）、edition 2024 | 全体 | `rust-toolchain.toml` で固定。MSRV は最新 stable から 2 つ前まで【要確認】 |
| 非同期ランタイム | `tokio` | 全体 | 1.x（LTS 系列を優先）【要確認】 |
| QUIC | `quinn` | ノード間・Seal↔ノード・Signal 間のデータ経路（T1） | マイナー固定。破壊的変更が多いため更新は手動。代替 `s2n-quic` / `quiche` は §7 スパイクで比較 |
| TLS | `rustls`（暗号プロバイダ: `aws-lc-rs` または `ring`、FIPS が必要なら `aws-lc-rs` の FIPS 構成）、`rustls-pki-types`、`webpki` | mTLS、カスタム verifier、`SigningKey` | quinn が要求する版と揃える。プロバイダは §7 で決定【要確認】 |
| 証明書処理 | `rcgen`（CA・CSR 生成）、`x509-parser`、`x509-cert`（RustCrypto） | 自己署名クラスタ CA、ノード証明書 | マイナー固定 |
| 楕円曲線・ハッシュ | `p256`、`elliptic-curve`、`sha2`、`hkdf`、`aead` / `chacha20poly1305` / `aes-gcm`（RustCrypto） | P-256 群・スカラー演算、KDF（threshold-crypto.md） | RustCrypto の安定リリースを固定。pre-release 版は使わない |
| HPKE | `hpke`（RFC 9180、DHKEM(P-256, HKDF-SHA256)） | 閾値 HPKE 復号、Transit blob | 【要確認】P-256 KEM のサポートと監査状況。不足時は `p256` 上で DHKEM を薄く自前実装（RFC 9180 のテストベクタで検証） |
| 閾値暗号 | `vsss-rs`（Shamir / Feldman）【要確認】、GJKR New-DKG・VSR・Share Refresh は**自前実装**（`qorynth-threshold` クレートに分離） | 2-of-3 Share、Feldman VSS、DKG | 自前部分は外部暗号監査の対象。`vsss-rs` を使わず自前とする判断もスパイクで行う |
| FROST（将来） | `frost-p256`、`frost-ed25519`（ZcashFoundation） | 将来の署名用別鍵（threshold-crypto.md §0） | 採用時に版を固定。【要確認】RFC 9591 準拠状況 |
| 秘密値の扱い | `zeroize`、`secrecy`、`subtle`、`memsec`（または `region`）、`libc`（`mlock`/`prctl(PR_SET_DUMPABLE)`） | ゼロ化、定数時間比較、メモリロック（T6） | マイナー固定 |
| TPM | `tss-esapi`（`libtss2` に依存）。`/dev/tpmrm0` を使用。代替: `cryptoki` + `tpm2-pkcs11` | 非エクスポート鍵、TLS 署名委譲（T4）、ノード ID | 【要確認】版、`libtss2` のバージョン固定と静的リンク可否。署名ラッパは自作の `qorynth-tpm` クレートに隔離 |
| Raft | `openraft` | メンバーシップ・クラスタ状態（T7） | マイナー固定。API 変動が大きい【要確認】。ストレージは自前（`redb` または `rocksdb`） |
| 永続化 | `redb`（純 Rust の組込み KV）または `rocksdb`、`serde` + `postcard`/`bincode`/`ciborium`（CBOR）、`ed25519-dalek` / `p256::ecdsa`（署名レコード） | last-known-good アドレス、`seq`、Signal ウォームキャッシュ、署名つき LWW レコード | 暗号化永続化が必要なものは TPM シール鍵で保護 |
| HTTP / OpenBao 連携 | `axum`（+ `hyper`、`tower`）、`serde` / `serde_json`、`reqwest`（`rustls-tls`、クライアント用） | Transit Seal 互換 API（`qorynth-seal`）、ヘルスチェック、OpenBao API クライアント | `axum` は 0.x のためマイナー固定【要確認】。OpenBao は 2.x 系を §7 スパイクで固定 |
| WebSocket / 承認口 | `axum` の WebSocket、`tokio-tungstenite` | Signal の承認端末向け口（HTTPS/WSS） | マイナー固定 |
| WebAuthn | `webauthn-rs` | 端末登録・承認（T9） | 【要確認】Passkey 対応版を固定 |
| CLI | `clap`（derive） | `qorynth` CLI | 4.x |
| ログ・監視 | `tracing`、`tracing-subscriber`、`opentelemetry` + `metrics-exporter-prometheus` | 構造化ログ、メトリクス、監査ログ | 秘密値を出さないフィールド制限をレビュー項目にする |
| エラー・設定 | `thiserror`、`anyhow`（バイナリ層のみ）、`figment` または `config` | 全体 | — |
| K8s / デプロイ | コンテナビルド: `cargo-chef` + multi-stage、ベースは distroless/cc 系（`libtss2` 同梱のため）。マニフェストは ArgoCD GitOps（既存方針）。K8s API 直接操作は原則不要、必要なら `kube` | デプロイ（T10） | `qorynth-signal`・`qorynth-seal` は静的 musl ビルドを目標、`qorynth-node` は `libtss2` 次第【要確認】 |
| 単体・プロパティテスト | `cargo test` + `cargo-nextest`、`proptest`、`rstest`、`insta`（スナップショット） | 閾値条件・状態遷移・RFC テストベクタ | — |
| ファジング | `cargo-fuzz`（libFuzzer）、`honggfuzz` | メッセージパーサ、HPKE blob、Transit API | CI で短時間、夜間で長時間 |
| ネットワーク障害注入 | `turmoil`、`tokio::time::pause`、`tc`/`toxiproxy`（E2E） | 分断・遅延・再起動シナリオ（T11） | — |
| E2E | `testcontainers`（OpenBao コンテナ）、`swtpm`（ソフトウェア TPM）、`kind`/`k3d`（3 ノード K8s） | フェーズ2〜6 の検証項目 | OpenBao 版固定。【要確認】`swtpm` を CI で動かすための権限 |
| 静的解析・サプライチェーン | `clippy`（`-D warnings`）、`rustfmt`、`cargo-deny`、`cargo-audit`、`cargo-vet`、`cargo-geiger`（unsafe 計測） | 品質・依存管理 | 暗号境界クレートは `#![forbid(unsafe_code)]`（TPM/FFI・mlock のみ例外クレートに隔離） |

### 6.1 クレート構成（案）

`qorynth-threshold`（DKG / VSS / HPKE 復号の純粋ロジック。ネットワーク・OS 依存なし）、`qorynth-tpm`（TPM と `SigningKey`）、`qorynth-transport`（quinn + rustls、verifier、hole punching）、`qorynth-node` / `qorynth-seal` / `qorynth-signal` / `qorynth-approval`（バイナリ）、`qorynth-cli`。秘密値を扱うコード境界と `unsafe` を数クレートに閉じ込め、監査範囲を限定する。

---

## 7. 技術的リスクと対処

| # | リスク | 影響 | 対処 |
|---|---|---|---|
| R1 | **学習コスト・チーム知見不足**（Rust 経験者の不在【要確認】） | 開発速度低下、レビュー品質低下 | フェーズ1を小さな実装（QUIC + mTLS のハンドシェイク）で始め、習熟期間を確保。`clippy` を厳格化。暗号境界以外は単純なスタイル（過度なジェネリクス・マクロ禁止）に統一。必要なら外部レビュー |
| R2 | **tss-esapi が C ライブラリ依存**（ビルド・配布・静的リンクが複雑） | `qorynth-node` の配布複雑化 | フェーズ1冒頭スパイクで `swtpm` 上の署名を検証。静的リンク不可なら distroless/cc ベースで動的リンク。最悪の代替: `cryptoki` + `tpm2-pkcs11`、さらに最悪は TPM 処理のみ別プロセス（Go/C）に分離して Unix ソケット経由で署名 |
| R3 | **rustls で TPM 署名が成立しない**（`SigningKey` が同期 API 前提で TPM の遅延を吸収できない等） | ハンドシェイク性能・設計 | スパイクで TPM 署名の遅延（数十〜数百 ms 想定【要確認】）を測定。長寿命接続・再接続頻度が低い前提（p2p-transport.md）なので許容見込み。ブロッキング呼び出しは専用スレッドプールへ。接続再確立の集中時はセッション再開（0-RTT は不使用のため通常再開のみ）を検討 |
| R4 | **quinn で hole punching 用ソケット制御が不十分**（API 変動・UDP ソケット共有） | フェーズ1の NAT 越え | スパイクで `AsyncUdpSocket` 差替えの実現性確認。不足なら `quiche`（Sans-IO）または `s2n-quic` に切替。iroh の実装を設計参考にする（依存はしない） |
| R5 | **openraft の API 変動・成熟度**【要確認】 | メンバーシップ層の保守コスト | マイナー固定、薄いラッパ（`qorynth-consensus`）で隔離。ステートマシンは小さく保つ（メンバーシップ・状態のみ）。成熟度が不足なら `raft-rs` へ、または Go の `hashicorp/raft` を別プロセスに切り出す案を比較 |
| R6 | **GJKR・VSR などの自前暗号プロトコル**（Rust でも既製がない） | 暗号的な脆弱性 | `qorynth-threshold` に隔離、RFC/論文のテストベクタ、`proptest`、独立した外部暗号レビュー。MVP では threshold-crypto.md §2.6 のフォールバック（OpenBao 標準 Shamir）で実運用検証に先行 |
| R7 | **メモリ消去の過信**（`zeroize` が効かないコピー：async の状態機械・`Vec` の再確保・スタックスピル） | Share のコピー残存 | 秘密値は固定長・`Box` 化・`Zeroizing` ラッパ、`async` を跨いで保持しない設計。`mlock`・core dump 抑止・スワップ無効化を運用要件化。コピー有無をテスト（デバッグビルドでメモリスキャン）で確認 |
| R8 | **依存クレートのサプライチェーン**（暗号・QUIC クレートの更新・乗っ取り） | 全体 | §6 の方針（ロックファイル・`cargo-vet`・`cargo-deny`・マイナー固定）。依存を最小化、ベンダリング（`cargo vendor`）の検討 |
| R9 | **OpenBao 側の仕様変更・Transit 互換の差異**【要確認】 | `qorynth-seal` | OpenBao 版を固定し E2E で回帰検出（openbao-integration.md §6 のスパイク）。言語選定とは独立 |
| R10 | **コンパイル時間・CI コスト** | 開発体験 | `cargo-chef`、`sccache`、ワークスペース分割、`mold`/`lld`。デバッグプロファイルで依存を最適化 |
| R11 | **Go への切替が必要になった場合の手戻り** | 工数 | フェーズ1を成功基準付きスパイク（§8-1）として先行。プロトコル仕様は言語非依存（ALPN・メッセージ定義を文書で確定）にしておき、切替時に再利用可能にする |

---

## 8. 未解決事項

1. **フェーズ1冒頭スパイク（言語決定の最終確認）。** 以下を検証し、成功を「言語決定の確定条件」とする。覆る場合は §5.2 の条件に従い Go に切替える。
   - quinn + rustls で、クラスタ CA + メンバーシップ照合の verifier を実装し、3 ノード mTLS が成立すること。0-RTT が無効であること。
   - `swtpm` 上で `tss-esapi` により非エクスポート鍵を作成し、`rustls::sign::SigningKey` 経由でハンドシェイク署名できること（遅延測定を含む）。
   - quinn で `AsyncUdpSocket` 差替え（または同等の機構）により hole punching 用ソケット共有ができること。
   - `hpke` クレートが DHKEM(P-256) を持つこと、`vsss-rs` が Feldman VSS を必要な形で提供すること（なければ自前方針）。
   - `openraft` が目標の障害シナリオ（1 台停止・再起動）で安定動作すること。
2. **チームの Rust 経験・体制の確認**【要確認】。経験者がいない場合の学習計画・外部レビュー体制。
3. **ライブラリの最新版・メンテナンス状況・FIPS 要否**。本書の【要確認】項目を Web で裏取りし、版を固定する（執筆時は Web 検索が使えなかった）。
4. **暗号プロバイダ（`aws-lc-rs` vs `ring`）の選択**、FIPS 要件の有無。
5. **TPM 実機の要件**: ノード配置先（物理 TPM / vTPM / クラウド）と `/dev/tpmrm0` へのアクセス（K8s での device plugin・権限）。
6. **承認端末向けフロントエンドとバックエンドの言語境界**。`qorynth-approval` の WebAuthn 検証は Rust（webauthn-rs）で Signal に組込む前提だが、Kotlin/TypeScript 側で扱う場合のインターフェース。
7. **Kotlin 資産（Keruta 等）との連携方法**。必要になった場合は HTTP/gRPC の API 境界に限定し、データ経路には入れない。
8. **Cloudflare エコシステムの利用範囲**。architecture.md §5 は Go の長所として挙げているが、鍵管理ノード本体で Cloudflare Workers を使う予定はない（データ経路・TPM 要件と相容れない）。承認端末向け静的配信等の周辺用途のみで検討。
9. **監査・外部レビュー**: 自前暗号（GJKR・VSR・HPKE 薄実装）の監査時期と、Rust 側のレビュー可能な審査員の確保。
