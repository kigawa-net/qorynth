# アーキテクチャ — Qorynth

## 1. コンポーネント詳細

### 1.1 `qorynth-node`（鍵管理ノード）

分散鍵管理と暗号処理の中核。3台構成でRaftにより状態を同期する。

**責務:**
- 閾値暗号による鍵Shareの分散保持
- 2-of-3クォーラムでの鍵処理（復号等）
- Raftによるクラスタ状態の整合性
- 鍵Shareのローテーション

**内部状態:**

```
状態遷移:
  LOCKED → ACTIVE → LOCKED
     ↑              ↓
     └───────┘
```

| 状態 | 説明 |
|---|---|
| LOCKED | 鍵利用不可。有効化承認待機 |
| ACTIVE | 鍵利用可能。2-of-3クォーラムで処理 |
| INVALIDATED | ノード失効。鍵Share更新後 |

### 1.2 `qorynth-seal`（Seal Gateway）

OpenBaoとのAuto-Unseal連携を担当。2台構成でフェイルオーバー。

**責務:**
- OpenBao Auto-Unsealプロトコルの実装
- ノード間認証（mTLS）
- フェイルオーバー制御

**設計判断が必要:**
- PKCS#11互換レイヤー（柔軟性あり、ただしレイテンシ制約）
- 専用KMSプラグイン（自由度高い、実装量多い）
- HTTP/gRPCラッパー（単純、ただしOpenBaoフローとの統合課題）

### 1.3 `qorynth-signal`（Signaling）

P2P接続確立のための制御経路。3台構成で冗長化。

**責務:**
- Peer Discovery（ピア発見）
- NAT Traversal（接続補助）
- 接続シグナリング

**設計判断が必要:**
- WebRTC DataChannel利用か
- 独自のQUICベースプロトコルか
- STUN/TURNの活用範囲

### 1.4 `qorynth-approval`（承認サービス）

論理サービス。5台以上の登録端末から3台以上の承認でHSM有効化。

**責務:**
- 端末登録・認証（WebAuthn / Passkey）
- 承認投票の収集・検証
- クォーラム判定

**データ経路の分離:**
Signalingと承認端末は鍵処理のデータ経路ではなく、接続確立・有効化の制御経路に属する。実際の鍵処理（復号等）は`qorynth-node`間で行われ、承認端末は関与しない。

### 1.5 `qorynth` CLI

管理・監視・復旧用のコマンドラインツール。

**想定コマンド:**
```
qorynth cluster status
qorynth node list
qorynth node revoke <id>
qorynth approval vote
qorynth backup create
qorynth backup restore
```

## 2. データフロー

### 2.1 通常鍵処理フロー（Auto-Unseal）

```
OpenBao → qorynth-seal → [P2P] → qorynth-node A
                              → qorynth-node B
                         (2-of-3クォーラムで復号)
                              → qorynth-seal → OpenBao
```

### 2.2 有効化承認フロー

```
登録端末1 → Signal → qorynth-approval
登録端末2 → Signal → qorynth-approval
登録端末3 → Signal → qorynth-approval
                          ↓
                    3-of-5クォーラム成立
                          ↓
                    クラスター ACTIVE
```

**承認経路は Signaling 経由である (p2p-transport.md と整合)**。承認端末は Signal の承認端末向け口（HTTPS/WSS）へ承認を送り、Signal は転送のみを行う（成否判定はせず、承認証明書はノードが検証する）。

**未解決事項 (p2p-transport.md と整合):** 「Signaling 全停止 + クラスタ全台再起動」の場合、承認の経路が失われ、承認が Signaling 経由のままでは**有効化不能**になる。対処案は、承認をノード直結の口でも受けられるようにすること（フェーズ3で確定。p2p-transport.md §3.6・§6.4・§8 参照）。

### 2.3 ノード再参加フロー（未確定）

```
再起動ノード → P2P → クラスタに発見
    ↓
既存ノードと状態同期（Raft）
    ↓
LOCKED状態になるか？ → ACTIVE維持か？
```

## 3. 通信プロトコル

| 経路 | プロトコル | 暗号化 | 認証 |
|---|---|---|---|
| qorynth-node ↔ qorynth-node | QUIC | TLS 1.3 | mTLS + TPM |
| qorynth-node ↔ qorynth-seal | QUIC | TLS 1.3 | mTLS |
| qorynth-seal ↔ OpenBao | HTTP/2 | TLS 1.3 | — |
| 承認端末 ↔ Signal | HTTPS/WSS | TLS 1.3 | WebAuthn/Passkey |
| Signal ↔ Signal | QUIC（ALPN `qorynth-signal-sync/1`、署名つきレコードの同期）(p2p-transport.md と整合) | TLS 1.3 | mTLS |

**Signal 構成 (p2p-transport.md と整合):**

- 3台の対等レプリカ構成。リーダーなしで **Raft は採用しない**（起動時の循環依存の回避と、1台でも動作可能な可用性のため）。クライアントは全 Signal に接続して登録し、Signal 間は署名つき LWW（`seq` 比較）で収束させる。
- 1台停止しても、残りの Signal で接続確立（登録・仲介）を継続できる。
- 接続先共有情報は永続化し、再起動後も継続する。ノードは last-known-good アドレス・Raft 既知 Peer アドレス・自身の `seq` をローカルに永続化し、Signal は Peer レコードを任意のローカル永続キャッシュ（ウォームスタート用）として保持する。

## 4. 既知の設計課題

| 課題 | 影響範囲 | 優先度 |
|---|---|---|
| 閾値暗号プロトコルの選定 | 全体 | 高 |
| OpenBao Auto-Unseal連携方式 | seal/gateway | 高 |
| ノード再起動時の状態遷移 | node | 中 |
| 盗難ノードの検知・失効 | 全体 | 中 |
| 鍵Shareのバックアップ/復旧 | 全体 | 中 |
| NAT Traversal戦略 | signal | 低 |

## 5. 技術スタック候補

言語は現在未決定。主な候補:

- **Go** — Cloudflareエコシステム、P2Pライブラリ豊富、デプロイ容易
- **Rust** — パフォーマンス、安全性、暗号処理に適す
- **Kotlin/JVM** — 既存エコシステム（Keruta等）との統合

暗号ライブラリも候補の評価が必要。
