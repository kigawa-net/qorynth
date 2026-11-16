# OpenBao 連携方式 — Qorynth

> **状態:** 設計案（連携方式の選定）
> **対象:** `qorynth-seal`（2台）と OpenBao（3台）の Auto-Unseal 連携、およびその認証・切替・運用
> **関連:** [設計概要](design-overview.md) / [アーキテクチャ](architecture.md) / [開発計画](development-plan.md)（フェーズ6） / [閾値暗号プロトコル選定](threshold-crypto.md)

本書は、設計概要 §6・アーキテクチャ §1.2 で「未確定」とされている **OpenBao 連携方式**（PKCS#11 互換か専用 KMS プラグインか）を選定し、threshold-crypto §5.1 に残されている **オンライン経路（盗難機器をネットワークへ接続して Unwrap を要求する攻撃）の閉め方**を具体化する。実装コードは含まない。認証情報・秘密値も含まない（プレースホルダ表記のみ）。

> **仕様確認の状況（重要）**
> 本書の OpenBao 固有の挙動（Seal 種別、Transit Seal が発行する API、ヘルスチェック、Seal migration の順序、recovery key の扱いなど）は、執筆時点の知識に基づく。執筆環境では公式ドキュメントを再確認できなかったため、断定できないものには **【要確認】** を付け、§6 の「フェーズ6冒頭スパイク」でチェックリスト化した。OpenBao の版（2.x 系を想定）はスパイクで固定する。

---

## 0. 要約

| 項目 | 結論 |
|---|---|
| 最終形の連携方式 | **Transit Seal 互換 API ファサード**。`qorynth-seal` が、OpenBao の `seal "transit"` が呼ぶ HTTP API（encrypt / decrypt）のサブセットを実装する。OpenBao は**無改造・標準バイナリ**のまま |
| 不採用 | PKCS#11 プロバイダ（共有ライブラリを OpenBao プロセスへロード）、OpenBao のフォーク／パッチによる専用 Seal Wrapper、独自 HTTP/gRPC（OpenBao 側の改造が前提） |
| 保険 | Transit 互換で致命的な非互換が見つかった場合のみ、専用 Seal Wrapper（フォーク）へ。連携面を「Wrap / Unwrap の 2 操作」に閉じているため、切替は `qorynth-seal` の外側（OpenBao 側）の差し替えで済む |
| MVP | OpenBao 標準 Shamir（n=3, t=2）。`qorynth-seal` は**外部 unsealer** として動作（`/sys/unseal` へ Part を投入）。threshold-crypto §2.6 |
| MVP → 最終形 | **OpenBao の Seal migration**（`unseal -migrate`）。**root key は不変**で、ストレージ上の root key の包み方が変わるだけなので、データの再暗号化は不要（§3.4）。切替後は旧 Part（= recovery key 化）を Qorynth ノードから消去し、recovery key を rekey する |
| オンライン経路の閉め方 | 多層（§4.4）: ①クラスタ `ACTIVE` ゲート ②Bao ノードごとの mTLS ID + 許可リスト（Raft）③**root key 用 Unwrap のクラス分け**と、④**OpenBao の `sealed` 状態・接続元アドレスとの突合** ⑤全 root key Unwrap の通知・監査 ⑥**ロックは軽く・解錠は重く**の非対称キルスイッチ。**盗難機器を元ネットワークに置かれた場合は暗号的には閉じられず、検知＋失効で閉じる**ことを残余リスクとして明記 |
| 要注意（既存資料との差分） | threshold-crypto §4.4 の「Qorynth の `d` と全バックアップを失った場合は OpenBao の recovery key／再初期化に依存」は、**recovery key で root key を復元できる保証がない**ため、「OpenBao のデータは復号不能になり得る」前提で運用を設計する（§5.4） |

---

## 1. OpenBao Auto-Unseal の仕組みと Qorynth への当てはめ

### 1.1 鍵階層と用語

OpenBao（HashiCorp Vault 由来）は、保存データを次の階層で守る。

```
保存データ ──暗号化──► barrier encryption key（keyring。ローテーション可能）
barrier encryption key ──暗号化──► root key（旧称 master key）
root key の保護方式 ＝ Seal の種別で決まる
   ・Shamir Seal : root key を Shamir 分割し、鍵片（unseal key）を運用者が保管
   ・Auto-Unseal : root key を外部の鍵（KMS / HSM 等）でラップし、ラップ結果をストレージに保存
```

| OpenBao 用語 | 意味 | 本書での扱い |
|---|---|---|
| root key | keyring を復号する鍵。**これを保護するのが Seal** | Qorynth が Wrap / Unwrap する対象（不透明なバイト列） |
| unseal key（Part） | Shamir Seal での root key の鍵片 | MVP の対象（§3.1） |
| recovery key | Auto-Unseal 下での Shamir 鍵片。**Unseal には使えない**。root token 再生成・rekey・Seal migration など管理操作の認可に使う | §3.5・§5.4 |

> **用語の整理（threshold-crypto 冒頭の注意への回答）**
> 既存資料の「Unseal Key Part」は、最終形では **「root key のラップ済み blob」**、MVP では **「Shamir の unseal key 片」**を指す。Qorynth はどちらも中身を解釈しない。最終形で Qorynth が見る入力は「HPKE 暗号文（blob）」と、出力は「root key の平文」だけである。

### 1.2 Auto-Unseal の流れ

```
[初期化 / Seal migration 時]  (1 回)
  OpenBao: root key を生成 ──Seal.Encrypt(root key)──► blob ──► ストレージ（Raft）に保存
                                  ▲
                          Qorynth: Y 宛の HPKE 暗号化（クォーラム不要）

[各 Bao ノードの起動時]  (ノードごと、再起動のたび)
  OpenBao: ストレージから blob 取得 ──Seal.Decrypt(blob)──► root key ──► keyring 復号 ──► unsealed
                                  ▲
                          Qorynth: 2-of-3 閾値 HPKE 復号（クォーラム必要）

[実行中]
  Seal のヘルスチェック（暗号操作の試行）が行われる可能性がある 【要確認: 有無・間隔・失敗時の挙動】
```

- 各 Bao ノードは**個別に** Unseal する。Raft のフォロワーも、自分で Seal.Decrypt を呼ぶ。
- Unseal 済みのノードは、Seal が一時的に落ちても動き続ける（Unseal は起動時の操作）。ただしヘルスチェックの扱いは【要確認】。
- OpenBao 内部の Seal は「Wrap / Unwrap（＋鍵 ID）」という小さな抽象で、標準の Seal 種別（`awskms`, `gcpckms`, `azurekeyvault`, `pkcs11`, `transit` など）はこの抽象の実装である。

### 1.3 Qorynth への当てはめ

| OpenBao 側の概念 | Qorynth 側 | 備考 |
|---|---|---|
| Seal.Encrypt(root key) | `qorynth-seal` が公開鍵 `Y` で HPKE 暗号化 | **クォーラム不要の公開操作**。`qorynth-node` を呼ばない（threshold-crypto §3.1） |
| Seal.Decrypt(blob) | `qorynth-seal` が `qorynth-node` 2 台へ部分復号を要求し合成（threshold-crypto §4.2） | クォーラム必須。クラスタ `ACTIVE` が前提 |
| Seal の鍵 ID / 鍵名 | `key_id`（と `key_version`） | 暗号文ヘッダに `suite`・`key_id`・`key_version` を持たせる（threshold-crypto §3.2） |
| 鍵ローテーション／rewrap | Key Rotation（threshold-crypto §1.2）。OpenBao 側の rewrap 手段は【要確認】（§6） | |
| Seal の可用性 | `qorynth-seal` 2 台 + 前段の VIP／LB | §5.1 |
| Recovery key | Qorynth は関与しない（OpenBao が運用者へ配る） | §3.5 |

### 1.4 `qorynth-seal` が満たすべき要件（連携面）

1. **OpenBao を無改造で接続できる**こと（版追従のコストを OpenBao 側に持たせない）。
2. 入出力は不透明バイト列。root key の平文は `qorynth-seal` のメモリ上にのみ現れ、返却後ただちにゼロ化する。
3. Wrap（Encrypt）は `qorynth-node` 不要で、Qorynth が全停止していても成立する（初期化・migration・ヘルスチェック用）。
4. Unwrap は §4 の認証・認可・状態ゲートを通った場合のみ。
5. 呼び出し頻度は低い（起動時中心）。レイテンシ要件は緩く、**可用性（再起動時に必ず 2 台集まること）**が支配的（threshold-crypto §6.2）。

---

## 2. 連携方式候補の比較

### 2.1 候補

| 記号 | 方式 | 概要 |
|---|---|---|
| A | **PKCS#11 プロバイダ** | OpenBao の `seal "pkcs11"` に、Qorynth が実装した PKCS#11 モジュール（`.so`）を `lib` として指定する。モジュールが `qorynth-seal` へ中継 |
| B | **専用 Seal Wrapper（フォーク／パッチ）** | OpenBao 本体に Qorynth 用の Wrapper（Encrypt / Decrypt / KeyId）を組み込む。OpenBao に外部 Seal プラグイン機構があるかは【要確認】だが、無ければフォーク維持が必要 |
| C | **Transit 互換 API ファサード** | `qorynth-seal` が Transit Secrets Engine の `encrypt` / `decrypt`（＋最小の認証系 API）を実装し、OpenBao の `seal "transit"`（`address` を `qorynth-seal` へ向ける）から利用させる |
| D | **独自 HTTP/gRPC** | アーキテクチャ §1.2 の「HTTP/gRPC ラッパー」。OpenBao がそのプロトコルを話せないため B の一種（OpenBao 側の改造が必須） |
| E | **外部 unsealer（Shamir）** | Seal は標準の Shamir のまま。`qorynth-seal` が Part を集めて `/sys/unseal` へ投入する。MVP 用 |

### 2.2 評価

| 観点 | A: PKCS#11 | B/D: 専用 Wrapper | **C: Transit 互換** | E: 外部 unsealer |
|---|---|---|---|---|
| OpenBao 無改造 | ○（ただし CGO 有効ビルドが必要【要確認: 公式配布物に含まれるか】） | ✕（フォーク維持） | **◎（標準の Transit Seal 設定のみ）** | ◎ |
| 暗号方式との適合 | △ PKCS#11 Seal が使う機構は AES-GCM や RSA-OAEP 系。EC 閾値鍵（HPKE）を直接見せられず、AES-GCM 風の呼び出しに HPKE 暗号文を載せる偽装が必要【要確認】 | ◎ 自由 | ◎ 暗号文は不透明な文字列。中身は HPKE | △ 再合成型（threshold-crypto §2.6） |
| 信頼境界 | ✕ `.so` が **OpenBao プロセス内**で動く。バグ・メモリ破壊が Bao に直結。モジュール内に Qorynth への接続資格情報を置く | △ 同一プロセス内に Qorynth のクライアントコード | **◎ プロセス・ホスト分離。ネットワーク境界で mTLS を強制できる** | ○ |
| 実装量 | 大（PKCS#11 のセッション・オブジェクト・属性検索・ログイン状態の模倣。複数言語の FFI／cgo） | 中（Wrapper 自体は小さいが追従コスト） | **中〜小（HTTP のサブセット数本）** | 小 |
| 版追従・保守 | 中（OpenBao の PKCS#11 利用方法の変化に依存） | ✕ 高（上流へのマージ継続） | ○ 中（互換テストを CI 化して検知。§2.4） | 小 |
| 認証 | PIN／セッション。Bao 側ホストの `.so` 設定に資格情報が必要 | 自由 | **mTLS ＋ 許可リスト（§4.2）。Bao 側設定は証明書パスのみ** | OpenBao の API 認証は不要（unseal API は無認証）。ネットワーク制御のみ |
| 汎用 KMS への拡張 | ✕ 署名等は別途 | ✕ | **◎ Transit API には sign / verify / rewrap / datakey もあり、将来の署名・暗号化 API と同じ形で提供できる。Vault 系クライアント資産を流用可** | ✕ |
| テスト容易性 | 低 | 低 | **高（実 OpenBao コンテナ ↔ ファサードの E2E を CI で回せる）** | 高 |
| 鍵の rewrap | 手段が不明確 | 自由 | **Transit の `rewrap` に対応づけられる**（Key Rotation と整合） | OpenBao `rekey` |

### 2.3 選定

> **最終形: C（Transit 互換 API ファサード）。MVP: E（外部 unsealer）。B は C の致命的非互換時の保険。A・D は採用しない。**

理由:

1. **OpenBao を触らない**。標準の Transit Seal 設定（`address` / `key_name` / `mount_path` / TLS 設定）だけで接続でき、OpenBao のアップグレードに自前パッチを当て続ける必要がない。
2. **信頼境界が明瞭**。PKCS#11 は `.so` を OpenBao プロセスの中に入れるため、「Qorynth 側の鍵処理コードが Bao ホストで動く」形になり、盗難・侵害時の影響範囲が広がる。C は `qorynth-seal` が別ホストで、Bao ↔ seal の間は mTLS のネットワーク境界である。
3. **暗号設計と素直に合う**。Transit の暗号文は `vault:v<N>:<base64>` 形式の不透明文字列で、`<N>` を `key_version`、本体を Qorynth の暗号文エンベロープ（`suite` / `key_id` / HPKE の `enc` と暗号文）にそのまま対応づけられる。AES-GCM 偽装のような不自然さがない。
4. **将来の汎用基盤と連続的**。Transit API の語彙（encrypt / decrypt / rewrap / sign / verify）は Qorynth の最終目標（署名・暗号化・復号）と一致する。同じファサードに機能を足すだけでよい。
5. **MVP からの移行コストが低い**。MVP の E も最終形の C も `qorynth-seal` の機能モードとして同居でき、OpenBao 側の差は Seal 設定のみ（§3）。

デメリットと対処:

- 「Transit 互換」は wire レベルのサブセットでしかなく、**OpenBao が Transit Seal で呼ぶ API の集合・レスポンスの解釈は版で変わり得る**。対処: §2.4 のとおり対象 API を最小化し、実 OpenBao との互換テストを CI に常設し、版を固定して上げる。
- 名前が紛らわしい（Qorynth は OpenBao／Vault ではない）。ドキュメントと API の `Server` ヘッダで「Transit 互換サブセット」であることを明示する。

### 2.4 ファサードが実装する API（想定サブセット）

| API（OpenBao の Transit 互換） | 用途 | Qorynth での実装 |
|---|---|---|
| `POST /v1/<mount>/encrypt/<key_name>` | Seal.Encrypt | HPKE 暗号化（`Y` 宛）。応答 `ciphertext` = `vault:v<key_version>:<base64(エンベロープ)>` |
| `POST /v1/<mount>/decrypt/<key_name>` | Seal.Decrypt | §4 のゲートを通過後に閾値復号。応答 `plaintext`（base64） |
| `POST /v1/<mount>/rewrap/<key_name>` | 将来（Key Rotation 時の blob 付け替え） | 旧鍵で閾値復号 → 新 `Y` で再暗号化。**平文を返さず内部で完結**させる |
| トークン関連（`auth/token/lookup-self` / `renew-self`） | Transit Seal がトークンの検証・更新を行う場合 | 静的な応答を返すか、OpenBao 側を `disable_renewal = true` にする【要確認: Transit Seal が起動時・定常に呼ぶ API の完全な一覧】 |

- HPKE の `info` には `"qorynth/v1" ‖ key_id ‖ key_version ‖ purpose` を束縛する。Transit の `context` は Seal からは渡されない前提なので、**用途の束縛は Qorynth 側で行う**（`purpose = "openbao-seal"`）。他用途の暗号文が混入して復号オラクルに使われることを防ぐ。
- HTTP の `Authorization` ヘッダ（`X-Vault-Token` 相当）は Transit Seal の仕様上必須だが、**主たる認証は mTLS（§4.2）**であり、トークンは形式上の第二要素として扱う。

---

## 3. MVP フォールバックと本方式の切り替え

### 3.1 MVP 構成（E: 外部 unsealer）

```
bao operator init -key-shares=3 -key-threshold=2      ← OpenBao 標準 Shamir（n=3, t=2）
   │ 出力された Unseal Key Part ×3 を、儀式で各 qorynth-node に 1 つずつ登録（暗号化保存）
   │ 出力後、運用者側の控えを破棄。初期 root token は用途完了後に失効
   ▼
[OpenBao 再起動]
  qorynth-seal: Bao ノードの sealed 状態を確認 → qorynth-node 2 台から Part を取得 → /sys/unseal へ 1 片ずつ投入
```

- Part の取得は §4 と同じ認可ゲート（クラスタ `ACTIVE`、`seal` ロール、許可リスト）を通す。MVP でも**オンライン経路の防御は同じ設計**にしておく（切替後に防御が変わらない）。
- 平文の Part が `qorynth-seal` のメモリとネットワーク（TLS 1.3）に現れる点、失効のたびに OpenBao の `rekey` が必要な点は MVP の既知の弱点（threshold-crypto §2.6）。MVP 期間中は 2 台盗難に加え **`qorynth-seal` 侵害でも root key 全体に到達し得る**ため、本番データは載せない、または期間を限定する。
- Part の保管は、各ノードの Share 保存と同じ機構（TPM 封印鍵で暗号化、`LOCKED` ではロードしない）を流用する（threshold-crypto §4.5）。

### 3.2 切替の前提条件

次がすべて満たされるまで切替に着手しない。

| # | 条件 | 確認方法 |
|---|---|---|
| 1 | 最終形の鍵（DKG 済みの `Y`、`key_id`、`epoch`）が確立し、全ペア KAT 復号に成功している | threshold-crypto §4.1 フェーズ3 |
| 2 | Transit 互換ファサードが本番相当の構成（mTLS・許可リスト・VIP）で稼働している | ステージングで検証 |
| 3 | **ステージングの OpenBao（本番と同版・同設定）で、ファサードを使った初期化・再起動・Seal migration が通っている** | E2E |
| 4 | OpenBao Raft の最新スナップショットと、Qorynth の Share バックアップ（§5.4）が取得済み | 復旧演習が済んでいること |
| 5 | recovery key の保管者（OpenBao 運用者）が決まっている（Qorynth ノードではない） | §3.5 |
| 6 | 切替中は Bao の再起動・ノード追加・設定変更を凍結する | 変更管理 |

### 3.3 切替手順

```
0. 準備     ステージングでの手順リハーサル。本番 Raft スナップショット取得（OpenBao 運用者）
1. 設定準備  各 Bao ノードに seal "transit" を追加した設定ファイルを用意する（まだ反映しない）
              ・address = qorynth-seal の VIP、key_name = key_id、mount_path = 互換パス
              ・TLS クライアント証明書・CA（パスのみ。内容は本書に含めない）
              ・disable_renewal の要否は §2.4 の確認結果に従う
2. 移行      OpenBao 公式の Seal migration 手順に従い、1 ノードずつ実施する
              ・設定を差し替えて再起動 → ノードは migration 待ちの sealed 状態になる
              ・旧 Seal（Shamir）の Part を閾値（2 片）投入して `unseal -migrate`
                （Part は qorynth-seal が MVP と同じ経路で取得し、migrate 用に投入する）
              ・実行ノードの順序（Raft HA でアクティブ／スタンバイのどちらから行うか）は
                公式手順に従う【要確認】
3. 検証      ・Bao が unsealed で、ストレージ上の root key の包みが Transit Seal（ファサード由来）になっていること
              ・全 Bao ノードを 1 台ずつ再起動し、**Part を使わず**自動 Unseal できること
              ・Qorynth ノードを 1 台停止した状態でも自動 Unseal できること
4. 後始末    §3.5（recovery key の扱いと旧 Part の消去）
```

- 各ステップの完了後に停止条件（異常時は先へ進まない）を明確にする。**手順 2 の途中で異常が出た場合は、未移行ノードを旧設定のまま維持**し、MVP 経路で Unseal できる状態を保つ。
- `qorynth-seal` は、移行中の Bao ノードに対し「旧 Part の投入（MVP モード）」と「新 Seal での Encrypt」の両方を、同じ許可リストと監査の下で処理する。

### 3.4 再暗号化が不要な理由

| 層 | 切替で変わるか | 説明 |
|---|---|---|
| 保存データ（シークレット） | **変わらない** | barrier encryption key で暗号化されたまま |
| barrier encryption key（keyring） | **変わらない** | root key で暗号化されたまま |
| **root key** | **変わらない** | Seal migration は root key の**包み方**だけを変える |
| root key の保護 | **変わる** | 「Shamir 分割」→「Y 宛の HPKE 暗号文を 1 つストレージに保存」。再ラップされるのは **root key 1 個（数十バイト）だけ** |

加えて、最終形の `Y` は Refresh / Resharing で変わらない（threshold-crypto §3.1）ため、切替後に Qorynth 側でノード失効・Share 更新を行っても、ストレージ上の blob は**再暗号化不要**である。blob の付け替えが必要になるのは Key Rotation（`d` の更新）のときだけ（§6）。

### 3.5 切替後の後始末（recovery key と旧 Part）

OpenBao のドキュメントでは、Shamir から Auto-Unseal への migration 後、旧 unseal key は **recovery key** として扱われる【要確認: 版ごとの挙動、および recovery key と旧 root key の関係】。

- recovery key では Unseal はできない。Unseal は Seal（Qorynth）が担う。
- したがって、**Qorynth ノードに残っている旧 Part は切替後に不要**であり、そのまま残すと「閾値 2 を破るバックドア」になる（旧 Part 2 片＋ストレージで root key に到達し得る可能性を残す）。

| 手順 | 内容 |
|---|---|
| 1. recovery key の rekey | OpenBao 運用者が `operator rekey` の recovery 対象で**新しい recovery key** を発行し、旧 Part を無効化する。新 recovery key は Qorynth ノードとは別の管理者・別媒体に保管 |
| 2. 旧 Part の消去 | 各 `qorynth-node` の保存領域から旧 Part を消去（上書き・ゼロ化）。`qorynth-seal` のメモリからも破棄。MVP モードの機能を設定で無効化 |
| 3. バックアップの失効 | MVP 期間に作成した Part のバックアップを失効 |
| 4. MVP モードの停止 | `qorynth-seal` の外部 unsealer 機能を無効化し、監査で再有効化を禁止 |

### 3.6 ロールバック

| 状況 | 方法 |
|---|---|
| 移行中（手順 2 の途中） | 未移行ノードは旧設定のまま。移行済みノードは旧 Part で再度 migration（Transit → Shamir）が可能か【要確認】。**§3.5 の rekey 前に限り、旧 Part でのロールバック余地がある** |
| rekey 後 | 新 recovery key（運用者保管）を使い、公式手順で Auto → Shamir の migration を行う【要確認】 |
| ファサードの互換不具合 | 保険案 B（専用 Wrapper）へ切替。連携面が Wrap / Unwrap に閉じているため、`qorynth-seal` の Encrypt / Decrypt 実装は流用できる |

> **トレードオフの明示:** §3.5 の rekey を急ぐほど安全だが、ロールバック余地は小さくなる。推奨は「全 Bao ノードの自動 Unseal 検証（§3.3 手順 3）＋ 1 週間程度の観察」→ rekey。観察期間中も旧 Part は暗号化保存のままとし、監査対象とする。

---

## 4. 認証・資格情報

### 4.1 信頼関係の全体像

| 区間 | 認証 | 認可 | 備考 |
|---|---|---|---|
| OpenBao → `qorynth-seal` | **mTLS**（Bao ノードごとの個別証明書）＋ 形式上のトークン | 許可リスト（Bao ノード ID × `key_id` × 操作）。Raft 管理 | 本書の中心 |
| `qorynth-seal` → `qorynth-node` | mTLS（`seal` ロール証明書。TPM 保護） | ノード側で `seal` ロール・`ACTIVE`・epoch・用途を検査 | threshold-crypto §4.2 |
| `qorynth-node` ↔ `qorynth-node` | mTLS ＋ TPM | メンバーシップ | Share は送らない |
| `qorynth-seal` → OpenBao（状態確認） | TLS（サーバ検証）。無認証の seal-status 参照のみ | 読み取り専用 | §4.4 の突合用 |

### 4.2 OpenBao → `qorynth-seal` の接続認証

1. **mTLS を一次認証とする。** Bao ノード 3 台は**個別のクライアント証明書**を持ち、`qorynth-seal` は証明書の公開鍵フィンガープリント（または SAN）を **Raft に保存された許可リスト**と照合する。CA が同一でも、許可リストに載っていない証明書は拒否する（CA 侵害・証明書流用への備え）。
2. **証明書の失効は許可リストで行う。** CRL・OCSP の配布に依存せず、`qorynth-seal` が**リクエストごとに許可リストを評価**するため、失効は Raft コミット後ただちに効く（§4.5）。
3. **権限は最小化する。** 各 Bao 証明書は `key_id = openbao-root`（仮称）に対する `encrypt` と `decrypt` のみ。`rewrap`・`sign` 等は不許可。Bao の通常運用で不要な管理系 API は公開しない。
4. **トークン（`X-Vault-Token` 相当）は二次的。** Transit Seal の仕様上必要な値を OpenBao 設定に置くが、**これ単独では何も許可しない**（mTLS ID が前提）。値は環境変数・シークレットファイルで渡し、設定ファイル本体・リポジトリ・ログに平文で置かない。ローテーションは許可リスト更新と同時に行う。
5. **TLS 終端に注意。** L7 ロードバランサで TLS を終端すると、クライアント証明書の ID が `qorynth-seal` に届かない。VIP／LB は **L4（TLS パススルー）** とするか、検証済みの ID を安全に転送する方式（PROXY プロトコル等＋信頼できる経路限定）を採る。
6. **TLS は 1.3、サーバ証明書は Bao 側で CA ピン留め（`tls_ca_cert` 相当）。** `tls_skip_verify` は禁止。
7. **証明書秘密鍵の保管。** OpenBao の Transit Seal はクライアント鍵をファイルパスで受け取るため、TPM 内の非エクスポート鍵を直接は使えない。MVP はファイル権限＋ディスク暗号化とし、強化案として、Bao ホスト上のローカル TLS プロキシ（TPM 鍵を使う）を挟む方式を §6 に挙げる。**この限界があるため、盗難した Bao ホストが鍵ごと渡る前提で §4.4 の多層防御を設計する。**

### 4.3 盗難シナリオ別の閉め方

| 盗まれたもの | 攻撃者ができること | 閉め方 |
|---|---|---|
| **Bao ノード 1 台（ディスクのみ）** | blob と Raft データを取得。mTLS 秘密鍵がディスク上にあれば入手 | オフラインでは `d` が必要で復号不可。オンライン使用は §4.4・§4.5（失効・接続元・状態突合） |
| **Bao ノード 1 台（稼働機そのもの）** | 上記に加え、盗難機をネットワークへ接続して Unwrap を要求 | §4.4 の L3〜L6。**元のネットワークの内側に置かれた場合は暗号的には閉じられず、検知と失効が最終防壁** |
| **Qorynth ノード 1 台** | Share 1 つ。部分復号を要求できるのは `seal` ロールのみで、他ノードから Share は得られない | threshold-crypto §5.1。ノード失効＋ Resharing |
| **`qorynth-seal` 1 台（稼働機）** | `seal` ロール証明書を使い、`qorynth-node` へ部分復号を要求できる = 事実上 **Unwrap 権限そのもの** | `seal` ロール証明書も TPM 保護＋許可リスト対象。`qorynth-node` 側でも `seal` 証明書の失効を Raft で即時反映。レート制限・監査。2 台構成なので侵害側を失効して継続 |
| **Bao 1 台 ＋ Qorynth 1 台（想定脅威）** | 1 Share では `d` は得られない。Bao の資格情報でのオンライン Unwrap が残る | オフラインは閾値で防ぐ。オンラインは §4.4 |
| **承認端末 3 台** | 有効化のみ可能（threshold-crypto §5.3） | 本書の範囲外 |

### 4.4 オンライン経路の閉め方（threshold-crypto §5.1 の残課題への回答）

#### 4.4.1 問題の整理

Auto-Unseal の性質上、**認証された Bao ノードは root key を得られる**。ストレージ（Raft）の blob は Bao ノードのディスクに常に存在するため、盗難した Bao ノードの資格情報で `decrypt` を呼べば、攻撃者は root key を得る。**暗号（閾値）では防げない**（`d` は Qorynth 側にあり、`qorynth-seal` が正当な要求と判断すれば復号してしまう）。よって、防御は「**要求が正当かどうかの判定精度**」に帰着する。

判定に使える情報:

- 誰が（Bao ノードの mTLS ID）
- どこから（接続元アドレス・経路）
- いつ・どの頻度で（root key の Unwrap は起動時のみで**極めて稀**）
- そのノードは**今 Unseal を必要としているか**（OpenBao の状態）
- クラスタは今 `ACTIVE` か（運用者の意図）

#### 4.4.2 多層防御

| 層 | 防御 | 実現方法 | 閉じる範囲 |
|---|---|---|---|
| L0 | クラスタ状態ゲート | `qorynth-node` はクラスタが `LOCKED`、または自ノードが `SHARE_LOADED` でなければ部分復号を返さない（threshold-crypto §4.2） | クラスタ全体が `LOCKED` の間は全 Unwrap が不可 |
| L1 | Bao ノードの個別 ID と許可リスト | §4.2。Raft 管理。リクエストごとに評価 | 登録外・失効済み証明書 |
| L2 | **ネットワーク制約** | `qorynth-seal` は内部ネットワークのみで待ち受け（Bao の登録アドレスからのみ許可）。ファイアウォール＋許可リストの接続元 | 外部ネットワークに持ち出された盗難機 |
| L3 | **暗号文のクラス分け** | ファサードが `encrypt` 時に暗号文のダイジェストを記録し、**初期化・migration のウィンドウ（運用者が明示的に開く）中に発行した暗号文を「root key クラス」**、それ以外（ヘルスチェック用などの任意の試験値）を「probe クラス」とする。`decrypt` は、**root key クラスのダイジェストに一致する暗号文のみ**を L4〜L6 の対象にし、**未登録の暗号文は拒否**（任意の点 `R` に対する DH オラクル化を防ぐ。threshold-crypto §2.7 の注意 2 の具体化）。probe クラスの扱い（クォーラム復号するか、キャッシュで応答するか）はヘルスチェックの仕様確定後に決める【要確認】 | 任意暗号文を使った復号オラクル、他用途の暗号文 |
| L4 | **OpenBao の `sealed` 状態との突合** | root key クラスの `decrypt` を受けたら、`qorynth-seal` は**許可リストに登録済みの当該 Bao ノードのアドレス**へ `seal-status` を問い合わせ（無認証・読み取り専用）、**`sealed: true` かつ要求の接続元がそのアドレスと一致する場合のみ**応答する。起動直後の競合に備え、数回の短い再試行（バックオフ）を許す | **実機が元の場所で稼働中なのに、複製・持出機が Unwrap を要求する**ケース、および元アドレス以外から要求する盗難機 |
| L5 | **全 root key Unwrap の通知と監査** | root key クラスの `decrypt` は発生が稀なので、**毎回**運用者チャネルへ通知し、監査ログ（要求元 ID・接続元・時刻・`key_id`・`request_id`）に追記。通知の無い Unwrap は存在しない設計にする | 検知。盗難機が元の環境で成功した場合の事後対応を早める |
| L6 | **非対称キルスイッチ** | **ロック（`ACTIVE` → `LOCKED`）は低い承認基準**（例: 登録管理者 1〜2 名）で即時実行できる。**解錠は 3-of-5**。実行中の Bao は Unseal 済みのため、ロックしても稼働は止まらない（以後の再起動と新規 Unseal だけが止まる） | 盗難発覚直後の即時遮断 |

> **L4 の注意:** L4 は「盗難機が元のアドレスに居ない」ことを要求する性質のため、**盗難機を元のネットワーク（同一アドレス）へ戻された場合は通過する**。また、正規ノードが電源断などで到達不能な場合に備え、**運用者が明示的に「当該ノードの Unseal を許可」する承認付き例外手順**（L6 と同系統の承認）を用意する。この例外は監査・通知対象とする。

> **L3 の依存:** 「ウィンドウ内で発行された暗号文を root key クラスとみなす」運用は、**OpenBao が初期化・migration の際にいつ・何回 `encrypt` を呼ぶか**に依存する【要確認】。呼び出しパターンが想定と異なる場合は、暗号文ごとの登録を運用者が手動で行う方式（`qorynth` CLI で root key blob のダイジェストを登録）に切り替える。

#### 4.4.3 「ロックは軽く、解錠は重く」の根拠

ロックは**拒否方向の操作**であり、悪用されても失われるのは可用性（Bao の再起動不能）で、機密性は損なわれない。解錠は**許可方向の操作**であり、悪用されると機密性が損なわれる。したがって、承認基準を非対称にして、盗難発覚から遮断までの時間を最短にする。ただし、ロックの悪用（可用性攻撃）を抑えるため、ロック実行は即時に通知し、解錠は 3-of-5 の通常の有効化承認（設計概要 §2）に従う。

### 4.5 失効手順と盗難ノードの Unwrap 要求の遮断

| 対象 | 手順（要約） |
|---|---|
| **盗難した Bao ノード** | ①（必要なら）L6 でクラスタをロック ②当該 Bao ノードの証明書を許可リストから削除（Raft コミット = 即時反映）③OpenBao 側で当該ノードを Raft ピアから除外し、証明書を再発行（新 ID）④新 ID を許可リストへ登録（これは 3-of-5 の登録承認）⑤ロック解除 ⑥ L5 の監査で、盗難後に当該 ID の Unwrap が無かったか確認 |
| **盗難した Qorynth ノード** | threshold-crypto §4.3（INVALIDATED ＋ Resharing）。`Y` は不変で blob は再暗号化不要 |
| **盗難した `qorynth-seal`** | `seal` ロール証明書を失効（`qorynth-node` 側の許可リストから削除）。残る 1 台で継続。新しい `seal` 証明書を発行 |
| **Bao 盗難＋ Qorynth 盗難（想定脅威）** | 上記 2 手順を並行。1 Share では `d` は得られないが、**旧 epoch の Share がもう 1 つ流出し得るか**を threshold-crypto §4.3 の基準で判断し、必要なら Key Rotation（blob の rewrap を含む） |

### 4.6 残余リスク

| リスク | 状態 | 備考 |
|---|---|---|
| 盗難機を元のネットワークへ戻され、L1〜L4 を通過 | **暗号的には閉じられない** | L5 の通知、L6 のロック、失効で時間を最小化する。物理・ネットワーク境界の運用に依存 |
| Bao のクライアント秘密鍵がファイルとして盗まれる | 受容（MVP） | TPM 保護のローカルプロキシは強化案（§6） |
| `qorynth-seal` の実行時侵害 | 受容（長期鍵 `d` は漏れないが、暗号文ごとの復号結果は得られる） | threshold-crypto §5.5 |
| 稼働中の Bao メモリ内の root key | 範囲外 | 設計概要 §3 の想定どおり |
| 解錠承認の迂回 | 承認端末側の設計課題 | threshold-crypto §5.3 |

---

## 5. 障害・運用

### 5.1 障害時の動作

| 状況 | 動作 | 運用上の注意 |
|---|---|---|
| **`qorynth-node` 1 台停止** | 残り 2 台で復号を継続。ヘッジ要求（3 台へ並列送信し先着 2 つを採用）で追加遅延なし（threshold-crypto §6.2） | 復旧までの期間は**閾値の余裕がゼロ**。この間は Bao の計画的な再起動を避ける。復旧不能なら Resharing（§4.5） |
| **`qorynth-node` 2 台停止** | 閾値未満で復号不可。**稼働中の Bao は Unseal 済みのため動作継続**。ただし**再起動した Bao ノードは Unseal できず `sealed` のまま待機**する | 2 台以下の間は Bao の再起動・ノード追加・設定変更を凍結する。Bao が起動時に Seal 不達で諦めるか、再試行するか、プロセス管理側のリトライ（バックオフ）が必要か【要確認】 |
| **`qorynth-seal` 1 台停止** | 残り 1 台で継続。OpenBao の Transit Seal 設定は**単一の `address`** のため、**前段の VIP（VRRP 等）または L4 LB のヘルスチェック切替**で冗長化する | L4（TLS パススルー）を維持（§4.2-5）。Bao 側のクライアントタイムアウト・再試行は【要確認】 |
| **`qorynth-seal` 2 台停止** | Unwrap 不可。Qorynth ノードが生きていても Bao は Unseal できない | 実行中の Bao は継続。復旧は `qorynth-seal` の再起動のみ（状態は Raft／ノード側にあり、`qorynth-seal` は実質ステートレス） |
| **OpenBao 1 台停止** | 残り 2 台で継続（Raft）。復帰時に自動 Unseal | 復帰は §4.4 の L4 を通る（`sealed: true` を確認できること） |
| **OpenBao 全台再起動** | クラスタが `ACTIVE` なら自動で Unseal（設計概要 §2-6） | 1 台ずつ起動し、各台の Unwrap が L5 で通知されることを確認（想定内の通知か判別できる運用手順） |
| **Qorynth 全台停止 → 再起動** | `LOCKED` に戻る。3-of-5 承認で `ACTIVE`（threshold-crypto §4.5） | **この間に Bao が再起動すると `sealed` のまま待機**になる。承認端末の可用性（5 台中 3 台が即時に動けること）が Bao の復旧時間を支配する |
| **Qorynth 全台停止と Bao 全台停止が重なる（全断）** | Qorynth の `ACTIVE` 化（3-of-5）→ `qorynth-seal` 起動 → Bao 起動の順 | **起動順序をランブックに固定**。Bao を先に上げても、再試行のバックオフで待てるようにする【要確認】 |
| **Qorynth の `ACTIVE` ゲートによる意図的な遮断（L6）** | 稼働中の Bao は継続、新規 Unseal のみ停止 | 解錠は 3-of-5 |

### 5.2 計画メンテナンス

| 作業 | 事前条件 | 手順の要点 |
|---|---|---|
| Bao の 1 台ずつのローリング再起動 | Qorynth の 3 台が全て `ACTIVE`（閾値の余裕あり） | 事前に `qorynth cluster status` 相当の確認。Unseal の通知（L5）を観測 |
| Qorynth ノード更新 | 稼働ノード 2 台以上 | 1 台ずつ。更新中は Bao の再起動を凍結 |
| `qorynth-seal` 更新 | もう 1 台が健全 | VIP から外して更新 → 戻す |
| Bao の版上げ | ステージングで互換テスト（§2.3）に合格 | ファサードの互換 CI に新版を追加してから本番へ |

### 5.3 監視と監査

| 項目 | 方法 |
|---|---|
| root key クラスの `decrypt` | **全件通知**（L5）。件数・接続元・結果。想定外（再起動予定なしでの発生）は即時アラート |
| probe クラスの Encrypt／Decrypt | 件数と失敗率を監視（ヘルスチェックの有無が確定したら閾値を決める）【要確認】 |
| 許可リスト外・失効済み証明書による接続 | 拒否件数とソースの記録 |
| Bao の `seal-status` | `qorynth-seal` が定期取得し、`sealed: true` が長時間継続している Bao ノードをアラート |
| Qorynth クラスタ状態 | `ACTIVE` / `LOCKED`、各ノードの `SHARE_*` 状態、epoch の一致（threshold-crypto §4.0） |
| 監査ログ | 追記専用・改ざん検知（Raft ログへのダイジェスト記録など）。Bao 側の監査ログとの突合を月次で実施 |

### 5.4 バックアップと復旧

OpenBao 側と Qorynth 側のバックアップは**相互依存**する。

- Raft スナップショットには、barrier で暗号化されたデータと、**ラップ済み root key（blob）**が含まれる【要確認】。
- スナップショットを復元しても、blob を復号できる Qorynth の鍵（`d` の該当 `key_version`）が無ければ Unseal できない。
- **スナップショットは Qorynth のバックアップと同じ場所・同じ保管者に置かない**（片方の漏洩が他方の価値を上げないようにするが、復旧時には両方が必要）。

| 失われたもの | 復旧方法 |
|---|---|
| Bao 1〜2 台 | 残りの Bao から Raft で再構築。新ノードの証明書を許可リストへ登録（3-of-5 承認）し、自動 Unseal |
| Bao 全台 | Raft スナップショットから復元 → 自動 Unseal（Qorynth が健在なら成立） |
| Qorynth 1 台 | threshold-crypto §4.3・§4.4（Resharing） |
| Qorynth 2 台 | バックアップの Share 1 つ＋残る 1 台で Resharing |
| Qorynth 3 台 | バックアップの Share 2 つ（2 名の復旧管理者）→ 新ノードへ Resharing。**この間 Bao の Unseal は不可**（実行中の Bao は継続） |
| **`d` と Share バックアップを 2 つ以上喪失** | **Bao の保存データは復号不能になり得る。** threshold-crypto §4.4 は「OpenBao の recovery key／再初期化に依存」と記しているが、**recovery key は Unseal 用の鍵ではなく、root key を復元できる保証がない**【要確認】。**復元できない前提**で運用する |

最後の行への対策:

1. Qorynth の Share バックアップ（threshold-crypto §4.4）を**最重要資産**として扱い、**定期的な復旧演習**（ステージングで 2 つの Share を復旧して Resharing → Bao の Unseal まで）を実施する。
2. OpenBao のシークレットを**再投入できる**ように、シークレットの正本（IaC・外部の暗号化バックアップ）を別途管理する方針を、OpenBao 運用者と合意する（本書の範囲外だが依存関係として明記）。
3. 【要確認】OpenBao に複数 Seal（Seal HA）相当の機能がある場合、Qorynth と独立した 2 つ目の Seal を保険として併用できるか。ただし 2 つ目の Seal 側が弱いと全体が弱くなる点に注意（§6）。

---

## 6. 未解決事項・今後の課題

### 6.1 フェーズ6冒頭スパイク（OpenBao 側の仕様確認）

実装着手前に、**採用する OpenBao の版**に対して次を検証し、本書の【要確認】を解消する。

| # | 確認事項 | 影響する節 |
|---|---|---|
| 1 | Transit Seal が起動時・定常に呼ぶ API の完全な一覧（encrypt / decrypt 以外にトークン lookup / renew、鍵情報の読み取り、`sys` 系があるか）と、`disable_renewal` の効果 | §2.4 |
| 2 | Seal のヘルスチェックの有無・間隔・内容・失敗時の挙動（警告のみか、サービス影響か） | §4.4 L3、§5.1 |
| 3 | 初期化・migration で `encrypt` が何回・どの値で呼ばれるか、root key blob の保存先 | §4.4 L3 |
| 4 | Shamir → Transit の Seal migration の手順（HA／Raft での順序）、旧 unseal key が recovery key になる際の正確な挙動 | §3.3・§3.5 |
| 5 | Transit → Shamir（および別 Transit 鍵名）への migration の可否と条件 | §3.6・Key Rotation |
| 6 | 起動時に Seal に到達できない場合の挙動（リトライの有無・間隔・タイムアウト） | §5.1 |
| 7 | Raft スナップショットに含まれる Seal 関連データ、スナップショット復元後の Unseal 条件 | §5.4 |
| 8 | recovery key で root key を復元できるか（できない前提の確認） | §5.4 |
| 9 | 外部 Seal プラグイン機構の有無（無ければ保険案 B はフォーク前提） | §2.3 |
| 10 | PKCS#11 Seal を使える公式配布物（CGO ビルド）の有無（不採用判断の再確認） | §2.2 |
| 11 | Seal HA（複数 Seal）相当の機能の有無 | §5.4 |
| 12 | OpenBao 側の Seal 設定項目（`key_name`・`mount_path`・TLS 項目）の最新の仕様 | §2.4・§3.3 |

### 6.2 設計上の未解決事項

| 項目 | 内容 | 状態 |
|---|---|---|
| Key Rotation 時の blob の付け替え | `rewrap` API で新 `Y` へ付け替えた後、OpenBao のストレージ上の blob をどう更新するか（Seal migration で別の `key_name` へ移す方式が有力）。旧 `key_version` の Share を、付け替え完了までどう保持するか | 要検討 |
| L3（暗号文クラス分け）の確定 | OpenBao の呼び出しパターン次第で、自動判別から運用者登録へ切り替える | スパイク後 |
| Bao クライアント鍵の TPM 保護 | ローカル TLS プロキシ（TPM 鍵）を挟む方式の採否。Bao ホストの構成が複雑化するトレードオフ | 要検討 |
| L4 の例外手順 | 正規ノードが到達不能のときの「Unseal 許可」の承認基準と手順 | 要検討 |
| ロックの承認基準 | 「1〜2 名」の根拠と、ロック悪用（可用性攻撃）への対策 | 承認設計（フェーズ3）と合わせて確定 |
| Bao ノード追加・入れ替えの承認基準 | 許可リストへの登録を 3-of-5 とするか | 要検討 |
| 運用者の分離 | OpenBao の recovery key 保管者と、Qorynth の復旧管理者・承認端末保有者の重複排除（1 人が両方を持たない） | 運用設計 |
| probe クラスの扱い | クォーラム復号するか、キャッシュで応答するか。ヘルスチェックの意図（Seal の実健全性の確認）と Qorynth 障害の波及のトレードオフ | スパイク後 |
| Seal HA による保険 | 2 つ目の独立した Seal を併用する案の採否（§5.4） | 要調査 |
| 汎用 API 化 | 外部クライアント向けに復号 API を公開する場合の認可・CCA 安全性（TDH2 系）。Transit 互換の `sign` / `verify` / `datakey` の提供順序 | 将来（threshold-crypto §3.2） |
| 量子耐性 | 暗号文ヘッダの `suite` による移行（threshold-crypto §3.4） | 将来 |
| 互換性の維持 | OpenBao の版上げごとに、ファサードの互換テスト（実 OpenBao ↔ ファサード）を CI で実行する体制 | 実装時 |

### 6.3 フェーズ6の入出力

| 入力 | 出力 |
|---|---|
| threshold-crypto の方式（フェーズ5の成果物）、承認・状態管理（フェーズ2〜4）、本書 | `qorynth-seal` の Transit 互換ファサード、MVP 用の外部 unsealer モード、許可リスト管理、L3〜L6 の実装、E2E テスト（実 OpenBao） |

---

## 付録: 参考（確認対象の仕様）

- OpenBao ドキュメント: Seal / Auto-Unseal、`seal "transit"`、`seal "pkcs11"`、Seal migration、recovery key（版を固定して確認すること）
- Vault Transit Secrets Engine の API（encrypt / decrypt / rewrap）と暗号文形式 `vault:v<N>:<base64>`
- RFC 9180 *Hybrid Public Key Encryption (HPKE)*
- 本リポジトリ: [threshold-crypto.md](threshold-crypto.md) §2.6・§2.7・§3.1・§4・§5.1

> 本書の OpenBao 固有の記述は執筆時点の知識に基づく。実装着手時に、対象バージョンの公式ドキュメントで最新の挙動・既知の脆弱性情報を確認すること。
