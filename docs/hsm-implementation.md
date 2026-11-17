# HSM 実装方式 — Qorynth

> 状態: 設計案
> 対象: qorynth-node / qorynth-seal / qorynth-signal の秘密鍵の保護・TLS 署名委譲・Share 封印
> 関連: [Seal認証](seal-authentication.md)（§2〜3 の詳細化） / [閾値暗号プロトコル選定](threshold-crypto.md)（§4.0・§4.5・§5.1） / [技術スタック選定](tech-stack.md)（§2 T4・T10・§3.2 TPM 行・§6 TPM 行・§7 R2・R3） / [開発計画](development-plan.md)（フェーズ2・フェーズ5）

本書は seal-authentication.md §2〜3 と tech-stack.md §3.2・§6 の方針を具体化する。design-overview.md §6 の「既製 HSM か TPM 独自 KMS か」は、既存の認証・技術スタック方針に沿って TPM 側に整理する。既存設計書は編集せず、認証情報・秘密値は記載しない。

## 0. 要約

| 項目 | 方針 |
|---|---|
| 採用 | TPM 2.0 の非エクスポート鍵を使う独自 KMS |
| ノード鍵 | TPM 内の非エクスポート ECDSA P-256。TLS 署名を TPM に委譲 |
| 実装 | tss-esapi + 自作 `qorynth-tpm` の `rustls::sign::Signer` ラッパ。同梱ビルド・静的リンク・配布は要検証 |
| 代替 | cryptoki + tpm2-pkcs11。最悪の代替は TPM 処理を Go/C の別プロセスに分離し Unix ソケットで署名 |
| デバイス・テスト | Linux の `/dev/tpmrm0`。自動テストは swtpm |
| Share 保存 | TPM 封印鍵で暗号化。LOCKED は PCR ポリシー + 測定起動によるポリシー強制。承認との結合を暗号的に強制する方式ではない |
| 盗難防御 | 1 台盗難の防御の本体は (2,3) Shamir の閾値。TPM は追加の保護層 |
| 配置 | 未確定。物理 TPM / vTPM / クラウド / K8s Pod の制約を §8 に分ける |

## 1. 範囲と前提

本書は TPM の鍵生成・署名委譲・封印、TPM 証明（EK チェーン検証 + AK Certify）、配置別の制約、既製 HSM との比較を扱う。

- 閾値暗号の DKG・分散復号・Share 更新は threshold-crypto.md を正とし、再定義しない。
- mTLS・CA・メンバーシップ・許可リストの詳細は seal-authentication.md を正とし、再定義しない。
- tss-esapi・rustls・quinn 等のライブラリ選定は tech-stack.md を正とし、再選定しない。本書は署名・配布に必要な接続箇所と制約を具体化する。
- ノード配置は未確定。特定の Pod・VM・物理機・クラウド環境を前提にしない。

フェーズ1 冒頭のスパイクで署名・配布の成立性を確認し、フェーズ2 でノード鍵・認証・証明、フェーズ5 で Share 封印と閾値暗号との統合を検証する。HSM 方式の判断は開発計画の「フェーズ5前」に先行する設計判断であり、実機検証済みという意味ではない。

## 2. 採用方針: TPM 2.0 非エクスポート鍵

TPM 2.0 を採用する理由は次のとおり。

1. ノード鍵、seal の 2 本の鍵、signal 鍵を TPM に置き、ディスクの複製だけでは資格情報を持ち出せない構造にする（seal-authentication.md §2.2）。signal の TPM 利用は同 §2.4 に従い「可能なら」とする。
2. `node_id` は証明書の SPKI の SHA-256（p2p-transport.md §5.2）。「TPM の鍵 = ノード ID」とは、TPM に保持するノード公開鍵が ID の根拠であるという意味で、EK や機器の製造番号そのものではない。同じ鍵を保持すれば再起動後も同じ `node_id` で相互認証できる（seal-authentication.md §6.4）。
3. ECDSA P-256 は TPM 2.0 で標準的にサポートされる鍵型として既存設計で採用済み（p2p-transport.md §2.3）。対象の実機・vTPM での利用可否は確認する。
4. TLS 署名を TPM に委譲し、TLS 秘密鍵を平文でプロセスメモリへ展開しない。Share を扱うメモリ上の処理とは区別する（threshold-crypto.md §4.1・§5.1）。

TPM が守るのは**秘密鍵の複製**であって、**盗難機器の現地利用**ではない。盗難された機械が許可されたソフトウェア状態で起動できれば、TPM 鍵はその機械で使える（seal-authentication.md §2.4）。1 台盗難の防御の本体は (2,3) Shamir の閾値であり、オンライン攻撃には既存の失効・ロール認可・ゲートも必要になる（threshold-crypto.md §5.1）。

YubiHSM・AWS CloudHSM 等を使う場合の影響は §5 で比較する。

## 3. 鍵の配置と保護対象

| 主体・用途 | 配置・保護 | 制約 |
|---|---|---|
| node の TLS 鍵 | TPM 内の非エクスポート ECDSA P-256。`fixedTPM` / `fixedParent`、PCR ポリシー付き | 同じ鍵を再利用して ID を維持。機器・鍵を交換した場合は新 ID として登録 |
| seal の Bao 向けサーバ鍵 | TPM 内 | ノード向けクライアント鍵とは別鍵・別証明書 |
| seal のノード向けクライアント鍵 | TPM 内、`seal` ロール | Bao 向けサーバ鍵との用途分離を維持（seal-authentication.md §2.4） |
| signal の TLS 鍵 | TPM（可能なら） | 承認口の Web PKI サーバ鍵は別リスナー・別鍵。Web PKI の管理方針は既存設計に従う |
| Bao のクライアント鍵 | ファイル権限・ディスク暗号化で保護 | OpenBao がファイルパスで受け取る仕様のため TPM 直接利用不可とする既存前提は【要確認】。強化案はローカル TLS プロキシ（seal-authentication.md §2.4・§8.2） |
| CA の Root / 中間鍵 | 別々のハードウェアトークン（PIV/HSM 相当） | Root はオフライン。ロール別中間 CA も別鍵・別トークン。常時稼働の CA サーバーは置かない |
| 復旧管理者鍵 | 各管理者のハードウェアトークン | 復旧承認・保管の詳細は seal-authentication.md に従う |
| Share 封印鍵 | 各ノードの TPM に束縛 | Share を暗号化して保存。TLS 署名鍵とは用途を分ける（threshold-crypto.md §4.0） |

Share の暗号化保存後は、保存処理の平文 Share・作業バッファを即ゼロ化する（threshold-crypto.md §4.1）。有効化中に必要な Share は §7 に従ってメモリへロードし、TLS 鍵と同じ「常に TPM 内だけ」の性質を持つとは扱わない。

TLS 署名は ECDSA P-256。署名遅延は**数十〜数百 ms 想定【要確認】**であり、機器・配置に依存する。初回接続・再接続のハンドシェイクで発生し、長期接続を使う通常の復号要求ごとには発生しない（seal-authentication.md §2.4、p2p-transport.md §7.1）。

## 4. 実装構成

**tss-esapi** は TSS2 ESAPI の安全ラッパとして採用する。同梱ビルドの方針は tech-stack.md §3.2・§6・§7 R2 に従い、`bundled` + `generate-bindings` により tpm2-tss を同梱ビルドして静的リンクする構成を検証する。

**公開情報による制約:** 2026-11-17 の crates.io API では、tss-esapi / tss-esapi-sys の更新継続と非 yanked のリリースを確認した。ただし `bundled` は公開プレリリースの feature に存在し、確認した最新の安定リリースには存在しない。`generate-bindings` は安定リリースにも存在する。同梱ビルド方針は維持するが、**安定版にそのまま指定できる、対象環境で静的リンク・配布が成立するとは断定しない**。採用する公開リリースと feature の組合せ、tpm2-tss のソース固定、ビルド依存・配布条件をスパイクで確定する。

署名ラッパは自作の **`qorynth-tpm`** に隔離する。

1. TPM 内で ECDSA P-256 鍵を生成し、公開鍵・オブジェクト属性を取得する。非エクスポート属性・PCR ポリシーを付け、再起動後に同じ鍵をロードできる永続ハンドルまたは TPM に束縛された保護済みオブジェクトを管理する。
2. `rustls::sign::SigningKey` から選択した方式の `Signer` を返し、証明書と対応付ける。`CryptoProvider` の拡張機構と証明書リゾルバを使って TPM 委譲署名を差し込む。秘密鍵のファイルを経由しない。
3. `Signer` の `sign(&self, msg)` と `scheme()` を実装する。このトレイトは dyn compatible。入力メッセージは未ハッシュなので、選択した ECDSA P-256 / SHA-256 に従ってハッシュし、`TPM2_Sign` に委譲する。TPM の署名値を rustls の要求する形式へ変換し、公開鍵で検証して統合を確認する。
4. TPM エラー・タイムアウト・未対応方式は接続失敗として返し、ソフトウェア鍵へ自動的に切り替えない。

`Signer` は同期 API なので、TPM のブロッキング呼び出しを専用スレッドプールへ置く（tech-stack.md §7 R3）。単に署名要求をワーカーへ渡して同期で待つだけでは、呼び出し元の停止は消えない。QUIC / rustls のハンドシェイクを進める処理を含め、非同期ランタイムを塞がない統合方法、並列数・キュー上限・タイムアウトをスパイクで検証する。

代替は **cryptoki + tpm2-pkcs11** による PKCS#11 経由の署名。さらに難しい場合は TPM 処理だけを Go/C の別プロセスへ分離し、Unix ソケットで署名する（tech-stack.md §7 R2）。別プロセス化しても鍵をエクスポートせず、接続権限と署名用途を制限する。配布には動的リンク構成も比較する。

Linux のデバイスは **`/dev/tpmrm0`** を使う（tech-stack.md §2 T10・§6）。テストは **swtpm** とし、鍵生成・署名・再起動後の同じ公開鍵の利用、PCR 不一致時の拒否、封印・解除を確認する。CI での swtpm の実行方法・権限は【要確認】。ソフト TPM での成功は実機の盗難耐性や署名性能の証明にはしない。

乱数は **OS の CSPRNG を必須**とする。TPM の乱数は追加エントロピーとして混合し、単独では使わない（threshold-crypto.md §6.1）。

裏取り先（版番号を本文に固定せず、採用時に公開メタデータと実環境を再確認する）:

- 維持状況・feature: [tss-esapi](https://crates.io/crates/tss-esapi)、[tss-esapi-sys](https://crates.io/crates/tss-esapi-sys)。機械可読情報は [tss-esapi API](https://crates.io/api/v1/crates/tss-esapi)・[tss-esapi-sys API](https://crates.io/api/v1/crates/tss-esapi-sys)。
- API と制約: [rustls Signer](https://docs.rs/rustls/latest/rustls/sign/trait.Signer.html)、[SigningKey](https://docs.rs/rustls/latest/rustls/sign/trait.SigningKey.html)、[安定リリースの tss-esapi-sys feature](https://docs.rs/crate/tss-esapi-sys/latest/features)。
- 代替の Rust ラッパ: [cryptoki](https://crates.io/crates/cryptoki)。更新継続・非 yanked の安定リリースは確認済み。対象 PKCS#11 モジュールとの互換性は要検証。

## 5. 既製 HSM との比較

| 比較軸 | 採用するローカル TPM | ローカル接続 HSM（YubiHSM 等） | ネットワーク HSM（AWS CloudHSM 等） |
|---|---|---|---|
| 固定された中央管理ノードなしとの整合 | 各ノードに鍵を分散配置できる | 各ノードに独立配置するなら整合可能 | 共有先への依存が中央の可用性・運用上の依存点になりうる |
| P-256 対応 | 既存の採用鍵型。対象実機で確認 | 対象機器・モジュールの対応を要確認 | 対象サービス・モジュールの対応を要確認 |
| rustls Signer への差し込み | tss-esapi + 自作ラッパ | PKCS#11 対応時は cryptoki + 自作ラッパを検証 | 同左。認証・セッション・障害時の処理も必要 |
| PKCS#11 での代替 | cryptoki + tpm2-pkcs11 | ベンダー提供の PKCS#11 モジュールが対象 | ベンダー提供の PKCS#11 モジュールが対象 |
| 配置の自由度 | 物理 TPM / vTPM の可用性とアクセス権限に依存 | USB 等の接続、Pod / VM への割当・パススルーが必要 | HSM サービスへのネットワーク到達性・配置・冗長化が必要 |
| 運用コスト | 機器交換、PCR 更新、証明・封印ポリシーの管理 | 機器の調達・交換・接続管理が追加 | サービス費用、ネットワーク、HSM 側の運用・障害対応が追加 |

PKCS#11 経由の統合は、TPM の代替経路と同じ `Signer` 境界を使える設計上の見込みであり、個々の機器との互換性を確認済みとはしない。tpm2-pkcs11 は TPM 向けであり、既製 HSM にはその製品のモジュールを使う。

ネットワーク HSM ではローカル `/dev/tpmrm0` に比べネットワーク往復が加わる。ただし総署名時間は機器性能にも依存し、必ず TPM より遅いとは断定しない。ローカル接続 HSM にネットワーク遅延や専用 HSM サーバーが必須とはしない。

**結論は TPM 2.0 非エクスポート鍵を採用する既存方針を維持する。** ローカル性、既定の P-256 鍵型、確認済みの rustls の署名差し込み口を利用できる点を重視する。共有のネットワーク HSM は「固定された中央管理ノードなし」と相性が悪くなりうるが、既製 HSM 全体が必ず方針に矛盾するとは扱わない。CA・復旧管理者のハードウェアトークン利用も変更しない。

## 6. TPM 証明（EK チェーン検証 + AK Certify）

発行儀式では TPM 内で鍵を生成し、**CSR と TPM 証明情報**を提出する。EK 証明書チェーンの検証と、AK による `TPM2_Certify` で申請鍵の TPM 内生成・非エクスポート属性を確認する方針は seal-authentication.md §3.2 に従う。検証手順は【要確認】であり、CSR だけで TPM 保護を確認したとは扱わない。

- **EK チェーン:** メーカー CA の取得・信頼の登録・失効確認の方法を確定する（seal-authentication.md §8.1）。vTPM では別の信頼アンカーや証拠が必要になる可能性がある。
- **AK と EK の結合:** Certify の署名を確認するだけでなく、その AK が検証対象の EK と同じ TPM に属することを確認する手順を要検証とする。資格情報アクティベーション等の適用を含め、発行儀式に具体化する。
- **申請鍵との結合:** Certify の対象 Name と公開領域・属性、CSR の SPKI の対応を照合する。`fixedTPM` / `fixedParent` 等を検証し、nonce による証拠の鮮度も確認する。TPM 内にあることと、承認された申請者であることは別に検証する。
- **vTPM・ソフト TPM:** 信頼する実装・運用者、証明の検証方法、本番で許容するかを要検討とする。swtpm を実機と同じ信頼水準には置かない（seal-authentication.md §8.1）。

失効時は該当証明書チェーン・TPM ID を許可リストの拒否側へ登録し、再発行による復活を防ぐ（seal-authentication.md §4.4 末尾）。TPM ID の具体的表現・チェーンの拒否範囲は要確定。新ノードは TPM 内で新しい鍵を生成し、既存の承認付き発行・メンバーシップ手順で mTLS 証明書を取得する（threshold-crypto.md §4.3）。

## 7. Share 封印と LOCKED 強制

Share は各ノードの **TPM 封印鍵で暗号化して保存**する（threshold-crypto.md §4.1・§4.5）。保存用鍵の封印解除と Share のローカル復号は、TLS 署名鍵の利用とは用途を分離する。暗号化保存時の平文・中間バッファは即ゼロ化し、保存用鍵も必要な期間だけ扱う。

全台再起動後は次の既存状態遷移に従う。

1. `LOCKED / SHARE_SEALED` で起動し、Share をメモリへロードしない。
2. Raft の状態を取得し、各ノードが有効化の承認証明書を検証する。
3. 承認成立後、TPM 封印鍵で Share を復号してメモリへロードする。公開 Share との整合性と現行 `epoch` を確認して `SHARE_LOADED / ACTIVE` とする。
4. 古い `epoch` なら `SHARE_STALE` とし、部分復号を返さず再同期する。LOCKED 化で不要になったロード済み Share はゼロ化する。

LOCKED の強制は **PCR ポリシー + 測定起動**を前提とし、承認検証を行うソフトウェアが測定された状態でしか封印を解けないようにする（threshold-crypto.md §4.5）。測定値がその承認検証コードまで覆うこと、許可されないコードへ差し替えられないこと、更新時に正しいポリシーを維持できることを確認する。

これは**承認と Share ロードの結合をポリシーで強制する方式**であり、PCR 自体が現在の承認成立や Raft の状態を検証するわけではない。測定済みソフトウェアの実行時侵害により迂回される余地は残る。封印の暗号化は使うが、承認端末の秘密がなければ復号不能となる意味の暗号的強制は未実装である。

強化案の「承認端末が保持する秘密から Share 保存鍵を導出する方式」は threshold-crypto.md §6.1 の要検討事項として残す。1 台だけ再起動した場合の再参加・再有効化ルールも、本書では確定しない。

Raft ログのハッシュ鎖の固定先は **【要検討: TPM NV】**（seal-authentication.md §6.4 末尾）。PCR への束縛だけで状態の巻き戻し防止まで保証するとは扱わない。

## 8. 配置別の制約

| 配置 | 成立条件・制約 | 未確認事項 |
|---|---|---|
| 物理 TPM | Linux で `/dev/tpmrm0` にアクセスできること。ホストの測定起動との関係を明確にしやすい | PCR が承認検証ソフトウェアまで覆うこと、実機 P-256 対応・署名性能・鍵の永続化・機器交換 |
| VM / vTPM | ゲストの PCR とホストの測定・管理権限の関係を確認する。物理 TPM と同じ PCR 条件を仮定しない | EK チェーンはメーカー CA ではなくホスト・プラットフォーム側の CA 等になる可能性があり、実装ごとの確認が必要。複製・スナップショット・移行時の鍵保護も要確認 |
| クラウド（AWS / GCP / Azure 等） | TPM / vTPM の提供有無、利用可能な機種・機能・デバイス・証明情報を配置候補ごとに確認 | EK チェーンと信頼アンカー、PCR の測定範囲、管理者・基盤への信頼、移行・バックアップ時の非複製性 |
| K8s Pod | 物理 / 仮想 TPM を使うホスト上で `/dev/tpmrm0` の公開、device plugin 等による割当、デバイス権限・セキュリティポリシーを設計 | ホスト PCR とコンテナイメージ・承認検証コードの測定の関係、複数 Pod の鍵分離、再配置時の同一鍵利用の可否 |

K8s の **hostNetwork はネットワーク設定であり、TPM デバイスの公開・権限を付与しない**。デバイスアクセスは別に設計する。クラウド上の K8s なら、クラウド / vTPM と Pod の両方の制約を満たす必要がある。

`fixedTPM` / `fixedParent` の鍵を異なる TPM のホストへ移して同じように使うことは前提にしない。Pod の再配置・VM の移行とノード ID の継続性が両立するかを確認し、機器交換は既存の新ノード登録・失効・Resharing と整合させる。

ノード配置先（物理 TPM / vTPM / クラウド）と `/dev/tpmrm0` へのアクセス、K8s の device plugin・権限は **【要確認】**のまま残す（tech-stack.md §8-5）。本書の採用方針を配置決定と読み替えない。

## 9. 未解決事項

- TPM 実機の要件・ノード配置先と `/dev/tpmrm0` へのアクセス。K8s の device plugin・権限・再配置時の鍵と ID の継続性（tech-stack.md §8-5）。
- EK チェーンの検証、メーカー CA の取得・失効確認、AK と EK の結合、vTPM・ソフト TPM の扱い（seal-authentication.md §3.2・§8.1）。
- CI で swtpm を動かすための実行方法・権限（tech-stack.md §6）。
- tss-esapi の `bundled` + `generate-bindings` を使う公開リリースの選定、同梱ビルド・静的リンク・対象環境への配布の成立性。安定リリースの feature 制約を踏まえて検証する（tech-stack.md §3.2・§6・§7 R2）。
- TPM 署名遅延の実測（数十〜数百 ms 想定【要確認】）と、同期 Signer・専用スレッドプール・QUIC ハンドシェイクの統合（seal-authentication.md §2.4、tech-stack.md §7 R3）。
- Bao クライアント鍵の TPM 直接利用に関する仕様確認と、ローカル TLS プロキシ案の採否（seal-authentication.md §8.2）。
- 測定起動の範囲、PCR 選択・ソフトウェア更新時のポリシー維持、実行時侵害に対する限界の検証（threshold-crypto.md §4.5）。
- Raft ログのハッシュ鎖の固定先として TPM NV を採用するか（seal-authentication.md §6.4 末尾）。
- 承認端末の秘密から Share 保存鍵を導出する強化案（threshold-crypto.md §6.1）。
