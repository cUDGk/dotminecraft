# `.minecraft` Self-Certifying Tunnel — 実装仕様書

## 0. この文書について

本システムの設計仕様書。
中央レジストリ・DNS・ポート開放・グローバルIPのいずれにも依存せず、Minecraft サーバーを `xxxx.minecraft` という自己証明アドレスで外部公開・接続できるシステムを作る。設計思想は Tor onion service v3 と同型。

**言語: Rust（理由は §9 セキュリティ要件参照）。OSS 公開前提。**

---

## 1. �目的と非目標

### 目的
- 鯖主が MC サーバーを `xxxx.minecraft` というアドレスで晒せる
- 利用者がそのアドレスだけで接続できる（IP・ポート・ドメイン不要）
- 名前の一意性と成りすまし不可を、**中央登録所なしで暗号的に**保証する
- メモリ安全なネットワークコードで untrusted 入力を捌く

### 非目標（スコープ外。実装しない）
- 低レイテンシ保証（趣味鯖前提。PvP 競技用途は想定外）
- Bedrock 対応（UDP。本仕様は **TCP / Java Edition のみ**）
- 匿名性の強保証（所在隠蔽は relay 経由で「多少」効く程度。Tor 級の匿名性は約束しない）
- 独自ブロックチェーン・独自 DHT のフルスクラッチ実装（libp2p の既製品に乗る）

---

## 2. 用語

| 用語 | 意味 |
|------|------|
| daemon | 本体バイナリ。publish モードと connect モードを持つ |
| name / アドレス | `[vanity].[keyid].minecraft` 形式の文字列 |
| keyid | アドレスの一意性・認証を担う 16字（鍵由来）部分 |
| vanity | アドレス先頭の任意 0〜8字の飾りラベル |
| publish | 鯖主側モード。名前を生やし DHT に自分を公告する |
| connect | 利用者側モード。名前を引いてトンネルを張りローカルポートを開く |
| record | DHT に置く署名付きの「自分の現在地」レコード |

---

## 3. アーキテクチャ全体像

両端とも **同じ daemon バイナリ**を動かす。違いは起動モードのみ。構造は対称。

```
鯖主側:
  MC server (localhost:25565)
        │
        ▼
  daemon --publish        ── ed25519鍵を保持 / 名前を生やす
        │                    DHTに署名付きrecordをput
        ▼
  [ libp2p network: Kademlia DHT + NAT越え + Circuit Relay v2 ]
        ▲
        │
  daemon --connect <name> ── 名前をkeyidにデコード → DHTでget
        │                    署名検証 → libp2pで接続
        ▼
  localhost:25566         ── 利用者はここにMCで繋ぐ
        ▲
        │
  Minecraft client ("サーバー追加" に localhost:25566)
```

データの流れ（接続確立後）:
```
MC client <-TCP-> connect daemon <-libp2p stream(暗号化)-> publish daemon <-TCP-> MC server
```

daemon は両モードとも本質的に **TCP ↔ libp2p stream の双方向 proxy**。向きが違うだけ。

---

## 4. 名前仕様（self-certifying name）

### 4.1 フォーマット

```
[vanity].[keyid].minecraft
```

- `keyid`: **必須・16字**。`base32(hash(pubkey))` の先頭16字。一意性と認証の本体。
- `vanity`: **任意・0〜8字**。飾りラベル。省略可。
- `.minecraft`: 固定サフィックス。

例:
```
k7f3xq2m9bv8nt4a.minecraft              (vanityなし, 16字)
survival.k7f3xq2m9bv8nt4a.minecraft     (vanity 8字 → 合計 8+16 = 24字)
```

### 4.2 keyid の導出

```
1. ed25519 鍵ペアを生成 (signing key / verifying key)
2. h = SHA-256(verifying_key_bytes)        # 32バイト
3. b32 = base32_nopad_lower(h)             # RFC4648, パディング無し, 小文字
   charset = a-z 2-7  (0/o, 1/l の混同が無い)
4. keyid = b32[:16]                         # 先頭16字 = 80ビット相当
```

- charset は **Tor と同じ base32 (a-z2-7)**。`0 1 8 9` を含めないことで誤読を防ぐ。
- 16字 = 80ビット。偶然衝突は誕生日限界 2^40 まで実質発生せず、狙った成りすまし(second-preimage)は 2^80 で非現実的。趣味ネット用途として妥当。
- **名前長は設定で伸長可能にする**こと。`--keyid-len`（既定16、最大52）。長くするほどビットが増える単純なダイヤル。Tor 級にしたい人が 26字(130bit) を選べるようにする。

### 4.3 vanity（前8字）の扱い

**2モードを実装する。既定は (A)。**

- **(A) ラベルモード（既定 / コストゼロ）**
  vanity は record 内に含めて署名するだけ。network 一意ではない（別人が自分の identity 下で同名 vanity を名乗れる）。だが **DHT 検索キーは keyid なので実害なし**。本人が名乗ったことだけは署名で証明される。
- **(B) vanity grinding（オプション / 計算コスト大）**
  `--vanity-prefix <str>` 指定時、keyid が望みの文字列で始まる鍵が出るまで鍵生成を総当たり。`.onion` の vanity アドレスと同手法。コスト目安（base32）:

  | prefix長 | 試行回数 | 体感 |
  |---|---|---|
  | 4字 | ~10^6 | 一瞬 |
  | 5字 | ~3×10^7 | 数秒 |
  | 6字 | ~10^9 | 数分 |
  | 7字 | ~3×10^10 | かなり重い |
  | 8字 | ~10^12 | 時間〜日 |

  grinding はマルチスレッドで回す。途中経過（試行数/秒・経過秒）を stderr に出す。`Ctrl-C` で中断可能。

### 4.4 デコード（接続時）

```
1. name から keyid 部分(末尾16字相当の鍵由来パート)を抽出
2. keyid は pubkey ハッシュの prefix なので、これ単体では pubkey を復元できない
   → DHT record に full verifying_key を含めて配布する（§5.2）
3. record取得後: SHA-256(record.pubkey)[:keyid_len] == keyid を検証
   一致しなければ拒否（成りすまし防止の要）
```

---

## 5. ネットワーク層（libp2p）

### 5.1 採用機能（自作しない）

rust-libp2p の既製機能に乗る:

- **Identity / PeerId**: ed25519。PeerId 自体が self-certifying。本システムの keyid とは別レイヤだが、署名検証の土台に使う。
- **Kademlia DHT**: record の put/get。
- **NAT越え**: AutoNAT + DCUtR(hole punching) + Circuit Relay v2。NAT 内同士でも繋がるように。relay 経由でも stream は E2E 暗号化される。
- **トランスポート暗号化**: Noise。
- **多重化**: yamux。
- **トランスポート**: TCP + QUIC（両方有効。QUIC があると hole punch 成功率が上がる）。

### 5.2 DHT レコード仕様

DHT key:
```
dht_key = SHA-256("mc-tunnel:v1:" || keyid_full)
```
※ keyid_full は truncate 前の full hash を使い、衝突空間を最大化する。

DHT value（署名付き。CBOR か MessagePack でシリアライズ）:
```
{
  "v":        1,                       // プロトコルバージョン
  "pubkey":   <32 bytes>,              // ed25519 verifying key（keyid検証用）
  "peer_id":  "<libp2p PeerId>",       // 接続先
  "addrs":    ["<multiaddr>", ...],    // 現在の到達可能アドレス（relay含む）
  "vanity":   "survival",              // 任意ラベル(A)。無ければ空文字
  "ts":       <unix秒>,                // 発行時刻（リプレイ対策）
  "ttl":      600                      // 秒
}
sig = ed25519_sign(signing_key, canonical_bytes(上記))
```

検証手順（connect 側）:
```
1. sig を pubkey で検証 → 失敗なら破棄
2. SHA-256(pubkey)[:keyid_len] == 要求した keyid → 不一致なら破棄
3. ts が現在時刻 ± 許容ズレ（例 ±300s）以内 → 外れたら破棄（古いrecord拒否）
4. 一番新しい(ts最大)かつ検証通過の record を採用
```

publish 側は **ttl/2 ごとに再 put** して鮮度を保つ。IP 変化時は即 put。

### 5.3 ブートストラップ

- 既定で **自前 bootstrap ノード**のアドレスを設定に持つ（OSS なら 1〜数台立てる前提。アドレスは config で差し替え可）。
- IPFS public DHT への相乗りは **オプション**（`--use-ipfs-dht`）。公共網に趣味データを撒くことになるので既定オフ。
- bootstrap ノードは単なる libp2p ノード。特権なし。落ちても既存接続は維持される（中央依存を作らない）。

---

## 6. プロキシ層

### 6.1 publish 側
```
- libp2p に custom protocol "/mc-tunnel/1.0.0" を登録
- 着信 inbound stream を受けたら localhost の MC server(既定 127.0.0.1:25565) へ TCP 接続
- stream ⇄ TCP を全二重コピー（tokio::io::copy_bidirectional 相当）
- どちらか片方が閉じたら両方クローズ
- 同時接続数の上限を設定可能に（--max-conns、既定 32）
```

### 6.2 connect 側
```
- localhost(既定 127.0.0.1:25566) で TCP listen
- 接続が来るたびに publish peer へ outbound stream を開く
- TCP ⇄ stream を全二重コピー
- peer 切断時はローカル接続も切る。再 resolve は次回接続時に行う
```

### 6.3 注意
- MC のハンドシェイクには一切介入しない（生バイトを素通し）。MC から見れば普通の TCP サーバー。
- 接続ごとに stream を分ける（1接続=1stream）。

---

## 7. daemon / CLI 仕様

### 7.1 サブコマンド

```
mc-tunnel init
    新規 ed25519 鍵を生成し keyid を表示。鍵を鍵ストアに保存。
    --vanity-prefix <str>   (B)モード grinding
    --keyid-len <n>         既定16, 最大52
    既存鍵があれば上書きせず警告（--force で上書き）

mc-tunnel name
    現在の鍵から導出される自分のアドレスを表示
    例: survival.k7f3xq2m9bv8nt4a.minecraft

mc-tunnel publish
    publish モードで常駐。MC server を晒す。
    --target <addr>     既定 127.0.0.1:25565
    --vanity <label>    (A)ラベル付与
    --max-conns <n>     既定 32

mc-tunnel connect <name>
    connect モードで常駐。ローカルポートを開く。
    --listen <addr>     既定 127.0.0.1:25566
    終了時にポート開放

mc-tunnel doctor
    疎通診断（bootstrap到達性, NAT種別, relay利用可否, 自分のmultiaddr）
```

### 7.2 設定ファイル

`~/.config/mc-tunnel/config.toml`（XDG 準拠 / OS 標準パス）:
```toml
[network]
bootstrap = ["/dns4/boot1.example/tcp/4001/p2p/12D3Koo...", ...]
use_ipfs_dht = false
keyid_len = 16

[publish]
target = "127.0.0.1:25565"
vanity = "survival"
max_conns = 32

[connect]
listen = "127.0.0.1:25566"
```
CLI フラグが config を上書きする優先順位にする。

### 7.3 出力
- 人間向けは stderr、機械向け(`--json`)は stdout。
- ログは `tracing` クレートで構造化。`RUST_LOG` で制御。

---

## 8. 鍵管理

- ed25519 秘密鍵は **鍵ストアに保存**。保存先優先順位:
  1. OS キーストア（macOS Keychain / Windows Credential Manager / Linux Secret Service）。`keyring` クレート利用。
  2. フォールバック: `~/.config/mc-tunnel/identity.key`、**パーミッション 0600**（Unix）で保存。Windows は ACL を本人のみに。
- 鍵はメモリ上で `zeroize` し、不要時にゼロ消去。
- **秘密鍵を stdout/ログ/DHT に絶対出さない**。`name` コマンドが出すのは公開情報(keyid)のみ。

---

## 9. セキュリティ要件（最重要）

untrusted な外部入力（libp2p stream、DHT record、MC からの TCP）を捌くため、以下を必須要件とする。

1. **Rust / `#![forbid(unsafe_code)]`** をクレート全体に課す。やむを得ず unsafe を使う場合は理由をコメントし監査対象として隔離。
2. **全ての外部入力をパース前に長さ・型検証**。DHT value のデシリアライズは上限サイズを設ける（DoS 対策）。
3. **署名検証を通らない record は一切信頼しない**（§5.2 の4手順を厳守）。
4. **keyid ↔ pubkey の一致検証を省略しない**。ここが成りすまし防止の要。
5. **リプレイ対策**: record の `ts` を検証。古い record で旧IPに誘導する攻撃を弾く。
6. **localhost バインド既定**。proxy の listen は既定で 127.0.0.1。`0.0.0.0` にするには明示フラグ＋警告。
7. **接続数・帯域のレート制限**で proxy を増幅攻撃の踏み台にしない。
8. **依存監査を CI に組み込む**: `cargo audit`（既知脆弱性）, `cargo deny`（ライセンス/重複）。
9. **fuzzing**: record パーサとプロトコルフレーミングに `cargo fuzz` のターゲットを用意。
10. **暗号は枯れた crate のみ**: `ed25519-dalek`, `sha2`, Noise は libp2p 同梱。自作暗号禁止。
11. MOD（Java, §11）には **鍵もネットワーク信頼境界も置かない**。MOD が漏れても daemon の信頼境界は割れない設計を維持する。

---

## 10. マイルストーン（この順で実装）

> 各 M は単体で動作確認できる単位。前を完成させてから次へ。

- **M0: スケルトン**
  Cargo workspace 構成。`init` / `name` が動く（鍵生成→keyid 表示）。`#![forbid(unsafe_code)]` 設定。
- **M1: libp2p 疎通**
  ノード2つ起動し ping が通る。bootstrap 接続確認。`doctor` の原型。
- **M2: DHT put/get**
  publish が署名付き record を put、connect が get して §5.2 の全検証を通す。まだ proxy はしない。
- **M3: proxy（コア完成）**
  M2 の上に §6 の双方向 proxy を載せる。**MOD なしで MC が `localhost:25566` 経由で繋がる**。← ここが OSS 初版(v0.1)。
- **M4: NAT越え強化**
  relay v2 / DCUtR を有効化し、NAT 内同士の疎通を確認。`doctor` で NAT 種別を判定。
- **M5: vanity grinding (B)**
  `--vanity-prefix` のマルチスレッド grinding。
- **M6: 堅牢化**
  fuzz ターゲット, レート制限, `cargo audit`/`deny` を CI 化。v1.0 へ。

---

## 11. MOD（フェーズ2 / 別リポジトリ可）

- 位置づけ: **利用者側 daemon のお化粧**。コアには一切手を入れない。
- Fabric MOD として実装。バックグラウンドで connect daemon を起動 or 既存 daemon に IPC 接続し、サーバーリストに入力された `xxxx.minecraft` を検知 → daemon に resolve させ → 接続先を `localhost:<port>` にすり替える。
- Java ↔ Rust は **ローカル IPC**（daemon が localhost で制御ポートを開き MOD はそこに JSON で喋る）。JNI は避ける（攻撃面・ビルド複雑性増）。
- MOD は鍵を扱わない。resolve 要求と接続先取得のみ。

---

## 12. リポジトリ構成（提案）

```
mc-tunnel/
├── Cargo.toml            # workspace
├── crates/
│   ├── core/             # 名前導出, record, 署名, 検証（unsafe禁止, テスト厚め）
│   ├── net/              # libp2p ラッパ（DHT, transport, relay）
│   ├── proxy/            # TCP ⇄ stream 双方向コピー
│   └── cli/              # daemon バイナリ (init/name/publish/connect/doctor)
├── fuzz/                 # cargo-fuzz ターゲット
├── .github/workflows/    # test + cargo audit + cargo deny + clippy
├── README.md             # Rust採用理由・脅威モデル・使い方を明記
└── SECURITY.md           # 脆弱性報告窓口
```

主要 crate: `libp2p`(kad,noise,yamux,tcp,quic,relay,dcutr,autonat), `ed25519-dalek`, `sha2`, `data-encoding`(base32), `tokio`, `serde`+`ciborium`(CBOR), `keyring`, `zeroize`, `tracing`, `clap`, `anyhow`/`thiserror`。

---

## 13. 受け入れ条件（Definition of Done for v0.1 = M3）

- [ ] `mc-tunnel init` で鍵生成、`mc-tunnel name` でアドレス表示
- [ ] 別マシン（または別プロセス）で publish した鯖に、name だけで connect でき、MC で実際にワールドに入れる
- [ ] 改竄した record / 署名不正 / keyid 不一致 / 古い ts の record を connect が拒否する（テストで保証）
- [ ] `#![forbid(unsafe_code)]` が全 crate で有効
- [ ] `cargo test` / `cargo clippy -- -D warnings` / `cargo audit` が CI で緑
- [ ] README に脅威モデルと「これは Tor 級の匿名性を保証しない」旨を明記
