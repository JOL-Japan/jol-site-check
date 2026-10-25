# かんたんサイト診断（JOL）

https://jol-jp.com/tools/site-check/ のソースコードです。
入力いただいた情報がどこへ送られ、診断で相手のサイトに何をしているかを、どなたでも確かめられるように公開しています。

ライセンスは **閲覧のみ可**（[LICENSE](LICENSE)）です。読む・手元で動かして確かめることはできますが、転用・再配布はできません。

このリポジトリは公開用の写しです。Pull Request などの変更は受け付けていません。不具合や安全上の問題は、下の「お問い合わせ」からお知らせください。

## このツールがすること・しないこと

| | 内容 | 該当するコード |
|---|---|---|
| 入力 | 「URLで調べる」はサイトのURL・メールアドレスだけ、「会社名から調べる」は会社名・メールアドレスだけ | [tools/site-check/app.js](tools/site-check/app.js) |
| 会社名から調べる | 「会社名から調べる」を使ったときだけ、ホームページの候補を探すために **会社名だけ** を検索サービス（Firecrawl）に送ります。メールアドレスは送りません。同じ会社名の結果は24時間使い回します | [api/_findsite.js](api/_findsite.js) |
| 送信先 | `https://jol-jp.com/api/site-check` のみ。ページの設定（CSP）で、ほかの宛先へは送れないようにしています | [tools/site-check/index.html](tools/site-check/index.html) |
| 診断 | ふだんは入力されたページに GET を **1回** 送るだけです（サイト側の転送は5回まで追います）。表示できないときだけ読み直します：証明書の設定に不備があれば検証を外して1回、https に繋がらなければ http で1回、それでもだめなら同じサイトのトップページを同じ手順で。1回の診断で使う時間は15秒までです。ログイン・パスの総当たり・脆弱性の試し打ちはしません | [api/_sitescan.js](api/_sitescan.js) |
| 接続しない先 | 社内ネットワーク・クラウドの管理用などの公開されていないアドレス（IPv6・IPv4を埋め込んだ形も含む）、IPアドレスの直接指定、80/443以外のポート。転送先も毎回同じ基準で確かめます | [api/_sitescan.js](api/_sitescan.js) `normalizeUrl` `isPrivateIp` |
| 画面に出すもの | PHP・WordPress の有無とリスクの目安だけ。版数などは、悪用を防ぐため画面に出しません | [api/_sitescan.js](api/_sitescan.js) `toPublic` |
| リスクがありそうなとき（高い可能性・要確認） | 「提案を待つ」「問い合わせる」「何も対策しない」から選べます。「何も対策しない」を選ぶと、JOLからは連絡しません。自由記述を送るのは「問い合わせる」のときだけです。選んだ対応は、診断のときに発行した署名つきの受付番号と同じサイト・メールのときだけ受け付けます | [tools/site-check/app.js](tools/site-check/app.js) [api/site-check.js](api/site-check.js) |
| シェア画像 | 「リンクをシェアする」で作る画像は、ブラウザの中で描きます。中身は診断結果だけで、会社名・サイトのURLは入れません | [tools/site-check/app.js](tools/site-check/app.js) `drawShare` |
| 保存 | ブラウザには保存しません。サーバーでも保存せず、JOL社内の管理システムにだけ転送します（「会社名から調べる」の会社名は上のとおり検索サービスに送ります） | [api/site-check.js](api/site-check.js) [api/_forward.js](api/_forward.js) |
| ログ | 入力値は残しません。残すのは結果の種類（例：`level=y`）だけ | [api/site-check.js](api/site-check.js) |
| 回数制限 | 人が続けて使うのは止めません。止めるのはボットらしい使い方だけです（入力画面を開いてすぐの送信、同じIPアドレスから15秒に3回を超える連打、同じIPアドレスから1時間に60回超、同じサイトへ1時間に30回超） | [api/site-check.js](api/site-check.js) [api/_ratelimit.js](api/_ratelimit.js) |
| 計測 | 広告・アクセス解析のタグはありません | [tools/site-check/index.html](tools/site-check/index.html) |

## 配信中のファイルと同じか確かめる

ブラウザで動くファイルは、[CHECKSUMS.txt](CHECKSUMS.txt) のハッシュと照らし合わせられます。

```sh
curl -s https://jol-jp.com/tools/site-check/app.js | shasum -a 256
curl -s https://jol-jp.com/tools/site-check/ | shasum -a 256   # index.html
```

サーバー側（`api/`）は外から中身を取り出せないため、ハッシュでの照合はできません。
ブラウザ側のファイルで「送信先が `/api/site-check` だけ」であることは確かめられます。

## 手元でテストする

Node.js 20 以上で:

```sh
node --test tests/site-check.test.mjs
```

## お問い合わせ

不具合や安全上の問題に気づいた場合は https://jol-jp.com/contact からお知らせください。

運営：株式会社NUTS（JOL）
