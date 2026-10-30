#!/bin/sh
# 非公開のサイトのリポジトリから、かんたんサイト診断のファイルだけを写し、
# 配信されるファイルのハッシュを CHECKSUMS.txt に書き出す。
# 公開してはいけない語が1つでも入っていれば、何も書き換えずに止める。
#   使い方: scripts/sync.sh <サイトのリポジトリのパス>
set -eu
SRC="${1:?サイトのリポジトリのパスを指定してください}"
DENY="$SRC/scripts/oss-denylist.txt"
cd "$(dirname "$0")/.."
FILES="tools/site-check/index.html tools/site-check/app.js tools/site-check/styles.css tools/site-check/pixel.js
tools/site-check/assets/logo-orange.svg tools/site-check/assets/logo-white.svg tools/site-check/assets/watermark.svg tools/site-check/assets/ad-boueitai.webp
api/site-check.js api/_sitescan.js api/_findsite.js api/_forward.js api/_ratelimit.js tests/site-check.test.mjs"

[ -f "$DENY" ] || { echo "禁止語の一覧がありません: $DENY" >&2; exit 1; }
bad=0
for f in $FILES; do
  [ -f "$SRC/$f" ] || { echo "見つかりません: $f" >&2; exit 1; }
  while IFS= read -r w; do
    case "$w" in ''|'#'*) continue;; esac
    if grep -qiF -- "$w" "$SRC/$f"; then echo "公開不可の語があります: $f" >&2; bad=1; fi
  done < "$DENY"
  # メールアドレス（例示用の example.* と GitHub の匿名アドレス以外）・鍵らしき文字列
  if grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$SRC/$f" | grep -vE '@example\.(com|co\.jp)$' | grep -q .; then echo "メールアドレスがあります: $f" >&2; bad=1; fi
  if grep -qE 'hooks\.slack|xox[abp]-|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE|gh[pousr]_[A-Za-z0-9]{20}|sk-[A-Za-z0-9]{20}' "$SRC/$f"; then echo "鍵らしき文字列があります: $f" >&2; bad=1; fi
done
[ "$bad" = 0 ] || { echo "公開を止めました（何も書き換えていません）" >&2; exit 1; }

for f in $FILES; do mkdir -p "$(dirname "$f")"; cp "$SRC/$f" "$f"; done
{
  echo "# jol-jp.com で配信しているファイルの SHA-256"
  echo "# 確認: curl -s https://jol-jp.com/<パス> | shasum -a 256"
  # index.html はサイトでは /tools/site-check/ で配信される
  for f in $FILES; do case "$f" in tools/*) p="/$f"; [ "$p" = /tools/site-check/index.html ] && p=/tools/site-check/; echo "$(shasum -a 256 "$f" | cut -d' ' -f1)  $p";; esac; done
} > CHECKSUMS.txt
# 最後に、公開フォルダ内のすべてのファイル（README・LICENSE などこちらで書いたものも）を同じ基準で調べる
for f in $(find . -type f -not -path './.git/*' -not -name sync.sh); do
  while IFS= read -r w; do
    case "$w" in ''|'#'*) continue;; esac
    if grep -qiF -- "$w" "$f"; then echo "公開不可の語があります: $f" >&2; bad=1; fi
  done < "$DENY"
  if grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$f" | grep -vE '@example\.(com|co\.jp)$' | grep -q .; then echo "メールアドレスがあります: $f" >&2; bad=1; fi
done
[ "$bad" = 0 ] || { echo "公開フォルダに公開不可の内容があります。公開しないでください" >&2; exit 1; }
echo "写しました（禁止語なし）"
