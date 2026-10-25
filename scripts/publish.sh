#!/bin/sh
# 公開する手順はこれだけ。ファイルを写して調べ（sync.sh）、コミットし、コミットの中身も調べてから push する。
#   使い方: scripts/publish.sh <サイトのリポジトリのパス> "変更の説明"
# 次のどれかに当たれば push しない:
#   - 作成者・コミッターのメールが GitHub の匿名アドレス (…@users.noreply.github.com) ではない
#   - コミットのメッセージにメールアドレス・URL・作業セッションなどの記録 (Claude-Session 等) が入っている
set -eu
SRC="${1:?サイトのリポジトリのパスを指定してください}"
MSG="${2:?変更の説明を指定してください}"
cd "$(dirname "$0")/.."

ANON='^[0-9]+\+[A-Za-z0-9-]+@users\.noreply\.github\.com$'
email="$(git config user.email || true)"
echo "$email" | grep -qE "$ANON" || { echo "コミットのメールを GitHub の匿名アドレスにしてください（git config user.email）: $email" >&2; exit 1; }

# 説明文そのものも、コミットする前に調べる
bad_msg() { grep -qiE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https?://|claude-session|session_[A-Za-z0-9]{8,}|co-authored-by' ; }
printf '%s' "$MSG" | bad_msg && { echo "説明にメールアドレス・URL・作業の記録は入れないでください" >&2; exit 1; }

./scripts/sync.sh "$SRC"
git add -A
git diff --cached --quiet && { echo "変更はありません"; exit 0; }
git commit -q -m "$MSG"

# これから push するすべてのコミットを調べる（ほかの手順で作られたコミットが混ざっていても止める）
git fetch -q origin 2>/dev/null || true
range="HEAD"; git rev-parse -q --verify origin/main >/dev/null && range="origin/main..HEAD"
bad=0
for c in $(git rev-list "$range"); do
  ae="$(git log -1 --format=%ae "$c")"; ce="$(git log -1 --format=%ce "$c")"
  echo "$ae" | grep -qE "$ANON" || { echo "作成者のメールが匿名アドレスではないコミットがあります: $(git log -1 --format=%h "$c")" >&2; bad=1; }
  echo "$ce" | grep -qE "$ANON" || { echo "コミッターのメールが匿名アドレスではないコミットがあります: $(git log -1 --format=%h "$c")" >&2; bad=1; }
  git log -1 --format=%B "$c" | bad_msg && { echo "メッセージにメールアドレス・URL・作業の記録があるコミットがあります: $(git log -1 --format=%h "$c")" >&2; bad=1; }
done
[ "$bad" = 0 ] || { echo "push を止めました。該当のコミットを作り直してください" >&2; exit 1; }
git push -q origin HEAD:main
echo "公開しました"
