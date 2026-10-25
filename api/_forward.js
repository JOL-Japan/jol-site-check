/*
 * かんたんサイト診断の受付内容を、社内の管理システムへ送る (Vercel Function 内部モジュール)
 *
 * 環境変数:
 *   SITE_CHECK_FORWARD_URL   … 送り先 (POST JSON, HTTPS)
 *   SITE_CHECK_FORWARD_TOKEN … 送り先の Bearer トークン
 *
 * どちらか未設定なら "skipped"。失敗しても throw せず "error:<status|message>" を返す
 * (診断結果の表示には影響させない)。入力値はログに出さない。
 * 送り先がしばらく使われず起動に時間がかかることがあるので、待ち時間は長めにとり、
 * 応答がない・送り先のエラー (5xx) のときは1回だけ送り直す (受け取り側は同じサイトなら同じ案件にまとめる)。
 */

const TIMEOUT_MS = 12000;
const TRIES = 2;

// POST → "ok" | "skipped" | "error:<status|message>"  (throw しない)
export async function forward(payload, { timeoutMs = TIMEOUT_MS, waitMs = 1000 } = {}) {
  const url = process.env.SITE_CHECK_FORWARD_URL;
  const token = process.env.SITE_CHECK_FORWARD_TOKEN;
  if (!url || !token) return "skipped";
  let result = "error:unknown";
  for (let i = 0; i < TRIES; i++) {
    if (i) await new Promise((r) => setTimeout(r, waitMs));
    result = await sendOnce(url, token, payload, timeoutMs);
    // 送り直して意味があるのは、応答がない・つながらない・送り先のエラーのときだけ
    if (!/^error:(timeout|network|5\d\d)$/.test(result)) break;
  }
  return result;
}

async function sendOnce(url, token, payload, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    return res.ok ? "ok" : `error:${res.status}`;
  } catch (e) {
    return `error:${e?.name === "AbortError" ? "timeout" : "network"}`;
  } finally {
    clearTimeout(timer);
  }
}
