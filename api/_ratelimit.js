/*
 * 送信APIの回数制限 (Vercel Function 内部モジュール)
 *
 * 同じ IP からの連続送信を、一定時間あたりの回数で止める。
 * 記録は関数インスタンスのメモリ上なので、インスタンスをまたいだ厳密な制限ではない
 * (一つのスクリプトからの連打を止めるための一次防御)。
 * 全体での厳密な制限は、配信側の設定でも行う。
 */

const buckets = new Map();
const MAX_KEYS = 5000;

// Vercel が付ける IP ヘッダーを優先 (x-forwarded-for は先頭がクライアント)
export function clientIp(req) {
  const h = req?.headers ?? {};
  const raw = h["x-vercel-forwarded-for"] || h["x-real-ip"] || h["x-forwarded-for"] || "";
  return String(raw).split(",")[0].trim() || "unknown";
}

// key ごとに windowMs の間 limit 回まで許可する。超えたら false
export function allow(key, { limit, windowMs }, now = Date.now()) {
  const hits = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);
  if (hits.length >= limit) {
    buckets.set(key, hits);
    return false;
  }
  hits.push(now);
  buckets.set(key, hits);

  // 記録が増えすぎたら古い key から捨てる (メモリを食い潰されないように)
  if (buckets.size > MAX_KEYS) {
    for (const k of buckets.keys()) {
      buckets.delete(k);
      if (buckets.size <= MAX_KEYS / 2) break;
    }
  }
  return true;
}

// テスト用
export function resetRateLimit() {
  buckets.clear();
}
