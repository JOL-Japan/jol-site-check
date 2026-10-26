/*
 * サイト攻撃リスク診断 会社名からホームページの候補を探す (Vercel Function 内部モジュール)
 *
 * URL をコピーして貼るのが難しい方向けに、会社名で検索して「このサイトですか？」と候補を出す。
 * 検索は Firecrawl の検索 API に1回だけ問い合わせる (日本向けの結果)。送るのは会社名だけ。
 * (DuckDuckGo の HTML 版は鍵が要らないが、数回の自動検索で確認画面を返すようになり使えなかった)
 * 求人・企業データベース・SNS などは公式サイトではないので候補から外し、1サイト1件にまとめる。
 * 候補は診断と同じ基準 (normalizeUrl) で確かめ、トップページの URL だけを返す。
 *
 * 検索の枠 (費用・毎分の上限) を使い切られないように:
 *   - 会社名らしくない入力 (URL・検索演算子・長すぎる文) は検索しない。返すのもドメインとタイトルだけで、
 *     一般の検索の代わりには使いにくくしてある
 *   - 同じ会社名の結果は24時間使い回す (検索に行かない)
 *   - 実際に検索へ行く回数を、全体で1分に8回・1日に300回までに抑える (Firecrawl の無料枠は1分10回)
 *     記録は関数インスタンスのメモリ上なので、インスタンスが増えればその分だけ緩む
 */

import { normalizeUrl, topOf } from "./_sitescan.js";

const SEARCH_URL = "https://api.firecrawl.dev/v2/search";
const RESULTS = 10; // 除外したあとに候補が残るよう、出す数より多めに取る
const TIMEOUT_MS = 6000;
export const MAX_SITES = 5;
const CACHE_MS = 24 * 60 * 60 * 1000; // 同じ会社名の結果を使い回す長さ
const CACHE_MAX = 1000;
const SEARCH_PER_MIN = 8;
const SEARCH_PER_DAY = 300;
const MINUTE_MS = 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const NAME_MIN = 2;
const NAME_MAX = 60;

/** 検索の全体の上限に達したときの例外 (少しおけば通る) */
export class SearchBusyError extends Error {}

/**
 * 会社名を検索に使える形に整える。会社名らしくなければ null
 * (URL・検索演算子・引用符・改行を含むもの、短すぎ・長すぎるもの)
 */
export function cleanCompany(v) {
  const s = String(v ?? "")
    .normalize("NFKC")
    .replace(/\s+/g, " ")
    .trim();
  if (s.length < NAME_MIN || s.length > NAME_MAX) return null;
  if (
    /[\x00-\x1f"<>]|:\/\/|www\.|\b(site|inurl|intitle|filetype|related|cache):/i.test(
      s,
    )
  )
    return null;
  if (/(^|\s)[-+]\S|\s(OR|AND)\s/.test(s)) return null;
  return s;
}

const cache = new Map();
function cached(key, now) {
  const hit = cache.get(key);
  if (hit && now - hit.at < CACHE_MS) return hit.sites;
  cache.delete(key);
  return null;
}
function remember(key, sites, now) {
  cache.set(key, { sites, at: now });
  // 増えすぎたら古いものから捨てる (Map は入れた順)
  if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
}
// 全体の上限内なら検索1回分を記録して true。IP ごとの記録 (_ratelimit.js) は増えすぎると古い key から捨てるため、
// 多くの IP から送られると全体の記録まで消えて上限が効かなくなる。ここに分けて持つ (最大 SEARCH_PER_DAY 件)
let searchTimes = [];
function tryTakeSearchSlot(now) {
  searchTimes = searchTimes.filter((t) => now - t < DAY_MS);
  const lastMinute = searchTimes.filter((t) => now - t < MINUTE_MS).length;
  if (lastMinute >= SEARCH_PER_MIN || searchTimes.length >= SEARCH_PER_DAY) return false;
  searchTimes.push(now);
  return true;
}

// テスト用
export function resetFindCache() {
  cache.clear();
  searchTimes = [];
}

// 公式サイトではないもの (ドメインの末尾で判定する)
const NOT_OFFICIAL = [
  // 百科事典・地図・動画・SNS・ブログ
  "wikipedia.org",
  "google.com",
  "google.co.jp",
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "x.com",
  "twitter.com",
  "linkedin.com",
  "tiktok.com",
  "line.me",
  "note.com",
  "ameblo.jp",
  "hatenablog.com",
  // 求人
  "indeed.com",
  "en-gage.net",
  "en-japan.com",
  "doda.jp",
  "mynavi.jp",
  "rikunabi.com",
  "townwork.net",
  "baitoru.com",
  "wantedly.com",
  "green-japan.com",
  "type.jp",
  "job-medley.com",
  "stanby.com",
  "openwork.jp",
  "jobtalk.jp",
  "hatalike.jp",
  "sumikominavi.com",
  "en-hyouban.com",
  "career-tasu.jp",
  "careermap.jp",
  "ryunavi.com",
  // 企業データベース・地図・不動産 (法人番号などの国のサイトは go.jp でまとめて外す)
  "houjin.info",
  "houjin.jp",
  "lawplayer.com",
  "baseconnect.in",
  "salesnow.jp",
  "musubu.in",
  "alarmbox.jp",
  "ullet.com",
  "buffett-code.com",
  "tdb.co.jp",
  "tsr-net.co.jp",
  "catr.jp",
  "bizmaps.jp",
  "kaisharesearch.com",
  "nikkei.com",
  "prtimes.jp",
  "mapion.co.jp",
  "itp.ne.jp",
  "navitime.co.jp",
  "yahoo.co.jp",
  "compalyze.co.jp",
  "kensetumap.com",
  "metoree.com",
  "nc-net.or.jp",
  "jmap.jp",
  "athome.co.jp",
  "suumo.jp",
  "homes.co.jp",
  "fukunavi.or.jp",
  "minnanokaigo.com",
  // 口コミ・通販
  "ekiten.jp",
  "hotpepper.jp",
  "tabelog.com",
  "amazon.co.jp",
  "rakuten.co.jp",
  "minkabu.jp",
];

// 国・自治体のサイト (go.jp / lg.jp / pref.〇〇.jp・city.〇〇.jp など) は、会社を紹介していても会社のホームページではない
const isOfficialHost = (host) =>
  !/\.(go|lg)\.jp$|(^|\.)(pref|city|town|vill)\.[a-z]+\.jp$/.test(host) &&
  !NOT_OFFICIAL.some((d) => host === d || host.endsWith("." + d));
// 一覧にない求人・口コミ・株価のページも、タイトルで外す
const NOT_OFFICIAL_TITLE = /求人|転職|評判|口コミ|株価/;

/** 公式サイトらしいものだけを、1サイト1件・最大 MAX_SITES 件にまとめる。url はトップページ */
export function pickSites(results) {
  const seen = new Set();
  const out = [];
  for (const r of results) {
    const u = normalizeUrl(r.url);
    if (!u) continue;
    const host = new URL(u).hostname.toLowerCase();
    const key = host.replace(/^www\./, "");
    if (
      seen.has(key) ||
      !isOfficialHost(host) ||
      NOT_OFFICIAL_TITLE.test(r.title)
    )
      continue;
    seen.add(key);
    out.push({ url: topOf(u), host, title: r.title.slice(0, 80) });
    if (out.length >= MAX_SITES) break;
  }
  return out;
}

/**
 * 会社名で検索して、ホームページの候補を返す
 * 環境変数: FIRECRAWL_API_KEY (未設定なら検索しない)
 * @param {string} company 会社名 (cleanCompany で整えたもの)
 * @returns {Promise<{url: string, host: string, title: string}[]>} 見つからなければ空
 * @throws {SearchBusyError} 検索の全体の上限に達したとき
 * @throws 鍵が未設定・検索先につながらない・エラーを返したとき
 */
export async function findSites(
  company,
  {
    fetchImpl = fetch,
    apiKey = process.env.FIRECRAWL_API_KEY,
    now = Date.now(),
  } = {},
) {
  if (!apiKey) throw new Error("search is not configured");
  const key = company.toLowerCase();
  const hit = cached(key, now);
  if (hit) return hit;
  if (!tryTakeSearchSlot(now))
    throw new SearchBusyError("search is busy");
  const r = await fetchImpl(SEARCH_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: company,
      limit: RESULTS,
      country: "JP",
      location: "Japan",
    }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`search failed: ${r.status}`);
  const j = await r.json();
  const pages = j?.data?.web ?? [];
  const sites = pickSites(
    pages.map((p) => ({
      url: String(p.url ?? ""),
      title: String(p.title ?? ""),
    })),
  );
  remember(key, sites, now);
  return sites;
}
