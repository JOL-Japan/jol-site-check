/*
 * かんたんサイト診断 受付 (Vercel Function)  /tools/site-check/ から呼ばれる
 *
 * 入力は「サイトのURL・会社名・メールアドレス」の3つだけ。
 * 1. 入力されたページを1回だけ見て (api/_sitescan.js)、PHP・WordPress・リスクの目安を判定
 * 2. 入力と判定の詳細を、社内の管理システムにだけ送って貯める (api/_forward.js)
 * 3. 画面には「あり/なし/リスクの目安」と受付番号 (rid) だけを返す
 * 4. リスクがありそうな結果で選んだ対応 (kind=choice) を、受付番号つきで同じ先へ送る
 *    wait=JOLからの提案を待つ / contact=JOLに問い合わせる / none=何も対策しない
 * 5. 会社名からホームページの候補を探す (kind=find, api/_findsite.js)。会社名だけを検索に使い、転送はしない
 *
 * 情報の取り扱い:
 *   - 入力値はこの関数では保存しない。ログにも出さない (ログは結果の種類だけ)
 *   - 送り先は社内の管理システムのみ (Bearer トークン付き・HTTPS)
 *   - 版数など攻撃の下調べに使える情報は画面に返さない。詳細は担当者が管理者本人と確認してから伝える
 *   - 人が続けて使うのは止めない。止めるのはボットらしい使い方だけ:
 *     見えない欄が埋まっている / 入力画面を開いてから送るまでが速すぎる (1秒未満) /
 *     同じIPから15秒に3回を超える連打 / 同じIPから1時間に60回超 / 同じサイトへ1時間に30回超 /
 *     会社名での候補探しは、同じIPから1分に3回超・1時間に10回超、ほかのサイトの画面からの送信も止める
 *     (検索全体の上限と会社名の確かめは api/_findsite.js)
 *   - 見えない欄・速すぎる送信は、人の誤判定でも困らないよう「もう一度押してください」と返す (偽の結果は返さない)
 *
 * 環境変数: api/_forward.js を参照 (未設定なら送らない)
 */

import { allow, clientIp } from "./_ratelimit.js";
import { forward } from "./_forward.js";
import { normalizeUrl, scanSite, judge, toPublic } from "./_sitescan.js";
import { findSites, cleanCompany, SearchBusyError } from "./_findsite.js";
import crypto from "node:crypto";

// 診断 (最大15秒) ＋ 送り先への転送 (最大12秒×2回) が収まる長さ
export const config = { maxDuration: 60 };

const EMAIL_RE = /^[^\s@<>()]+@[^\s@<>()]+\.[^\s@<>()]+$/;
const LEVEL_OUT = { r: "r", y: "y", g: "g", x: null };
const CHOICES = new Set(["wait", "contact", "none"]);

// 受付番号 = 乱数 + 署名。署名は「乱数・サイト・メール」に対して付けるので、
// 実際に診断した本人のブラウザ以外からは、選んだ対応 (kind=choice) を送れない
const RID_KEY = process.env.SITE_CHECK_RID_SECRET || process.env.SITE_CHECK_FORWARD_TOKEN || crypto.randomBytes(32).toString("hex");
const RID_RE = /^[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]{16}$/;
const ridSig = (r, host, email) => crypto.createHmac("sha256", RID_KEY).update(`${r}|${host}|${email.toLowerCase()}`).digest("base64url").slice(0, 16);
export function newRid(host, email) {
  const r = crypto.randomBytes(9).toString("base64url");
  return `${r}.${ridSig(r, host, email)}`;
}
export function ridOk(rid, host, email) {
  if (!RID_RE.test(rid)) return false;
  const [r, sig] = rid.split(".");
  const want = ridSig(r, host, email);
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want));
}

const noStore = (res) => res.setHeader("Cache-Control", "no-store");

export function buildSiteCheckPayload({ company, email, url, rid = null }, j, page = null) {
  return {
    source: "site-check",
    company: company || null, email, url,
    level: LEVEL_OUT[j.level] ?? null,
    flags: j.flags.map((f) => ({ lv: f.lv === "r" ? "r" : "y", t: String(f.t).slice(0, 80) })),
    rid,
    // 改ざんの兆候があれば、急ぎの連絡として扱ってもらう
    emergency: j.flags.some((f) => f.t.startsWith("改ざん")),
    page,
  };
}

export function buildChoicePayload({ company, email, url, rid, choice, message, tel }, page = null) {
  return {
    source: "site-check",
    company: company || null, email, url, tel: tel || null, message: message || null,
    rid, choice, page,
  };
}

export default async function handler(req, res, deps = {}) {
  noStore(res);
  if (req.method !== "POST") return res.status(405).json({ error: "method not allowed" });
  // 壊れた JSON などは、中身を出さずに 400
  let p;
  try { p = req.body ?? {}; } catch { return res.status(400).json({ error: "invalid body" }); }
  if (typeof p !== "object" || Array.isArray(p)) return res.status(400).json({ error: "invalid body" });
  try {
    return await handle(req, res, deps, p);
  } catch {
    console.error("site-check failed");
    if (!res.headersSent) return res.status(500).json({ error: "failed" });
  }
}

async function handle(req, res, deps, p) {
  const ip = clientIp(req);
  const limited = (why) => { console.warn(`site-check limited ${why}`); return res.status(429).json({ error: "too many requests" }); };
  // ボットらしい送信は診断も転送もしない。人だった場合に備え、押し直せば通るように 409 で返す
  const retry = (why) => { console.warn(`site-check retry ${why}`); return res.status(409).json({ error: "retry" }); };
  // 見えない欄（ブラウザの自動入力で埋まらない名前にしてある）
  if (p.hp_x) return retry("hp");

  if (p.kind === "find") return find(req, res, deps, p, { ip, limited, retry });

  if (p.kind === "choice") {
    if (!allow(`site-check-choice:${ip}`, { limit: 30, windowMs: 10 * 60 * 1000 })) return limited("choice");
  } else {
    // 入力画面を開いてから送るまでの時間 (人は1秒では入力できない)
    if (!(Number(p.t) >= 1000)) return retry("fast");
    if (!allow(`site-check-burst:${ip}`, { limit: 3, windowMs: 15 * 1000 })) return limited("burst");
    if (!allow(`site-check:${ip}`, { limit: 60, windowMs: 60 * 60 * 1000 })) return limited("ip");
  }

  const url = normalizeUrl(p.url);
  const company = String(p.company ?? "").trim().slice(0, 80);
  const email = String(p.email ?? "").trim().slice(0, 160);
  if (!url) return res.status(400).json({ error: "invalid url" });
  // 会社名は任意（URLで調べるときは聞かない。管理システム側でページの題名から補う）
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "invalid email" });
  if (p.agree !== true) return res.status(400).json({ error: "agreement is required" });

  if (p.kind === "choice") {
    const rid = String(p.rid ?? "");
    if (!CHOICES.has(p.choice) || !ridOk(rid, new URL(url).hostname.toLowerCase(), email)) return res.status(400).json({ error: "invalid choice" });
    const message = p.choice === "contact" ? String(p.message ?? "").trim().slice(0, 2000) : "";
    const tel = p.choice === "contact" ? String(p.tel ?? "").trim().slice(0, 40) : "";
    const sent = await (deps.forward ?? forward)(buildChoicePayload({ company, email, url, rid, choice: p.choice, message, tel }, "/tools/site-check/"));
    console.log(`site-check choice=${p.choice} forward=${sent}`);
    return res.status(200).json({ ok: true });
  }

  // 同じサイトへの診断は1時間に30回まで (このツール経由で他社サイトに連続アクセスさせない)
  const host = new URL(url).hostname.toLowerCase();
  if (!allow(`site-check-host:${host}`, { limit: 30, windowMs: 60 * 60 * 1000 })) return limited("host");

  const scan = await (deps.scanSite ?? scanSite)(url);
  const j = judge(scan);
  const rid = newRid(host, email);
  const sent = await (deps.forward ?? forward)(buildSiteCheckPayload({ company, email, url, rid }, j, "/tools/site-check/"));

  // 入力値 (URL・会社名・メール) はログに出さない
  console.log(`site-check level=${j.level} reachable=${scan.reachable ? 1 : 0} forward=${sent}`);
  return res.status(200).json({ ok: true, rid, result: toPublic(scan, j) });
}

// 会社名から候補を探す。メールアドレスなどは受け取らず、会社名だけを検索に使う
async function find(req, res, deps, p, { ip, limited, retry }) {
  // ブラウザは送り元を Sec-Fetch-Site で付ける。ほかのサイトの画面に埋め込んで検索させるのを止める
  const site = req.headers?.["sec-fetch-site"];
  if (site && site !== "same-origin") return res.status(403).json({ error: "forbidden" });
  if (!(Number(p.t) >= 1000)) return retry("fast");
  if (!allow(`site-check-find-burst:${ip}`, { limit: 3, windowMs: 60 * 1000 })) return limited("find-burst");
  if (!allow(`site-check-find:${ip}`, { limit: 10, windowMs: 60 * 60 * 1000 })) return limited("find");
  const company = cleanCompany(p.company);
  if (!company) return res.status(400).json({ error: "invalid company" });
  let sites;
  try {
    sites = await (deps.findSites ?? findSites)(company);
  } catch (e) {
    if (e instanceof SearchBusyError) {
      console.warn("site-check find busy");
      res.setHeader("Retry-After", "60");
      return res.status(503).json({ error: "busy" });
    }
    console.warn("site-check find failed");
    return res.status(502).json({ error: "search failed" });
  }
  // 会社名・見つかった URL はログに出さない
  console.log(`site-check find n=${sites.length}`);
  return res.status(200).json({ ok: true, sites });
}
