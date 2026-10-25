/*
 * かんたんサイト診断の外形チェック (Vercel Function 内部モジュール)
 *
 * ふだんは入力されたページに GET を1回送るだけ (サイト側の転送は5回まで追う)。
 * 表示できなかったときだけ読み直す: 証明書の設定不備なら検証を外して1回、https に繋がらなければ http で1回、
 * それでもだめ・エラーなら同じサイトのトップページを同じ手順で1回。全体で15秒を超えたら打ち切る。
 * 応答ヘッダーと HTML から「PHP の形跡」「WordPress の形跡」「見えている版数」を読む。
 * ログイン・パスの総当たり・脆弱性の試し打ちなど、サイトに負荷や影響を与えることはしない。
 *
 * 誰でも URL を入れられるため、攻撃の下調べに使われないよう、
 * 画面 (toPublic) には「あり/なし/リスクの目安」だけを返し、版数などの詳細は社内にだけ渡す。
 */

import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";

export const UA = "Mozilla/5.0 (compatible; JOL-SiteCheck/1.1; +https://jol-jp.com/tools/site-check/; public-info-only)";
const MAX_BYTES = 600_000;
const MAX_HOPS = 5;
// 中間証明書が足りないサーバー (国内のレンタルサーバーに多い) はブラウザでは開けるが Node では弾かれる。
// 公開ページを読むだけなので、このときは証明書の検証を外して読み直し、「設定に不備」として指摘する
// (ドメイン名が証明書と合わない場合は別のサーバーの可能性があるので読み直さない)
const TLS_CHAIN = new Set(["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "SELF_SIGNED_CERT_IN_CHAIN", "DEPTH_ZERO_SELF_SIGNED_CERT", "CERT_HAS_EXPIRED"]);
const TOTAL_MS = 15000; // 1回の診断でサイトに使う時間の上限 (転送の時間と合わせて関数の上限60秒に収める)
const RULES = { phpMin: "8.2", wpMin: "6.8", certWarnDays: 21 };

/* ---------- 入力の整形 ---------- */

// http/https・既定ポートのみ。IP 直打ち・ユーザー情報付きは受けない。下層ページはそのページを見る (# 以降は捨てる)
export function normalizeUrl(v) {
  let s = String(v ?? "").trim();
  if (!s || s.length > 300) return null;
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (!/^https?:$/.test(u.protocol) || u.username || u.password) return null;
  if (u.port && u.port !== "80" && u.port !== "443") return null;
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host) || !host.includes(".") || /\.(local|localhost|internal|lan|home|corp)$/i.test(host)) return null;
  u.hash = "";
  return u.href;
}
export const topOf = (url) => new URL(url).origin + "/";

/* ---------- 宛先の安全確認 (社内ネットワーク・クラウドの管理用アドレスへは出さない) ---------- */

// 公開されたインターネットのアドレスだけ通す。IPv6 は通常の公開アドレス (2000::/3) だけを許し、
// IPv4 を埋め込んだ形 (::ffff:a.b.c.d・::a.b.c.d・6to4・NAT64) は中の IPv4 で判定する
export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19)) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113) || a >= 224;
  }
  const s = String(ip).toLowerCase();
  if (!net.isIPv6(s)) return true;
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) return isPrivateIp(v4[1]);
  const first = parseInt(s.split(":")[0] || "0", 16);
  if (first < 0x2000 || first > 0x3fff) return true; // 2000::/3 以外 (::1, fc00::/7, fe80::/10, fec0::, 64:ff9b:: など)
  if (s.startsWith("2002:") || s.startsWith("2001:db8:") || /^2001:0?:/.test(s)) return true; // 6to4・文書用・Teredo
  return false;
}

function safeLookup(hostname, opts, cb) {
  dns.lookup(hostname, opts, (err, address, family) => {
    if (err) return cb(err);
    const list = Array.isArray(address) ? address : [{ address, family }];
    if (list.some((x) => isPrivateIp(x.address))) {
      return cb(Object.assign(new Error("private address"), { code: "EPRIVATE" }));
    }
    cb(null, address, family);
  });
}

/* ---------- 1回の GET ---------- */

function getOnce(urlStr, { timeout, deadline, insecureTls }) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    if (!/^https?:$/.test(u.protocol) || (u.port && u.port !== "80" && u.port !== "443") || net.isIP(u.hostname.replace(/^\[|\]$/g, ""))) {
      return reject(Object.assign(new Error("bad redirect"), { code: "EBADURL" }));
    }
    const left = Math.max(500, Math.min(timeout, deadline - Date.now()));
    if (deadline - Date.now() <= 0) return reject(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }));
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(u, {
      method: "GET", lookup: safeLookup, timeout: left, agent: false, rejectUnauthorized: !insecureTls,
      headers: { "User-Agent": UA, Accept: "text/html,*/*;q=0.5", "Accept-Language": "ja" },
    }, (res) => {
      let cert = null;
      try {
        const c = res.socket?.getPeerCertificate?.();
        if (c && c.valid_to) cert = { validTo: Date.parse(c.valid_to), validFrom: c.valid_from ? Date.parse(c.valid_from) : null, issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || "" };
      } catch {}
      const chunks = [];
      let size = 0, finished = false;
      const done = () => {
        if (finished) return;
        finished = true;
        resolve({ url: u.href, status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), cert });
      };
      res.on("data", (d) => { size += d.length; if (size <= MAX_BYTES) chunks.push(d); else res.destroy(); });
      res.on("end", done); res.on("close", done); res.on("error", done);
    });
    req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
    // 少しずつ送ってくる相手でも、時間が来たら必ず切る (timeout は無通信の時間しか見ないため)
    const hard = setTimeout(() => req.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })), Math.max(0, deadline - Date.now()));
    req.on("close", () => clearTimeout(hard));
    req.on("error", reject);
    req.end();
  });
}

export async function fetchPage(urlStr, { timeout = 7000, budgetMs = 9000, insecureTls = false, until = Infinity } = {}) {
  const deadline = Math.min(Date.now() + budgetMs, until);
  let cur = urlStr;
  for (let i = 0; i <= MAX_HOPS; i++) {
    if (Date.now() >= deadline) throw Object.assign(new Error("timeout"), { code: "ETIMEDOUT" });
    const r = await getOnce(cur, { timeout, deadline, insecureTls });
    if (r.status >= 300 && r.status < 400 && r.headers.location) { cur = new URL(r.headers.location, cur).href; continue; }
    return r;
  }
  throw Object.assign(new Error("too many redirects"), { code: "EHOPS" });
}

/* ---------- 解析 ---------- */

const verLt = (a, b) => {
  const x = String(a).split(".").map(Number), y = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0);
  }
  return false;
};

// 改ざんの兆候 (よくある手口だけ。断定はせず「要確認」の材料にする)
const TAMPER = [
  /(viagra|cialis|levitra|バイアグラ|シアリス|レビトラ)/i,
  /(online\s*casino|オンラインカジノ|slot\s*gacor|judi\s*online)/i,
  /(スーパーコピー|ブランドコピー|偽物ブランド)/,
  // 長い符号化した中身を書き出すものだけ (昔の解析タグの document.write(unescape('%3C')) は対象外)
  /(eval|document\.write)\s*\(\s*(atob|unescape|String\.fromCharCode)\s*\(\s*(["'][^"']{60,}|(\d+\s*,\s*){20})/i,
];

// 運用の様子を見る材料 (公開の診断画面には出さない。toPublic で落とす)
// WordPress 以外の CMS・サービス。本文かヘッダーに目印があれば、その名前を出す
const CMS_SIGNS = [
  [/smart[ _-]?cms|smart-lgov/i, "SMART CMS"],
  [/Movable ?Type|\/mt-static\//i, "Movable Type"],
  [/a-?blog ?cms|ablogcms/i, "a-blog cms"],
  [/Drupal\.settings|\/sites\/(?:all|default)\/(?:themes|modules|files)\/|x-drupal|"generator":"drupal/i, "Drupal"],
  [/\/media\/jui\/|Joomla!/i, "Joomla"],
  [/EC-CUBE|eccube/i, "EC-CUBE"],
  [/cdn\.shopify\.com|x-shopify/i, "Shopify"],
  [/static\.wixstatic\.com|x-wix-/i, "Wix"],
  [/static1\.squarespace\.com|squarespace/i, "Squarespace"],
  [/jimdo/i, "Jimdo"],
  [/studio\.design|\.studio\.site/i, "STUDIO"],
  [/peraichi/i, "ペライチ"],
  [/amebaownd/i, "Ameba Ownd"],
  [/HeartCore/i, "HeartCore"],
  [/\/etc\.clientlibs\//i, "Adobe Experience Manager"],
  [/sitecore/i, "Sitecore"],
  [/concrete5|concrete cms/i, "Concrete CMS"],
  [/sites\.google\.com/i, "Googleサイト"],
];
// CDN・WAF (ヘッダーと Cookie の目印)
const CDN_SIGNS = [
  [/incap_ses|visid_incap|x-iinfo/, "Imperva"],
  [/cf-ray|cloudflare/, "Cloudflare"],
  [/akamai/, "Akamai"],
  [/cloudfront|x-amz-cf-id/, "CloudFront"],
  [/fastly/, "Fastly"],
  [/sucuri/, "Sucuri"],
  [/x-azure-ref/, "Azure Front Door"],
];

export function analyze(page) {
  const h = page.headers || {}, body = String(page.body || "");
  const xp = String(h["x-powered-by"] || ""), server = String(h.server || "");
  const cookies = [].concat(h["set-cookie"] || []).join(";");
  const hstr = JSON.stringify(h).toLowerCase();
  const phpM = (xp + " " + server).match(/PHP\/(\d+\.\d+)/i);
  const generator = ((body.match(/<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)/i) ||
    body.match(/<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/i) || [])[1] || "").trim();
  const gen = generator.match(/^WordPress\s*([\d.]+)/i);
  // ?ver= は WordPress 本体と同じ番号が付くファイルだけ見る (jquery.min.js?ver= は jQuery の番号)
  const verQ = body.match(/wp-includes\/(?:css\/dist\/block-library\/style(?:\.min)?\.css|js\/wp-emoji-release\.min\.js|css\/dashicons(?:\.min)?\.css)\?ver=(\d+\.\d+(?:\.\d+)?)/i);
  const wp = /\/wp-(content|includes|json)\//i.test(body) || /wp-json/i.test(String(h.link || "")) || !!gen;
  // WordPress は PHP で動くので、WordPress なら PHP もありとする
  const php = wp || !!phpM || /PHPSESSID/i.test(cookies) || /(href|action|src)=["'][^"']*\.php\b/i.test(body);
  const wpVer = gen ? gen[1] : verQ && wp ? verQ[1] : "";
  let cms = wp ? "WordPress" : "";
  if (!cms) cms = (CMS_SIGNS.find(([re]) => re.test(body) || re.test(hstr)) || [])[1] || "";
  // generator の版数は、CMS 名を generator から取ったときだけ使う (WordPress のときはプラグインの版のことがある)
  const genCms = !cms && !!generator;
  if (genCms) cms = generator.replace(/\s*(?:version\s*)?v?\d[\d.]*\s*$/i, "").slice(0, 40);
  const cdn = CDN_SIGNS.filter(([re]) => re.test(hstr)).map(([, n]) => n);
  const analytics = [
    [/GTM-[A-Z0-9]{4,}/, "Googleタグマネージャー"],
    [/["'?&=]G-[A-Z0-9]{6,}["'&]|gtag\s*\(/, "Googleアナリティクス"],
    [/UA-\d{4,}-\d+/, "旧アナリティクス(UA)"],
    [/fbq\s*\(/, "Meta広告"],
    [/connect\.facebook\.net\/[^"']*sdk\.js/, "Facebook埋め込み"],
    [/s\.yjtag\.jp|yjtag/, "Yahoo!タグ"],
    [/clarity\.ms/, "Microsoft Clarity"],
  ].filter(([re]) => re.test(body)).map(([, n]) => n);
  const jq = (body.match(/jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.min)?\.js/i) ||
    body.match(/jquery(?:\.min)?\.js\?ver=(\d+\.\d+(?:\.\d+)?)/i) || [])[1] || "";
  // 著作権の年はページの表示部分から読む (埋め込みスクリプトやコメントの中のライセンス表記は外す)
  const visible = body.replace(/<(script|style)\b[\s\S]*?<\/\1>|<!--[\s\S]*?-->/gi, " ");
  const years = [...visible.matchAll(/(?:©|&copy;|copyright)[^<]{0,30}?((?:19|20)\d{2})(?:\s*[-–〜~]\s*((?:19|20)\d{2}))?/gi)]
    .map((m) => +(m[2] || m[1])).filter((y) => y >= 1995 && y <= new Date().getFullYear() + 1);
  return {
    php, wp,
    phpVer: phpM ? phpM[1] : "",
    wpVer,
    exposesVersion: !!phpM,
    tamper: TAMPER.some((re) => re.test(body)),
    cms, cmsVer: wpVer || (genCms ? ((generator.match(/v?(\d[\d.]*)\s*$/) || [])[1] || "").replace(/\.$/, "") : ""),
    server: server.slice(0, 60), poweredBy: xp.slice(0, 60),
    cdn, analytics,
    jquery: jq, jqueryOld: !!jq && verLt(jq, "3.5"),
    jqueryFiles: new Set((body.match(/<script[^>]+src=["'][^"']*jquery[^"']*\.js/gi) || []).map((s) => s.toLowerCase())).size,
    copyrightYear: years.length ? Math.max(...years) : null,
    lastModified: h["last-modified"] ? Date.parse(h["last-modified"]) || null : null,
    sec: {
      hsts: !!h["strict-transport-security"],
      csp: !!(h["content-security-policy"] || h["content-security-policy-report-only"]),
      xfo: !!h["x-frame-options"],
      xcto: !!h["x-content-type-options"],
    },
  };
}

/* ---------- 判定 ---------- */

// level: r=リスク高 / y=要確認 / g=低め / x=判定できず
export function judge(scan) {
  if (!scan.reachable) return { level: "x", flags: [{ lv: "y", t: "サイトに接続できませんでした" }] };
  const flags = [];
  const add = (lv, t) => flags.push({ lv, t });
  if (scan.tamper) add("r", "改ざんの可能性がある記述");
  if (scan.phpVer && verLt(scan.phpVer, RULES.phpMin)) add("r", `PHP ${scan.phpVer}（サポート終了の版）`);
  else if (scan.phpVer) add("y", `PHP ${scan.phpVer}`);
  if (scan.exposesVersion) add("y", "PHPの版数を外に表示している");
  if (scan.wpVer && verLt(scan.wpVer, RULES.wpMin)) add("r", `WordPress ${scan.wpVer}（古い版）`);
  else if (scan.wpVer) add("y", `WordPress ${scan.wpVer}`);
  if (scan.php && !scan.phpVer) add("y", scan.wp ? "WordPress（PHPの版数は外から見えない）" : "PHPを使用（版数は外から見えない）");
  if (scan.https === false) add("r", "暗号化（https）に対応していない");
  else if (scan.certBad === "expired") add("r", "SSL証明書の期限切れ");
  else if (scan.certBad) add("y", "SSL証明書の設定に不備の可能性（中間証明書の不足など）");
  else if (scan.certDays != null && scan.certDays < RULES.certWarnDays) add("y", `SSL証明書の期限が近い（残り${Math.max(0, scan.certDays)}日）`);
  if (scan.status >= 400) add("y", `ページがエラー（${scan.status}）`);
  const level = flags.some((f) => f.lv === "r") ? "r" : scan.php || flags.length ? "y" : "g";
  // PHP だけで見たリスク（画面の「PHPに関するリスク」）。証明書などは「それ以外のリスク」で出す
  const phpLevel = !scan.php ? "g" : flags.some((f) => f.lv === "r" && /^(PHP|WordPress)/.test(f.t)) ? "r" : "y";
  return { level, flags, phpLevel };
}

/* ---------- 1サイトの診断 ---------- */

// 1つのURLを読む。https で証明書の設定に不備があれば検証を外して読み直す。https で繋がらなければ http を1回試す
async function readOne(url, opts) {
  try { return { page: await fetchPage(url, opts), httpsOk: null, certBad: false }; }
  catch (e) {
    if (TLS_CHAIN.has(e.code)) {
      try { return { page: await fetchPage(url, { ...opts, insecureTls: true }), httpsOk: true, certBad: e.code === "CERT_HAS_EXPIRED" ? "expired" : "chain" }; } catch {}
    }
    if (url.startsWith("https:") && e.code !== "EPRIVATE" && e.code !== "EBADURL") {
      try { return { page: await fetchPage("http:" + url.slice(6), opts), httpsOk: false, certBad: false }; } catch {}
    }
    return { page: null, code: e.code || "ERR" };
  }
}

export async function scanSite(url, opts = {}) {
  opts = { ...opts, until: Date.now() + (opts.totalMs ?? TOTAL_MS) };
  let r = await readOne(url, opts);
  // 下層ページに届かない・エラーのときは、同じサイトのトップページを見る
  const top = topOf(url);
  if ((!r.page || r.page.status >= 400) && top !== url && r.code !== "EPRIVATE" && r.code !== "ENOTFOUND" && Date.now() < opts.until) {
    const t = await readOne(top, opts);
    if (t.page && (!r.page || t.page.status < 400)) r = t;
  }
  if (!r.page) return { reachable: false, code: r.code };
  const page = r.page;
  const a = analyze(page);
  const httpsOk = r.httpsOk === null ? new URL(page.url).protocol === "https:" : r.httpsOk;
  return {
    reachable: true, status: page.status, https: httpsOk, certBad: r.certBad,
    certDays: page.cert && httpsOk && !r.certBad ? Math.floor((page.cert.validTo - Date.now()) / 864e5) : null,
    certFrom: page.cert && httpsOk ? page.cert.validFrom : null,
    certTo: page.cert && httpsOk ? page.cert.validTo : null,
    certIssuer: page.cert && httpsOk ? page.cert.issuer : "",
    finalUrl: page.url,
    ...a,
  };
}

// PHP 以外で、外から誰でも分かるリスクを1文で (暗号化・証明書・不審な記述)。版数は出さない
export function otherRisk(scan) {
  if (!scan.reachable) return null;
  if (scan.tamper) return "ページに不審な記述が見つかりました（改ざんの可能性があります）";
  if (scan.https === false) return "暗号化（https）に対応していません";
  if (scan.certBad === "expired") return "SSL証明書の期限が切れています";
  if (scan.certBad) return "SSL証明書の設定に不備がある可能性があります";
  if (scan.certDays != null && scan.certDays < RULES.certWarnDays) return `SSL証明書の期限が近づいています（残り${Math.max(0, scan.certDays)}日）`;
  return "外から見える範囲では見つかりませんでした";
}

// 画面に返す分：あり/なしとリスクの目安、それ以外のリスク1文だけ (版数・個別の指摘は返さない)
export function toPublic(scan, j) {
  return {
    reachable: !!scan.reachable,
    other: otherRisk(scan),
    php: scan.reachable ? !!scan.php : null,
    wp: scan.reachable ? !!scan.wp : null,
    https: scan.reachable ? scan.https !== false : null,
    level: j.level,
    phpLevel: j.phpLevel ?? null,
  };
}
