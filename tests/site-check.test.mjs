/**
 * サイト攻撃リスク診断 (api/site-check.js, api/_sitescan.js, api/_findsite.js) のテスト
 * 実行: node --test tests/site-check.test.mjs
 */
import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { resetRateLimit, allow } from "../api/_ratelimit.js";
import { normalizeUrl, topOf, isPrivateIp, analyze, judge, toPublic, otherRisk } from "../api/_sitescan.js";
import handler, { buildSiteCheckPayload, newRid } from "../api/site-check.js";
import { forward } from "../api/_forward.js";
import { pickSites, findSites, cleanCompany, resetFindCache, SearchBusyError, MAX_SITES } from "../api/_findsite.js";

function mockRes() {
  return {
    statusCode: 0, body: null, headers: {},
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
  };
}
const req = (body, ip = "203.0.113.9") => ({ method: "POST", headers: { "x-real-ip": ip }, body });
const INPUT = { url: "example.co.jp", company: "株式会社テスト", email: "taro@example.co.jp", agree: true, t: 8000 };
// 診断のときに発行される、正しい署名つきの受付番号
const RID = newRid("example.co.jp", "taro@example.co.jp");
const WP_SCAN = { reachable: true, status: 200, https: true, certDays: 80, php: true, wp: true, phpVer: "7.4", wpVer: "6.2.1", exposesVersion: true, tamper: false };

describe("normalizeUrl", () => {
  test("https を補い、下層ページはそのページのまま（# 以降は捨てる）", () => {
    assert.equal(normalizeUrl("example.co.jp/about?x=1#top"), "https://example.co.jp/about?x=1");
    assert.equal(normalizeUrl("http://www.example.com"), "http://www.example.com/");
    assert.equal(topOf("https://example.co.jp/company/info/"), "https://example.co.jp/");
  });
  test("IP直打ち・社内向け・独自ポート・認証情報つきは受けない", () => {
    for (const v of ["http://127.0.0.1", "http://[::1]/", "http://169.254.169.254/", "localhost", "http://intranet.local",
      "https://example.com:8080", "https://user:pw@example.com", "ftp://example.com", "", "a".repeat(400)]) {
      assert.equal(normalizeUrl(v), null, v);
    }
  });
});

test("isPrivateIp", () => {
  for (const ip of ["10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "::1", "fd00::1", "::ffff:10.0.0.1"]) assert.equal(isPrivateIp(ip), true, ip);
  // IPv6 の特殊な範囲・IPv4 を埋め込んだ形・文書用のアドレスも社内向けとして止める
  for (const ip of ["64:ff9b::a00:1", "2002:a00:1::1", "::10.0.0.1", "fe90::1", "fec0::1", "192.0.0.1", "203.0.113.9", "2001:db8::1"]) assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2606:4700::1111"]) assert.equal(isPrivateIp(ip), false, ip);
});

describe("analyze / judge", () => {
  test("WordPress と PHP の版数を読む（jQuery の ver は使わない）", () => {
    const a = analyze({
      headers: { "x-powered-by": "PHP/7.4.33" },
      body: '<link href="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"><link href="/wp-includes/css/dist/block-library/style.min.css?ver=6.2.1">',
    });
    assert.equal(a.wp, true); assert.equal(a.php, true);
    assert.equal(a.phpVer, "7.4"); assert.equal(a.wpVer, "6.2.1");
  });
  test("静的なサイトは PHP・WordPress なし → 低め", () => {
    const a = analyze({ headers: { server: "Vercel" }, body: "<html><title>x</title></html>" });
    assert.equal(a.php, false); assert.equal(a.wp, false);
    assert.equal(judge({ reachable: true, status: 200, https: true, certDays: 60, ...a }).level, "g");
  });
  test("古い版・https 非対応はリスク高", () => {
    assert.equal(judge(WP_SCAN).level, "r");
    assert.equal(judge({ ...WP_SCAN, phpVer: "", wpVer: "", exposesVersion: false, https: false }).level, "r");
  });
  test("版数が見えない WordPress は要確認", () => {
    assert.equal(judge({ ...WP_SCAN, phpVer: "", wpVer: "", exposesVersion: false }).level, "y");
  });
  test("証明書：期限切れはリスク高、中間証明書の不足は要確認", () => {
    const base = { reachable: true, status: 200, https: true, certDays: null, php: false, wp: false, phpVer: "", wpVer: "", exposesVersion: false, tamper: false };
    assert.equal(judge({ ...base, certBad: "expired" }).level, "r");
    assert.equal(judge({ ...base, certBad: "chain" }).level, "y");
  });
  test("PHPに関するリスクは PHP だけで見る（証明書の不備は全体の目安だけに効く）", () => {
    const noPhp = { reachable: true, status: 200, https: true, certDays: null, certBad: "chain", php: false, wp: false, phpVer: "", wpVer: "", exposesVersion: false, tamper: false };
    assert.deepEqual([judge(noPhp).level, judge(noPhp).phpLevel], ["y", "g"]);
    assert.equal(judge(WP_SCAN).phpLevel, "r");
    assert.equal(judge({ ...WP_SCAN, phpVer: "", wpVer: "", exposesVersion: false }).phpLevel, "y");
  });
  test("つながらなければ判定できず", () => {
    assert.equal(judge({ reachable: false }).level, "x");
  });
});

test("それ以外のリスクは、外から誰でも分かることを1文だけ（重いものを優先）", () => {
  const base = { reachable: true, status: 200, https: true, certDays: 80, certBad: false, tamper: false };
  assert.equal(otherRisk({ ...base }), "外から見える範囲では見つかりませんでした");
  assert.match(otherRisk({ ...base, certDays: 5 }), /期限が近づいています（残り5日）/);
  assert.equal(otherRisk({ ...base, certBad: "expired" }), "SSL証明書の期限が切れています");
  assert.match(otherRisk({ ...base, certBad: "chain" }), /設定に不備/);
  assert.equal(otherRisk({ ...base, https: false, certDays: 5 }), "暗号化（https）に対応していません");
  assert.match(otherRisk({ ...base, tamper: true, https: false }), /不審な記述/);
  assert.equal(otherRisk({ reachable: false }), null);
  // 版数は入れない
  assert.doesNotMatch(otherRisk({ ...base, phpVer: "7.4", wpVer: "6.2" }), /7\.4|6\.2/);
});

test("画面に返す分には版数・指摘の中身を含めない", () => {
  const pub = toPublic(WP_SCAN, judge(WP_SCAN));
  assert.deepEqual(Object.keys(pub).sort(), ["https", "level", "other", "php", "phpLevel", "reachable", "wp"]);
  assert.doesNotMatch(JSON.stringify(pub), /7\.4|6\.2/);
});

describe("handler", () => {
  let logs, savedLog, savedWarn;
  beforeEach(() => {
    resetRateLimit();
    logs = [];
    savedLog = console.log; savedWarn = console.warn;
    console.log = (...a) => logs.push(a.join(" "));
    console.warn = (...a) => logs.push(a.join(" "));
  });
  afterEach(() => { console.log = savedLog; console.warn = savedWarn; });

  test("診断して社内の管理システムへ送り、画面には目安だけを返す", async () => {
    const sent = [];
    const res = mockRes();
    await handler(req(INPUT), res, { scanSite: async () => WP_SCAN, forward: async (p) => { sent.push(p); return "ok"; } });
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers["cache-control"], "no-store");
    assert.deepEqual(res.body.result, { reachable: true, other: "外から見える範囲では見つかりませんでした", php: true, wp: true, https: true, level: "r", phpLevel: "r" });
    assert.equal(sent.length, 1);
    assert.equal(sent[0].source, "site-check");
    assert.equal(sent[0].url, "https://example.co.jp/");
    assert.equal(sent[0].company, "株式会社テスト");
    assert.equal(sent[0].email, "taro@example.co.jp");
    assert.equal(sent[0].level, "r");
    assert.ok(sent[0].flags.some((f) => f.t.includes("PHP 7.4")));
    // ログに入力値を出さない
    assert.doesNotMatch(logs.join("\n"), /example|テスト|taro/);
  });

  test("入力不足・同意なしは 400、診断も転送もしない", async () => {
    let called = 0;
    const deps = { scanSite: async () => { called++; return WP_SCAN; }, forward: async () => { called++; return "ok"; } };
    for (const [i, b] of [{ ...INPUT, url: "http://10.0.0.1" }, { ...INPUT, email: "x@" }, { ...INPUT, agree: false }].entries()) {
      const res = mockRes();
      await handler(req(b, "203.0.113." + (20 + i)), res, deps);
      assert.equal(res.statusCode, 400);
    }
    assert.equal(called, 0);
  });

  test("URLで調べるときは会社名なしで診断できる（会社名は null で送る）", async () => {
    const sent = [];
    const res = mockRes();
    await handler(req({ ...INPUT, company: "" }, "203.0.113.77"), res, { scanSite: async () => WP_SCAN, forward: async (p) => { sent.push(p); return "ok"; } });
    assert.equal(res.statusCode, 200);
    assert.equal(sent[0].company, null);
    assert.equal(sent[0].url, "https://example.co.jp/");
  });

  test("ブラウザの自動入力で余計な欄が埋まっていても、人は止めない", async () => {
    const res = mockRes();
    await handler(req({ ...INPUT, hp_x: "自動入力された値" }, "203.0.113.88"), res, { scanSite: async () => WP_SCAN, forward: async () => "ok" });
    assert.equal(res.statusCode, 200);
  });

  test("同じサイトへの診断は1時間に30回まで", async () => {
    const deps = { scanSite: async () => WP_SCAN, forward: async () => "ok" };
    const codes = [];
    for (let i = 0; i < 31; i++) {
      const res = mockRes();
      await handler(req(INPUT, "198.51.100." + i), res, deps);
      codes.push(res.statusCode);
    }
    assert.deepEqual(codes, [...Array(30).fill(200), 429]);
  });

  test("人の使い方なら別々のサイトを続けて診断できる（連打だけ止める）", async () => {
    const deps = { scanSite: async () => WP_SCAN, forward: async () => "ok" };
    const codes = [];
    const t0 = Date.now();
    for (let i = 0; i < 8; i++) {
      const res = mockRes();
      // 15秒に3回までなので、時計を進めながら送る
      const realNow = Date.now;
      Date.now = () => t0 + i * 6000;
      try { await handler(req({ ...INPUT, url: `site${i}.example.jp` }), res, deps); } finally { Date.now = realNow; }
      codes.push(res.statusCode);
    }
    assert.deepEqual(codes, Array(8).fill(200));
    // 同じIPから一気に4回は連打として止める
    const burst = [];
    for (let i = 0; i < 4; i++) { const res = mockRes(); await handler(req({ ...INPUT, url: `b${i}.example.jp` }, "192.0.2.50"), res, deps); burst.push(res.statusCode); }
    assert.deepEqual(burst, [200, 200, 200, 429]);
  });

  test("入力画面を開いてすぐの送信（ボットらしい速さ）は診断も転送もしない", async () => {
    let called = 0;
    const deps = { scanSite: async () => { called++; return WP_SCAN; }, forward: async () => { called++; return "ok"; } };
    for (const t of [200, undefined]) {
      const res = mockRes();
      await handler(req({ ...INPUT, t }), res, deps);
      assert.equal(res.statusCode, 409);
    }
    assert.equal(called, 0);
  });

  test("診断の応答に受付番号を付け、同じ番号で送る", async () => {
    const sent = [];
    const res = mockRes();
    await handler(req(INPUT), res, { scanSite: async () => WP_SCAN, forward: async (p) => { sent.push(p); return "ok"; } });
    assert.match(res.body.rid, /^[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]{16}$/);
    assert.equal(sent[0].rid, res.body.rid);
  });

  test("選んだ対応は診断せずに受付番号つきで送る", async () => {
    const sent = [];
    let scanned = 0;
    const deps = { scanSite: async () => { scanned++; return WP_SCAN; }, forward: async (p) => { sent.push(p); return "ok"; } };
    const res = mockRes();
    await handler(req({ ...INPUT, kind: "choice", rid: RID, choice: "contact", message: "相談したい", tel: "03-0000-0000" }), res, deps);
    assert.equal(res.statusCode, 200);
    assert.equal(scanned, 0);
    assert.equal(sent[0].choice, "contact");
    assert.equal(sent[0].rid, RID);
    assert.equal(sent[0].message, "相談したい");
    // 問い合わせ以外では自由記述を送らない
    await handler(req({ ...INPUT, kind: "choice", rid: RID, choice: "none", message: "x" }), mockRes(), deps);
    assert.equal(sent[1].choice, "none");
    assert.equal(sent[1].message, null);
    assert.doesNotMatch(logs.join("\n"), /相談|03-0000|taro/);
  });

  test("受付番号・選択肢が不正なら 400", async () => {
    // 形だけ合わせた偽の番号・別のサイトやメールの番号は通さない
    const forged = "abcdefABCDEF.0123456789abcdef";
    const otherSite = newRid("other.example.jp", "taro@example.co.jp");
    for (const b of [{ kind: "choice", rid: "short", choice: "wait" }, { kind: "choice", rid: RID, choice: "other" },
      { kind: "choice", rid: forged, choice: "wait" }, { kind: "choice", rid: otherSite, choice: "wait" }]) {
      const res = mockRes();
      await handler(req({ ...INPUT, ...b }), res, { forward: async () => "ok" });
      assert.equal(res.statusCode, 400);
    }
  });

  test("壊れた本文は中身を出さずに 400", async () => {
    const res = mockRes();
    const bad = { method: "POST", headers: {}, get body() { throw new SyntaxError("Unexpected token"); } };
    await handler(bad, res);
    assert.equal(res.statusCode, 400);
    assert.doesNotMatch(JSON.stringify(res.body), /Unexpected|token/);
  });

  test("GET は 405", async () => {
    const res = mockRes();
    await handler({ method: "GET", headers: {} }, res);
    assert.equal(res.statusCode, 405);
  });

  const FIND = { kind: "find", company: "株式会社テスト", t: 8000 };
  const SITES = [{ url: "https://example.co.jp/", host: "example.co.jp", title: "株式会社テスト" }];

  test("会社名で候補を探す：会社名だけを検索に渡し、診断も転送もしない", async () => {
    const asked = [];
    let called = 0;
    const res = mockRes();
    await handler(req({ ...FIND, email: "taro@example.co.jp" }), res, {
      findSites: async (c) => { asked.push(c); return SITES; },
      scanSite: async () => { called++; }, forward: async () => { called++; },
    });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.sites, SITES);
    assert.deepEqual(asked, ["株式会社テスト"]);
    assert.equal(called, 0);
    assert.doesNotMatch(logs.join("\n"), /example|テスト/);
  });

  test("会社名での検索が失敗したら 502、全体の上限なら 503、会社名らしくない入力は 400", async () => {
    const res = mockRes();
    await handler(req(FIND), res, { findSites: async () => { throw new Error("down"); } });
    assert.equal(res.statusCode, 502);
    const busy = mockRes();
    await handler(req(FIND, "203.0.113.30"), busy, { findSites: async () => { throw new SearchBusyError("busy"); } });
    assert.equal(busy.statusCode, 503);
    assert.equal(busy.headers["retry-after"], "60");
    let n = 0;
    for (const [i, company] of [" ", "株式会社テスト site:example.com", "https://example.co.jp", "x".repeat(61)].entries()) {
      const r = mockRes();
      await handler(req({ ...FIND, company }, "203.0.113." + (50 + i)), r, { findSites: async () => { n++; return SITES; } });
      assert.equal(r.statusCode, 400, company);
    }
    assert.equal(n, 0);
  });

  test("会社名での検索は同じIPから1分に3回・1時間に10回まで（速すぎる送信・ほかのサイトからは検索しない）", async () => {
    let n = 0;
    const deps = { findSites: async () => { n++; return SITES; } };
    for (const b of [{ ...FIND, t: 100 }]) {
      const res = mockRes();
      await handler(req(b, "203.0.113.40"), res, deps);
      assert.equal(res.statusCode, 409);
    }
    const cross = mockRes();
    await handler({ ...req(FIND, "203.0.113.40"), headers: { "x-real-ip": "203.0.113.40", "sec-fetch-site": "cross-site" } }, cross, deps);
    assert.equal(cross.statusCode, 403);
    const codes = [];
    for (let i = 0; i < 4; i++) { const r = mockRes(); await handler(req(FIND, "203.0.113.41"), r, deps); codes.push(r.statusCode); }
    assert.deepEqual(codes, [200, 200, 200, 429]);
    assert.equal(n, 3);
  });
});

describe("会社名からホームページの候補を探す", () => {
  test("求人・企業データベース・SNS を外し、1サイト1件・トップページにまとめる", () => {
    const sites = pickSites([
      { url: "https://ja.wikipedia.org/wiki/x", title: "wiki" },
      { url: "https://www.example.co.jp/company/about", title: "会社概要｜テスト" },
      { url: "https://example.co.jp/", title: "トップ" },
      { url: "https://jp.indeed.com/cmp/x", title: "求人" },
      { url: "https://baseconnect.in/companies/x", title: "企業DB" },
      { url: "http://10.0.0.1/", title: "社内" },
      { url: "https://www.pref.tochigi.lg.jp/x", title: "株式会社テスト - 栃木県" },
      { url: "https://miyagi-ijuguide.pref.miyagi.jp/x", title: "株式会社テスト - 宮城県" },
      { url: "https://other-review.example.com/x", title: "株式会社テストの評判・口コミ" },
      { url: "https://shop.example.net/item", title: "通販" },
    ]);
    assert.deepEqual(sites.map((x) => x.url), ["https://www.example.co.jp/", "https://shop.example.net/"]);
    assert.equal(sites[0].title, "会社概要｜テスト");
  });

  test("候補は最大5件", () => {
    const many = Array.from({ length: 9 }, (_, i) => ({ url: `https://s${i}.example.com/`, title: "" }));
    assert.equal(pickSites(many).length, MAX_SITES);
  });

  test("検索 API には会社名だけを送り、結果から候補を作る", async () => {
    resetFindCache(); resetRateLimit();
    let sent;
    const fetchImpl = async (url, init) => {
      sent = { url, init };
      return { ok: true, json: async () => ({ success: true, data: { web: [{ title: "テスト", url: "https://example.co.jp/about" }] } }) };
    };
    const sites = await findSites("株式会社テスト", { fetchImpl, apiKey: "k" });
    assert.deepEqual(sites, [{ url: "https://example.co.jp/", host: "example.co.jp", title: "テスト" }]);
    assert.equal(sent.init.headers.Authorization, "Bearer k");
    assert.equal(JSON.parse(sent.init.body).query, "株式会社テスト");
  });

  test("会社名を整える：全角・空白をそろえ、URL・検索演算子・長すぎる入力は受けない", () => {
    assert.equal(cleanCompany("　株式会社　ＮＵＴＳ "), "株式会社 NUTS");
    for (const v of ["", "a", "x".repeat(61), "テスト site:example.com", "テスト -求人", "A OR B", "www.example.co.jp", "https://x.jp", 'テスト"株"']) {
      assert.equal(cleanCompany(v), null, v);
    }
  });

  test("同じ会社名は使い回し、検索に行くのは全体で1分に8回まで", async () => {
    resetFindCache(); resetRateLimit();
    let calls = 0;
    const fetchImpl = async () => { calls++; return { ok: true, json: async () => ({ data: { web: [] } }) }; };
    const now = 1_000_000;
    await findSites("株式会社テスト", { fetchImpl, apiKey: "k", now });
    await findSites("株式会社テスト", { fetchImpl, apiKey: "k", now: now + 1000 });
    assert.equal(calls, 1);
    for (let i = 1; i < 8; i++) await findSites("会社" + i, { fetchImpl, apiKey: "k", now });
    await assert.rejects(findSites("会社9", { fetchImpl, apiKey: "k", now }), SearchBusyError);
    assert.equal(calls, 8);
    // 多くの IP からの送信で IP ごとの記録が捨てられても、全体の上限は消えない
    for (let i = 0; i < 6000; i++) allow(`site-check-find:198.18.${i >> 8}.${i & 255}`, { limit: 10, windowMs: 3600_000 }, now);
    await assert.rejects(findSites("会社10", { fetchImpl, apiKey: "k", now }), SearchBusyError);
    // 1分たてばまた検索できる
    await findSites("会社9", { fetchImpl, apiKey: "k", now: now + 61_000 });
    assert.equal(calls, 9);
  });

  test("鍵がない・検索先がエラーを返したときは例外（空の候補と区別する）", async () => {
    await assert.rejects(findSites("x", { fetchImpl: async () => { throw new Error("must not call"); }, apiKey: "" }), /not configured/);
    await assert.rejects(findSites("x", { fetchImpl: async () => ({ ok: false, status: 429 }), apiKey: "k" }), /429/);
  });
});

test("改ざんの兆候があれば緊急として転送", () => {
  const j = judge({ ...WP_SCAN, tamper: true });
  assert.equal(buildSiteCheckPayload({ company: "a", email: "b@c.d", url: "https://c.d/" }, j).emergency, true);
});

describe("forward（社内の管理システムへ送る）", () => {
  let savedFetch;
  beforeEach(() => { savedFetch = globalThis.fetch; process.env.SITE_CHECK_FORWARD_URL = "https://inbound.example.jp/"; process.env.SITE_CHECK_FORWARD_TOKEN = "t"; });
  afterEach(() => { globalThis.fetch = savedFetch; delete process.env.SITE_CHECK_FORWARD_URL; delete process.env.SITE_CHECK_FORWARD_TOKEN; });

  test("送り先のエラー・つながらないときは1回だけ送り直す", async () => {
    let n = 0;
    globalThis.fetch = async () => { n++; if (n === 1) return { ok: false, status: 503 }; return { ok: true, status: 200 }; };
    assert.equal(await forward({ a: 1 }, { waitMs: 0 }), "ok");
    assert.equal(n, 2);
    n = 0;
    globalThis.fetch = async () => { n++; if (n === 1) throw new TypeError("fetch failed"); return { ok: true, status: 200 }; };
    assert.equal(await forward({ a: 1 }, { waitMs: 0 }), "ok");
    assert.equal(n, 2);
  });

  test("応答がないときも送り直し、それでもだめならエラーを返す", async () => {
    let n = 0;
    globalThis.fetch = (u, o) => { n++; return new Promise((_, ng) => o.signal.addEventListener("abort", () => ng(Object.assign(new Error("aborted"), { name: "AbortError" })))); };
    assert.equal(await forward({ a: 1 }, { timeoutMs: 20, waitMs: 0 }), "error:timeout");
    assert.equal(n, 2);
  });

  test("合言葉の違い（401）などは送り直さない", async () => {
    let n = 0;
    globalThis.fetch = async () => { n++; return { ok: false, status: 401 }; };
    assert.equal(await forward({ a: 1 }, { waitMs: 0 }), "error:401");
    assert.equal(n, 1);
  });

  test("設定がなければ送らない", async () => {
    delete process.env.SITE_CHECK_FORWARD_URL;
    let n = 0;
    globalThis.fetch = async () => { n++; return { ok: true, status: 200 }; };
    assert.equal(await forward({ a: 1 }), "skipped");
    assert.equal(n, 0);
  });
});
