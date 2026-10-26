/* ==========================================================
   サイト攻撃リスク診断
   - URL・会社名・メールアドレスを /api/site-check へ送り、
     サーバー側で公開ページを見て判定する（ふだんは1回。表示できないときだけ読み直す）
   - 画面に出すのは「あり/なし/リスクの目安」だけ（版数などの詳細は担当者から本人確認のうえ連絡）
   - URL をコピーして貼るのが難しい方向けに、会社名で探して候補から選べるタブもある（検索はサーバー側）
   - 入力はこの端末に保存しない（localStorage 等は使わない）
   ========================================================== */
(function () {
  "use strict";

  var ENDPOINT = "/api/site-check";
  var A = "/tools/site-check/assets/";
  var OSS_URL = "https://github.com/JOL-Japan/jol-site-check";
  var app = document.getElementById("app");
  var draft = { url: "", company: "", email: "", own: false };
  var formShownAt = 0; // 入力画面を開いた時刻（ボットらしい速さの送信を見分ける）
  var tab = "url"; // 入力画面のタブ（url=URLで調べる・既定 / company=会社名から調べる）

  var NOTICE = "この診断は、公開されているページから外形的に読み取れる情報をもとにした目安です。" +
    "管理画面・プラグイン・サーバーの内部を診断するものではありません。" +
    "結果をもとにした判断や対応によって生じた損害について、当社は責任を負いかねます。" +
    "具体的な対応は、ホームページの制作会社・サーバー会社にご確認ください。";

  var LEVELS = {
    r: { label: "目安：リスクが高い可能性があります",
         body: "外から見える範囲で、古い版や対策が必要そうな点が見つかりました。早めに制作会社・サーバー会社へ確認することをおすすめします。",
         steps: ["制作会社・サーバー会社に「PHPやWordPressの版は最新ですか」と確認する", "連絡先がわからない・返事がない場合は、早めに専門家へ相談する"] },
    y: { label: "目安：確認をおすすめします",
         body: "PHPやWordPressが使われているようです。更新されているかどうかは外からは確かめきれないため、一度確認しておくと安心です。",
         steps: ["制作会社・サーバー会社に「PHPやWordPressの版は最新ですか」と確認する", "保守の契約があるか、更新を誰が担当しているかを確かめる"] },
    g: { label: "目安：PHPに関する大きなリスクは見つかりませんでした",
         body: "外から見える範囲では、PHPやWordPressの形跡は見つかりませんでした。ほかのリスクがないという意味ではなく、外から見えない部分も判定できません。",
         steps: ["お問い合わせフォームなど、別のページや別のシステムがあれば、その管理先も確認する"] },
    x: { label: "判定できませんでした",
         body: "サイトに接続できませんでした。URLが正しいか、サイトが表示できる状態かをご確認のうえ、もう一度お試しください。",
         steps: ["ブラウザでサイトが表示できるか確かめる", "表示できない場合は、サーバー会社に状況を確認する"] }
  };

  /* ---------- helpers ---------- */
  function el(html) { var t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; }
  function qs(sel, root) { return (root || document).querySelector(sel); }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; });
  }
  function mount(node) { app.innerHTML = ""; app.appendChild(node); window.scrollTo(0, 0); }
  function toast(msg) {
    var t = qs(".toast") || document.body.appendChild(el('<div class="toast" role="status"></div>'));
    t.textContent = msg; t.classList.add("show");
    clearTimeout(toast._t); toast._t = setTimeout(function () { t.classList.remove("show"); }, 2200);
  }
  function header() {
    return '<header class="top-header"><img class="header-logo" src="' + A + 'logo-orange.svg" alt="JOL" /></header>';
  }

  /* ============================================================
     イントロ
     ============================================================ */
  function icon(d) {
    return '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.9" ' +
      'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + d + '</svg>';
  }
  var ICONS = {
    shield: icon('<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6L12 3z"/><path d="M8.6 12.2l2.4 2.4 4.6-4.8"/>'),
    code: icon('<path d="M8.5 7.5L4 12l4.5 4.5M15.5 7.5L20 12l-4.5 4.5M13.5 5l-3 14"/>'),
    lock: icon('<rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2.5"/>'),
    home: icon('<path d="M3.5 11L12 4l8.5 7"/><path d="M6 9.5V20h12V9.5"/><path d="M10 20v-5h4v5"/>'),
    eye: icon('<path d="M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>'),
    chev: icon('<path d="M6 9l6 6 6-6"/>')
  };
  // このサイト自体のセキュリティーを守るしくみ（[アイコン, 見出し, 説明, リンク]）
  var GUARDS = [
    ["code", "コードをGitHubで公開", "このページのコードはすべて公開しています。送信先や診断の中身を、どなたでも確かめられます。",
      [OSS_URL, "公開しているコードを見る（GitHub）"]],
    ["lock", "情報は暗号化して送信", "入力いただいた情報は、HTTPSで暗号化して送ります。「会社名から調べる」ときだけ、ホームページを探すために会社名を検索サービス（Firecrawl）に送ります。それ以外は第三者に渡さず、広告・アクセス解析のタグもありません。"],
    ["home", "運営会社を確かめられます", "このツールは JOL（株式会社NUTS）が運営しています。弊社のサイトから、運営元をご確認いただけます。",
      ["https://jol-jp.com/", "JOLのサイトを見る"]],
    ["eye", "見るだけ・侵入しない", "診断では、入力されたページを見るだけです（ふだんは1回。表示できないときだけ、読み直しや同じサイトのトップページの確認をします）。ログインや侵入を試すことは一切しません。"]
  ];

  // タイトルの上の線画：ブラウザの画面を虫めがねで調べ、盾のチェックで安心を表す（白い線だけ）
  var HERO_ART =
    '<svg viewBox="0 0 220 140" width="220" height="140" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">' +
      '<rect x="22" y="18" width="150" height="104" rx="12" fill="rgba(255,255,255,0.12)"/>' +
      '<path d="M22 40h150"/>' +
      '<circle cx="36" cy="29" r="2.4"/><circle cx="46" cy="29" r="2.4"/><circle cx="56" cy="29" r="2.4"/>' +
      '<path d="M38 58h54M38 72h40M38 86h48M38 100h30" stroke-opacity="0.75"/>' +
      '<path d="M128 54l17 6.5v12c0 10-7.2 17.6-17 20.5-9.8-2.9-17-10.5-17-20.5v-12z" fill="rgba(255,255,255,0.18)"/>' +
      '<path d="M120.5 73.5l5.2 5.2 9.8-10.2"/>' +
      '<g class="fig-art-lens"><circle cx="168" cy="96" r="20" fill="rgba(255,255,255,0.16)"/><path d="M182.5 110.5l16 16"/>' +
        '<path d="M159 90a11 11 0 0 1 9-6" stroke-opacity="0.8"/></g>' +
      '<path class="fig-art-spark" d="M196 30v12M190 36h12"/>' +
      '<path class="fig-art-spark fig-art-spark--2" d="M12 92v8M8 96h8"/>' +
    '</svg>';

  function renderIntro() {
    var guards = GUARDS.map(function (g) {
      return '<li><span class="ti">' + ICONS[g[0]] + '</span><div><p class="tt">' + g[1] + '</p><p class="td">' + g[2] + '</p>' +
        (g[3] ? '<a class="tl" href="' + g[3][0] + '" target="_blank" rel="noopener noreferrer">' + g[3][1] + '</a>' : '') + '</div></li>';
    }).join("");
    var s = el('<div class="screen fig-screen"></div>');
    s.innerHTML =
      '<div class="fig-intro">' +
        '<div class="fig-top"><img class="fig-logo" src="' + A + 'logo-white.svg" alt="JOL" /></div>' +
        '<div class="fig-body">' +
          '<span class="fig-badge">たった5秒で分析！</span>' +
          '<div class="fig-art" aria-hidden="true">' + HERO_ART + '</div>' +
          '<h1 class="fig-title">サイト攻撃リスク診断</h1>' +
          '<p class="fig-sub">ホームページに PHP や WordPress が<br />使われているか、リスクはあるか。<br />外から見える範囲で、目安をお出しします。</p>' +
          '<details class="guard">' +
            '<summary><span class="ti">' + ICONS.shield + '</span><span class="g-t">このサイト自体の<br />セキュリティーを守るしくみ</span><span class="g-chev">' + ICONS.chev + '</span></summary>' +
            '<ul class="trust">' + guards + '</ul>' +
          '</details>' +
          '<div class="actions"><button class="fig-start" id="startBtn">今すぐ無料分析</button></div>' +
        '</div>' +
        '<p class="fig-copy">JOL all right reserved.</p>' +
      '</div>';
    mount(s);
    qs("#startBtn", s).addEventListener("click", renderForm);
  }

  /* ============================================================
     注意事項（読んで「理解して進める」を押してから入力へ）
     ============================================================ */
  /* ============================================================
     入力
     ============================================================ */
  function field(name, label, type, ph, extra) {
    return '<div class="field" data-f="' + name + '">' +
      '<label for="f-' + name + '">' + label + '<span class="req">必須</span></label>' +
      '<input class="input" id="f-' + name + '" name="' + name + '" type="' + type + '" placeholder="' + ph + '" value="' + esc(draft[name]) + '" ' + extra + ' />' +
      '<p class="field-err"></p></div>';
  }

  var TABS = [["url", "URLで調べる"], ["company", "会社名から調べる"]]; // 左が既定の URL

  function tabs() {
    return '<div class="tabs" role="tablist" aria-label="調べ方">' + TABS.map(function (t) {
      var on = t[0] === tab;
      return '<button type="button" class="tab" role="tab" id="tab-' + t[0] + '" data-tab="' + t[0] + '" aria-controls="checkForm" ' +
        'aria-selected="' + on + '" tabindex="' + (on ? 0 : -1) + '">' + t[1] + '</button>';
    }).join("") + '</div>';
  }

  function renderForm() {
    var isCompany = tab === "company";
    var s = el('<div class="screen"></div>');
    s.innerHTML = header() +
      '<h2 class="notice-title">診断するサイト</h2>' + tabs() +
      '<form class="form" id="checkForm" role="tabpanel" aria-labelledby="tab-' + tab + '" novalidate>' +
        (isCompany
          ? '<p class="tab-lead">会社名を入れると、こちらでホームページを探して候補をお見せします。</p>'
          : field("url", "ホームページのURL", "url", "https://example.co.jp", 'inputmode="url" autocomplete="url" maxlength="200"')) +
        // 会社名は「会社名から調べる」ときだけ聞く（URLで調べるときは不要）
        (isCompany ? field("company", "会社名", "text", "株式会社〇〇", 'autocomplete="organization" maxlength="80"') : '') +
        field("email", "メールアドレス", "email", "you@example.co.jp", 'inputmode="email" autocomplete="email" maxlength="120"') +
        '<label class="consent"><input type="checkbox" name="own" />ご自身または自社で管理しているホームページです</label>' +
        // 開始前の注意事項（旧「はじめる前に」）もここにまとめる。小窓を挟むと離れる人が増えるため
        '<p class="form-note">入力いただいた内容は、診断結果のご連絡とご相談への対応にだけ使い、JOLの社内で管理します。' +
          (isCompany ? 'ホームページを探すときは、会社名だけを検索サービスに送ります。' : '') +
          'この診断は、公開されているページから外形的に読み取れる情報をもとにした目安です。入力されたページを見るだけで、ログインや侵入はしません。管理画面・プラグイン・サーバーの内部を診断するものではありません。' +
          '<b>結果をもとにした判断や対応によって生じた損害について、当社は責任を負いかねます。</b>' +
          '具体的な対応は、ホームページの制作会社・サーバー会社にご確認ください。' +
          '送信により<a href="/privacy" target="_blank" rel="noopener">プライバシーポリシー</a>に同意したものとみなします。</p>' +
        '<div class="actions"><button class="btn-primary" type="submit" id="goBtn">' + (isCompany ? "ホームページを探す" : "診断する") + '</button>' +
        '<button class="btn-ghost" type="button" id="backBtn">← もどる</button></div>' +
      '</form>';
    mount(s);
    if (!formShownAt) formShownAt = Date.now();
    var form = qs("#checkForm", s);
    var own = form.elements.own;
    own.checked = !!draft.own;
    function read() {
      return { url: isCompany ? draft.url : form.elements.url.value.trim(), company: isCompany ? form.elements.company.value.trim() : draft.company,
        email: form.elements.email.value.trim(), own: own.checked };
    }
    bindTabs(s, function (next) { draft = read(); tab = next; renderForm(); qs("#tab-" + next).focus(); });
    qs("#backBtn", s).addEventListener("click", renderIntro);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var v = read();
      draft = v;
      var errs = {};
      if (!isCompany && !/^(https?:\/\/)?[^\s\/.]+\.[^\s]+$/i.test(v.url)) errs.url = "URLをご確認ください（例：https://example.co.jp）";
      if (isCompany && !v.company) errs.company = "会社名を入力してください";
      else if (isCompany && v.company.length < 2) errs.company = "会社名を正式な名前で入力してください";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.email)) errs.email = "メールアドレスをご確認ください";
      ["url", "company", "email"].forEach(function (k) {
        var f = qs('[data-f="' + k + '"]', form);
        if (!f) return;
        f.classList.toggle("error", !!errs[k]);
        qs(".field-err", f).textContent = errs[k] || "";
      });
      if (Object.keys(errs).length) return;
      if (!v.own) return toast("管理しているホームページかどうかの確認にチェックしてください");
      if (isCompany) findSites(v);
      else submit({ url: v.url, company: "", email: v.email });
    });
  }

  // 左右の矢印キーでタブを移る（WAI-ARIA のタブの操作）
  function bindTabs(s, onChange) {
    var list = qs(".tabs", s);
    list.addEventListener("click", function (e) {
      var b = e.target.closest("[data-tab]");
      if (b && b.getAttribute("data-tab") !== tab) onChange(b.getAttribute("data-tab"));
    });
    list.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      e.preventDefault();
      var i = TABS.map(function (t) { return t[0]; }).indexOf(tab);
      onChange(TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length][0]);
    });
  }

  // 送信。入力画面を開いてすぐ（自動入力などで1秒未満）だとサーバーが 409 を返すので、
  // 少し待って1回だけ自動で送り直す（人に「もう一度押して」と言わせない）。body は送るたびに作り直す（経過時間を入れ直す）
  function post(makeBody) {
    var send = function () {
      return fetch(ENDPOINT, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(makeBody()), credentials: "omit" });
    };
    return send().then(function (r) {
      if (r.status !== 409) return r;
      return new Promise(function (ok) { setTimeout(ok, 1200); }).then(send);
    });
  }

  /* ============================================================
     会社名からホームページの候補を探す
     ============================================================ */
  function findSites(v) {
    renderLoading("ホームページを探しています…", "会社名で検索しています。数秒お待ちください。");
    post(function () { return { kind: "find", company: v.company, t: Date.now() - formShownAt }; })
      .then(function (r) {
        if (r.status === 429 || r.status === 409 || r.status === 400) throw new Error(String(r.status));
        if (!r.ok) throw new Error(r.status === 503 ? "busy" : "search");
        return r.json();
      })
      .then(function (j) { renderCandidates(j.sites || [], v); })
      .catch(function (err) {
        var m = err && err.message;
        if (m === "429" || m === "409" || m === "400") {
          renderForm();
          return toast(m === "409" ? "もう一度「ホームページを探す」を押してください" :
            m === "400" ? "会社名だけを入力してください（例：株式会社〇〇）" :
            "短い間に検索が続いたため、少しおいてお試しください");
        }
        renderCandidates(null, v, m === "busy");
      });
  }

  // フリーメール・携帯・プロバイダのドメインは会社のホームページではない
  var FREE_MAIL = /(^|\.)(gmail\.com|googlemail\.com|yahoo\.co\.jp|ymail\.ne\.jp|yahoo\.com|icloud\.com|me\.com|mac\.com|outlook\.(com|jp)|hotmail\.(com|co\.jp)|live\.(com|jp)|msn\.com|aol\.com|docomo\.ne\.jp|ezweb\.ne\.jp|au\.com|softbank\.ne\.jp|i\.softbank\.jp|ymobile\.ne\.jp|nifty\.com|biglobe\.ne\.jp|ocn\.ne\.jp|so-net\.ne\.jp|plala\.or\.jp|dion\.ne\.jp|zoho\.com|proton\.me|protonmail\.com|example\.(com|co\.jp))$/i;
  var withoutWww = function (host) { return host.toLowerCase().replace(/^www\./, ""); };

  // 会社のメールアドレスのドメインは、たいていその会社のホームページ。
  // 社名とドメインが違う会社や、同じ名前の会社が多いときは検索では見分けられないので、いちばん上に出す
  // （入力されたメールアドレスから端末の中で作るだけで、どこにも送らない）
  function emailSite(email) {
    var domain = (email.split("@")[1] || "").toLowerCase();
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain) || FREE_MAIL.test(domain)) return null;
    return { url: "https://" + domain + "/", host: domain, title: "ご入力のメールアドレスと同じドメインです" };
  }

  // 検索結果の前にメールアドレスのドメインを足す（同じサイトは1つにまとめる）
  function candidateList(sites, email) {
    var mine = emailSite(email);
    if (!mine) return sites || [];
    return [mine].concat((sites || []).filter(function (x) { return withoutWww(x.host) !== withoutWww(mine.host); }));
  }

  function candidatesText(list, sites, company, busy) {
    var name = "「" + esc(company) + "」";
    if (list.length) return ["このホームページですか？", name + "とメールアドレスから見つけたホームページです。当てはまるものを押すと診断をはじめます。"];
    if (sites) return ["見つかりませんでした", name + "のホームページを見つけられませんでした。会社名を正式な名前に変えるか、URLを入れてお試しください。"];
    return ["うまく探せませんでした", (busy ? "検索が混み合っています。" : "") + "時間をおいてもう一度お試しいただくか、URLを入れてお試しください。"];
  }

  // sites が null のときは検索そのものに失敗した（busy=検索が混み合っている）。
  // それでもメールアドレスのドメインがあれば候補に出す
  function renderCandidates(sites, v, busy) {
    var list = candidateList(sites, v.email);
    var found = list.length > 0;
    var text = candidatesText(list, sites, v.company, busy);
    var s = el('<div class="screen"></div>');
    s.innerHTML = header() +
      '<h2 class="notice-title">' + text[0] + '</h2>' +
      '<p class="tab-lead">' + text[1] + '</p>' +
      (found ? '<ul class="site-list">' + list.map(function (x, i) {
        return '<li><button type="button" class="site-btn" data-i="' + i + '">' +
          '<span class="site-host">' + esc(x.host) + '</span>' +
          (x.title ? '<span class="site-title">' + esc(x.title) + '</span>' : '') + '</button></li>';
      }).join("") + '</ul>' : '') +
      '<div class="actions">' +
        '<button class="btn-secondary" type="button" id="toUrlBtn">' + (found ? "どれでもない（URLを入れて調べる）" : "URLを入れて調べる") + '</button>' +
        '<button class="btn-ghost" type="button" id="backBtn">← 会社名を変えて探す</button>' +
      '</div>';
    mount(s);
    if (found) {
      Array.prototype.forEach.call(s.querySelectorAll(".site-btn"), function (b) {
        b.addEventListener("click", function () {
          var site = list[Number(b.getAttribute("data-i"))];
          // 診断できずに入力画面へもどったとき、選んだ URL が入った「URLで調べる」を開く
          draft.url = site.url;
          tab = "url";
          submit({ url: site.url, company: v.company, email: v.email });
        });
      });
    }
    qs("#toUrlBtn", s).addEventListener("click", function () { tab = "url"; renderForm(); });
    qs("#backBtn", s).addEventListener("click", renderForm);
  }

  function submit(v) {
    renderLoading();
    post(function () { return { url: v.url, company: v.company, email: v.email, agree: true, t: Date.now() - formShownAt }; })
      .then(function (r) {
        if (r.status === 429) throw new Error("429");
        if (r.status === 409) throw new Error("409");
        if (r.status === 400) throw new Error("400");
        if (!r.ok) throw new Error(String(r.status));
        return r.json();
      })
      .then(function (j) { renderResult(j.result, { url: v.url, company: v.company, email: v.email, rid: j.rid || "" }); })
      .catch(function (err) {
        renderForm();
        var m = err && err.message;
        toast(m === "409" ? "もう一度「診断する」を押してください" :
          m === "429" ? "短い間に診断が続いたため、少しおいてお試しください" :
          m === "400" ? "入力内容をご確認ください（URLは https:// から始まる公開サイトのアドレス）" :
          "診断できませんでした。時間をおいてお試しください");
      });
  }

  function renderLoading(title, desc) {
    var s = el('<div class="screen"></div>');
    s.innerHTML = header() +
      '<div class="scan-wait" role="status"><div class="scan-ring" aria-hidden="true"></div>' +
      '<p class="scan-t">' + (title || "サイトを確認しています…") + '</p>' +
      '<p class="scan-d">' + (desc || "入力されたページを確認しています。数秒お待ちください。") + '</p></div>';
    mount(s);
  }

  /* ============================================================
     結果
     ============================================================ */
  // 「それ以外のリスク」に何か見つかったか（見つからなければ「見つかりませんでした」で終わる文）
  function otherBad(r) { return !!r.other && !/見つかりませんでした$/.test(r.other); }

  function row(label, val, yes, no) {
    var cls = val === null ? "na" : val ? "on" : "off";
    var txt = val === null ? "判定できず" : val ? yes : no;
    return '<li class="sc-row sc-' + cls + '"><span class="sc-k">' + label + '</span><span class="sc-v">' + txt + '</span></li>';
  }

  // リスクがありそうなときに選んでもらう、その後の対応
  // 選択肢のアイコン（白い線）。レポート＝封筒と書類、対面/オンライン＝人と画面
  var CH_ICON = {
    wait: '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M7 3.5h7l4 4V12"/><path d="M14 3.5v4h4"/><path d="M9.5 8.5h2.5M9.5 11.5h4"/><rect x="3" y="12.5" width="18" height="8" rx="1.8"/><path d="M3.6 13.2L12 17.6l8.4-4.4"/></svg>',
    contact: '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="7.5" r="2.6"/><path d="M3.5 16.5c.5-2.8 2.3-4.3 4.5-4.3s4 1.5 4.5 4.3"/><rect x="13.5" y="5" width="8" height="6" rx="1.2"/><path d="M16 13.5h3M17.5 11v2.5"/><path d="M3 20.5h18"/></svg>'
  };
  var CHOICES = [
    { k: "wait", t: "貴社のリスク詳細レポートをメールで受け取る（無料）", d: "リスクの高い企業様から順番にお送りします" },
    { k: "contact", t: "対面/オンラインでより詳しく調査を依頼する", d: "担当者から1営業日以内にご連絡します" },
    { k: "none", t: "何も対策しない", d: "JOLからご連絡することはありません。" }
  ];
  var DONE = {
    wait: ["受け付けました", "リスクの高い企業様から順番に、貴社のリスク詳細レポートをご入力のメールアドレスへお送りします（無料）。"],
    contact: ["調査のご依頼を受け付けました", "JOLの担当者から1営業日以内に、ご入力のメールアドレスへご連絡します。"],
    none: ["承知しました", "JOLからご連絡することはありません。気になったときは、いつでもお問い合わせください。"]
  };

  function choiceBlock() {
    return '<div class="sc-choice no-print" id="choiceBox">' +
      '<h3 class="section-label section-label--lg">今後の対応をお選びください</h3>' +
      '<p class="ch-lead">版数などの詳しい結果は、悪用を防ぐため画面には表示していません。</p>' +
      '<div class="ch-list">' +
      CHOICES.map(function (c) {
        // 「何も対策しない」は控えめな文字だけのボタン。ほかは矢印つきの角丸の CTA
        if (c.k === "none") return '<button type="button" class="ch-btn ch-none" data-choice="none"><span class="ch-t">' + esc(c.t) + '</span></button>';
        return '<button type="button" class="ch-btn ch-' + c.k + '" data-choice="' + c.k + '">' +
          '<span class="ch-ico" aria-hidden="true">' + CH_ICON[c.k] + '</span>' +
          '<span class="ch-body"><span class="ch-t">' + esc(c.t) + '</span><span class="ch-d">' + esc(c.d) + '</span></span>' +
          '<span class="ch-arrow" aria-hidden="true"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5l7 7-7 7"/></svg></span></button>';
      }).join("") +
      '</div>' +
      '<form class="ch-more" id="chMore" hidden novalidate>' +
        '<textarea class="input ch-msg" name="message" maxlength="2000" rows="4" placeholder="ご相談内容（任意）"></textarea>' +
        '<input class="input" name="tel" type="tel" inputmode="tel" autocomplete="tel" maxlength="40" placeholder="お電話番号（任意・お電話をご希望の場合）" />' +
        '<button class="btn-primary" type="submit" id="contactBtn">調査を依頼する</button>' +
      '</form></div>';
  }

  // 「提案を待つ」「何も対策しない」は押したらすぐ送る。「問い合わせる」は相談内容の欄を開いてから送る
  function bindChoice(s, ctx) {
    var box = qs("#choiceBox", s), more = qs("#chMore", s);
    var btns = Array.prototype.slice.call(box.querySelectorAll(".ch-btn"));
    function lock(on) { btns.concat([qs("#contactBtn", s)]).forEach(function (b) { b.disabled = on; }); }
    function send(v, extra) {
      lock(true);
      var body = { kind: "choice", url: ctx.url, company: ctx.company, email: ctx.email, agree: true, rid: ctx.rid, choice: v };
      for (var k in extra) body[k] = extra[k];
      fetch(ENDPOINT, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), credentials: "omit" })
        .then(function (r) { if (!r.ok) throw new Error(String(r.status)); })
        .then(function () {
          ctx.url = ctx.company = ctx.email = "";
          box.innerHTML = '<div class="thanks"><div class="t-check">✓</div>' +
            '<p class="sc-follow-t">' + DONE[v][0] + '</p><p class="sc-follow-d">' + DONE[v][1] + '</p></div>';
        })
        .catch(function (err) {
          lock(false);
          toast(err && err.message === "429" ? "送信が続いたため、しばらくおいてお試しください" : "送信できませんでした。時間をおいてお試しください");
        });
    }
    btns.forEach(function (b) {
      b.addEventListener("click", function () {
        var v = b.getAttribute("data-choice");
        btns.forEach(function (x) { x.classList.toggle("is-on", x === b); });
        if (v === "contact") { more.hidden = false; more.elements.message.focus(); return; }
        more.hidden = true;
        send(v, {});
      });
    });
    more.addEventListener("submit", function (e) {
      e.preventDefault();
      send("contact", { message: more.elements.message.value.trim(), tel: more.elements.tel.value.trim() });
    });
  }

  /* ============================================================
     シェア用の画像（結果だけを描く。会社名・サイトのURLは入れない）
     ============================================================ */
  var TOOL_URL = "https://jol-jp.com/tools/site-check/";
  // 要確認も急ぎを伝えるため赤（リスク高と同じ色）
  var LV_COLOR = { r: ["#ff5b4a", "#e5162c"], y: ["#ff5b4a", "#e5162c"], g: ["#22d67e", "#00b85a"] };

  function loadImg(src) {
    return new Promise(function (ok, ng) { var i = new Image(); i.onload = function () { ok(i); }; i.onerror = ng; i.src = src; });
  }
  function rrect(c, x, y, w, h, r) {
    c.beginPath(); c.moveTo(x + r, y); c.arcTo(x + w, y, x + w, y + h, r); c.arcTo(x + w, y + h, x, y + h, r);
    c.arcTo(x, y + h, x, y, r); c.arcTo(x, y, x + w, y, r); c.closePath();
  }
  // 行に分ける。「、」「は」「が」などの後ろで切れるならそこで切り、だめなら1文字ずつ詰める（日本語向け）
  function lines(c, text, maxW) {
    if (c.measureText(text).width <= maxW) return [text];
    var best = -1;
    for (var i = 1; i < text.length - 1; i++) {
      if (/[、。はがをにで]/.test(text[i - 1]) && c.measureText(text.slice(0, i)).width <= maxW) best = i;
    }
    if (best < 0) { best = 1; while (best < text.length && c.measureText(text.slice(0, best + 1)).width <= maxW) best++; }
    return [text.slice(0, best)].concat(lines(c, text.slice(best), maxW));
  }

  // 高さは中身に合わせて決める（見出しが2行になっても帯からはみ出さない）
  function drawShare(r, lv, risk) {
    var W = 1080, cv = document.createElement("canvas"), F = '"Noto Sans JP", sans-serif', col = LV_COLOR[lv];
    var c = cv.getContext("2d");
    var fonts = document.fonts && document.fonts.load ? Promise.all(["700 50px", "500 32px"].map(function (f) { return document.fonts.load(f + ' "Noto Sans JP"', "診断"); })).catch(function () {}) : Promise.resolve();
    return fonts
      .then(function () { return loadImg(A + "logo-white.svg").catch(function () { return null; }); })
      .then(function (logo) {
        c.font = "700 50px " + F;
        var head = lines(c, headOf(r, lv).label.replace("目安：", ""), W - 240);
        var rows = [["PHP", r.php ? "使われている形跡あり" : "見つかりませんでした", !r.php],
          ["WordPress", r.wp ? "使われている形跡あり" : "見つかりませんでした", !r.wp], ["PHPに関するリスク", risk, null]];
        c.font = "700 34px " + F;
        var other = r.other ? lines(c, r.other, W - 240) : [];
        var otherH = other.length ? 70 + other.length * 50 + 20 : 0;
        var cardY = 400, bandH = 120 + head.length * 66 + 30, rowH = 116, cardH = bandH + rows.length * rowH + otherH + 30;
        var H = cardY + cardH + 230;
        cv.width = W; cv.height = H;

        var g = c.createLinearGradient(0, 0, W, H); g.addColorStop(0, "#ff8a3d"); g.addColorStop(1, "#ff6b1a");
        c.fillStyle = g; c.fillRect(0, 0, W, H);
        if (logo) c.drawImage(logo, 80, 70, 150, 150 * (logo.height / logo.width || 0.4));
        c.fillStyle = "#fff"; c.textAlign = "left"; c.textBaseline = "alphabetic";
        c.font = "700 64px " + F; c.fillText("サイト攻撃リスク診断", 80, 290);
        c.font = "500 32px " + F; c.globalAlpha = 0.9; c.fillText("外から見える範囲での目安です", 80, 345); c.globalAlpha = 1;

        // 結果カード（上の帯に結果の見出し、下に3行）
        c.save(); rrect(c, 60, cardY, W - 120, cardH, 40); c.clip();
        c.fillStyle = "#fff"; c.fillRect(60, cardY, W - 120, cardH);
        var hg = c.createLinearGradient(60, cardY, W - 60, cardY + bandH); hg.addColorStop(0, col[0]); hg.addColorStop(1, col[1]);
        c.fillStyle = hg; c.fillRect(60, cardY, W - 120, bandH);
        c.restore();
        c.fillStyle = "#fff"; c.textAlign = "center";
        c.font = "700 30px " + F; c.fillText("診断結果", W / 2, cardY + 80);
        c.font = "700 50px " + F;
        head.forEach(function (t, i) { c.fillText(t, W / 2, cardY + 160 + i * 66); });

        rows.forEach(function (row, i) {
          var y = cardY + bandH + 30 + i * rowH + 62;
          if (i) { c.fillStyle = "#ececf2"; c.fillRect(120, y - 72, W - 240, 2); }
          c.textAlign = "left"; c.fillStyle = "#1b1b1b"; c.font = "700 38px " + F; c.fillText(row[0], 120, y);
          c.textAlign = "right"; c.font = "700 36px " + F;
          c.fillStyle = row[2] === null ? (r.phpLevel === "g" ? "#067a41" : col[1]) : row[2] ? "#067a41" : "#a15c00";
          c.fillText(row[1], W - 120, y);
        });

        // それ以外のリスク（1文）：見出しの下に折り返して出す
        if (other.length) {
          var oy = cardY + bandH + 30 + rows.length * rowH;
          c.fillStyle = "#ececf2"; c.fillRect(120, oy - 10, W - 240, 2);
          c.textAlign = "left"; c.fillStyle = "#1b1b1b"; c.font = "700 38px " + F; c.fillText("それ以外のリスク", 120, oy + 52);
          c.fillStyle = otherBad(r) ? "#c4121f" : "#067a41"; c.font = "700 34px " + F;
          other.forEach(function (t, i) { c.fillText(t, 120, oy + 112 + i * 50); });
        }

        var fy = cardY + cardH + 100;
        c.textAlign = "center"; c.fillStyle = "#fff";
        c.font = "700 40px " + F; c.fillText("あなたのサイトも5秒で無料分析", W / 2, fy);
        c.font = "500 32px " + F; c.fillText(TOOL_URL.replace("https://", ""), W / 2, fy + 58);
        return new Promise(function (ok) { cv.toBlob(function (b) { ok({ blob: b, url: cv.toDataURL("image/png") }); }, "image/png"); });
      });
  }

  // 保存する前に、保存される画像をそのまま見せる
  function shareResult(r, lv, risk, btn) {
    btn.disabled = true;
    drawShare(r, lv, risk).then(function (img) {
      var ov = el('<div class="sh-ov" role="dialog" aria-modal="true" aria-label="保存される画像">' +
        '<div class="sh-box"><p class="sh-t">保存される画像</p>' +
        '<img class="sh-img" alt="診断結果の画像" src="' + img.url + '" />' +
        '<p class="sh-note">会社名・サイトのURLは入りません。</p>' +
        '<div class="actions"><button class="btn-primary" id="shSave">画像を保存・シェアする</button>' +
        '<button class="btn-ghost" id="shClose">閉じる</button></div></div></div>');
      document.body.appendChild(ov);
      var close = function () { ov.remove(); btn.disabled = false; };
      qs("#shClose", ov).addEventListener("click", close);
      ov.addEventListener("click", function (e) { if (e.target === ov) close(); });
      qs("#shSave", ov).addEventListener("click", function () { saveImage(img.blob); });
    }).catch(function () {
      btn.disabled = false;
      toast("画像を作れませんでした。時間をおいてお試しください");
    });
  }

  // スマホは共有シート（画像を保存・送る）、それ以外は画像をダウンロード
  function saveImage(blob) {
    var name = "site-check-result.png";
    var file = typeof File === "function" ? new File([blob], name, { type: "image/png" }) : null;
    if (file && navigator.canShare && navigator.canShare({ files: [file] })) {
      navigator.share({ files: [file], title: "サイト攻撃リスク診断", text: "サイト攻撃リスク診断の結果です " + TOOL_URL }).catch(function () {});
      return;
    }
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
    toast("画像を保存しました");
  }

  // 結果の見出しと説明。何が見つかったかで言い分ける（言い切らず「おそれ」「可能性」にとどめる）
  function headOf(r, lv) {
    var L = LEVELS[lv];
    if (lv !== "r" && lv !== "y") return { label: L.label, body: L.body };
    if (r.php && r.phpLevel === "r") return { label: "古いPHP・WordPressの可能性を感知",
      body: "外から見える範囲で、サポートが終わった古い版の可能性があります。古い版は公開済みの弱点を狙った攻撃の対象になりやすく、改ざんや情報の流出につながるおそれがあります。早急に運用担当者や技術担当者へ確認してください。" };
    if (r.php) return { label: "PHPの利用を感知",
      body: "最新のものに更新されているか要確認です。PHPやWordPressは更新が止まると、公開済みの弱点を狙われやすくなります。外からは確認しきれないので、一度運用担当者や技術担当者に確認しておくと安心です。" };
    if (lv === "r") return { label: "早急な確認が必要な点を感知",
      body: "PHPやWordPressの形跡は見つかりませんでしたが、それ以外に早急な確認が必要な点が見つかりました。放置すると、閲覧者に警告が表示されたり、情報の盗み見や改ざんにつながるおそれがあります。" };
    return { label: "セキュリティ上の注意点を感知",
      body: "PHPやWordPressの形跡は見つかりませんでしたが、それ以外に確認しておきたい点が見つかりました。一度運用担当者や技術担当者に確認しておくと安心です。" };
  }

  // 放置した場合に起こりうること（見つかったものに合わせて2〜3件）
  function harmsOf(r) {
    if (r.php) return ["ホームページが改ざんされ、不審なページや広告を差し込まれるおそれ", "詐欺サイトやウイルスへ誘導する踏み台にされるおそれ", "お問い合わせなどで送られた情報が流出するおそれ"];
    if (/不審な記述/.test(r.other || "")) return ["不審なページや広告の表示が続くおそれ", "検索結果やブラウザで「危険なサイト」と表示されるおそれ"];
    if (otherBad(r)) return ["ブラウザに「安全ではありません」と表示され、閲覧者が離れるおそれ", "入力された情報が途中で盗み見られるおそれ"];
    return [];
  }

  function renderResult(r, ctx) {
    var lv = LEVELS[r.level] ? r.level : "x";
    var L = LEVELS[lv];
    var RISK = { r: "高い可能性", y: "要確認", g: "低め", x: "判定できず" };
    // 「PHPに関するリスク」は PHP だけで見た目安（証明書などは「それ以外のリスク」）
    var plv = RISK[r.phpLevel] ? r.phpLevel : lv, risk = RISK[plv];
    // PHP は見つからず、それ以外のリスクで要確認・高い可能性になったときの説明
    var head = headOf(r, lv), harms = lv === "r" || lv === "y" ? harmsOf(r) : [];
    var s = el('<div class="screen"></div>');
    var html = header() +
      '<div class="result-head lv-' + lv + '">' +
        '<p class="r-eyebrow">診断結果（目安）</p>' +
        '<div class="r-emoji"><span class="r-dot"></span></div>' +
        '<p class="r-type">' + esc(head.label) + '</p>' +
        '<p class="r-catch">' + esc(head.body) + '</p>' +
      '</div>' +
      '<ul class="sc-list">' +
        row("PHP", r.php, "使われている形跡あり", "見つかりませんでした") +
        row("WordPress", r.wp, "使われている形跡あり", "見つかりませんでした") +
        '<li class="sc-row sc-lv-' + plv + '"><span class="sc-k">PHPに関するリスク</span><span class="sc-v">' + risk + '</span></li>' +
        (r.other ? '<li class="sc-row sc-row--text' + (otherBad(r) ? ' sc-other-bad' : '') + '"><span class="sc-k">それ以外のリスク</span>' +
          '<span class="sc-t">' + esc(r.other) + '</span></li>' : '') +
      '</ul>' +
      (harms.length ? '<div class="sc-harm"><p class="sc-harm-t"><span class="sc-harm-ico" aria-hidden="true">!</span>放置した場合に起こりうること</p><ul>' +
        harms.map(function (t) { return '<li>' + esc(t) + '</li>'; }).join("") + '</ul></div>' : '');

    // リスクがありそう（高い可能性・要確認）なときは、その後の対応を選んでもらう
    if ((lv === "r" || lv === "y") && ctx && ctx.rid) {
      html += choiceBlock();
    } else if (lv === "g") {
      // リスクが見つからなければ、こちらからは連絡しない。相談したい方だけ問い合わせへ
      html += '<div class="sc-follow"><p class="sc-follow-d">セキュリティやサイトの運用保守などのご相談をご希望の場合は、' +
        '<a href="/contact" target="_blank" rel="noopener">お問い合わせ</a>ください。</p></div>';
    } else if (lv !== "x") {
      html += '<div class="sc-follow"><p class="sc-follow-t">詳しい結果は担当者からご連絡します</p>' +
        '<p class="sc-follow-d">版数などの詳しい結果は、悪用を防ぐため画面には表示していません。' +
        'サイトの管理者さまであることを確認のうえ、JOLの担当者から1営業日以内にご入力のメールアドレスへご連絡します。</p></div>';
    }

    html += '<h3 class="section-label section-label--lg">次にやること</h3><ol class="steps">';
    L.steps.forEach(function (t) { html += '<li>' + esc(t) + '</li>'; });
    html += '</ol>';

    html += '<div class="actions no-print">' +
      (lv !== "x" ? '<button class="btn-secondary" id="shareBtn">リンクをシェアする</button>' : '') +
      '<button class="btn-secondary" id="retryBtn">もう一度診断する</button></div>';

    html += '<p class="disclaimer"><b>ご注意</b>　' + esc(NOTICE) + '</p>' +
      '<div class="logo-footer"><img src="' + A + 'logo-orange.svg" alt="JOL" /></div>';

    s.innerHTML = html;
    mount(s);
    qs("#retryBtn", s).addEventListener("click", renderForm);
    var share = qs("#shareBtn", s);
    if (share) share.addEventListener("click", function () { shareResult(r, lv, risk, share); });
    if (qs("#choiceBox", s)) bindChoice(s, ctx);
    // 結果を出したら入力は手元に残さない（もどる用の下書きも消す）
    if (lv !== "x") draft = { url: "", company: "", email: "", own: false };
  }

  renderIntro();
})();
