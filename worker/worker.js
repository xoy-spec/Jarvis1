// Push-Schlüssel (nur in deinem Worker, nicht in GitHub). Nicht weitergeben.
const VAPID = { d: "2-fL07Q2hFEriMiN_g2WJ0GbA4SggxVtjFtj7Ced3xc", x: "H926OYs5SA7evb33H2bdZCxJK5s4tTsVurj9SkdydSc", y: "AtkBRo-fVPRKnDx8j_DoDxLzsOsfM9UCty6Gi1Ihaa4", pub: "BB_dujmLOUgO3r299x9m3WQsSSubOLU7Fbq4_UpHcnUnAtkBRo-fVPRKnDx8j_DoDxLzsOsfM9UCty6Gi1Ihaa4" };
/* ---- Web Push (RFC 8291 aes128gcm + VAPID) ---- */
const b64u = (buf) => { let s = ""; const a = new Uint8Array(buf); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = (s) => { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const b = atob(s), a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; };
const enc = new TextEncoder();
const cat = (...as) => { const n = as.reduce((x, a) => x + a.length, 0), o = new Uint8Array(n); let p = 0; as.forEach((a) => { o.set(a, p); p += a.length; }); return o; };
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt, info: info }, k, len * 8));
}
async function pushEncrypt(sub, text, T) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const eph = T && T.eph ? T.eph : await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, secret, cat(enc.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = T && T.salt ? T.salt : crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const plain = cat(enc.encode(text), new Uint8Array([2]));
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
  const rs = new Uint8Array([0, 0, 16, 0]);
  return cat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}
async function vapidAuth(endpoint, V) {
  const aud = new URL(endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud: aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "https://xoy-spec.github.io/Jarvis1" })));
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", d: V.d, x: V.x, y: V.y, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + body)));
  return "vapid t=" + head + "." + body + "." + b64u(sig) + ", k=" + V.pub;
}
async function pushSend(sub, obj, V) {
  const body = await pushEncrypt(sub, JSON.stringify(obj));
  const r = await fetch(sub.endpoint, { method: "POST", headers: { Authorization: await vapidAuth(sub.endpoint, V), "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "3600", Urgency: "normal" }, body: body });
  return r.status;
}

const cleanRem = (a) => (Array.isArray(a) ? a : []).slice(0, 150).map((r) => ({ id: String(r.id || "").slice(0, 80), at: Number(r.at) || 0, t: String(r.t || "").slice(0, 80), b: String(r.b || "").slice(0, 180) })).filter((r) => r.id && r.at);
const devId = (ep) => { let h = 7; for (let i = 0; i < ep.length; i++) h = (h * 33 + ep.charCodeAt(i)) | 0; return (h >>> 0).toString(36) + ep.length.toString(36); };
async function runPush(env) {
  if (!env.JARVIS_KV) return;
  const idx = (await env.JARVIS_KV.get("push:index", "json")) || [];
  let idxChanged = false;
  const now = Date.now();
  for (const id of idx.slice()) {
    const rec = await env.JARVIS_KV.get("push:" + id, "json");
    if (!rec || !rec.sub) { idx.splice(idx.indexOf(id), 1); idxChanged = true; continue; }
    rec.sent = rec.sent || {};
    const due = (rec.rem || []).filter((r) => r.at <= now && r.at > now - 2 * 3600000 && !rec.sent[r.id]).sort((a, b) => a.at - b.at);
    if (!due.length) continue;
    let gone = false, changed = false;
    const list = due.length > 4 ? due.slice(0, 3) : due;
    for (const r of list) {
      let st = 0;
      try { st = await pushSend(rec.sub, { t: r.t, b: r.b, tag: r.id }, VAPID); } catch (e) { st = 0; }
      if (st >= 200 && st < 300) { rec.sent[r.id] = now; changed = true; }
      else if (st === 404 || st === 410) { gone = true; break; }
    }
    if (!gone && due.length > 4) {
      const rest = due.slice(3);
      let st = 0;
      try { st = await pushSend(rec.sub, { t: "Jarvis: " + rest.length + " weitere Erinnerungen", b: rest.map((r) => r.t).join(", ").slice(0, 160), tag: "more:" + now }, VAPID); } catch (e) { st = 0; }
      if (st >= 200 && st < 300) { rest.forEach((r) => { rec.sent[r.id] = now; }); changed = true; }
    }
    if (gone) { await env.JARVIS_KV.delete("push:" + id); idx.splice(idx.indexOf(id), 1); idxChanged = true; continue; }
    if (changed) {
      Object.keys(rec.sent).forEach((k) => { if (now - rec.sent[k] > 3 * 86400000) delete rec.sent[k]; });
      rec.rem = (rec.rem || []).filter((r) => r.at > now - 86400000);
      await env.JARVIS_KV.put("push:" + id, JSON.stringify(rec));
    }
  }
  if (idxChanged) await env.JARVIS_KV.put("push:index", JSON.stringify(idx));
}
export default {
  async fetch(request, env) {
    const LIMIT = 200;
    const cors = {
      "Access-Control-Allow-Origin": ["https://xoy-spec.github.io", "https://behator99-lang.github.io"].indexOf(request.headers.get("Origin")) >= 0 ? request.headers.get("Origin") : "https://xoy-spec.github.io",
      "Vary": "Origin",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Jarvis-Code",
    };
    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { ...cors, "content-type": "application/json" },
      });
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    if (request.method !== "POST") return json({ error: { message: "Nur POST" } }, 405);
    const sent = request.headers.get("X-Jarvis-Code") || "";
    let who = "";
    if (env.JARVIS_CODE && sent === env.JARVIS_CODE) who = "owner";
    else if (sent && env.JARVIS_GUESTS) {
      String(env.JARVIS_GUESTS).split(",").forEach((g) => {
        const i = g.indexOf(":");
        if (i > 0 && g.slice(i + 1).trim() === sent) who = g.slice(0, i).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "").slice(0, 20) || "gast";
      });
    }
    if (!who) {
      return json({ error: { message: "Zugangscode falsch" } }, 401);
    }
    const isOwner = who === "owner";
    const dataKey = isOwner ? "data" : "data:" + who;
    let payload;
    try {
      payload = await request.json();
    } catch (e) {
      return json({ error: { message: "Ungültige Anfrage" } }, 400);
    }

    if (payload.action === "sync_get") {
      if (!env.JARVIS_KV) return json({ error: { message: "Speicher nicht verbunden" } }, 500);
      return json({ data: await env.JARVIS_KV.get(dataKey, "json") });
    }
    if (payload.action === "sync_set") {
      if (!env.JARVIS_KV) return json({ error: { message: "Speicher nicht verbunden" } }, 500);
      const d = payload.data || {};
      const arr = (x) => (Array.isArray(x) ? x : []);
      const clean = {
        notes: arr(d.notes),
        todos: arr(d.todos),
        facts: arr(d.facts),
        inv: arr(d.inv),
        fav: arr(d.fav),
        updated: Number(d.updated) || Date.now(),
      };
      const str = JSON.stringify(clean);
      if (str.length > 500000) return json({ error: { message: "Zu viele Daten" } }, 413);
      await env.JARVIS_KV.put(dataKey, str);
      return json({ ok: true });
    }

    if (payload.action === "quotes") {
      const GROUPS = {
        idx: [["^GDAXI", "DAX", "Index"], ["^GSPC", "S&P 500", "Index"], ["^IXIC", "Nasdaq", "Index"], ["^DJI", "Dow Jones", "Index"], ["GC=F", "Gold", "Rohstoff"], ["CL=F", "Öl (WTI)", "Rohstoff"], ["EURUSD=X", "EUR/USD", "Währung"]],
        de1: [["ADS.DE", "Adidas"], ["AIR.DE", "Airbus"], ["ALV.DE", "Allianz"], ["BAS.DE", "BASF"], ["BAYN.DE", "Bayer"], ["BEI.DE", "Beiersdorf"], ["BMW.DE", "BMW"], ["BNR.DE", "Brenntag"], ["CBK.DE", "Commerzbank"], ["CON.DE", "Continental"], ["1COV.DE", "Covestro"], ["DTG.DE", "Daimler Truck"], ["DBK.DE", "Deutsche Bank"], ["DB1.DE", "Deutsche Börse"], ["DHL.DE", "DHL Group"], ["DTE.DE", "Dt. Telekom"], ["EOAN.DE", "E.ON"], ["FRE.DE", "Fresenius"], ["FME.DE", "Fresenius Med."], ["HNR1.DE", "Hannover Rück"], ["HEI.DE", "Heidelberg Mat."]],
        de2: [["HEN3.DE", "Henkel"], ["IFX.DE", "Infineon"], ["MBG.DE", "Mercedes-Benz"], ["MRK.DE", "Merck"], ["MTX.DE", "MTU"], ["MUV2.DE", "Münchener Rück"], ["P911.DE", "Porsche AG"], ["PAH3.DE", "Porsche SE"], ["QIA.DE", "Qiagen"], ["RHM.DE", "Rheinmetall"], ["RWE.DE", "RWE"], ["SAP.DE", "SAP"], ["SRT3.DE", "Sartorius"], ["SIE.DE", "Siemens"], ["ENR.DE", "Siemens Energy"], ["SHL.DE", "Siemens Health."], ["SY1.DE", "Symrise"], ["VOW3.DE", "Volkswagen"], ["VNA.DE", "Vonovia"], ["ZAL.DE", "Zalando"]],
        us: [["AAPL", "Apple"], ["MSFT", "Microsoft"], ["NVDA", "Nvidia"], ["AMZN", "Amazon"], ["GOOGL", "Alphabet"], ["META", "Meta"], ["TSLA", "Tesla"], ["AVGO", "Broadcom"], ["NFLX", "Netflix"], ["AMD", "AMD"], ["JPM", "JPMorgan"], ["V", "Visa"]],
        etf: [["EUNL.DE", "iShares MSCI World", "Welt, Industrieländer"], ["VWCE.DE", "Vanguard FTSE All-World", "Welt inkl. Schwellenländer"], ["SXR8.DE", "iShares S&P 500", "500 große US-Firmen"], ["EXS1.DE", "iShares DAX", "40 DAX-Konzerne"], ["XDWD.DE", "Xtrackers MSCI World", "Welt, Industrieländer"], ["IS3N.DE", "iShares MSCI EM IMI", "Schwellenländer"], ["SXRV.DE", "iShares Nasdaq 100", "100 große Tech-Werte"], ["EXSA.DE", "iShares STOXX Europe 600", "Europa breit"]],
      };
      const g = GROUPS[payload.group];
      if (!g) return json({ error: { message: "Unbekannte Gruppe" } }, 400);
      const ck = "q:" + payload.group;
      if (env.JARVIS_KV) {
        const c = await env.JARVIS_KV.get(ck, "json");
        if (c && Date.now() - c.t < 240000) return json(c);
      }
      let err = "";
      const one = async (row) => {
        try {
          const r = await fetch("https://query1.finance.yahoo.com/v8/finance/chart/" + encodeURIComponent(row[0]) + "?range=1d&interval=1d", {
            headers: { "User-Agent": "Mozilla/5.0 (compatible; JarvisApp/1.0)", Accept: "application/json" },
          });
          if (!r.ok) throw new Error("HTTP " + r.status);
          const j = await r.json();
          const m = j && j.chart && j.chart.result && j.chart.result[0] && j.chart.result[0].meta;
          if (!m || typeof m.regularMarketPrice !== "number") throw new Error("keine Daten");
          const prev = typeof m.chartPreviousClose === "number" ? m.chartPreviousClose : m.previousClose;
          const c = prev ? ((m.regularMarketPrice - prev) / prev) * 100 : null;
          return { s: row[0], n: row[1], i: row[2] || "", p: m.regularMarketPrice, c: c, cur: m.currency || "" };
        } catch (e) {
          if (!err) err = row[0] + ": " + e.message;
          return null;
        }
      };
      const res = (await Promise.all(g.map(one))).filter(Boolean);
      const out = { t: Date.now(), items: res, failed: g.length - res.length, err: err };
      if (env.JARVIS_KV && res.length) await env.JARVIS_KV.put(ck, JSON.stringify(out), { expirationTtl: 900 });
      return json(out);
    }

    if (payload.action === "cal") {
      let u = String(payload.url || "").trim().replace(/^webcal:\/\//i, "https://");
      let host = "";
      try { host = new URL(u).hostname; } catch (e) { return json({ error: { message: "Kein gültiger Link" } }, 400); }
      const okHost = (h) => /(^|\.)icloud\.com$/i.test(h);
      if (!okHost(host)) return json({ error: { message: "Bitte den iCloud-Kalenderlink einfügen (icloud.com)" } }, 400);
      let h = 0;
      for (let i = 0; i < u.length; i++) h = (h * 31 + u.charCodeAt(i)) | 0;
      const ck = "cal:" + (h >>> 0).toString(36);
      if (env.JARVIS_KV) {
        const c = await env.JARVIS_KV.get(ck, "json");
        if (c && Date.now() - c.t < 300000) return json(c);
      }
      let txt = "";
      try {
        let cur = u;
        for (let hop = 0; hop < 4; hop++) {
          const r = await fetch(cur, { redirect: "manual", headers: { "User-Agent": "JarvisApp/1.0", Accept: "text/calendar" } });
          if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
            const nx = new URL(r.headers.get("location"), cur).toString();
            if (!okHost(new URL(nx).hostname)) throw new Error("Weiterleitung nicht erlaubt");
            cur = nx;
            continue;
          }
          if (!r.ok) throw new Error("HTTP " + r.status + " (ist der Kalender öffentlich?)");
          txt = (await r.text()).slice(0, 3000000);
          break;
        }
        if (txt.indexOf("BEGIN:VCALENDAR") < 0) throw new Error("Das war kein Kalender");
      } catch (e) {
        return json({ error: { message: "Kalender nicht lesbar: " + e.message } }, 502);
      }
      const berlin = (d) => {
        const p = {};
        new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Berlin", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false })
          .formatToParts(d).forEach((x) => { p[x.type] = x.value; });
        return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute);
      };
      const parseDt = (o) => {
        if (!o) return null;
        const m = o.v.match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})?)?(Z?)$/);
        if (!m) return null;
        if (o.allDay || m[4] === undefined) return { t: Date.UTC(+m[1], +m[2] - 1, +m[3]), ad: true };
        if (m[7] === "Z") return { t: berlin(new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]))), ad: false };
        return { t: Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]), ad: false };
      };
      const unesc = (t) => String(t || "").replace(/\\n/gi, " ").replace(/\\,/g, ",").replace(/\;/g, ";").replace(/\\\\/g, "\\");
      const lines = txt.replace(/\r?\n[ \t]/g, "").split(/\r?\n/);
      const evs = [];
      let cur = null;
      for (const ln of lines) {
        if (ln === "BEGIN:VEVENT") { cur = { ex: [] }; continue; }
        if (ln === "END:VEVENT") { if (cur) evs.push(cur); cur = null; continue; }
        if (!cur) continue;
        const i = ln.indexOf(":");
        if (i < 0) continue;
        const left = ln.slice(0, i), val = ln.slice(i + 1);
        const name = left.split(";")[0].toUpperCase();
        const allDay = /VALUE=DATE(?!-)/i.test(left);
        if (name === "DTSTART") cur.s = { v: val, allDay };
        else if (name === "DTEND") cur.e = { v: val, allDay };
        else if (name === "SUMMARY") cur.t = unesc(val);
        else if (name === "LOCATION") cur.l = unesc(val);
        else if (name === "RRULE") cur.r = val;
        else if (name === "UID") cur.uid = val;
        else if (name === "RECURRENCE-ID") cur.rid = val.slice(0, 8);
        else if (name === "EXDATE") val.split(",").forEach((x) => cur.ex.push(x.slice(0, 8)));
        else if (name === "STATUS" && /CANCELLED/i.test(val)) cur.cx = 1;
      }
      const nowB = berlin(new Date());
      const d0 = Math.floor(nowB / 86400000) * 86400000;
      const wEnd = d0 + 15 * 86400000;
      const overrides = {};
      evs.forEach((e) => { if (e.rid && e.uid) { (overrides[e.uid] = overrides[e.uid] || {})[e.rid] = 1; } });
      const dayStr = (t) => { const d = new Date(t); return "" + d.getUTCFullYear() + String(d.getUTCMonth() + 1).padStart(2, "0") + String(d.getUTCDate()).padStart(2, "0"); };
      const iso = (t, ad) => { const d = new Date(t); const p = (n) => String(n).padStart(2, "0"); return d.getUTCFullYear() + "-" + p(d.getUTCMonth() + 1) + "-" + p(d.getUTCDate()) + (ad ? "" : "T" + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes())); };
      const out = [];
      const add = (e, st, dur, ad) => {
        const en = st + dur;
        if (en <= d0 || st >= wEnd) return;
        out.push({ s: iso(st, ad), e: iso(en, ad), t: e.t || "(ohne Titel)", l: e.l || "", a: ad ? 1 : 0, k: st });
      };
      for (const e of evs) {
        if (e.cx || !e.s) continue;
        const a = parseDt(e.s);
        if (!a) continue;
        const b = e.e ? parseDt(e.e) : null;
        const dur = b ? Math.max(0, b.t - a.t) : (a.ad ? 86400000 : 3600000);
        if (!e.r) { add(e, a.t, dur, a.ad); continue; }
        const rr = {};
        e.r.split(";").forEach((x) => { const p = x.split("="); rr[p[0]] = p[1]; });
        const iv = Math.max(1, parseInt(rr.INTERVAL || "1", 10));
        const cnt = rr.COUNT ? parseInt(rr.COUNT, 10) : 0;
        let until = Infinity;
        if (rr.UNTIL) { const u2 = parseDt({ v: rr.UNTIL, allDay: rr.UNTIL.length === 8 }); if (u2) until = u2.t + 86400000; }
        const tod = a.ad ? 0 : (a.t % 86400000);
        const day0 = a.t - tod;
        const skip = new Set(e.ex);
        const ov = (overrides[e.uid] || {});
        let n = 0;
        const emit = (st) => {
          n++;
          if (st >= until) return false;
          const ds = dayStr(st);
          if (!skip.has(ds) && !ov[ds]) add(e, st, dur, a.ad);
          return !(cnt && n >= cnt);
        };
        const F = rr.FREQ;
        let guard = 0;
        if (F === "DAILY") {
          for (let k = 0; guard++ < 4000; k++) { const st = day0 + k * iv * 86400000 + tod; if (st >= wEnd) break; if (!emit(st)) break; }
        } else if (F === "WEEKLY") {
          const map = { MO: 0, TU: 1, WE: 2, TH: 3, FR: 4, SA: 5, SU: 6 };
          const wd0 = (new Date(day0).getUTCDay() + 6) % 7;
          const days = rr.BYDAY ? rr.BYDAY.split(",").map((x) => map[x.slice(-2)]).filter((x) => x !== undefined).sort((x, y) => x - y) : [wd0];
          const wk0 = day0 - wd0 * 86400000;
          outer: for (let k = 0; guard++ < 1500; k++) {
            for (const d of days) {
              const st = wk0 + (k * iv * 7 + d) * 86400000 + tod;
              if (st < a.t) continue;
              if (st >= wEnd) break outer;
              if (!emit(st)) break outer;
            }
          }
        } else if (F === "MONTHLY" || F === "YEARLY") {
          const sd = new Date(a.t);
          for (let k = 0; guard++ < 600; k++) {
            const st = F === "MONTHLY"
              ? Date.UTC(sd.getUTCFullYear(), sd.getUTCMonth() + k * iv, sd.getUTCDate(), sd.getUTCHours(), sd.getUTCMinutes())
              : Date.UTC(sd.getUTCFullYear() + k * iv, sd.getUTCMonth(), sd.getUTCDate(), sd.getUTCHours(), sd.getUTCMinutes());
            if (st >= wEnd) break;
            if (!emit(st)) break;
          }
        } else add(e, a.t, dur, a.ad);
      }
      out.sort((x, y) => x.k - y.k);
      const res = { t: Date.now(), items: out.slice(0, 80).map((x) => ({ s: x.s, e: x.e, t: x.t, l: x.l, a: x.a })) };
      if (env.JARVIS_KV) await env.JARVIS_KV.put(ck, JSON.stringify(res), { expirationTtl: 900 });
      return json(res);
    }

    if (payload.action && payload.action.indexOf("push_") === 0) {
      if (!env.JARVIS_KV) return json({ error: { message: "Speicher nicht verbunden" } }, 500);
      if (payload.action === "push_key") return json({ key: VAPID.pub });
      if (payload.action === "push_sub") {
        const s = payload.sub || {};
        if (!s.endpoint || !/^https:\/\//.test(s.endpoint) || !s.keys || !s.keys.p256dh || !s.keys.auth) return json({ error: { message: "Ungültiges Gerät" } }, 400);
        const id = devId(s.endpoint);
        const old = (await env.JARVIS_KV.get("push:" + id, "json")) || {};
        const rec = { sub: { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } }, rem: cleanRem(payload.reminders), sent: old.sent || {}, upd: Date.now() };
        await env.JARVIS_KV.put("push:" + id, JSON.stringify(rec));
        let idx = (await env.JARVIS_KV.get("push:index", "json")) || [];
        if (idx.indexOf(id) < 0) { idx.push(id); if (idx.length > 6) idx = idx.slice(-6); await env.JARVIS_KV.put("push:index", JSON.stringify(idx)); }
        return json({ ok: true, id: id });
      }
      const id = String(payload.id || "");
      const rec = id ? await env.JARVIS_KV.get("push:" + id, "json") : null;
      if (payload.action === "push_set") {
        if (!rec) return json({ error: { message: "Dieses Gerät ist nicht angemeldet" }, gone: true }, 404);
        rec.rem = cleanRem(payload.reminders);
        rec.upd = Date.now();
        await env.JARVIS_KV.put("push:" + id, JSON.stringify(rec));
        return json({ ok: true, n: rec.rem.length });
      }
      if (payload.action === "push_off") {
        await env.JARVIS_KV.delete("push:" + id);
        const idx = ((await env.JARVIS_KV.get("push:index", "json")) || []).filter((x) => x !== id);
        await env.JARVIS_KV.put("push:index", JSON.stringify(idx));
        return json({ ok: true });
      }
      if (payload.action === "push_test") {
        if (!rec) return json({ error: { message: "Dieses Gerät ist nicht angemeldet" }, gone: true }, 404);
        let st = 0, msg = "";
        try { st = await pushSend(rec.sub, { t: "Jarvis", b: "Test: Erinnerungen funktionieren.", tag: "test" }, VAPID); } catch (e) { msg = String(e && e.message || e); }
        return json({ status: st, err: msg, n: (rec.rem || []).length });
      }
      return json({ error: { message: "Unbekannte Aktion" } }, 400);
    }

    const { messages, system, mode } = payload;
    if (!Array.isArray(messages) || !messages.length) {
      return json({ error: { message: "Keine Nachrichten" } }, 400);
    }
    if (env.JARVIS_KV) {
      const key = "count:" + (isOwner ? "" : who + ":") + new Date().toISOString().slice(0, 10);
      const lim = isOwner ? LIMIT : (parseInt(env.GUEST_LIMIT || "", 10) || 40);
      const n = parseInt((await env.JARVIS_KV.get(key)) || "0", 10);
      if (n >= lim) {
        return json({ error: { message: "Tageslimit erreicht (" + lim + "). Morgen geht es weiter." } }, 429);
      }
      await env.JARVIS_KV.put(key, String(n + (mode === "search" ? 3 : 1)), { expirationTtl: 172800 });
    }
    const standard = "Du bist Jarvis, ein hilfreicher, höflicher KI-Assistent. Antworte auf Deutsch, kurz und präzise.";
    const body = {
      model: "claude-haiku-5-5",
      max_tokens: mode === "search" ? 4000 : 1500,
      system: typeof system === "string" && system.length < 12000 ? system : standard,
      messages: messages.slice(-20),
    };
    if (mode === "search") {
      body.tools = [{ type: "web_search_20250305", name: "web_search", max_uses: 3 }];
    }
    const callApi = () => fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    });
    const r = await callApi();
    let data = await r.json();
    let status = r.status;
    // Bei langen Websuchen pausiert die API (pause_turn). Dann machen wir automatisch weiter.
    for (let i = 0; i < 3 && status === 200 && data && data.stop_reason === "pause_turn" && Array.isArray(data.content); i++) {
      body.messages = body.messages.concat([{ role: "assistant", content: data.content }]);
      const r2 = await callApi();
      const d2 = await r2.json();
      if (!r2.ok) { data = d2; status = r2.status; break; }
      d2.content = data.content.concat(d2.content || []);
      data = d2;
    }
    return json(data, status);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runPush(env));
  },
};
