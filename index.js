/**
 * Proxy CORS untuk Pencari Kata (Cloudflare Workers), versi 7
 * Alamat di aplikasi: Filter > "Alamat proxy" > https://NAMA.AKUNMU.workers.dev
 * Aplikasi memanggil:  <proxy>/?url=<alamat-asli-yang-di-encode>
 *
 * Fitur:
 *  - Cache memori + cache tepi Cloudflare; stale-while-revalidate (HIT / STALE) untuk GET dan POST baca-saja
 *  - Cache singkat untuk 404; hasil lama dipakai saat sumber error (STALE-ERR)
 *  - Coba ulang otomatis (429/502/503/504) dengan jeda acak + Retry-After; anggaran waktu total < 10 dtk
 *  - Hedging: sumber lambat dikirimi permintaan kedua, yang tercepat menang
 *  - Pemutus sirkuit per sumber; jeda per sumber yang menyesuaikan diri (melambat saat 429)
 *  - Permintaan kembar digabung; batas laju per pengguna; kunci API opsional lewat Secret
 *  - Redirect diperiksa di SETIAP lompatan terhadap daftar putih
 *  - /health (statistik per sumber), header X-Proxy-Cache / -Tries / -Time, &nocache=1
 */

// ---- Pengaturan ----------------------------------------------------------
const ALLOWED_HOSTS = [
  'photon.komoot.io', 'geonames.org', 'open-meteo.com', 'wikidata.org', 'marineregions.org',
  'gbif.org', 'checklistbank.org', 'inaturalist.org', 'europepmc.org', 'wikimedia.org',
  'kew.org', 'ipni.org', 'paleobiodb.org', 'boldsystems.org', 'opentreeoflife.org',
  'worldfloraonline.org', 'marinespecies.org', 'itis.gov', 'obis.org', 'ensembl.org',
  'ncbi.nlm.nih.gov', 'nlm.nih.gov', 'ebi.ac.uk', 'fda.gov', 'uniprot.org', 'cancer.gov', 'nci.nih.gov',
  'macrostrat.org', 'sciencebase.gov', 'wikipedia.org', 'wiktionary.org',
  'githubusercontent.com', 'jsdelivr.net',
  'mymemory.translated.net', 'translate.googleapis.com', 'kemdikbud.go.id', 'obolibrary.org',
  'usgs.gov', 'bgs.ac.uk', 'mindat.org', 'dbpedia.org', 'crossref.org', 'openalex.org'
];
const ALLOWED_ORIGINS = [];          // [] = semua asal boleh. Contoh kunci: ['https://usernamemu.github.io', 'null']

const TTL_RULES = [                  // lama cache segar per sumber (detik)
  [/githubusercontent\.com$|jsdelivr\.net$/, 86400],
  [/ebi\.ac\.uk$|uniprot\.org$|macrostrat\.org$|nlm\.nih\.gov$/, 3600],
  [/gbif\.org$|checklistbank\.org$|itis\.gov$|worldfloraonline\.org$|opentreeoflife\.org$|paleobiodb\.org$/, 1800],
  [/wikipedia\.org$|wikidata\.org$|wiktionary\.org$|wikimedia\.org$/, 900]
];
const DEFAULT_TTL = 300, NEG_TTL = 60;
const STALE_WINDOW = 24 * 3600;      // hasil lama masih boleh dikirim sambil diperbarui di belakang layar
const STALE_ERR = 7 * 24 * 3600;     // hasil lama boleh dipakai kalau sumber error
const gapFor = (h, env) =>           // jeda minimum antar permintaan ke satu sumber (ms)
  /pubchem\.ncbi\.nlm\.nih\.gov$/.test(h) ? 150 :
  /eutils\.ncbi\.nlm\.nih\.gov$/.test(h) ? (env && env.NCBI_API_KEY ? 120 : 340) :
  /marinespecies\.org$/.test(h) ? 60 : 0;

const MAX_URL = 4096, MAX_BODY = 200 * 1024, MAX_ENTRY = 4 * 1024 * 1024;
const MEM_MAX_BYTES = 24 * 1024 * 1024, MEM_MAX_ENTRIES = 400;
const TOTAL_MS = 8500;               // aplikasi memutus di 10 dtk: Worker harus menjawab lebih dulu
const SLOW_HOSTS = /(paleobiodb\.org|checklistbank\.org|boldsystems\.org|worldfloraonline\.org|kew\.org|ipni\.org)$/;
const HEDGE_HOSTS = /(gbif\.org|checklistbank\.org|paleobiodb\.org|boldsystems\.org|opentreeoflife\.org|inaturalist\.org|worldfloraonline\.org|wikipedia\.org|wikidata\.org|wiktionary\.org|ebi\.ac\.uk|uniprot\.org|macrostrat\.org|obis\.org|ipni\.org|kew\.org)$/;
const HEDGE_MS = 2200;
const budgetFor = h => SLOW_HOSTS.test(h) ? { per: 7500, tries: 2 } : { per: 4500, tries: 3 };
const RETRY = new Set([429, 502, 503, 504]);
const BREAKER_FAILS = 5, BREAKER_MS = 20000;
const RATE_PER_MIN = 240;
const BROWSER_MAX_AGE = 60;
const UA = 'PencariKata-Proxy/7.0 (personal, non-commercial)';

// ---- Kode ----------------------------------------------------------------
const sleep = ms => new Promise(r => setTimeout(r, ms));
const hostAllowed = h => ALLOWED_HOSTS.some(d => h === d || h.endsWith('.' + d));
const ttlFor = h => { for (const [re, t] of TTL_RULES) if (re.test(h)) return t; return DEFAULT_TTL; };
const urlAllowed = u => /^https?:$/.test(u.protocol) && !u.port && !u.username && !u.password && hostAllowed(u.hostname);
const inflight = new Map(), gates = new Map(), circuit = new Map(), buckets = new Map(), penalty = new Map(), stats = new Map();
const bootAt = Date.now();
const mem = new Map();
let memBytes = 0;

function memGet(k) { const e = mem.get(k); if (!e) return null; mem.delete(k); mem.set(k, e); return e; }
function memPut(k, e) {
  const old = mem.get(k);
  if (old) { memBytes -= old.buf.byteLength; mem.delete(k); }
  mem.set(k, e); memBytes += e.buf.byteLength;
  while ((memBytes > MEM_MAX_BYTES || mem.size > MEM_MAX_ENTRIES) && mem.size) {
    const [kk, v] = mem.entries().next().value; memBytes -= v.buf.byteLength; mem.delete(kk);
  }
}
function cors(origin) {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS.length ? origin : '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Expose-Headers': 'Retry-After, Content-Type, X-Proxy-Cache, X-Proxy-Tries, X-Proxy-Time',
    'Vary': 'Origin'
  };
}
const text = (status, msg, origin, extra) =>
  new Response(msg, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...cors(origin), ...(extra || {}) } });
const json = (obj, origin) => new Response(JSON.stringify(obj), { headers: { 'Content-Type': 'application/json', ...cors(origin) } });
async function sha(buf) {
  const d = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

function note(h, ok, ms, why) {
  let t = stats.get(h);
  if (!t) { if (stats.size > 100) return; t = { ok: 0, fail: 0, ms: 0, last: '' }; stats.set(h, t); }
  if (ok) { t.ok++; t.ms = t.ms ? Math.round(t.ms * 0.8 + ms * 0.2) : Math.round(ms); }
  else { t.fail++; t.last = String(why || '').slice(0, 80); }
}
function adapt(h, status) {            // melambat saat 429, pulih pelan-pelan saat lancar
  const p = penalty.get(h) || 0;
  if (status === 429) penalty.set(h, Math.min(2000, Math.max(200, p * 2)));
  else if (p && status < 400) penalty.set(h, p * 0.7 < 50 ? 0 : Math.floor(p * 0.7));
}
function pace(host, gap) {
  if (!gap) return Promise.resolve();
  const prev = gates.get(host) || Promise.resolve();
  gates.set(host, prev.then(() => sleep(gap)));
  return prev;
}
const breakerOpen = h => { const c = circuit.get(h); return !!c && c.openUntil > Date.now(); };
function breakerNote(h, ok) {
  let c = circuit.get(h);
  if (!c) { if (circuit.size > 100) return; c = { fails: 0, openUntil: 0 }; circuit.set(h, c); }
  if (ok) { c.fails = 0; c.openUntil = 0; }
  else if (++c.fails >= BREAKER_FAILS) { c.openUntil = Date.now() + BREAKER_MS; c.fails = 0; }
}
function allowRate(ip) {
  const now = Date.now();
  if (buckets.size > 2000) for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k);
  let b = buckets.get(ip);
  if (!b || b.reset < now) { b = { n: 0, reset: now + 60000 }; buckets.set(ip, b); }
  return ++b.n <= RATE_PER_MIN;
}

// Satu percobaan; redirect diikuti manual dan tiap lompatan diperiksa daftar putih.
async function one(url, method, headers, body, cf, ms) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms);
  try {
    let u = url, m = method, b = body;
    for (let hop = 0; hop < 5; hop++) {
      const r = await fetch(u, { method: m, headers, body: b, cf, redirect: 'manual', signal: ac.signal });
      const loc = r.headers.get('Location');
      if (r.status >= 300 && r.status < 400 && loc) {
        const next = new URL(loc, u);
        if (!urlAllowed(next)) { const e = new Error('Redirect ke domain terlarang'); e.fatal = true; throw e; }
        if (r.status !== 307 && r.status !== 308) { m = 'GET'; b = undefined; }
        u = next.toString(); continue;
      }
      return r;
    }
    throw new Error('Terlalu banyak redirect');
  } finally { clearTimeout(timer); }
}
// Hedging: bila belum menjawab dalam HEDGE_MS, kirim permintaan kedua; jawaban sehat tercepat menang.
function hedged(args, ms) {
  return new Promise((resolve, reject) => {
    let pending = 0, done = false, bad = null, timer;
    const end = (fn, v) => { if (done) return; done = true; clearTimeout(timer); fn(v); };
    const launch = () => {
      pending++;
      one(...args, ms).then(r => {
        pending--;
        if (!RETRY.has(r.status)) return end(resolve, r);
        bad = r; if (!pending) end(resolve, bad);
      }, e => { pending--; if (!pending) bad ? end(resolve, bad) : end(reject, e); });
    };
    launch();
    timer = setTimeout(() => { if (!done) launch(); }, HEDGE_MS);
  });
}
async function upstream(o) {
  const t0 = Date.now(), { per, tries } = budgetFor(o.host);
  const canHedge = o.method === 'GET' && HEDGE_HOSTS.test(o.host);
  for (let i = 1; ; i++) {
    const left = TOTAL_MS - (Date.now() - t0);
    const ms = Math.max(1500, Math.min(per, left));
    try {
      const args = [o.url, o.method, o.headers, o.body, o.cf];
      const res = await (canHedge ? hedged(args, ms) : one(...args, ms));
      if (!RETRY.has(res.status) || i >= tries || TOTAL_MS - (Date.now() - t0) < 1500) return { res, tries: i };
      const ra = Number(res.headers.get('Retry-After')) || 0;
      await sleep(Math.min(ra ? ra * 1000 : 350 + Math.random() * 450, 1500));
    } catch (e) {
      if (e.fatal || i >= tries || TOTAL_MS - (Date.now() - t0) < 1500) throw e;
      await sleep(250 + Math.random() * 350);
    }
  }
}

// Ambil dari sumber; permintaan kembar ke kunci yang sama digabung.
function load(k, o) {
  const ex = inflight.get(k);
  if (ex) return ex;
  const p = (async () => {
    if (breakerOpen(o.host)) { const e = new Error('Sumber sedang bermasalah, dilewati sementara'); e.circuit = true; throw e; }
    await pace(o.host, o.gap + (penalty.get(o.host) || 0));
    const t1 = Date.now();
    let r;
    try { r = await upstream(o); }
    catch (e) { breakerNote(o.host, false); note(o.host, false, 0, e && e.message); throw e; }
    const { res, tries } = r, status = res.status;
    breakerNote(o.host, status < 500); adapt(o.host, status);
    note(o.host, status < 500 && status !== 429, Date.now() - t1, 'HTTP ' + status);
    const ct = res.headers.get('Content-Type') || 'application/json';
    const ra = res.headers.get('Retry-After');
    const buf = status === 204 ? new ArrayBuffer(0) : await res.arrayBuffer();
    const ttl = status === 200 ? o.ttl : status === 404 ? Math.min(o.ttl, NEG_TTL) : 0;
    if (o.cacheOn && ttl > 0 && buf.byteLength <= MAX_ENTRY) memPut(k, { at: Date.now(), status, ct, buf, ttl });
    return { status, ct, ra, buf, tries };
  })().finally(() => inflight.delete(k));
  inflight.set(k, p);
  return p;
}

function answer(r, origin, state, t0, head) {
  const h = { 'X-Proxy-Cache': state, 'X-Proxy-Tries': String(r.tries || 0), 'X-Proxy-Time': String(Date.now() - t0), ...cors(origin) };
  if (r.ct) h['Content-Type'] = r.ct;
  if (r.ra) h['Retry-After'] = r.ra;
  if (r.status === 200 && state !== 'BYPASS') h['Cache-Control'] = 'public, max-age=' + BROWSER_MAX_AGE;
  const empty = head || r.status === 204 || !r.buf || !r.buf.byteLength;
  return new Response(empty ? null : r.buf, { status: r.status, headers: h });
}

export default {
  async fetch(request, env, ctx) {
    const t0 = Date.now();
    const origin = request.headers.get('Origin') || '';
    if (ALLOWED_ORIGINS.length && !ALLOWED_ORIGINS.includes(origin || 'null')) return text(403, 'Asal tidak diizinkan', origin);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(origin) });
    if (!['GET', 'HEAD', 'POST'].includes(request.method)) return text(405, 'Metode tidak didukung', origin);

    const reqUrl = new URL(request.url);
    if (reqUrl.pathname === '/health') {
      const open = [...circuit].filter(([, c]) => c.openUntil > Date.now()).map(([h]) => h);
      return json({ ok: true, name: 'Pencari Kata proxy', version: 7, time: new Date().toISOString(),
        hosts: ALLOWED_HOSTS.length, inflight: inflight.size, circuitOpen: open, memEntries: mem.size,
        memMB: Math.round(memBytes / 104857.6) / 10, uptimeSec: Math.round((Date.now() - bootAt) / 1000),
        slowed: Object.fromEntries(penalty), sources: Object.fromEntries(stats) }, origin);
    }
    const target = reqUrl.searchParams.get('url');
    if (!target) return text(200, 'Proxy Pencari Kata aktif. Pakai: /?url=<alamat yang di-encode>   |   cek: /health', origin);
    if (target.length > MAX_URL) return text(414, 'Alamat terlalu panjang', origin);

    let dest;
    try { dest = new URL(target); } catch (_) { return text(400, 'Alamat tidak valid', origin); }
    if (!/^https?:$/.test(dest.protocol)) return text(400, 'Hanya http/https', origin);
    if (dest.username || dest.password) return text(400, 'Kredensial di alamat tidak diizinkan', origin);
    if (dest.port) return text(400, 'Port khusus tidak diizinkan', origin);
    if (!hostAllowed(dest.hostname)) return text(403, 'Domain tidak ada di daftar putih: ' + dest.hostname, origin);

    if (env && env.NCBI_API_KEY && dest.hostname === 'eutils.ncbi.nlm.nih.gov' && !dest.searchParams.has('api_key')) dest.searchParams.set('api_key', env.NCBI_API_KEY);
    if (env && env.FDA_API_KEY && dest.hostname === 'api.fda.gov' && !dest.searchParams.has('api_key')) dest.searchParams.set('api_key', env.FDA_API_KEY);

    const head = request.method === 'HEAD';
    const method = head ? 'GET' : request.method;
    const headers = new Headers({ 'User-Agent': UA, 'Accept': request.headers.get('Accept') || 'application/json, text/plain, */*' });
    const ct = request.headers.get('Content-Type');
    if (ct) headers.set('Content-Type', ct);
    let body;
    if (method === 'POST') {
      body = await request.arrayBuffer();
      if (body.byteLength > MAX_BODY) return text(413, 'Isi permintaan terlalu besar', origin);
    }

    const nocache = reqUrl.searchParams.get('nocache') === '1';
    const ttl = ttlFor(dest.hostname);
    const url = dest.toString();
    dest.hash = ''; dest.searchParams.sort();
    const key = method === 'POST'
      ? 'post:' + await sha(await new Blob([url, '|', ct || '', '|', body]).arrayBuffer())
      : dest.toString();
    const job = { url, method, headers, body, ttl, cacheOn: !nocache, host: dest.hostname, gap: gapFor(dest.hostname, env),
      cf: method === 'POST' || nocache ? undefined : { cacheEverything: true, cacheTtlByStatus: { '200-299': ttl, '404': Math.min(ttl, NEG_TTL), '500-599': 0 } } };

    const old = nocache ? null : memGet(key);
    if (old) {
      const age = (Date.now() - old.at) / 1000;
      const r = { status: old.status, ct: old.ct, buf: old.buf, tries: 0 };
      if (age <= old.ttl) return answer(r, origin, 'HIT', t0, head);
      if (age <= old.ttl + (old.status === 200 ? STALE_WINDOW : 0)) {
        if (!breakerOpen(dest.hostname) && !inflight.has(key)) ctx.waitUntil(load(key, job).catch(() => {}));
        return answer(r, origin, 'STALE', t0, head);
      }
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'anon';
    if (!inflight.has(key) && !allowRate(ip)) return text(429, 'Terlalu banyak permintaan, coba lagi sebentar', origin, { 'Retry-After': '30' });

    const fallback = () => old && old.status === 200 && (Date.now() - old.at) / 1000 <= STALE_ERR
      ? answer({ status: 200, ct: old.ct, buf: old.buf, tries: 0 }, origin, 'STALE-ERR', t0, head) : null;
    try {
      const r = await load(key, job);
      const fb = (r.status >= 500 || r.status === 429) ? fallback() : null;
      return fb || answer(r, origin, nocache ? 'BYPASS' : 'MISS', t0, head);
    } catch (e) {
      const fb = fallback();
      if (fb) return fb;
      if (e && e.circuit) return text(503, e.message, origin, { 'Retry-After': '20', 'X-Proxy-Cache': 'CIRCUIT' });
      return text(502, 'Gagal menghubungi sumber: ' + (e && e.message ? e.message : 'error'), origin);
    }
  }
};
