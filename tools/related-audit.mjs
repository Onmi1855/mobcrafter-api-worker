import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const now = new Date();

function getArg(flag, fallback = null) {
  const argv = process.argv.slice(2);
  const i = argv.indexOf(flag);
  if (i === -1) return fallback;
  const v = argv[i + 1];
  if (!v || v.startsWith("--")) return "";
  return v;
}

function toInt(value, fallback) {
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(n) ? n : fallback;
}

function clampInt(value, fallback, min, max) {
  const v = toInt(value, fallback);
  return Math.max(min, Math.min(max, v));
}

function pLimit(concurrency) {
  let active = 0;
  const queue = [];

  const next = () => {
    if (active >= concurrency) return;
    const job = queue.shift();
    if (!job) return;
    active++;
    Promise.resolve()
      .then(job.fn)
      .then(job.resolve, job.reject)
      .finally(() => {
        active--;
        next();
      });
  };

  return (fn) =>
    new Promise((resolve, reject) => {
      queue.push({ fn, resolve, reject });
      next();
    });
}

function shuffleInPlace(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

const DEFAULT_API = "http://127.0.0.1:8787";
const apiBase = String(getArg("--api", process.env.MC_API || DEFAULT_API) || DEFAULT_API)
  .trim()
  .replace(/\/$/, "");

const pages = clampInt(getArg("--pages", "20"), 20, 1, 2000);
const pageSize = clampInt(getArg("--pageSize", "50"), 50, 1, 50);
const sample = clampInt(getArg("--sample", "200"), 200, 1, 5000);
const concurrency = clampInt(getArg("--concurrency", "6"), 6, 1, 32);
const outDirArg = String(getArg("--out", "") || "").trim();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OPERATOR_TAGS = new Set(["featured", "starter", "beginner", "vanilla"]);
const MAX_SHOW = 6;
const PAGE_SIZE = 30;

function norm(s) {
  return String(s || "").trim().toLowerCase();
}

function uniq(arr) {
  const out = [];
  const seen = new Set();
  for (const x of arr || []) {
    const k = norm(x);
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(k);
  }
  return out;
}

function normalizeTags(tags) {
  if (Array.isArray(tags)) return tags.map((t) => String(t || "")).filter(Boolean);
  const s = String(tags || "");
  if (!s.trim()) return [];
  return s
    .split(/[\s,]+/g)
    .map((t) => String(t || "").trim())
    .filter(Boolean);
}

function toScoreTagList(rawTags) {
  const arr = Array.isArray(rawTags) ? rawTags : normalizeTags(rawTags || "");
  return uniq(arr).filter((t) => !OPERATOR_TAGS.has(t));
}

function tokenizeTitleWords(s) {
  const v = norm(s);
  if (!v) return [];
  const cleaned = v.replace(/[^a-z0-9]+/g, " ");
  const parts = cleaned
    .split(/\s+/)
    .map((w) => w.trim())
    .filter(Boolean);
  return uniq(parts.filter((w) => w.length >= 3 && w.length <= 32 && !OPERATOR_TAGS.has(w)));
}

function pickQueryTerm({ myTagsAll, myTagsScore, myTitleWords, myVanilla }) {
  for (const t of myTagsScore) return t;

  let best = "";
  for (const w of myTitleWords) {
    if (w.length > best.length) best = w;
  }
  if (best) return best;

  if (myVanilla) return "vanilla";

  // Last resort: allow operator/utility/difficulty tags (except featured)
  for (const t of myTagsAll) {
    if (t === "featured") continue;
    if (OPERATOR_TAGS.has(t)) return t;
  }

  return "";
}

async function fetchJson(pathname) {
  const url = apiBase + pathname;
  const res = await fetch(url, { headers: { "Cache-Control": "no-store" } });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${url} ${text.slice(0, 200)}`);
  }
  return res.json();
}

async function fetchSubmissionsPage(page) {
  const sp = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
    sort: "new",
  });
  const data = await fetchJson(`/api/public/submissions?${sp.toString()}`);
  return Array.isArray(data?.items) ? data.items : [];
}

const listCache = new Map();
async function fetchPublicList({ q }) {
  const key = norm(q);
  if (!key) return [];
  if (listCache.has(key)) return listCache.get(key);

  const sp = new URLSearchParams({
    q: String(q),
    page_size: String(PAGE_SIZE),
    sort: "dl",
  });
  const data = await fetchJson(`/api/public/submissions?${sp.toString()}`);
  const items = Array.isArray(data?.items) ? data.items : [];
  listCache.set(key, items);
  return items;
}

function scoreCandidate({
  meta,
  myTagsScore,
  myVanilla,
  myTitleWords,
  maxDl,
  candidate,
}) {
  const author = String(meta?.author_name || meta?.authorName || "").trim();
  const itAuthor = String(candidate?.author_name || candidate?.authorName || "").trim();
  const sameAuthor = Boolean(author && itAuthor && norm(itAuthor) === norm(author));

  const itTagsAll = uniq(normalizeTags(candidate?.tags || ""));
  const itTagsScore = toScoreTagList(itTagsAll);
  const itVanilla = itTagsAll.includes("vanilla");

  const myTagSet = new Set(myTagsScore);
  let sharedTags = 0;
  for (const t of itTagsScore) {
    if (myTagSet.has(t)) sharedTags++;
  }

  const itWords = tokenizeTitleWords(candidate?.title || "");
  const myWordSet = new Set(myTitleWords);
  let sharedWords = 0;
  for (const w of itWords) {
    if (myWordSet.has(w)) sharedWords++;
  }

  const dl = Number(candidate?.download_count ?? candidate?.downloadCount ?? 0) || 0;
  const dlBoost = maxDl > 0 ? Math.round(10 * (Math.log1p(Math.max(0, dl)) / Math.log1p(maxDl))) : 0;
  const dlBoostClamped = Math.max(0, Math.min(10, dlBoost));

  let score = 0;
  if (sameAuthor) score += 100;
  score += sharedTags * 20;
  const vanillaBonus = myVanilla && itVanilla ? 10 : 0;
  score += vanillaBonus;
  score += sharedWords * 5;
  score += dlBoostClamped;

  const signalScore = (sameAuthor ? 100 : 0) + sharedTags * 20 + vanillaBonus + sharedWords * 5;

  return {
    id: String(candidate?.id || "").trim(),
    no: Number(candidate?.submission_no ?? candidate?.submissionNo ?? 0) || null,
    title: String(candidate?.title || candidate?.unit_id || candidate?.unitId || "Untitled"),
    author: itAuthor,
    dl,
    score,
    sameAuthor,
    sharedTags,
    sharedWords,
    itVanilla,
    vanillaBonus,
    dlBoost: dlBoostClamped,
    signalScore,
  };
}

async function analyzeOne(meta) {
  const title = String(meta?.title || "").trim();
  const author = String(meta?.author_name || meta?.authorName || "").trim();
  const tags = normalizeTags(meta?.tags || "");
  const myId = String(meta?.id || "").trim();

  const myTagsAll = uniq(tags);
  const myTagsScore = toScoreTagList(myTagsAll);
  const myVanilla = myTagsAll.includes("vanilla");
  const myTitleWords = tokenizeTitleWords(title);

  const qTerm = pickQueryTerm({ myTagsAll, myTagsScore, myTitleWords, myVanilla });
  const qAuthor = author;

  const byAuthorPromise = qAuthor && qAuthor.length >= 2
    ? fetchPublicList({ q: qAuthor }).catch(() => [])
    : Promise.resolve([]);

  const byQueryPromise = qTerm && qTerm.length >= 2 && norm(qTerm) !== norm(qAuthor)
    ? fetchPublicList({ q: qTerm }).catch(() => [])
    : Promise.resolve([]);

  const [byAuthor, byQuery] = await Promise.all([byAuthorPromise, byQueryPromise]);

  const candidatesMap = new Map();
  for (const it of ([]).concat(byAuthor || []).concat(byQuery || [])) {
    const id = String(it?.id || "").trim();
    if (!id || id === myId) continue;
    if (!candidatesMap.has(id)) candidatesMap.set(id, it);
  }
  const candidates = Array.from(candidatesMap.values());

  const maxDl = candidates.reduce((m, it) => {
    const dl = Number(it?.download_count ?? it?.downloadCount ?? 0) || 0;
    return Math.max(m, dl);
  }, 0);

  const scored = candidates
    .map((it) => scoreCandidate({ meta, myTagsScore, myVanilla, myTitleWords, maxDl, candidate: it }))
    .filter((x) => (Number(x.score) || 0) > 0)
    .sort((a, b) => (b.score - a.score) || (b.dl - a.dl));

  const moreBy = scored.filter((x) => x.sameAuthor).slice(0, MAX_SHOW);
  const moreByShown = new Set(moreBy.map((x) => x.id).filter(Boolean));
  const related = scored.filter((x) => !moreByShown.has(x.id)).slice(0, MAX_SHOW);

  const dlOnlyRelated = related.filter((x) => x.signalScore === 0 && x.dlBoost > 0);
  const vanillaOnlyRelated = related.filter((x) => myVanilla && x.itVanilla && !x.sameAuthor && x.sharedTags === 0 && x.sharedWords === 0);

  return {
    id: myId,
    no: Number(meta?.submission_no ?? meta?.submissionNo ?? 0) || null,
    title,
    author,
    tags: myTagsAll,
    myVanilla,
    qTerm,
    candidates: candidates.length,
    scored: scored.length,
    moreBy,
    related,
    dlOnlyRelated,
    vanillaOnlyRelated,
  };
}

function pct(n, d) {
  if (!d) return "0.0%";
  return `${(100 * (n / d)).toFixed(1)}%`;
}

function mdEscape(s) {
  return String(s || "").replace(/[\r\n]+/g, " ").replace(/\|/g, "\\|");
}

function topN(arr, n) {
  return [...arr].slice(0, n);
}

async function main() {
  console.log(`[related-audit] api=${apiBase} pages=${pages} pageSize=${pageSize} sample=${sample} concurrency=${concurrency}`);

  let pool = [];
  for (let p = 1; p <= pages; p++) {
    const items = await fetchSubmissionsPage(p);
    pool = pool.concat(items);
    if (items.length === 0) break;
    if (p % 5 === 0) console.log(`[related-audit] fetched pages=${p} pool=${pool.length}`);
  }

  // Deduplicate pool by id
  const uniqMap = new Map();
  for (const it of pool) {
    const id = String(it?.id || "").trim();
    if (!id) continue;
    if (!uniqMap.has(id)) uniqMap.set(id, it);
  }
  pool = Array.from(uniqMap.values());

  shuffleInPlace(pool);
  const picked = pool.slice(0, Math.min(sample, pool.length));
  console.log(`[related-audit] picked=${picked.length} from pool=${pool.length}`);

  const limit = pLimit(concurrency);
  let done = 0;

  const results = await Promise.all(
    picked.map((meta) =>
      limit(async () => {
        const r = await analyzeOne(meta);
        done++;
        if (done % 25 === 0) console.log(`[related-audit] analyzed ${done}/${picked.length} cache=${listCache.size}`);
        return r;
      })
    )
  );

  const total = results.length;
  const relatedEmpty = results.filter((r) => r.related.length === 0).length;
  const bothEmpty = results.filter((r) => r.related.length === 0 && r.moreBy.length === 0).length;
  const moreByOnly = results.filter((r) => r.related.length === 0 && r.moreBy.length > 0).length;

  const anyDlOnlyMix = results.filter((r) => r.dlOnlyRelated.length > 0).length;
  const dlOnlyItems = results.flatMap((r) => r.dlOnlyRelated.map((x) => ({ owner: r, cand: x })));

  const vanillaUnits = results.filter((r) => r.myVanilla);
  const vanillaTotal = vanillaUnits.length;
  const vanillaRelatedPairs = vanillaUnits.flatMap((r) => r.related.map((x) => ({ owner: r, cand: x })));
  const vanillaRelatedVanilla = vanillaRelatedPairs.filter((p) => p.cand.itVanilla).length;

  const vanillaOnlyPairs = results.flatMap((r) => r.vanillaOnlyRelated.map((x) => ({ owner: r, cand: x })));

  const moreByDominant = results
    .map((r) => {
      const shown = r.moreBy.length + r.related.length;
      const ratio = shown > 0 ? r.moreBy.length / shown : 0;
      return { r, shown, ratio };
    })
    .filter((x) => x.shown > 0)
    .sort((a, b) => b.ratio - a.ratio);

  const outDir = outDirArg
    ? outDirArg
    : path.resolve(__dirname, "..", "reports");

  fs.mkdirSync(outDir, { recursive: true });
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const outPath = path.join(outDir, `related-audit-${stamp}.md`);

  const lines = [];
  lines.push(`# Related audit`);
  lines.push("");
  lines.push(`- date: ${now.toISOString()}`);
  lines.push(`- api: ${apiBase}`);
  lines.push(`- pool: ${pool.length} (pages=${pages} pageSize=${pageSize} sort=new)`);
  lines.push(`- sample: ${total}`);
  lines.push(`- query cache entries: ${listCache.size}`);
  lines.push("");

  lines.push(`## Empty related ratio`);
  lines.push("");
  lines.push(`- related empty: ${relatedEmpty}/${total} (${pct(relatedEmpty, total)})`);
  lines.push(`- both empty (moreBy=0 & related=0): ${bothEmpty}/${total} (${pct(bothEmpty, total)})`);
  lines.push(`- moreBy only (related=0 & moreBy>0): ${moreByOnly}/${total} (${pct(moreByOnly, total)})`);
  lines.push("");

  lines.push(`## DL-only mixed-in ("unrelated" proxy)`);
  lines.push("");
  lines.push(`- units with >=1 DL-only related: ${anyDlOnlyMix}/${total} (${pct(anyDlOnlyMix, total)})`);
  lines.push(`- total DL-only related items (across all units): ${dlOnlyItems.length}`);
  lines.push("");

  lines.push(`## More-by-author dominance`);
  lines.push("");
  lines.push(`- top cases (moreBy share of shown items)`);
  lines.push("");
  lines.push(`|submission_no|title|author|tags|qTerm|moreBy|related|moreByShare|`);
  lines.push(`|---:|---|---|---|---|---:|---:|---:|`);
  for (const x of topN(moreByDominant, 15)) {
    const r = x.r;
    lines.push(
      `|${r.no ?? ""}|${mdEscape(r.title)}|${mdEscape(r.author)}|${mdEscape(r.tags.join(" "))}|${mdEscape(r.qTerm)}|${r.moreBy.length}|${r.related.length}|${(x.ratio * 100).toFixed(0)}%|`
    );
  }
  lines.push("");

  lines.push(`## Vanilla clustering`);
  lines.push("");
  lines.push(`- vanilla units: ${vanillaTotal}/${total} (${pct(vanillaTotal, total)})`);
  lines.push(`- vanilla related pairs: ${vanillaRelatedPairs.length}`);
  lines.push(`- vanilla related (candidate is vanilla): ${vanillaRelatedVanilla}/${vanillaRelatedPairs.length} (${pct(vanillaRelatedVanilla, vanillaRelatedPairs.length)})`);
  lines.push(`- vanilla-only related items (bonus-only matches): ${vanillaOnlyPairs.length}`);
  lines.push("");

  lines.push(`## Example DL-only cases (first 30)`);
  lines.push("");
  lines.push(`|owner_no|owner_title|qTerm|cand_no|cand_title|cand_dl|dlBoost|`);
  lines.push(`|---:|---|---|---:|---|---:|---:|`);
  for (const p of topN(dlOnlyItems, 30)) {
    lines.push(
      `|${p.owner.no ?? ""}|${mdEscape(p.owner.title)}|${mdEscape(p.owner.qTerm)}|${p.cand.no ?? ""}|${mdEscape(p.cand.title)}|${p.cand.dl}|${p.cand.dlBoost}|`
    );
  }
  lines.push("");

  lines.push(`## Example vanilla-only cases (first 30)`);
  lines.push("");
  lines.push(`|owner_no|owner_title|qTerm|cand_no|cand_title|sharedTags|sharedWords|dlBoost|`);
  lines.push(`|---:|---|---|---:|---|---:|---:|---:|`);
  for (const p of topN(vanillaOnlyPairs, 30)) {
    lines.push(
      `|${p.owner.no ?? ""}|${mdEscape(p.owner.title)}|${mdEscape(p.owner.qTerm)}|${p.cand.no ?? ""}|${mdEscape(p.cand.title)}|${p.cand.sharedTags}|${p.cand.sharedWords}|${p.cand.dlBoost}|`
    );
  }

  fs.writeFileSync(outPath, lines.join("\n"), "utf8");
  console.log(`[related-audit] wrote ${outPath}`);
}

main().catch((e) => {
  console.error("[related-audit] failed:", e);
  process.exit(1);
});
