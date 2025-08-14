import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pino from "pino";
import pg from "pg";
import axios from "axios";

dotenv.config();
const app = express();
const logger = pino();
app.use(cors());
app.use(express.json());

const {
  PORT = 3000,
  DATABASE_URL,
  APP_SECRET,
  FINTOC_SECRET_KEY,
  FINTOC_LINK_TOKEN
} = process.env;

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // <— clave para evitar el error del certificado
});







// --- CATEGORIZACIÓN ---
const CATEGORIES = [
  "Supermercado", "Comida y Bebida", "Transporte", "Combustible",
  "Suscripciones", "Servicios", "Salud", "Educación",
  "Entretenimiento", "Viajes", "Ropa", "Hogar", "Tecnología",
  "Finanzas", "Otros"
];

// Heurística simple si no hay IA (palabras clave -> categoría)
function heuristicCategory(s) {
  const t = (s || "").toLowerCase();
  const has = (kw) => t.includes(kw);
  if (["jumbo","lider","unimarc","tottus","santa isabel","super"].some(has)) return "Supermercado";
  if (["uber","cabify","didi","metro","bus","bip"].some(has)) return "Transporte";
  if (["copec","shell","terpel","enex","pronto"].some(has)) return "Combustible";
  if (["netflix","spotify","youtube premium","amazon prime","disney"].some(has)) return "Suscripciones";
  if (["entel","movistar","vtr","claro","telefonía","internet","luz","agua","gas"].some(has)) return "Servicios";
  if (["farmacia","cruz verde","salcobrand","ahumada","isapre","clinica","salud"].some(has)) return "Salud";
  if (["colegiatura","universidad","curso","udemy","colegio"].some(has)) return "Educación";
  if (["cinema","cine","tiktok","spotify","steam","juego","ticket"].some(has)) return "Entretenimiento";
  if (["hotel","airbnb","latam","sky airline","bus"].some(has)) return "Viajes";
  if (["falabella","h&m","zara","nike","adidas"].some(has)) return "Ropa";
  if (["sodimac","homy","easy"].some(has)) return "Hogar";
  if (["apple","iphone","mac","pc","samsung","computador"].some(has)) return "Tecnología";
  if (["comisión","cargo banco","interés"].some(has)) return "Finanzas";
  if (["café","restaurant","restobar","burger","pizza","sushi","kfc","mc donald","mcdonald"].some(has)) return "Comida y Bebida";
  return "Otros";
}

// Llama Hugging Face Zero-Shot (BART-MNLI) si hay token
// Modelo recomendado para español/multilenguaje:
const HF_MODEL = process.env.HF_MODEL || "joeddav/xlm-roberta-large-xnli";
// Si prefieres BART (inglés): "facebook/bart-large-mnli"

async function aiCategoryZeroShot(text, labels=CATEGORIES) {
  const token = process.env.HF_API_TOKEN;
  if (!token) return null; // si no hay token, cae a heurística

  try {
    const resp = await fetch(`https://api-inference.huggingface.co/models/${HF_MODEL}`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        inputs: text,
        parameters: { candidate_labels: labels.join(", ") } // también puedes enviar array
      })
    });

    if (!resp.ok) return null; // evita botar el flujo si el servicio rate-limita
    const data = await resp.json();

    // En Inference API, la respuesta suele incluir 'labels' ordenadas por score
    if (Array.isArray(data.labels) && data.labels.length) return data.labels[0];

    // Algunos providers devuelven formato distinto; contempla ambas
    if (Array.isArray(data) && data[0]?.labels?.length) return data[0].labels[0];

    return null;
  } catch {
    return null;
  }
}

async function classifyCategory({ descripcion, merchant, monto }) {
  const baseText = [merchant, descripcion].filter(Boolean).join(" - ").trim();
  const text = baseText || `monto ${monto}`;
  const ai = await aiCategoryZeroShot(text);
  return ai || heuristicCategory(text);
}





async function query(q, params) {
  const c = await pool.connect();
  try { return await c.query(q, params); } finally { c.release(); }
}
app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

app.post("/echo", express.json(), (req, res) => {
  res.json({ ok: true, you_sent: req.body, headers: req.headers });
});
app.get("/health", async (_req, res) => {
  try { await query("select 1"); res.json({ ok: true }); }
  catch (e) { logger.error(e); res.status(500).json({ ok:false, error: e.message }); }
});

function requireAppSecret(req, res, next) {
  const fromHeader =
    req.get("X-App-Token") ||
    req.get("x-app-token") ||
    (req.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const fromQuery = req.query?.app_token;
  const fromBody  = req.body?.app_token;

  const token = fromHeader || fromQuery || fromBody;
  if (!APP_SECRET) return res.status(500).json({ error: "APP_SECRET not set" });
  if (token !== APP_SECRET) return res.status(401).json({ error: "invalid token" });
  next();
}

app.post("/events/transaction", requireAppSecret, async (req, res) => {
  try {
    let { ts, lat, lon, address, card_last4, user_id = "demo" } = req.body || {};
    if (!ts || lat == null || lon == null) {
      return res.status(400).json({ error: "missing fields" });
    }

    // Normaliza lat/lon: acepta "‑33,44" o "‑33.44"
    const toNum = (x) => {
      if (x === null || x === undefined) return null;
      const s = String(x).replace(",", ".");
      const n = Number(s);
      return Number.isFinite(n) ? n : null;
    };
    const latN = toNum(lat);
    const lonN = toNum(lon);
    if (latN == null || lonN == null) {
      return res.status(400).json({ error: "bad lat/lon" });
    }

    // Inserta
    const q = `insert into tap_events (user_id, ts, lat, lon, address)
               values ($1, $2, $3, $4, $5) returning id`;
    const r = await query(q, [user_id, ts, latN, lonN, address || null]);

    return res.json({ ok: true, id: r.rows[0].id });
  } catch (e) {
    logger.error(e);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/movements/manual", async (req, res) => {
  try {
    const { fecha, monto, moneda="CLP", descripcion, merchant, user_id="demo", lat=null, lon=null, address=null, categoria=null } = req.body || {};
    if (!fecha || monto == null) return res.status(400).json({ ok:false, error: "missing fecha/monto" });

    const cat = categoria || await classifyCategory({ descripcion, merchant, monto });
    const id = `manual_${Date.now()}_${Math.random().toString(36).slice(2)}`;

    await query(
      `insert into movements (id, user_id, fecha, monto, moneda, descripcion, merchant, pending, lat, lon, address, categoria, raw)
       values ($1,$2,$3,$4,$5,$6,$7,false,$8,$9,$10,$11,$12)`,
      [id, user_id, fecha, monto, moneda, descripcion || null, merchant || null, lat, lon, address, cat, {}]
    );
    res.json({ ok:true, id, categoria: cat });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

app.get("/movements", async (req, res) => {
  const user_id = req.query.user_id || "demo";
  const category = req.query.category || null;
  const qtext = req.query.q || null;
  const onlyThisMonth = (req.query.month === "current");

  const params = [user_id];
  let sql = `
    select id, user_id, fecha, monto, moneda, descripcion, merchant,
           pending, lat, lon, address, categoria
    from movements
    where user_id = $1
  `;

  if (onlyThisMonth) {
    sql += ` and date_trunc('month', fecha) = date_trunc('month', now()) `;
  }
  if (category) {
    params.push(category);
    sql += ` and categoria = $${params.length} `;
  }
  if (qtext) {
    params.push(`%${qtext}%`);
    sql += ` and (coalesce(descripcion,'') ilike $${params.length} or coalesce(merchant,'') ilike $${params.length}) `;
  }
  sql += ` order by fecha desc nulls last limit 500`;

  try {
    const r = await query(sql, params);
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

const FINTOC = axios.create({
  baseURL: "https://api.fintoc.com/v1",
  headers: { Authorization: process.env.FINTOC_SECRET_KEY || "" }
});

async function getCheckingAccountId() {
  const r = await FINTOC.get("/accounts", { params: { link_token: process.env.FINTOC_LINK_TOKEN } });
  const accounts = r.data || [];
  const checking = accounts.find(a => a.type === "checking_account") || accounts[0];
  if (!checking) throw new Error("No accounts in link");
  return checking.id;
}

async function listRecentMovements(accountId, per_page=300) {
  const r = await FINTOC.get(`/accounts/${accountId}/movements`, {
    params: { link_token: process.env.FINTOC_LINK_TOKEN, per_page, page: 1 }
  });
  return r.data || [];
}

function reconcile(taps, movs) {
  const toMs = (x) => new Date(x).getTime();
  const WIN = 10 * 60 * 1000;
  return movs.map(m => {
    const t = m.transaction_date || m.post_date;
    const mt = toMs(t);
    let match = null, best = Infinity;
    for (const ev of taps) {
      const dt = Math.abs(mt - toMs(ev.ts));
      if (dt <= WIN && dt < best) { best = dt; match = ev; }
    }
    return {
      id: m.id,
      user_id: "demo",
      fecha: t,
      monto: (m.amount || 0) ,          // ya corregido a pesos
      moneda: m.currency || "CLP",
      descripcion: m.description || null,
      pending: !!m.pending,
      merchant: (m.merchant || m.counterparty?.name || null),
      lat: match?.lat ?? null,
      lon: match?.lon ?? null,
      address: match?.address ?? null,
      categoria: null,
      raw: m
    };
  });
}

app.post("/jobs/reclassify", async (req, res) => {
  const force = String(req.query.force || "false") === "true";
  try {
    const toFix = await query(
      force
        ? "select id, descripcion, merchant, monto from movements"
        : "select id, descripcion, merchant, monto from movements where categoria is null"
    );

    let updated = 0;
    for (const row of toFix.rows) {
      const cat = await classifyCategory({
        descripcion: row.descripcion,
        merchant: row.merchant,
        monto: row.monto
      });
      if (cat) {
        await query("update movements set categoria = $1 where id = $2", [cat, row.id]);
        updated++;
      }
    }
    res.json({ ok: true, updated, force });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});


// helper: elegir cuenta por tipo
async function getAccountIdByType(type /* 'checking' | 'credit' */) {
  const r = await FINTOC.get("/accounts", { params: { link_token: process.env.FINTOC_LINK_TOKEN } });
  const accounts = r.data || [];
  if (type === "credit") {
    const cc = accounts.find(a => a.type === "credit_card");
    if (!cc) throw new Error("No credit card account in link");
    return cc.id;
  }
  // default checking
  const chk = accounts.find(a => a.type === "checking_account") || accounts[0];
  if (!chk) throw new Error("No accounts in link");
  return chk.id;
}

async function listMovements(accountId, per_page=300) {
  const r = await FINTOC.get(`/accounts/${accountId}/movements`, {
    params: { link_token: process.env.FINTOC_LINK_TOKEN, per_page, page: 1 }
  });
  return r.data || [];
}

// === NUEVO jobs/refresh con type + force + debug + cache merchant ===
app.get("/jobs/refresh", async (req, res) => {
  const t0 = Date.now();
  const typeParam = String(req.query.type || "checking"); // 'checking' | 'credit' | 'all'
  const force = String(req.query.force_reclass || "0") === "1";
  const debug = String(req.query.debug || "0") === "1";
  const dryRun = String(req.query.dry_run || "0") === "1";
  const limit = Number(req.query.limit || 0);

  try {
    // 1) Determinar qué cuentas procesar
    const types = (typeParam === "all") ? ["checking","credit"] : [typeParam];

    let totalUpserts = 0;
    let totalMatchedWithTap = 0;

    for (const kind of types) {
      const accountId = await getAccountIdByType(kind);
      let movs = await listMovements(accountId);
      if (limit && Number.isFinite(limit)) movs = movs.slice(0, limit);

      const taps = (await query(
        "select * from tap_events where user_id=$1 order by ts desc limit 200",
        ["demo"]
      )).rows;

      // 2) Reconcile por tiempo
      let merged = reconcile(taps, movs).map(m => {
        const merchant = m.merchant ?? m.raw?.merchant ?? m.raw?.counterparty?.name ?? null;
        return { ...m, merchant, categoria: m.categoria ?? null };
      });

      // 3) Traer categorías ya guardadas (para NO reclasificar)
      const ids = merged.map(m => m.id);
      const existing = await query("select id, categoria from movements where id = any($1)", [ids]);
      const byId = new Map(existing.rows.map(r => [r.id, r.categoria]));

      // 4) cargar cache de merchants existentes (opcional: on-demand)
      async function getCachedCategory(merchant) {
        if (!merchant) return null;
        const key = merchant.trim().toLowerCase();
        if (!key) return null;
        const r = await query("select categoria from merchant_category_map where merchant=$1", [key]);
        return r.rows[0]?.categoria || null;
      }
      async function setCachedCategory(merchant, categoria) {
        if (!merchant || !categoria) return;
        const key = merchant.trim().toLowerCase();
        await query(
          `insert into merchant_category_map (merchant, categoria, updated_at)
           values ($1,$2,now())
           on conflict (merchant) do update set categoria=excluded.categoria, updated_at=now()`,
          [key, categoria]
        );
      }

      const upsertQ = `
        insert into movements
          (id, user_id, fecha, monto, moneda, descripcion, merchant, pending, lat, lon, address, categoria, raw)
        values
          ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        on conflict (id) do update set
          user_id     = excluded.user_id,
          fecha       = excluded.fecha,
          monto       = excluded.monto,
          moneda      = excluded.moneda,
          descripcion = excluded.descripcion,
          merchant    = coalesce(excluded.merchant, movements.merchant),
          pending     = excluded.pending,
          lat         = coalesce(excluded.lat, movements.lat),
          lon         = coalesce(excluded.lon, movements.lon),
          address     = coalesce(excluded.address, movements.address),
          categoria   = coalesce(excluded.categoria, movements.categoria),
          raw         = excluded.raw,
          updated_at  = now()
      `;

      let upserts = 0;
      let matchedWithTap = 0;

      for (const m of merged) {
        if (m.lat != null && m.lon != null) matchedWithTap++;

        // === DECISIÓN DE CATEGORÍA SIN FORZAR ===
        let categoriaFinal = null;

        const catExisting = byId.get(m.id);
        if (catExisting && !force) {
          categoriaFinal = catExisting;
          debug && logger.info({ id: m.id, categoria: catExisting, source: "db", kind }, "skip classify (already set)");
        } else if (m.categoria && !force) {
          categoriaFinal = m.categoria;
          debug && logger.info({ id: m.id, categoria: m.categoria, source: "merged", kind }, "skip classify (merged)");
        } else {
          // intentar cache por merchant
          const cached = await getCachedCategory(m.merchant);
          if (cached && !force) {
            categoriaFinal = cached;
            debug && logger.info({ id: m.id, categoria: cached, source: "cache", merchant: m.merchant, kind }, "use merchant cache");
          } else {
            // llamar IA (o heurística si no hay token), solo si hace falta
            const t1 = Date.now();
            const ai = await aiCategoryZeroShot([m.merchant, m.descripcion].filter(Boolean).join(" - ") || `monto ${m.monto}`);
            if (ai) {
              categoriaFinal = ai;
              debug && logger.info({ id: m.id, categoria: ai, source: "ai", ms: Date.now() - t1, kind }, "classified");
            } else {
              const heu = heuristicCategory([m.merchant, m.descripcion].filter(Boolean).join(" - "));
              categoriaFinal = heu;
              debug && logger.info({ id: m.id, categoria: heu, source: "heuristic", kind }, "classified");
            }
            // guarda en cache por merchant
            await setCachedCategory(m.merchant, categoriaFinal);
          }
        }

        // escribe (salvo dry-run)
        if (!dryRun) {
          await query(upsertQ, [
            m.id, m.user_id, m.fecha, m.monto, m.moneda, m.descripcion,
            m.merchant, m.pending, m.lat, m.lon, m.address, categoriaFinal, m.raw
          ]);
          upserts++;
        } else {
          debug && logger.info({ id: m.id, categoria: categoriaFinal, kind }, "DRY-RUN upsert preview");
        }
      }

      totalUpserts += upserts;
      totalMatchedWithTap += matchedWithTap;
      logger.info({ kind, upserts, matchedWithTap }, "refresh pass done");
    }

    const took = Date.now() - t0;
    return res.json({ ok: true, upserts: totalUpserts, matchedWithTap: totalMatchedWithTap, ms: took, type: typeParam, force, dryRun });
  } catch (e) {
    logger.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// Igual que /events/transaction, pero vía GET con querystring
app.get("/events/transaction-get", requireAppSecret, async (req, res) => {
  try {
    const { ts, lat, lon, address, user_id = "demo" } = req.query || {};
    if (!ts || lat == null || lon == null) {
      return res.status(400).json({ ok:false, error: "missing fields" });
    }
    const toNum = (x) => {
      const s = String(x).replace(",", ".");
      const n = Number(s);
      return Number.isFinite(n) ? n : null;
    };
    const latN = toNum(lat), lonN = toNum(lon);
    if (latN == null || lonN == null) {
      return res.status(400).json({ ok:false, error: "bad lat/lon" });
    }
    const q = `insert into tap_events (user_id, ts, lat, lon, address)
               values ($1, $2, $3, $4, $5) returning id`;
    const r = await query(q, [user_id, ts, latN, lonN, address || null]);
    return res.json({ ok:true, id: r.rows[0].id });
  } catch (e) {
    return res.status(500).json({ ok:false, error: e.message });
  }
});
app.listen(PORT, () => logger.info(`API listening on :${PORT}`));
