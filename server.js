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





// ========================= CATEGORÍAS (macro) =========================
const CATEGORIES = [
  "Transporte",
  "Comida",
  "Mercado",
  "Suscripciones",
  "Servicios básicos",
  "Entretenimiento",
  "Delivery",
  "Otros"
];

// Palabras clave por categoría (marcas/terminología comunes en Chile)
const KW = {
  "Transporte": [
    "uber","cabify","didi","beat","taxi","metro","subte","bus","bip","autopista","tag",
    "estacionamiento","parking","peaje","red movilidad","latam"
  ],
  "Comida": [
    "cafe","cafetería","cafeteria","restaurant","restobar","bar","pub","burger","pizza","sushi","empanada",
    "kfc","mcdonald","mc donald","burger king","doggis","juan maestro","tanta","domino","telepizza",
    "starbucks","juan valdez","dunkin","sangucheria","pasteleria","pastelería","pronto"
  ],
  "Mercado": [
    "supermercado","super","minimarket","almacen","almacén","kiosko","kiosco","feria","bazar",
    "lider","jumbo","tottus","unimarc","santa isabel","acuenta","ok market","oks market","spid",
    "falabella","paris","ripley","h&m","hm","zara","nike","adidas","tricot","la polar","outlet","tienda",
    "farmacia","cruz verde","salcobrand","ahumada","santa isabel","unimarc"
  ],
  "Suscripciones": [
    "netflix","spotify","youtube premium","youtube","disney+","disney plus","amazon prime","hbo","max","appletv",
    "apple tv","icloud","xbox game pass","playstation plus","patreon","notion","dropbox","adobe","microsoft 365"
  ],
  "Servicios básicos": [
    "luz","electricidad","enel","cge","gas","metrogas","lipigas","abastible","gasco",
    "agua","esval","aguas andinas","internet","fibra","telefonía","telefonia","entel","movistar","vtr","claro",
    "unired","sii","patente","contribuciones","unired"
  ],
  "Entretenimiento": [
    "cine","cinemark","cinépolis","ticket","passline","puntoticket","event","concierto","festival","teatro",
    "casino","discoteca","discoteque","club","bar","tragos","alcohol","liquidos","licores","vino","cerveza",
    "steam","epic games","xbox","playstation","nintendo","juego","event","evento"
  ],
  "Delivery": [
    "ubereats","uber eats","rappi","pedidosya","pedido ya","just eat","cornershop","jokr","glovo"
  ],
  "Otros": []
};

// ------------------ Utilidades de normalización ------------------
function norm(s = "") {
  return s.toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "") // quita acentos
    .replace(/[^a-z0-9\s\.\-]/g, " ")                 // deja letras/números/espacios/.- 
    .replace(/\s+/g, " ")
    .trim();
}

function hasTerm(text, term) {
  const t = norm(term);
  if (!t) return false;
  if (t.includes(" ")) return text.includes(t); // frase
  const re = new RegExp(`(^|[^a-z0-9])${t}([^a-z0-9]|$)`); // palabra aprox
  return re.test(text);
}

// ------------------ Heurística robusta ------------------
function heuristicCategory(input) {
  const t = norm(input || "");
  let best = "Otros";
  let bestScore = 0;

  for (const cat of CATEGORIES) {
    const kws = KW[cat] || [];
    let score = 0;
    for (const kw of kws) {
      if (hasTerm(t, kw)) score++;
    }
    if (score > bestScore) { bestScore = score; best = cat; }
  }

  // Reglas extra rápidas (fallback)
  if (best === "Otros") {
    if (/\b(uber|cabify|didi|bip|metro|bus|peaje|autopista)\b/.test(t)) best = "Transporte";
    else if (/\b(uber\s?eats|rappi|pedidos)\b/.test(t)) best = "Delivery";
    else if (/\b(netflix|spotify|disney|hbo|max|appletv|icloud)\b/.test(t)) best = "Suscripciones";
    else if (/\b(luz|gas|agua|internet|entel|movistar|vtr|claro|unired)\b/.test(t)) best = "Servicios básicos";
    else if (/\b(jumbo|lider|tottus|unimarc|santa isabel|zara|h&m|falabella|paris|ripley)\b/.test(t)) best = "Mercado";
    else if (/\b(cafe|restaurant|restobar|sushi|pizza|burger|starbucks|mcdonald)\b/.test(t)) best = "Comida";
    else if (/\b(ticket|cine|concierto|bar|alcohol|licor|casino)\b/.test(t)) best = "Entretenimiento";
  }
  return best;
}

// ------------------ IA Zero-shot con prompt en español ------------------
const HF_MODEL = process.env.HF_MODEL || "joeddav/xlm-roberta-large-xnli";

function buildIAInput({ descripcion, merchant, monto }) {
  const base = [merchant, descripcion, (monto!=null?`monto ${monto} CLP`:null)]
    .filter(Boolean).join(" - ");

  const hints = Object.entries(KW)
    .filter(([cat]) => cat !== "Otros")
    .map(([cat, arr]) => `${cat}: ${arr.slice(0,8).join(", ")}`) // top 8 por categoría
    .join(" | ");

  return `Clasifica en UNA sola categoría (Transporte, Comida, Mercado, Suscripciones, Servicios básicos, Entretenimiento, Delivery u Otros) esta transacción en Chile según comercio/descripcion/monto.
Glosario (no exhaustivo): ${hints}
Transacción: ${base}`;
}

async function aiCategoryZeroShot(text, labels = CATEGORIES) {
  const token = process.env.HF_API_TOKEN;
  if (!token) return null;

  const body = {
    inputs: text,
    parameters: {
      candidate_labels: labels,         // array
      multi_label: false,
      hypothesis_template: "Esta transacción pertenece a la categoría {label}."
    }
  };

  try {
    const resp = await fetch(`https://api-inference.huggingface.co/models/${HF_MODEL}`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (Array.isArray(data.labels) && data.labels.length) return data.labels[0];
    if (Array.isArray(data) && data[0]?.labels?.length) return data[0].labels[0];
    return null;
  } catch {
    return null;
  }
}

async function classifyCategory({ descripcion, merchant, monto }) {
  const text = buildIAInput({ descripcion, merchant, monto });
  const ai = await aiCategoryZeroShot(text, CATEGORIES);
  if (ai) return ai;

  // Fallback a heurística
  const baseText = [merchant, descripcion].filter(Boolean).join(" - ").trim() || `monto ${monto}`;
  return heuristicCategory(baseText);
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
          (id, user_id, fecha, monto, moneda, descripcion, merchant, pending, lat, lon, address, categoria, raw, tipo_cuenta)
        values
          ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
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
          tipo_cuenta = excluded.tipo_cuenta,
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
            m.merchant, m.pending, m.lat, m.lon, m.address, categoriaFinal, m.raw,
            kind  // <= NUEVO: 'checking' o 'credit'
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
