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
async function aiCategoryZeroShot(text, labels=CATEGORIES) {
  const token = process.env.HF_API_TOKEN;
  if (!token) return null;
  try {
    const resp = await fetch("https://api-inference.huggingface.co/models/facebook/bart-large-mnli", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ inputs: text, parameters: { candidate_labels: labels.join(", ") } })
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    // data.labels en orden de confianza
    return Array.isArray(data.labels) && data.labels.length ? data.labels[0] : null;
  } catch (_) { return null; }
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

app.get("/jobs/refresh", async (req, res) => {
  // reutiliza exactamente la misma lógica del POST /jobs/refresh
  try {
    const accountId = await getCheckingAccountId();
    const movs = await listRecentMovements(accountId);
    const taps = (await query(
      "select * from tap_events where user_id=$1 order by ts desc limit 50",
      ["demo"]
    )).rows;
    const merged = reconcile(taps, movs);

    const upsertQ = `insert into movements (id, user_id, fecha, monto, moneda, descripcion, pending, lat, lon, address, raw)
                     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                     on conflict (id) do update set
                       user_id=excluded.user_id,
                       fecha=excluded.fecha,
                       monto=excluded.monto,
                       moneda=excluded.moneda,
                       descripcion=excluded.descripcion,
                       pending=excluded.pending,
                       lat=coalesce(excluded.lat, movements.lat),
                       lon=coalesce(excluded.lon, movements.lon),
                       address=coalesce(excluded.address, movements.address),
                       raw=excluded.raw,
                       updated_at=now()`;
    for (const m of merged) {
      // Clasifica si no hay categoría (o la dejamos recalcular siempre si quieres)
      if (!m.categoria) {
        m.categoria = await classifyCategory({
          descripcion: m.descripcion,
          merchant: m.merchant,
          monto: m.monto
        });
      }
      await query(upsertQ, [
        m.id, m.user_id, m.fecha, m.monto, m.moneda, m.descripcion, m.pending,
        m.lat, m.lon, m.address, m.raw
      ]);
      // Después del upsert, asegúrate de guardar la categoría
      await query(
        "update movements set categoria = $1 where id = $2",
        [m.categoria, m.id]
      );
    }
    res.json({ ok: true, upserted: merged.length });
  } catch (e) {
    logger.error(e); res.status(500).json({ ok:false, error: e.message });
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
