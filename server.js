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
  const token = req.header("X-App-Token");
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

app.get("/movements", async (req, res) => {
  const user_id = req.query.user_id || "demo";
  try {
    const r = await query(
      `select id, user_id, fecha, monto, moneda, descripcion, pending, lat, lon, address
       from movements where user_id = $1
       order by fecha desc nulls last limit 200`,
      [user_id]
    );
    res.json(r.rows);
  } catch (e) {
    logger.error(e); res.status(500).json({ ok:false, error: e.message });
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
      monto: (m.amount || 0) / 100.0,
      moneda: m.currency || "CLP",
      descripcion: m.description || null,
      pending: !!m.pending,
      lat: match?.lat ?? null,
      lon: match?.lon ?? null,
      address: match?.address ?? null,
      raw: m
    };
  });
}

app.post("/jobs/refresh", async (_req, res) => {
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
      await query(upsertQ, [m.id, m.user_id, m.fecha, m.monto, m.moneda, m.descripcion, m.pending, m.lat, m.lon, m.address, m.raw]);
    }
    res.json({ ok: true, upserted: merged.length });
  } catch (e) {
    logger.error(e); res.status(500).json({ ok:false, error: e.message });
  }
});

app.listen(PORT, () => logger.info(`API listening on :${PORT}`));
