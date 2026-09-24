require("dotenv").config();

const express = require("express");
const axios = require("axios");
const { z } = require("zod");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const pino = require("pino");
const Bottleneck = require("bottleneck");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  redact: [
    "req.headers.authorization",
    "req.headers.x-app-secret",
    "req.headers.x-signature",
    "*.access_token",
    "*.refresh_token",
    "*.client_secret",
    "*.token",
    "*.authorization"
  ]
});

const config = {
  port: Number(process.env.PORT || 3000),
  appBaseUrl: process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
  wpSharedSecret: process.env.WP_SHARED_SECRET || "",
  n8nSharedSecret: process.env.N8N_SHARED_SECRET || "",
  n8nWebhookUrl: process.env.N8N_WEBHOOK_URL || "",
  n8nBatchResultsWebhookUrl: process.env.N8N_BATCH_RESULTS_WEBHOOK_URL || "",
  databaseUrl: process.env.DATABASE_URL || "",
  databaseSsl: String(process.env.DATABASE_SSL || "false") === "true",
  dbPoolMax: Math.max(1, Math.min(20, Number(process.env.DB_POOL_MAX || 5))),
  batchWorkerIntervalMs: Math.max(250, Number(process.env.BATCH_WORKER_INTERVAL_MS || 1000)),
  callbackWorkerIntervalMs: Math.max(500, Number(process.env.CALLBACK_WORKER_INTERVAL_MS || 2000)),
  batchLeaseMs: Math.max(60000, Number(process.env.BATCH_LEASE_MS || 1000 * 60 * 30)),
  callbackLeaseMs: Math.max(30000, Number(process.env.CALLBACK_LEASE_MS || 1000 * 60 * 2)),
  batchMaxAttempts: Math.max(1, Number(process.env.BATCH_MAX_ATTEMPTS || 5)),
  callbackMaxAttempts: Math.max(0, Number(process.env.CALLBACK_MAX_ATTEMPTS || 0)),
  retryBaseMs: Math.max(1000, Number(process.env.RETRY_BASE_MS || 5000)),
  retryMaxMs: Math.max(10000, Number(process.env.RETRY_MAX_MS || 1000 * 60 * 15)),
  callbackTimeoutMs: Math.max(5000, Number(process.env.N8N_CALLBACK_TIMEOUT_MS || 30000)),
  meliClientId: process.env.MELI_CLIENT_ID || "",
  meliClientSecret: process.env.MELI_CLIENT_SECRET || "",
  meliRedirectUri: process.env.MELI_REDIRECT_URI || "",
  meliSiteId: process.env.MELI_SITE_ID || "MLA",
  meliAuthMode: String(process.env.MELI_AUTH_MODE || "standard").trim().toLowerCase(),
  allowedOrigins: (process.env.ALLOWED_ORIGINS || "").split(",").map(value => value.trim()).filter(Boolean),
  maxProductsPerRequest: Number(process.env.MAX_PRODUCTS_PER_JOB || 100),
  meliConcurrency: Number(process.env.MELI_CONCURRENCY || 2),
  productConcurrency: Math.max(1, Math.floor(Number(process.env.PRODUCT_CONCURRENCY) || 2)),
  meliMinTimeMs: Number(process.env.MELI_MIN_TIME_MS || 700),
  cacheTtlMs: Number(process.env.CACHE_TTL_MS || 1000 * 60 * 60 * 6),
  httpTimeoutMs: Number(process.env.HTTP_TIMEOUT_MS || 20000),
  maxApiDiagnosticLogs: Number(process.env.MAX_API_DIAGNOSTIC_LOGS || 20),
  requireApiPreflight: String(process.env.REQUIRE_API_PREFLIGHT || "true") === "true",
  catalogItemsPageSize: Math.max(1, Math.min(50, Number(process.env.MELI_CATALOG_ITEMS_PAGE_SIZE || 50))),
  maxCatalogItemPages: Math.max(1, Math.min(20, Number(process.env.MELI_MAX_CATALOG_ITEM_PAGES || 20))),
  maxUpcAssociatedItems: Math.max(1, Math.min(1000, Number(process.env.MELI_MAX_UPC_ASSOCIATED_ITEMS || 1000))),
  upcItemBatchSize: Math.max(1, Math.min(20, Number(process.env.MELI_UPC_ITEM_BATCH_SIZE || 20))),
  maxUpcCatalogProducts: Math.max(1, Math.min(100, Number(process.env.MELI_MAX_UPC_CATALOG_PRODUCTS || 30))),
  maxUpcCatalogDepth: Math.max(0, Math.min(5, Number(process.env.MELI_MAX_UPC_CATALOG_DEPTH || 3))),
  maxUpcRelatedItems: Math.max(1, Math.min(200, Number(process.env.MELI_MAX_UPC_RELATED_ITEMS || 50))),
  maxUpcUserProducts: Math.max(1, Math.min(200, Number(process.env.MELI_MAX_UPC_USER_PRODUCTS || 50))),
  maxUpcWebPages: Math.max(0, Math.min(100, Number(process.env.MELI_MAX_UPC_WEB_PAGES || 20))),
  upcAttemptLogBodyChars: Math.max(0, Math.min(4000, Number(process.env.MELI_UPC_ATTEMPT_LOG_BODY_CHARS || 800))),
  cacheSuccessfulResults: String(process.env.CACHE_SUCCESSFUL_RESULTS || "true") === "true",
  logCatalogSamples: String(process.env.LOG_CATALOG_SAMPLES || "false") === "true",
  tokenRefreshLeadMs: Number(process.env.MELI_TOKEN_REFRESH_LEAD_MS || 1000 * 60 * 60),
  tokenCheckIntervalMs: Number(process.env.MELI_TOKEN_CHECK_INTERVAL_MS || 1000 * 60 * 10)
};

const jobs = new Map();
const productCache = new Map();
const authStates = new Map();

let meliTokens = {
  access_token: process.env.MELI_ACCESS_TOKEN || "",
  refresh_token: process.env.MELI_REFRESH_TOKEN || "",
  expires_at: process.env.MELI_ACCESS_TOKEN_EXPIRES_AT ? Number(process.env.MELI_ACCESS_TOKEN_EXPIRES_AT) : 0,
  user_id: process.env.MELI_USER_ID || ""
};

let refreshPromise = null;
let apiVerificationCache = {
  checked_at: 0,
  ok: false,
  user_id: "",
  global_selling_verified: false,
  status: "not_checked",
  error: ""
};
let apiDiagnosticCount = 0;
let lastTokenRefreshWarningAt = 0;
let dbPool = null;
let databaseReady = false;
let batchWorkerRunning = false;
let callbackWorkerRunning = false;

const meliLimiter = new Bottleneck({
  maxConcurrent: config.meliConcurrency,
  minTime: config.meliMinTimeMs
});

const http = axios.create({
  timeout: config.httpTimeoutMs,
  headers: {
    "User-Agent": "MeliMonitorService/4.0",
    "Accept-Language": "es-AR,es;q=0.9,en;q=0.8"
  },
  maxRedirects: 3,
  validateStatus: status => status >= 200 && status < 600
});

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (!config.allowedOrigins.length) return callback(null, true);
    if (config.allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin no permitido"));
  }
}));
app.use(express.json({ limit: "2mb" }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 240,
  standardHeaders: true,
  legacyHeaders: false
}));

const jobSchema = z.object({
  sheet_url: z.string().min(10).max(1000),
  sheet_name: z.string().min(1).max(100).optional().default(""),
  email: z.string().email().optional().or(z.literal(""))
});

const productSchema = z.object({
  row_number: z.number().int().positive(),
  ean: z.union([z.string(), z.number()]),
  brand: z.string().optional().default(""),
  name: z.string().optional().default("")
});

const monitorSchema = z.object({
  job_id: z.string().min(8).max(100),
  products: z.array(productSchema).min(1),
  total_products: z.union([z.string(), z.number()]).optional(),
  batch_index: z.union([z.string(), z.number()]).optional(),
  total_batches: z.union([z.string(), z.number()]).optional()
});

const callbackSchema = z.object({
  job_id: z.string().min(8).max(100),
  status: z.string().min(2).max(50),
  updated_rows: z.number().int().nonnegative().optional().default(0),
  error: z.string().max(1000).optional().default("")
});

const testProductSchema = z.object({
  ean: z.union([z.string(), z.number()]),
  brand: z.string().optional().default(""),
  name: z.string().optional().default("")
});

const upcLookupProductSchema = z.object({
  row_number: z.number().int().positive(),
  mla: z.union([z.string(), z.number()])
});

const upcLookupSchema = z.object({
  job_id: z.string().min(8).max(100).optional().default(""),
  mlas: z.array(z.union([z.string(), z.number()])).max(100).optional().default([]),
  products: z.array(upcLookupProductSchema).max(100).optional().default([]),
  total_products: z.union([z.string(), z.number()]).optional(),
  batch_index: z.union([z.string(), z.number()]).optional(),
  total_batches: z.union([z.string(), z.number()]).optional()
}).refine(data => data.mlas.length > 0 || data.products.length > 0, {
  message: "Debe enviar mlas o products"
});

function nowIso() {
  return new Date().toISOString();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function normalizeEan(value) {
  return String(value || "").replace(/[^\d]/g, "").trim();
}

function isValidEan(value) {
  const ean = normalizeEan(value);
  return ean.length >= 8 && ean.length <= 14;
}

function safeJobId() {
  return `job_${Date.now()}_${uuidv4().replace(/-/g, "").slice(0, 12)}`;
}

function publicJob(job) {
  return {
    job_id: job.job_id,
    job_type: job.job_type,
    status: job.status,
    sheet_url: job.sheet_url,
    sheet_name: job.sheet_name,
    total: job.total,
    processed: job.processed,
    ok: job.ok,
    not_found: job.not_found,
    no_offers: job.no_offers,
    api_errors: job.api_errors,
    errors: job.errors,
    updated_rows: job.updated_rows,
    created_at: job.created_at,
    started_at: job.started_at,
    finished_at: job.finished_at,
    error: job.error,
    total_batches: Number(job.total_batches || 0),
    synced_batches: Number(job.synced_batches || 0)
  };
}

function createEmptyJob(data) {
  return {
    job_id: data.job_id,
    job_type: data.job_type || "ean_to_mla",
    sheet_url: data.sheet_url || "",
    sheet_name: data.sheet_name || "",
    email: data.email || "",
    status: data.status || "pending",
    total: Number(data.total || 0),
    processed: 0,
    ok: 0,
    not_found: 0,
    no_offers: 0,
    api_errors: 0,
    errors: 0,
    updated_rows: 0,
    created_at: data.created_at || nowIso(),
    started_at: null,
    finished_at: null,
    error: "",
    total_batches: Number(data.total_batches || 0),
    synced_batches: Number(data.synced_batches || 0)
  };
}


function dateToIso(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString();
}

function jobFromRow(row) {
  if (!row) return null;
  return {
    job_id: row.job_id,
    job_type: row.job_type,
    sheet_url: row.sheet_url || "",
    sheet_name: row.sheet_name || "",
    email: row.email || "",
    status: row.status || "pending",
    total: Number(row.total || 0),
    processed: Number(row.processed || 0),
    ok: Number(row.ok_count || 0),
    not_found: Number(row.not_found || 0),
    no_offers: Number(row.no_offers || 0),
    api_errors: Number(row.api_errors || 0),
    errors: Number(row.errors || 0),
    updated_rows: Number(row.updated_rows || 0),
    total_batches: Number(row.total_batches || 0),
    synced_batches: Number(row.synced_batches || 0),
    created_at: dateToIso(row.created_at),
    started_at: dateToIso(row.started_at),
    finished_at: dateToIso(row.finished_at),
    error: row.error || ""
  };
}

async function initializeDatabase() {
  if (!config.databaseUrl) {
    databaseReady = false;
    return false;
  }

  dbPool = new Pool({
    connectionString: config.databaseUrl,
    ssl: config.databaseSsl ? { rejectUnauthorized: false } : false,
    max: config.dbPoolMax
  });

  await dbPool.query("SELECT 1");

  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS meli_monitor_jobs (
      job_id TEXT PRIMARY KEY,
      job_type TEXT NOT NULL,
      sheet_url TEXT NOT NULL DEFAULT '',
      sheet_name TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      total INTEGER NOT NULL DEFAULT 0,
      processed INTEGER NOT NULL DEFAULT 0,
      ok_count INTEGER NOT NULL DEFAULT 0,
      not_found INTEGER NOT NULL DEFAULT 0,
      no_offers INTEGER NOT NULL DEFAULT 0,
      api_errors INTEGER NOT NULL DEFAULT 0,
      errors INTEGER NOT NULL DEFAULT 0,
      updated_rows INTEGER NOT NULL DEFAULT 0,
      total_batches INTEGER NOT NULL DEFAULT 0,
      synced_batches INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      started_at TIMESTAMPTZ,
      finished_at TIMESTAMPTZ,
      error TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS meli_monitor_batches (
      batch_id TEXT PRIMARY KEY,
      job_id TEXT NOT NULL REFERENCES meli_monitor_jobs(job_id) ON DELETE CASCADE,
      job_type TEXT NOT NULL,
      batch_index INTEGER NOT NULL,
      total_batches INTEGER NOT NULL,
      total_products INTEGER NOT NULL,
      payload JSONB NOT NULL,
      payload_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      attempts INTEGER NOT NULL DEFAULT 0,
      callback_attempts INTEGER NOT NULL DEFAULT 0,
      results JSONB,
      summary JSONB,
      updated_rows INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      next_callback_at TIMESTAMPTZ,
      lease_expires_at TIMESTAMPTZ,
      callback_lease_expires_at TIMESTAMPTZ,
      last_error TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      started_at TIMESTAMPTZ,
      processed_at TIMESTAMPTZ,
      synced_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(job_id, batch_index)
    )
  `);

  await dbPool.query(`
    CREATE INDEX IF NOT EXISTS idx_meli_monitor_batches_processing
    ON meli_monitor_batches(status, next_attempt_at, created_at)
  `);

  await dbPool.query(`
    CREATE INDEX IF NOT EXISTS idx_meli_monitor_batches_callback
    ON meli_monitor_batches(status, next_callback_at, created_at)
  `);

  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS meli_monitor_state (
      state_key TEXT PRIMARY KEY,
      state_value JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  databaseReady = true;
  return true;
}

async function saveJob(job) {
  if (!databaseReady || !dbPool || !job) return;

  await dbPool.query(`
    INSERT INTO meli_monitor_jobs (
      job_id, job_type, sheet_url, sheet_name, email, status, total,
      processed, ok_count, not_found, no_offers, api_errors, errors,
      updated_rows, total_batches, synced_batches, created_at, started_at,
      finished_at, error, updated_at
    ) VALUES (
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
      COALESCE($17::timestamptz, NOW()),$18::timestamptz,$19::timestamptz,$20,NOW()
    )
    ON CONFLICT (job_id) DO UPDATE SET
      job_type = EXCLUDED.job_type,
      sheet_url = CASE WHEN EXCLUDED.sheet_url <> '' THEN EXCLUDED.sheet_url ELSE meli_monitor_jobs.sheet_url END,
      sheet_name = CASE WHEN EXCLUDED.sheet_name <> '' THEN EXCLUDED.sheet_name ELSE meli_monitor_jobs.sheet_name END,
      email = CASE WHEN EXCLUDED.email <> '' THEN EXCLUDED.email ELSE meli_monitor_jobs.email END,
      status = EXCLUDED.status,
      total = EXCLUDED.total,
      processed = EXCLUDED.processed,
      ok_count = EXCLUDED.ok_count,
      not_found = EXCLUDED.not_found,
      no_offers = EXCLUDED.no_offers,
      api_errors = EXCLUDED.api_errors,
      errors = EXCLUDED.errors,
      updated_rows = EXCLUDED.updated_rows,
      total_batches = GREATEST(meli_monitor_jobs.total_batches, EXCLUDED.total_batches),
      synced_batches = EXCLUDED.synced_batches,
      started_at = COALESCE(EXCLUDED.started_at, meli_monitor_jobs.started_at),
      finished_at = EXCLUDED.finished_at,
      error = EXCLUDED.error,
      updated_at = NOW()
  `, [
    job.job_id,
    job.job_type || "ean_to_mla",
    job.sheet_url || "",
    job.sheet_name || "",
    job.email || "",
    job.status || "pending",
    Number(job.total || 0),
    Number(job.processed || 0),
    Number(job.ok || 0),
    Number(job.not_found || 0),
    Number(job.no_offers || 0),
    Number(job.api_errors || 0),
    Number(job.errors || 0),
    Number(job.updated_rows || 0),
    Number(job.total_batches || 0),
    Number(job.synced_batches || 0),
    job.created_at || null,
    job.started_at || null,
    job.finished_at || null,
    job.error || ""
  ]);
}

async function getPersistentJob(jobId) {
  if (!databaseReady || !dbPool) return jobs.get(jobId) || null;
  const result = await dbPool.query("SELECT * FROM meli_monitor_jobs WHERE job_id = $1", [jobId]);
  const job = jobFromRow(result.rows[0]);
  if (job) jobs.set(job.job_id, job);
  return job;
}

async function persistMeliTokens() {
  if (!databaseReady || !dbPool || !meliTokens.access_token) return;
  await dbPool.query(`
    INSERT INTO meli_monitor_state(state_key, state_value, updated_at)
    VALUES ('meli_tokens', $1::jsonb, NOW())
    ON CONFLICT (state_key) DO UPDATE SET state_value = EXCLUDED.state_value, updated_at = NOW()
  `, [JSON.stringify(meliTokens)]);
}

async function loadMeliTokensFromDatabase() {
  if (!databaseReady || !dbPool) return;
  const result = await dbPool.query("SELECT state_value FROM meli_monitor_state WHERE state_key = 'meli_tokens'");
  const stored = result.rows[0]?.state_value;
  if (!stored || typeof stored !== "object") return;

  meliTokens = {
    access_token: stored.access_token || meliTokens.access_token || "",
    refresh_token: stored.refresh_token || meliTokens.refresh_token || "",
    expires_at: Number(stored.expires_at || meliTokens.expires_at || 0),
    user_id: stored.user_id ? String(stored.user_id) : meliTokens.user_id || ""
  };
}

function payloadHash(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function retryDelayMs(attempt) {
  const exponential = Math.min(config.retryMaxMs, config.retryBaseMs * Math.pow(2, Math.max(0, attempt - 1)));
  const jitter = Math.floor(Math.random() * Math.min(1000, Math.max(1, exponential * 0.2)));
  return exponential + jitter;
}

async function ensurePersistentJobForBatch(jobId, jobType, totalProducts, totalBatches) {
  let job = await getPersistentJob(jobId);

  if (!job) {
    job = createEmptyJob({
      job_id: jobId,
      job_type: jobType,
      status: "queued",
      total: totalProducts,
      total_batches: totalBatches
    });
    job.started_at = nowIso();
    await saveJob(job);
    jobs.set(job.job_id, job);
    return job;
  }

  const updated = await dbPool.query(`
    UPDATE meli_monitor_jobs
    SET job_type = $2,
        total = GREATEST(total, $3),
        total_batches = GREATEST(total_batches, $4),
        status = CASE
          WHEN status IN ('completed', 'completed_with_errors', 'failed') THEN status
          ELSE 'queued'
        END,
        started_at = COALESCE(started_at, NOW()),
        finished_at = CASE
          WHEN status IN ('completed', 'completed_with_errors', 'failed') THEN finished_at
          ELSE NULL
        END,
        error = CASE
          WHEN status IN ('completed', 'completed_with_errors', 'failed') THEN error
          ELSE ''
        END,
        updated_at = NOW()
    WHERE job_id = $1
    RETURNING *
  `, [jobId, jobType, Number(totalProducts || 0), Number(totalBatches || 0)]);

  job = jobFromRow(updated.rows[0]);
  if (job) jobs.set(job.job_id, job);
  return job;
}

async function enqueuePersistentBatch({ jobId, jobType, batchIndex, totalBatches, totalProducts, payload }) {
  if (!databaseReady || !dbPool) {
    throw apiError("PostgreSQL no está configurado o disponible", { code: "database_not_ready", status: 503 });
  }
  if (!Number.isInteger(batchIndex) || batchIndex < 1) {
    throw apiError("batch_index inválido", { code: "invalid_batch_index", status: 400 });
  }
  if (!Number.isInteger(totalBatches) || totalBatches < 1) {
    throw apiError("total_batches inválido", { code: "invalid_total_batches", status: 400 });
  }

  const job = await ensurePersistentJobForBatch(jobId, jobType, totalProducts, totalBatches);
  const hash = payloadHash(payload);
  const batchId = `batch_${jobId}_${batchIndex}_${uuidv4().replace(/-/g, "").slice(0, 8)}`;

  const inserted = await dbPool.query(`
    INSERT INTO meli_monitor_batches (
      batch_id, job_id, job_type, batch_index, total_batches, total_products,
      payload, payload_hash, status, next_attempt_at, created_at, updated_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,'pending',NOW(),NOW(),NOW())
    ON CONFLICT (job_id, batch_index) DO NOTHING
    RETURNING *
  `, [
    batchId,
    jobId,
    jobType,
    batchIndex,
    totalBatches,
    totalProducts,
    JSON.stringify(payload),
    hash
  ]);

  if (inserted.rows.length) {
    return { duplicate: false, batch: inserted.rows[0], job };
  }

  const existingResult = await dbPool.query(
    "SELECT * FROM meli_monitor_batches WHERE job_id = $1 AND batch_index = $2",
    [jobId, batchIndex]
  );
  const existing = existingResult.rows[0];

  if (!existing) {
    throw apiError("No se pudo recuperar la tanda existente", { code: "batch_lookup_failed", status: 500 });
  }

  if (existing.payload_hash !== hash) {
    throw apiError("Ya existe una tanda con el mismo job_id y batch_index pero contenido diferente", {
      code: "batch_conflict",
      status: 409
    });
  }

  return { duplicate: true, batch: existing, job };
}

async function claimNextBatch() {
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    const selected = await client.query(`
      SELECT *
      FROM meli_monitor_batches
      WHERE (
        (status = 'pending' AND next_attempt_at <= NOW())
        OR (status = 'processing' AND lease_expires_at IS NOT NULL AND lease_expires_at <= NOW())
      )
      ORDER BY created_at ASC, batch_index ASC
      FOR UPDATE SKIP LOCKED
      LIMIT 1
    `);

    if (!selected.rows.length) {
      await client.query("COMMIT");
      return null;
    }

    const batch = selected.rows[0];
    const updated = await client.query(`
      UPDATE meli_monitor_batches
      SET status = 'processing',
          attempts = attempts + 1,
          started_at = COALESCE(started_at, NOW()),
          lease_expires_at = NOW() + ($2::bigint * INTERVAL '1 millisecond'),
          last_error = '',
          updated_at = NOW()
      WHERE batch_id = $1
      RETURNING *
    `, [batch.batch_id, config.batchLeaseMs]);

    await client.query("COMMIT");
    return updated.rows[0] || null;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function startBatchLeaseHeartbeat(batchId) {
  const intervalMs = Math.max(15000, Math.floor(config.batchLeaseMs / 3));
  const timer = setInterval(() => {
    dbPool.query(`
      UPDATE meli_monitor_batches
      SET lease_expires_at = NOW() + ($2::bigint * INTERVAL '1 millisecond'), updated_at = NOW()
      WHERE batch_id = $1 AND status = 'processing'
    `, [batchId, config.batchLeaseMs]).catch(error => {
      logger.error({ batch_id: batchId, error: error.message }, "No se pudo renovar el lease de una tanda");
    });
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}

function buildUpcBatchSummary(results, requested) {
  const apiErrors = results.filter(result => String(result.status || "").startsWith("api_")).length;
  return {
    requested,
    processed: results.length,
    found: results.filter(result => result.status === "ok").length,
    without_identifier: results.filter(result => ["identifier_not_available", "identifier_candidates", "partial_scan"].includes(result.status)).length,
    with_candidates: results.filter(result => result.status === "identifier_candidates").length,
    partial_scans: results.filter(result => result.status === "partial_scan").length,
    invalid: results.filter(result => result.status === "invalid_mla").length,
    not_found: results.filter(result => result.status === "item_not_found").length,
    api_errors: apiErrors,
    errors: results.filter(result => !["ok", "identifier_not_available", "identifier_candidates", "partial_scan", "invalid_mla", "item_not_found"].includes(result.status)).length
  };
}

async function processQueuedBatch(batch) {
  const stopHeartbeat = startBatchLeaseHeartbeat(batch.batch_id);
  try {
    const verification = await verifyMeliApiConnection(false);
    if (!verification.ok) {
      throw apiError(`MercadoLibre no está disponible: ${verification.status}`, {
        code: "meli_api_not_ready",
        status: 503,
        retryable: true
      });
    }

    const payload = batch.payload || {};
    const inputs = Array.isArray(payload.products) ? payload.products : [];
    let results;
    let summary;

    if (batch.job_type === "mla_to_upc") {
      results = await mapWithConcurrency(inputs, config.productConcurrency, async entry => {
        try {
          return await resolveUpcsByMla(entry);
        } catch (error) {
          const rawMla = entry && typeof entry === "object" ? entry.mla : entry;
          return {
            row_number: entry && typeof entry === "object" ? entry.row_number || null : null,
            input: String(rawMla || ""),
            mla: normalizeMlaId(rawMla),
            title: "",
            catalog_product_id: null,
            primary_identifier: null,
            upc: null,
            upcs: [],
            gtins: [],
            candidate_upcs: [],
            candidate_gtins: [],
            identifiers: [],
            status: "unexpected_error",
            error: String(error.message || error).slice(0, 1000),
            checked_at: nowIso()
          };
        }
      });
      summary = buildUpcBatchSummary(results, inputs.length);
    } else {
      results = await mapWithConcurrency(inputs, config.productConcurrency, async row => {
        try {
          return await resolveProduct(row);
        } catch (error) {
          const ean = normalizeEan(row.ean);
          logger.error({
            job_id: batch.job_id,
            batch_id: batch.batch_id,
            row_number: row.row_number,
            ean,
            error: error.message
          }, "Falló inesperadamente el procesamiento de un producto en background");
          return resultError(row, ean, "unexpected_error", error.message);
        }
      });
      summary = countBatchResults(results);
    }

    await dbPool.query(`
      UPDATE meli_monitor_batches
      SET status = 'callback_pending',
          results = $2::jsonb,
          summary = $3::jsonb,
          processed_at = NOW(),
          next_callback_at = NOW(),
          lease_expires_at = NULL,
          last_error = '',
          updated_at = NOW()
      WHERE batch_id = $1
    `, [batch.batch_id, JSON.stringify(results), JSON.stringify(summary)]);

    logger.info({
      job_id: batch.job_id,
      batch_id: batch.batch_id,
      indice_tanda: batch.batch_index,
      total_tandas: batch.total_batches,
      procesados: results.length
    }, "La tanda asíncrona terminó y quedó lista para sincronizar con n8n");

    await refreshJobAggregates(batch.job_id);
  } catch (error) {
    const attempts = Number(batch.attempts || 1);
    const exhausted = attempts >= config.batchMaxAttempts;
    const delayMs = retryDelayMs(attempts);

    await dbPool.query(`
      UPDATE meli_monitor_batches
      SET status = $2,
          next_attempt_at = CASE WHEN $2 = 'pending' THEN NOW() + ($3::bigint * INTERVAL '1 millisecond') ELSE next_attempt_at END,
          lease_expires_at = NULL,
          last_error = $4,
          updated_at = NOW()
      WHERE batch_id = $1
    `, [batch.batch_id, exhausted ? "failed" : "pending", delayMs, String(error.message || error).slice(0, 2000)]);

    logger.error({
      job_id: batch.job_id,
      batch_id: batch.batch_id,
      intento: attempts,
      agotado: exhausted,
      reintento_en_ms: exhausted ? null : delayMs,
      error: error.message
    }, exhausted ? "La tanda asíncrona falló definitivamente" : "La tanda asíncrona falló y será reintentada");

    await refreshJobAggregates(batch.job_id);
  } finally {
    stopHeartbeat();
  }
}

async function claimNextCallback() {
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    const selected = await client.query(`
      SELECT *
      FROM meli_monitor_batches
      WHERE (
        (status = 'callback_pending' AND COALESCE(next_callback_at, NOW()) <= NOW())
        OR (status = 'callback_delivering' AND callback_lease_expires_at IS NOT NULL AND callback_lease_expires_at <= NOW())
      )
      ORDER BY processed_at ASC NULLS LAST, created_at ASC
      FOR UPDATE SKIP LOCKED
      LIMIT 1
    `);

    if (!selected.rows.length) {
      await client.query("COMMIT");
      return null;
    }

    const batch = selected.rows[0];
    const updated = await client.query(`
      UPDATE meli_monitor_batches
      SET status = 'callback_delivering',
          callback_attempts = callback_attempts + 1,
          callback_lease_expires_at = NOW() + ($2::bigint * INTERVAL '1 millisecond'),
          updated_at = NOW()
      WHERE batch_id = $1
      RETURNING *
    `, [batch.batch_id, config.callbackLeaseMs]);

    await client.query("COMMIT");
    return updated.rows[0] || null;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function deliverBatchCallback(batch) {
  try {
    if (!config.n8nBatchResultsWebhookUrl) {
      throw new Error("Falta N8N_BATCH_RESULTS_WEBHOOK_URL");
    }

    const job = await getPersistentJob(batch.job_id);
    if (!job) throw new Error("job_not_found");

    const payload = {
      event: "batch.completed",
      job_id: batch.job_id,
      job_type: batch.job_type,
      batch_id: batch.batch_id,
      batch_index: Number(batch.batch_index),
      total_batches: Number(batch.total_batches),
      total_products: Number(batch.total_products),
      sheet_url: job.sheet_url,
      sheet_name: job.sheet_name,
      batch_summary: batch.summary || {},
      results: Array.isArray(batch.results) ? batch.results : [],
      processed_at: dateToIso(batch.processed_at)
    };

    const response = await http.post(config.n8nBatchResultsWebhookUrl, payload, {
      timeout: config.callbackTimeoutMs,
      headers: {
        "Content-Type": "application/json",
        "X-App-Secret": config.n8nSharedSecret
      }
    });

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`n8n_batch_callback_http_${response.status}`);
    }

    const updatedRows = Number(response.data?.updated_rows || 0);

    await dbPool.query(`
      UPDATE meli_monitor_batches
      SET status = 'synced',
          updated_rows = $2,
          synced_at = NOW(),
          callback_lease_expires_at = NULL,
          last_error = '',
          updated_at = NOW()
      WHERE batch_id = $1
    `, [batch.batch_id, Number.isFinite(updatedRows) && updatedRows >= 0 ? updatedRows : 0]);

    logger.info({
      job_id: batch.job_id,
      batch_id: batch.batch_id,
      indice_tanda: batch.batch_index,
      filas_actualizadas: Number.isFinite(updatedRows) ? updatedRows : 0
    }, "n8n confirmó la actualización de Google Sheets para la tanda");

    await refreshJobAggregates(batch.job_id);
  } catch (error) {
    const attempts = Number(batch.callback_attempts || 1);
    const exhausted = config.callbackMaxAttempts > 0 && attempts >= config.callbackMaxAttempts;
    const delayMs = retryDelayMs(attempts);

    await dbPool.query(`
      UPDATE meli_monitor_batches
      SET status = $2,
          next_callback_at = CASE WHEN $2 = 'callback_pending' THEN NOW() + ($3::bigint * INTERVAL '1 millisecond') ELSE next_callback_at END,
          callback_lease_expires_at = NULL,
          last_error = $4,
          updated_at = NOW()
      WHERE batch_id = $1
    `, [batch.batch_id, exhausted ? "callback_failed" : "callback_pending", delayMs, String(error.message || error).slice(0, 2000)]);

    logger.error({
      job_id: batch.job_id,
      batch_id: batch.batch_id,
      intento_callback: attempts,
      agotado: exhausted,
      reintento_en_ms: exhausted ? null : delayMs,
      error: error.message
    }, exhausted ? "El callback de la tanda a n8n falló definitivamente" : "El callback de la tanda a n8n falló y será reintentado");

    await refreshJobAggregates(batch.job_id);
  }
}

async function refreshJobAggregates(jobId) {
  const jobResult = await dbPool.query("SELECT * FROM meli_monitor_jobs WHERE job_id = $1", [jobId]);
  if (!jobResult.rows.length) return null;
  const current = jobFromRow(jobResult.rows[0]);
  const batchResult = await dbPool.query(`
    SELECT status, summary, updated_rows, total_batches, total_products
    FROM meli_monitor_batches
    WHERE job_id = $1
    ORDER BY batch_index ASC
  `, [jobId]);

  const rows = batchResult.rows;
  let processed = 0;
  let ok = 0;
  let notFound = 0;
  let noOffers = 0;
  let apiErrors = 0;
  let errors = 0;
  let updatedRows = 0;
  let syncedBatches = 0;
  let failedBatches = 0;

  for (const row of rows) {
    const summary = row.summary || {};
    processed += Number(summary.processed || 0);
    updatedRows += Number(row.updated_rows || 0);
    if (row.status === "synced") syncedBatches += 1;
    if (["failed", "callback_failed"].includes(row.status)) failedBatches += 1;

    if (current.job_type === "mla_to_upc") {
      ok += Number(summary.found || 0);
      notFound += Number(summary.not_found || 0);
      noOffers += Number(summary.without_identifier || 0);
      apiErrors += Number(summary.api_errors || 0);
      errors += Number(summary.errors || 0);
    } else {
      ok += Number(summary.ok || 0);
      notFound += Number(summary.product_not_found || 0);
      noOffers += Number(summary.offers_not_found || 0) + Number(summary.catalog_only || 0);
      apiErrors += Number(summary.api_errors || 0);
      errors += Number(summary.catalog_only || 0)
        + Number(summary.product_not_found || 0)
        + Number(summary.offers_not_found || 0)
        + Number(summary.invalid_ean || 0)
        + Number(summary.api_errors || 0)
        + Number(summary.other_errors || 0);
    }
  }

  const totalBatches = Math.max(
    Number(current.total_batches || 0),
    ...rows.map(row => Number(row.total_batches || 0)),
    0
  );
  const terminalBatches = syncedBatches + failedBatches;
  const allBatchesKnown = totalBatches > 0 && rows.length >= totalBatches;
  const allTerminal = allBatchesKnown && terminalBatches >= totalBatches;
  let status = rows.length ? "processing" : current.status;
  let finishedAt = null;
  let error = "";

  if (allTerminal) {
    if (failedBatches === 0) {
      status = "completed";
    } else if (syncedBatches === 0) {
      status = "failed";
      error = `${failedBatches} tanda(s) no pudieron completarse o sincronizarse`;
    } else {
      status = "completed_with_errors";
      error = `${failedBatches} tanda(s) no pudieron completarse o sincronizarse`;
    }
    finishedAt = nowIso();
  }

  const updated = await dbPool.query(`
    UPDATE meli_monitor_jobs
    SET status = $2,
        processed = $3,
        ok_count = $4,
        not_found = $5,
        no_offers = $6,
        api_errors = $7,
        errors = $8,
        updated_rows = $9,
        total_batches = $10,
        synced_batches = $11,
        started_at = COALESCE(started_at, NOW()),
        finished_at = $12::timestamptz,
        error = $13,
        updated_at = NOW()
    WHERE job_id = $1
    RETURNING *
  `, [
    jobId,
    status,
    processed,
    ok,
    notFound,
    noOffers,
    apiErrors,
    errors,
    updatedRows,
    totalBatches,
    syncedBatches,
    finishedAt,
    error
  ]);

  const job = jobFromRow(updated.rows[0]);
  if (job) jobs.set(job.job_id, job);
  return job;
}

async function runBatchWorkerCycle() {
  if (!databaseReady || batchWorkerRunning) return;
  batchWorkerRunning = true;
  let claimed = null;
  try {
    claimed = await claimNextBatch();
    if (claimed) await processQueuedBatch(claimed);
  } catch (error) {
    logger.error({ error: error.message }, "Falló el ciclo del worker de tandas");
  } finally {
    batchWorkerRunning = false;
  }
  if (claimed) setImmediate(() => runBatchWorkerCycle().catch(() => {}));
}

async function runCallbackWorkerCycle() {
  if (!databaseReady || callbackWorkerRunning) return;
  callbackWorkerRunning = true;
  let claimed = null;
  try {
    claimed = await claimNextCallback();
    if (claimed) await deliverBatchCallback(claimed);
  } catch (error) {
    logger.error({ error: error.message }, "Falló el ciclo del worker de callbacks");
  } finally {
    callbackWorkerRunning = false;
  }
  if (claimed) setImmediate(() => runCallbackWorkerCycle().catch(() => {}));
}

function isGoogleSheetUrl(url) {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    if (!["docs.google.com", "drive.google.com"].includes(host)) return false;
    if (host === "docs.google.com" && !parsed.pathname.includes("/spreadsheets/")) return false;
    return true;
  } catch {
    return false;
  }
}

function verifySharedSecret(req, expectedSecret) {
  if (!expectedSecret) return true;
  const received = req.header("x-app-secret") || "";
  if (!received) return false;
  const a = Buffer.from(received);
  const b = Buffer.from(expectedSecret);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function verifyHmac(req, expectedSecret) {
  if (!expectedSecret) return true;
  const signature = req.header("x-signature");
  if (!signature) return true;
  const body = JSON.stringify(req.body || {});
  const expected = crypto.createHmac("sha256", expectedSecret).update(body).digest("hex");
  const cleanSignature = signature.replace(/^sha256=/, "");
  const a = Buffer.from(cleanSignature);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function requireWp(req, res, next) {
  if (!verifySharedSecret(req, config.wpSharedSecret)) {
    return res.status(401).json({ ok: false, error: "unauthorized_wordpress" });
  }
  if (!verifyHmac(req, config.wpSharedSecret)) {
    return res.status(401).json({ ok: false, error: "invalid_wordpress_signature" });
  }
  return next();
}

function requireN8n(req, res, next) {
  if (!verifySharedSecret(req, config.n8nSharedSecret)) {
    return res.status(401).json({ ok: false, error: "unauthorized_n8n" });
  }
  if (!verifyHmac(req, config.n8nSharedSecret)) {
    return res.status(401).json({ ok: false, error: "invalid_n8n_signature" });
  }
  return next();
}

function requireWpOrN8n(req, res, next) {
  const wpValid = Boolean(config.wpSharedSecret) && verifySharedSecret(req, config.wpSharedSecret) && verifyHmac(req, config.wpSharedSecret);
  const n8nValid = Boolean(config.n8nSharedSecret) && verifySharedSecret(req, config.n8nSharedSecret) && verifyHmac(req, config.n8nSharedSecret);

  if (!wpValid && !n8nValid) {
    return res.status(401).json({ ok: false, error: "unauthorized_client" });
  }

  return next();
}

function getMeliAuthBase() {
  if (config.meliAuthMode === "global_selling") return "https://global-selling.mercadolibre.com";
  if (config.meliSiteId === "MLB") return "https://auth.mercadolivre.com.br";
  return "https://auth.mercadolibre.com.ar";
}

function hasMeliCredentials() {
  return Boolean(config.meliClientId && config.meliClientSecret && config.meliRedirectUri);
}

function hasMeliToken() {
  return Boolean(meliTokens.access_token);
}

function tokenWillExpireSoon() {
  if (!meliTokens.access_token) return true;
  if (!meliTokens.expires_at) return false;
  return Date.now() > meliTokens.expires_at - config.tokenRefreshLeadMs;
}

function tokenExpired() {
  if (!meliTokens.access_token) return true;
  if (!meliTokens.expires_at) return false;
  return Date.now() >= meliTokens.expires_at;
}

function classifyApiError(status, data) {
  const detail = data && typeof data === "object" ? JSON.stringify(data).slice(0, 1000) : String(data || "").slice(0, 1000);
  if (status === 401) return { code: "api_unauthorized", retryable: false, requires_reauthorization: true, detail };
  if (status === 403) return { code: "api_forbidden", retryable: false, requires_reauthorization: false, detail };
  if (status === 404) return { code: "api_endpoint_not_found", retryable: false, requires_reauthorization: false, detail };
  if (status === 429) return { code: "api_rate_limited", retryable: true, requires_reauthorization: false, detail };
  if (status >= 500) return { code: "api_unavailable", retryable: true, requires_reauthorization: false, detail };
  return { code: `api_http_${status}`, retryable: status >= 500, requires_reauthorization: false, detail };
}

function apiError(message, properties = {}) {
  const error = new Error(message);
  Object.assign(error, properties);
  return error;
}

async function exchangeMeliToken(payload) {
  logger.info({ grant_type: payload.grant_type }, "Comienza el intercambio de credenciales OAuth con MercadoLibre");

  const response = await http.post(
    "https://api.mercadolibre.com/oauth/token",
    new URLSearchParams(payload).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json"
      }
    }
  );

  if (response.status < 200 || response.status >= 300) {
    const classified = classifyApiError(response.status, response.data);
    logger.error({
      estado_http: response.status,
      codigo: classified.code,
      detalle: classified.detail
    }, "Falló el intercambio de token OAuth con MercadoLibre");
    throw apiError("meli_oauth_error", {
      status: response.status,
      code: classified.code,
      data: response.data,
      retryable: classified.retryable,
      requires_reauthorization: classified.requires_reauthorization
    });
  }

  const data = response.data || {};

  meliTokens = {
    access_token: data.access_token || "",
    refresh_token: data.refresh_token || meliTokens.refresh_token || "",
    expires_at: Date.now() + Number(data.expires_in || 10800) * 1000,
    user_id: data.user_id ? String(data.user_id) : meliTokens.user_id || ""
  };

  apiVerificationCache = {
    checked_at: 0,
    ok: false,
    user_id: meliTokens.user_id,
    global_selling_verified: false,
    status: "token_updated",
    error: ""
  };

  logger.info({
    user_id: meliTokens.user_id || null,
    expires_at: new Date(meliTokens.expires_at).toISOString(),
    refresh_token_presente: Boolean(meliTokens.refresh_token),
    campos_respuesta: Object.keys(data).filter(key => !["access_token", "refresh_token"].includes(key))
  }, "El token OAuth de MercadoLibre fue actualizado correctamente");

  await persistMeliTokens();
  return meliTokens;
}

async function refreshMeliToken() {
  if (!hasMeliCredentials()) {
    throw apiError("Faltan las credenciales de la aplicación de MercadoLibre", {
      code: "api_credentials_missing",
      status: 503,
      retryable: false,
      requires_reauthorization: false
    });
  }

  if (!meliTokens.refresh_token) {
    throw apiError("No hay refresh token disponible", {
      code: "api_reauthorization_required",
      status: 401,
      retryable: false,
      requires_reauthorization: true
    });
  }

  if (refreshPromise) return refreshPromise;

  logger.info({
    token_vencido: tokenExpired(),
    expires_at: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null
  }, "Comienza la renovación del token de MercadoLibre");

  refreshPromise = exchangeMeliToken({
    grant_type: "refresh_token",
    client_id: config.meliClientId,
    client_secret: config.meliClientSecret,
    refresh_token: meliTokens.refresh_token
  }).finally(() => {
    refreshPromise = null;
  });

  return refreshPromise;
}

async function ensureMeliToken() {
  if (!hasMeliToken()) {
    throw apiError("No hay un access token de MercadoLibre disponible", {
      code: "api_not_authenticated",
      status: 401,
      retryable: false,
      requires_reauthorization: true
    });
  }

  if (tokenWillExpireSoon()) {
    await refreshMeliToken();
  }

  return meliTokens.access_token;
}

async function checkAndRefreshMeliToken() {
  if (!hasMeliToken() || !tokenWillExpireSoon()) return;

  if (!meliTokens.refresh_token) {
    const now = Date.now();
    if (now - lastTokenRefreshWarningAt >= config.tokenCheckIntervalMs) {
      lastTokenRefreshWarningAt = now;
      logger.warn({
        token_vencido: tokenExpired(),
        expires_at: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null,
        oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
      }, "El token necesita renovación, pero no hay refresh token disponible");
    }
    return;
  }

  try {
    await refreshMeliToken();
    logger.info({
      expires_at: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null
    }, "El token de MercadoLibre fue renovado preventivamente");
  } catch (error) {
    logger.error({
      codigo: error.code || "token_refresh_error",
      estado_http: error.status || null,
      requiere_reautorizacion: Boolean(error.requires_reauthorization),
      error: error.message
    }, "Falló la renovación preventiva del token de MercadoLibre");
  }
}

async function meliRequest(path, options = {}) {
  return meliLimiter.schedule(async () => {
    const method = options.method || "GET";
    const params = options.params || {};
    const data = options.data;
    const auth = options.auth !== false;
    const operation = options.operation || path;
    const maxRetries = options.maxRetries === undefined ? 1 : Number(options.maxRetries);

    let headers = { Accept: "application/json" };

    if (auth) {
      const token = await ensureMeliToken();
      headers.Authorization = `Bearer ${token}`;
    }

    const perform = async () => http.request({
      method,
      url: `https://api.mercadolibre.com${path}`,
      params,
      data,
      headers
    });

    let attempt = 0;

    while (true) {
      attempt += 1;
      const startedAt = Date.now();
      let response;

      try {
        response = await perform();
      } catch (error) {
        logger.error({
          operacion: operation,
          endpoint: path,
          intento: attempt,
          duracion_ms: Date.now() - startedAt,
          error: error.message
        }, "No se pudo completar una solicitud a la API de MercadoLibre");

        if (attempt <= maxRetries) {
          await sleep(1000 * attempt);
          continue;
        }

        throw apiError("Error de red consultando MercadoLibre", {
          code: "api_network_error",
          status: 503,
          endpoint: path,
          operation,
          retryable: true,
          cause: error.message
        });
      }

      logger.debug({
        operacion: operation,
        endpoint: path,
        estado_http: response.status,
        duracion_ms: Date.now() - startedAt,
        intento: attempt
      }, "La API de MercadoLibre respondió una solicitud");

      if (response.status === 401 && auth && hasMeliCredentials() && meliTokens.refresh_token && attempt === 1) {
        logger.warn({
          operacion: operation,
          endpoint: path
        }, "La API respondió 401 y se intentará renovar el token");
        await refreshMeliToken();
        headers.Authorization = `Bearer ${meliTokens.access_token}`;
        continue;
      }

      if (response.status === 429 && attempt <= maxRetries) {
        const retryAfter = Number(response.headers["retry-after"] || 2);
        logger.warn({
          operacion: operation,
          endpoint: path,
          estado_http: response.status,
          espera_segundos: retryAfter,
          intento: attempt
        }, "La API de MercadoLibre aplicó un límite de solicitudes");
        await sleep(Math.max(1, retryAfter) * 1000);
        continue;
      }

      if (response.status >= 400) {
        const classified = classifyApiError(response.status, response.data);
        logger.warn({
          operacion: operation,
          endpoint: path,
          estado_http: response.status,
          codigo: classified.code,
          detalle: classified.detail,
          reintentable: classified.retryable,
          requiere_reautorizacion: classified.requires_reauthorization
        }, "La API de MercadoLibre devolvió un error");

        throw apiError(`Error de API en ${operation}`, {
          code: classified.code,
          status: response.status,
          endpoint: path,
          operation,
          data: response.data,
          retryable: classified.retryable,
          requires_reauthorization: classified.requires_reauthorization
        });
      }

      return response.data;
    }
  });
}

async function verifyMeliApiConnection(force = false) {
  const cacheAge = Date.now() - apiVerificationCache.checked_at;
  if (!force && apiVerificationCache.checked_at && cacheAge < 60 * 1000) {
    return apiVerificationCache;
  }

  if (!hasMeliCredentials()) {
    apiVerificationCache = {
      checked_at: Date.now(),
      ok: false,
      user_id: "",
      status: "credentials_missing",
      error: "Faltan MELI_CLIENT_ID, MELI_CLIENT_SECRET o MELI_REDIRECT_URI"
    };
    return apiVerificationCache;
  }

  if (!hasMeliToken()) {
    apiVerificationCache = {
      checked_at: Date.now(),
      ok: false,
      user_id: "",
      status: "token_missing",
      error: "No hay access token disponible. Se requiere completar OAuth."
    };
    return apiVerificationCache;
  }

  logger.info({
    token_presente: true,
    token_vencido: tokenExpired(),
    refresh_token_presente: Boolean(meliTokens.refresh_token)
  }, "Comienza la verificación de conexión con la API de MercadoLibre");

  try {
    const user = await meliRequest("/users/me", {
      operation: "verificar_conexion_api",
      maxRetries: 0
    });

    const userId = user && user.id ? String(user.id) : meliTokens.user_id || "";
    meliTokens.user_id = userId;
    let globalSellingVerified = false;

    if (config.meliAuthMode === "global_selling") {
      const globalUser = await meliRequest(`/marketplace/users/${userId}`, {
        operation: "verificar_usuario_global_selling",
        maxRetries: 0
      });

      globalSellingVerified = String(globalUser?.site_id || "").toUpperCase() === "CBT";

      if (!globalSellingVerified) {
        throw apiError("El usuario OAuth no fue reconocido como una cuenta Global Selling CBT", {
          code: "global_selling_account_required",
          status: 403,
          endpoint: `/marketplace/users/${userId}`,
          retryable: false,
          requires_reauthorization: true
        });
      }
    }

    apiVerificationCache = {
      checked_at: Date.now(),
      ok: true,
      user_id: userId,
      global_selling_verified: globalSellingVerified,
      status: "connected",
      error: ""
    };

    logger.info({
      user_id: userId || null,
      sitio: config.meliSiteId,
      auth_mode: config.meliAuthMode,
      global_selling_verified: globalSellingVerified
    }, "La conexión con la API de MercadoLibre fue validada correctamente");

    return apiVerificationCache;
  } catch (error) {
    apiVerificationCache = {
      checked_at: Date.now(),
      ok: false,
      user_id: meliTokens.user_id || "",
      global_selling_verified: false,
      status: error.code || "connection_failed",
      error: error.message
    };

    logger.error({
      codigo: error.code || "connection_failed",
      estado_http: error.status || null,
      endpoint: error.endpoint || "/users/me",
      requiere_reautorizacion: Boolean(error.requires_reauthorization),
      error: error.message
    }, "No fue posible validar la conexión con la API de MercadoLibre");

    return apiVerificationCache;
  }
}

function cacheGet(key) {
  const item = productCache.get(key);
  if (!item) return null;
  if (Date.now() > item.expires_at) {
    productCache.delete(key);
    return null;
  }
  return item.value;
}

function cacheSet(key, value) {
  productCache.set(key, {
    value,
    expires_at: Date.now() + config.cacheTtlMs
  });
}

function extractResults(data) {
  if (!data) return [];
  if (Array.isArray(data.results)) return data.results;
  if (Array.isArray(data.items)) return data.items;
  if (Array.isArray(data.products)) return data.products;
  if (Array.isArray(data.offers)) return data.offers;
  if (Array.isArray(data)) return data;
  return [];
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return "";
}

function firstNumber(...values) {
  for (const value of values) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    const parsed = parsePrice(value);
    if (parsed !== null) return parsed;
  }
  return null;
}

function parsePrice(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "object") {
    return firstNumber(
      value.amount,
      value.value,
      value.price,
      value.current_price,
      value.sale_price,
      value.display_amount
    );
  }
  const text = String(value).trim();
  if (!text) return null;
  const clean = text
    .replace(/[^\d,.-]/g, "")
    .replace(/\.(?=\d{3}(\D|$))/g, "")
    .replace(",", ".");
  const num = Number(clean);
  return Number.isFinite(num) ? num : null;
}

function normalizeCatalogId(value) {
  const text = String(value || "");
  const match = text.match(/ML[A-Z]?\d{5,}/i);
  return match ? match[0].toUpperCase() : "";
}

function normalizeItemId(value) {
  const text = String(value || "");
  const match = text.match(/MLA\d{5,}|MLB\d{5,}|MLM\d{5,}|MLC\d{5,}|MCO\d{5,}|MPE\d{5,}|MLU\d{5,}/i);
  return match ? match[0].toUpperCase() : "";
}

function normalizeMlaId(value) {
  const text = String(value || "").trim().toUpperCase();
  const match = text.match(/MLA[-\s]?(\d{5,})/);
  if (match) return `MLA${match[1]}`;
  if (/^\d{5,}$/.test(text)) return `MLA${text}`;
  return "";
}

function classifyProductIdentifier(value) {
  if (value.length === 8) return "GTIN-8";
  if (value.length === 12) return "UPC";
  if (value.length === 13) return "EAN";
  if (value.length === 14) return "GTIN-14";
  return "GTIN";
}

function isValidProductIdentifier(value) {
  const normalized = normalizeEan(value);
  if (![8, 12, 13, 14].includes(normalized.length)) return false;

  const digits = normalized.split("").map(Number);
  const expectedCheckDigit = digits.pop();
  let sum = 0;
  let positionFromRight = 1;

  for (let index = digits.length - 1; index >= 0; index -= 1) {
    sum += digits[index] * (positionFromRight % 2 === 1 ? 3 : 1);
    positionFromRight += 1;
  }

  return (10 - (sum % 10)) % 10 === expectedCheckDigit;
}

function extractProductIdentifiers(payload, source) {
  const found = new Map();
  const visited = new Set();
  const acceptedIds = new Set([
    "GTIN",
    "GTIN8",
    "GTIN_8",
    "GTIN12",
    "GTIN_12",
    "GTIN13",
    "GTIN_13",
    "GTIN14",
    "GTIN_14",
    "UPC",
    "UPC_A",
    "EAN",
    "EAN8",
    "EAN_8",
    "EAN13",
    "EAN_13",
    "JAN"
  ]);

  function addValue(rawValue, attributeId) {
    const value = normalizeEan(rawValue);
    if (!isValidProductIdentifier(value)) return;
    const key = `${attributeId}:${value}`;
    if (!found.has(key)) {
      found.set(key, {
        type: classifyProductIdentifier(value),
        attribute_id: attributeId,
        value,
        source
      });
    }
  }

  function visit(value, depth) {
    if (!value || typeof value !== "object" || depth > 8 || visited.has(value)) return;
    visited.add(value);

    if (!Array.isArray(value)) {
      for (const [key, child] of Object.entries(value)) {
        const directId = String(key).toUpperCase();
        if (acceptedIds.has(directId) && (typeof child === "string" || typeof child === "number")) {
          addValue(child, directId);
        }
      }

      const attributeId = firstString(value.id, value.attribute_id, value.attributeId).toUpperCase();
      const attributeName = firstString(value.name, value.attribute_name, value.attributeName).toUpperCase();
      const identifierId = acceptedIds.has(attributeId)
        ? attributeId
        : acceptedIds.has(attributeName)
          ? attributeName
          : "";

      if (identifierId) {
        addValue(value.value_name, identifierId);
        addValue(value.value, identifierId);
        if (Array.isArray(value.values)) {
          for (const entry of value.values) {
            if (entry && typeof entry === "object") {
              addValue(entry.name, identifierId);
              addValue(entry.value_name, identifierId);
              addValue(entry.value, identifierId);
            } else {
              addValue(entry, identifierId);
            }
          }
        }
      }
    }

    for (const child of Object.values(value)) {
      if (child && typeof child === "object") visit(child, depth + 1);
    }
  }

  visit(payload, 0);

  const byValue = new Map();
  for (const identifier of found.values()) {
    const existing = byValue.get(identifier.value);
    if (!existing || identifier.attribute_id === "UPC") {
      byValue.set(identifier.value, identifier);
    }
  }

  return [...byValue.values()];
}

function getPath(object, path) {
  if (!object || typeof object !== "object") return undefined;
  const parts = Array.isArray(path) ? path : String(path).split(".");
  let current = object;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    current = current[part];
  }
  return current;
}

function firstPath(object, paths) {
  for (const path of paths) {
    const value = getPath(object, path);
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return undefined;
}

function deepFindValue(object, acceptedKeys, maxDepth = 4) {
  const keys = new Set(acceptedKeys.map(key => String(key).toLowerCase()));
  const visited = new Set();

  function visit(value, depth) {
    if (!value || typeof value !== "object" || depth > maxDepth || visited.has(value)) return undefined;
    visited.add(value);

    for (const [key, child] of Object.entries(value)) {
      if (keys.has(key.toLowerCase()) && child !== undefined && child !== null && child !== "") {
        return child;
      }
    }

    for (const child of Object.values(value)) {
      if (Array.isArray(child)) {
        for (const entry of child.slice(0, 5)) {
          const found = visit(entry, depth + 1);
          if (found !== undefined) return found;
        }
      } else if (child && typeof child === "object") {
        const found = visit(child, depth + 1);
        if (found !== undefined) return found;
      }
    }

    return undefined;
  }

  return visit(object, 0);
}

function normalizeStatus(value) {
  return firstString(value).toLowerCase();
}

function normalizeCurrency(value) {
  return firstString(value).toUpperCase();
}

function normalizeSold(value) {
  const number = firstNumber(value);
  if (number === null || number < 0) return null;
  return Math.trunc(number);
}

function normalizeCatalogProduct(raw) {
  if (!raw || typeof raw !== "object") return null;

  const catalogProductId = normalizeCatalogId(firstString(
    raw.catalog_product_id,
    raw.catalogProductId,
    raw.product_id,
    raw.productId,
    raw.id
  ));

  if (!catalogProductId) return null;

  return {
    catalog_product_id: catalogProductId,
    title: firstString(raw.name, raw.title),
    raw
  };
}

function normalizeCatalogOffer(raw, catalogProductId, source) {
  if (!raw || typeof raw !== "object") return null;

  const itemId = normalizeItemId(firstString(
    firstPath(raw, [
      "item_id",
      "itemId",
      "id",
      "item.id",
      "item.item_id",
      "offer.item_id",
      "offer.id"
    ]),
    deepFindValue(raw, ["item_id", "itemId"], 3)
  ));

  const priceValue = firstPath(raw, [
    "price",
    "amount",
    "current_price",
    "currentPrice",
    "sale_price",
    "salePrice",
    "price.amount",
    "sale_price.amount",
    "salePrice.amount",
    "prices.presentation.display_amount",
    "prices.presentation.displayAmount",
    "offer.price",
    "offer.price.amount",
    "item.price"
  ]);

  const deepPriceValue = priceValue === undefined
    ? deepFindValue(raw, ["current_price", "sale_price", "display_amount", "price"], 4)
    : undefined;

  const soldValue = firstPath(raw, [
    "sold_quantity",
    "soldQuantity",
    "sold",
    "sales.quantity",
    "sales.sold_quantity",
    "item.sold_quantity",
    "offer.sold_quantity"
  ]);

  const deepSoldValue = soldValue === undefined
    ? deepFindValue(raw, ["sold_quantity", "soldQuantity"], 4)
    : undefined;

  const status = normalizeStatus(firstPath(raw, [
    "status",
    "item.status",
    "offer.status"
  ]));

  const currency = normalizeCurrency(firstPath(raw, [
    "currency_id",
    "currencyId",
    "currency",
    "price.currency_id",
    "price.currencyId",
    "sale_price.currency_id",
    "item.currency_id",
    "offer.currency_id"
  ]));

  const link = firstString(firstPath(raw, [
    "permalink",
    "link",
    "url",
    "item.permalink",
    "item.url",
    "offer.permalink"
  ]));

  if (!itemId) return null;

  const sold = normalizeSold(soldValue === undefined ? deepSoldValue : soldValue);

  return {
    item_id: itemId,
    catalog_product_id: catalogProductId || normalizeCatalogId(raw.catalog_product_id) || null,
    price: firstNumber(priceValue, deepPriceValue),
    currency_id: currency || null,
    status: status || null,
    link: link || null,
    sold,
    sold_source: sold !== null ? "catalog_items_api" : "not_available",
    source,
    raw
  };
}

function summarizeRawOffer(raw) {
  if (!raw || typeof raw !== "object") return null;
  const summary = {
    keys: Object.keys(raw).slice(0, 30)
  };
  const candidates = [
    "id",
    "item_id",
    "itemId",
    "price",
    "amount",
    "current_price",
    "sale_price",
    "sold_quantity",
    "status",
    "currency_id",
    "permalink"
  ];
  for (const key of candidates) {
    if (raw[key] !== undefined) summary[key] = raw[key];
  }
  if (raw.item && typeof raw.item === "object") {
    summary.item_keys = Object.keys(raw.item).slice(0, 20);
  }
  if (raw.price && typeof raw.price === "object") {
    summary.price_keys = Object.keys(raw.price).slice(0, 20);
  }
  if (raw.sale_price && typeof raw.sale_price === "object") {
    summary.sale_price_keys = Object.keys(raw.sale_price).slice(0, 20);
  }
  return summary;
}

function extractPaging(data, fallbackOffset, fallbackLimit, received) {
  const paging = data && typeof data === "object" && data.paging && typeof data.paging === "object"
    ? data.paging
    : {};
  const total = firstNumber(paging.total, data?.total);
  const offset = firstNumber(paging.offset, data?.offset, fallbackOffset) ?? fallbackOffset;
  const limit = firstNumber(paging.limit, data?.limit, fallbackLimit) ?? fallbackLimit;
  const nextOffset = offset + received;
  return {
    total,
    offset,
    limit,
    next_offset: nextOffset,
    has_more: total !== null ? nextOffset < total : received >= limit
  };
}

function resultError(row, ean, status, error, details = {}) {
  return {
    row_number: row.row_number,
    ean,
    catalog_product_id: details.catalog_product_id || null,
    item_id: details.item_id || null,
    min_price: null,
    link: details.link || details.item_id || null,
    mla: details.item_id || null,
    sold: null,
    sold_source: "not_available",
    source: details.source || "mercadolibre_api",
    status,
    error: error ? String(error).slice(0, 500) : "",
    api_http_status: details.api_http_status || null,
    api_endpoint: details.api_endpoint || null,
    retryable: Boolean(details.retryable),
    requires_reauthorization: Boolean(details.requires_reauthorization),
    checked_at: nowIso()
  };
}

function buildResolvedResult(row, ean, data) {
  return {
    row_number: row.row_number,
    ean,
    catalog_product_id: data.catalog_product_id || null,
    item_id: data.item_id || null,
    min_price: data.min_price === undefined ? null : data.min_price,
    link: data.link || data.item_id || null,
    mla: data.item_id || null,
    sold: null,
    sold_source: "not_available",
    sold_start_time: null,
    source: data.source || "mercadolibre_api",
    status: "ok",
    error: "",
    warning: "",
    api_http_status: 200,
    api_endpoint: data.api_endpoint || null,
    retryable: false,
    requires_reauthorization: false,
    checked_at: nowIso()
  };
}

function buildCatalogOnlyResult(row, ean, data) {
  return {
    row_number: row.row_number,
    ean,
    catalog_product_id: data.catalog_product_id || null,
    item_id: data.item_id || null,
    min_price: null,
    link: data.item_id || null,
    mla: data.item_id || null,
    sold: data.sold === undefined ? null : data.sold,
    sold_source: data.sold_source || "not_available",
    source: data.source || "catalog_items_api",
    status: "catalog_only",
    error: "MercadoLibre informó publicaciones MLA asociadas, pero no expuso un precio utilizable",
    api_http_status: 200,
    api_endpoint: data.api_endpoint || null,
    retryable: false,
    requires_reauthorization: false,
    checked_at: nowIso()
  };
}

async function searchProductsByEan(ean) {
  const errors = [];
  const exactPath = "/products/search";

  try {
    const data = await meliRequest(exactPath, {
      params: {
        site_id: config.meliSiteId,
        product_identifier: ean,
        status: "active"
      },
      operation: "buscar_producto_catalogo_por_identificador",
      maxRetries: 1
    });

    const results = extractResults(data).map(normalizeCatalogProduct).filter(Boolean);

    logger.info({
      ean,
      endpoint: exactPath,
      productos_catalogo_encontrados: results.length,
      catalog_product_ids: results.slice(0, 5).map(result => result.catalog_product_id)
    }, "Finalizó la búsqueda exacta del producto por UPC/EAN");

    if (results.length) {
      return {
        results,
        endpoint: exactPath,
        operation: "buscar_producto_catalogo_por_identificador",
        errors
      };
    }
  } catch (error) {
    errors.push(error);
    logger.warn({
      ean,
      endpoint: exactPath,
      codigo: error.code || "api_error",
      estado_http: error.status || null
    }, "Falló la búsqueda exacta del producto por UPC/EAN");

    if (["api_unauthorized", "api_not_authenticated", "api_reauthorization_required"].includes(error.code)) {
      throw error;
    }
  }

  return {
    results: [],
    endpoint: null,
    operation: null,
    errors
  };
}

async function fetchCatalogOffers(catalogProductId) {
  const path = `/products/${catalogProductId}/items`;
  const rawOffers = [];
  const normalizedOffers = [];
  const errors = [];
  const seenItemIds = new Set();
  let offset = 0;
  let pagesRead = 0;
  let lastPaging = null;

  for (let page = 0; page < config.maxCatalogItemPages; page += 1) {
    try {
      const data = await meliRequest(path, {
        params: {
          limit: config.catalogItemsPageSize,
          offset
        },
        operation: "listar_publicaciones_del_producto_catalogo",
        maxRetries: 1
      });

      const pageRaw = extractResults(data);
      const pageNormalized = pageRaw
        .map(raw => normalizeCatalogOffer(raw, catalogProductId, "catalog_items_api"))
        .filter(Boolean);

      for (const raw of pageRaw) rawOffers.push(raw);
      for (const offer of pageNormalized) {
        if (seenItemIds.has(offer.item_id)) continue;
        seenItemIds.add(offer.item_id);
        normalizedOffers.push(offer);
      }

      lastPaging = extractPaging(data, offset, config.catalogItemsPageSize, pageRaw.length);
      pagesRead += 1;

      logger.info({
        catalog_product_id: catalogProductId,
        endpoint: path,
        pagina: page + 1,
        offset,
        recibidos: pageRaw.length,
        normalizados: pageNormalized.length,
        total_acumulado: normalizedOffers.length,
        paging: lastPaging
      }, "Se obtuvo una página de publicaciones asociadas al producto de catálogo");

      if (pageRaw.length === 0 || !lastPaging.has_more || lastPaging.next_offset <= offset) break;
      offset = lastPaging.next_offset;
    } catch (error) {
      errors.push(error);
      logger.warn({
        catalog_product_id: catalogProductId,
        endpoint: path,
        pagina: page + 1,
        offset,
        codigo: error.code || "api_error",
        estado_http: error.status || null
      }, "Falló la lectura de publicaciones asociadas al producto de catálogo");
      break;
    }
  }

  if (config.logCatalogSamples && rawOffers.length) {
    logger.info({
      catalog_product_id: catalogProductId,
      endpoint: path,
      paginas_leidas: pagesRead,
      publicaciones_unicas: normalizedOffers.length,
      muestra_estructura: rawOffers.slice(0, 3).map(summarizeRawOffer),
      muestra_normalizada: normalizedOffers.slice(0, 5).map(offer => ({
        item_id: offer.item_id,
        price: offer.price,
        currency_id: offer.currency_id,
        status: offer.status,
        sold: offer.sold,
        link_presente: Boolean(offer.link)
      }))
    }, "Diagnóstico de la respuesta de publicaciones del producto de catálogo");
  }

  return {
    offers: normalizedOffers,
    raw_offers: rawOffers,
    endpoint: path,
    paging: lastPaging,
    pages_read: pagesRead,
    errors
  };
}

function isOfferActive(offer) {
  if (!offer || !offer.item_id) return false;
  if (!offer.status) return true;
  return ["active", "under_review"].includes(offer.status);
}

function isOfferCurrencyAllowed(offer) {
  if (!offer.currency_id) return true;
  return offer.currency_id === "ARS";
}

function pickBestOffer(offers) {
  return (offers || [])
    .filter(offer => isOfferActive(offer))
    .filter(offer => isOfferCurrencyAllowed(offer))
    .filter(offer => offer.price !== null && offer.price !== undefined && Number(offer.price) > 0)
    .sort((a, b) => {
      const priceDifference = Number(a.price) - Number(b.price);
      if (priceDifference !== 0) return priceDifference;
      const aSold = a.sold === null ? -1 : Number(a.sold);
      const bSold = b.sold === null ? -1 : Number(b.sold);
      return bSold - aSold;
    })[0] || null;
}

function firstCriticalApiError(errors) {
  const list = (errors || []).filter(Boolean);
  return list.find(error => [
    "api_unauthorized",
    "api_not_authenticated",
    "api_reauthorization_required",
    "api_rate_limited",
    "api_unavailable",
    "api_network_error"
  ].includes(error.code)) || null;
}

function logApiDiagnostic(payload, message) {
  if (apiDiagnosticCount >= config.maxApiDiagnosticLogs) return;
  apiDiagnosticCount += 1;
  logger.warn({
    ...payload,
    diagnostico_numero: apiDiagnosticCount,
    diagnosticos_maximos: config.maxApiDiagnosticLogs
  }, message);
}

async function resolveProduct(row) {
  const ean = normalizeEan(row.ean);

  if (!isValidEan(ean)) {
    return resultError(row, ean, "invalid_ean", "EAN inválido");
  }

  const cacheKey = `api-v5-price-only:${config.meliSiteId}:ean:${ean}`;
  const cached = cacheGet(cacheKey);

  if (cached) {
    return {
      ...cached,
      row_number: row.row_number,
      checked_at: nowIso(),
      source: `${cached.source || "mercadolibre_api"}_cache`
    };
  }

  if (!hasMeliToken()) {
    return resultError(row, ean, "api_not_authenticated", "No hay un access token de MercadoLibre disponible", {
      requires_reauthorization: true
    });
  }

  let productSearch;

  try {
    productSearch = await searchProductsByEan(ean);
  } catch (error) {
    return resultError(row, ean, error.code || "api_error", error.message, {
      api_http_status: error.status,
      api_endpoint: error.endpoint,
      retryable: error.retryable,
      requires_reauthorization: error.requires_reauthorization
    });
  }

  const accumulatedErrors = [...productSearch.errors];

  if (!productSearch.results.length) {
    const critical = firstCriticalApiError(accumulatedErrors);

    if (critical) {
      return resultError(row, ean, critical.code || "api_error", critical.message, {
        api_http_status: critical.status,
        api_endpoint: critical.endpoint,
        retryable: critical.retryable,
        requires_reauthorization: critical.requires_reauthorization
      });
    }

    logApiDiagnostic({
      row_number: row.row_number,
      ean,
      marca: row.brand || "",
      nombre: String(row.name || "").slice(0, 200)
    }, "La API no encontró un producto de catálogo para el UPC/EAN");

    return resultError(row, ean, "product_not_found", "La API de MercadoLibre no encontró un producto de catálogo para el UPC/EAN", {
      api_endpoint: productSearch.endpoint
    });
  }

  const catalogProductId = productSearch.results[0].catalog_product_id;
  let catalogResult;

  try {
    catalogResult = await fetchCatalogOffers(catalogProductId);
  } catch (error) {
    return resultError(row, ean, error.code || "api_error", error.message, {
      catalog_product_id: catalogProductId,
      api_http_status: error.status,
      api_endpoint: error.endpoint,
      retryable: error.retryable,
      requires_reauthorization: error.requires_reauthorization
    });
  }

  accumulatedErrors.push(...catalogResult.errors);
  const offers = catalogResult.offers;
  const offersEndpoint = catalogResult.endpoint;

  const best = pickBestOffer(offers);
  const itemCandidates = offers.filter(offer => offer.item_id);
  const firstItem = itemCandidates[0] || null;

  logger.info({
    row_number: row.row_number,
    ean,
    catalog_product_id: catalogProductId,
    publicaciones_catalogo: catalogResult.offers.length,
    publicaciones_unicas: offers.length,
    publicaciones_activas: offers.filter(isOfferActive).length,
    publicaciones_con_precio: offers.filter(offer => offer.price !== null && offer.price !== undefined && Number(offer.price) > 0).length,
    publicaciones_con_vendidos: offers.filter(offer => offer.sold !== null && offer.sold !== undefined).length,
    monedas: [...new Set(offers.map(offer => offer.currency_id).filter(Boolean))],
    endpoint_seleccionado: offersEndpoint,
    mejor_item_id: best?.item_id || null,
    menor_precio: best?.price ?? null,
    vendidos_mejor_oferta: best?.sold ?? null
  }, "Finalizó la evaluación de publicaciones para calcular el menor precio");

  if (best) {
    const result = buildResolvedResult(row, ean, {
      catalog_product_id: catalogProductId,
      item_id: best.item_id,
      min_price: best.price,
      link: best.item_id,
      source: best.source,
      api_endpoint: offersEndpoint
    });

    logger.info({
      row_number: row.row_number,
      ean,
      catalog_product_id: catalogProductId,
      item_id: result.item_id,
      meli_price: result.min_price,
      status: result.status,
      source: result.source,
      api_endpoint: result.api_endpoint
    }, "Producto resuelto con la publicación de menor precio disponible");

    if (config.cacheSuccessfulResults) cacheSet(cacheKey, result);
    return result;
  }

  const critical = firstCriticalApiError(accumulatedErrors);

  if (critical && !firstItem) {
    return resultError(row, ean, critical.code || "api_error", critical.message, {
      catalog_product_id: catalogProductId,
      api_http_status: critical.status,
      api_endpoint: critical.endpoint,
      retryable: critical.retryable,
      requires_reauthorization: critical.requires_reauthorization
    });
  }

  if (firstItem) {
    logApiDiagnostic({
      row_number: row.row_number,
      ean,
      catalog_product_id: catalogProductId,
      item_id: firstItem.item_id,
      publicaciones_recibidas: offers.length,
      publicaciones_con_precio: offers.filter(offer => offer.price !== null && offer.price !== undefined).length,
      muestra_normalizada: offers.slice(0, 5).map(offer => ({
        item_id: offer.item_id,
        price: offer.price,
        currency_id: offer.currency_id,
        status: offer.status,
        sold: offer.sold,
        source: offer.source
      }))
    }, "MercadoLibre informó MLA asociados, pero no expuso un precio utilizable");

    return buildCatalogOnlyResult(row, ean, {
      catalog_product_id: catalogProductId,
      item_id: firstItem.item_id,
      sold: firstItem.sold,
      sold_source: firstItem.sold_source,
      source: firstItem.source,
      api_endpoint: offersEndpoint
    });
  }

  return resultError(row, ean, "offers_not_found", "MercadoLibre reconoció el producto, pero no informó publicaciones MLA asociadas", {
    catalog_product_id: catalogProductId,
    api_endpoint: offersEndpoint
  });
}

function mergeIdentifierEvidence(store, identifiers, context = {}) {
  for (const identifier of identifiers) {
    const value = normalizeEan(identifier.value);
    if (!isValidProductIdentifier(value)) continue;

    let evidence = store.get(value);

    if (!evidence) {
      evidence = {
        value,
        type: classifyProductIdentifier(value),
        attribute_ids: new Set(),
        sources: new Set(),
        item_ids: new Set(),
        catalog_product_ids: new Set(),
        catalog_direct: false,
        catalog_tree_direct: false,
        verified: false,
        verification_status: "pending",
        reverse_catalog_product_ids: new Set()
      };
      store.set(value, evidence);
    }

    if (identifier.attribute_id) evidence.attribute_ids.add(String(identifier.attribute_id));
    if (identifier.source) evidence.sources.add(String(identifier.source));
    if (context.source) evidence.sources.add(String(context.source));
    if (context.item_id) evidence.item_ids.add(String(context.item_id));
    if (context.catalog_product_id) evidence.catalog_product_ids.add(String(context.catalog_product_id));
    if (context.catalog_direct) evidence.catalog_direct = true;
    if (context.catalog_tree_direct) evidence.catalog_tree_direct = true;
  }
}

async function fetchAssociatedItemDetails(itemIds) {
  const uniqueItemIds = [...new Set(itemIds.map(normalizeItemId).filter(Boolean))];
  const limitedItemIds = uniqueItemIds.slice(0, config.maxUpcAssociatedItems);
  const detailsById = new Map();
  const errors = [];

  for (let index = 0; index < limitedItemIds.length; index += config.upcItemBatchSize) {
    const batch = limitedItemIds.slice(index, index + config.upcItemBatchSize);

    try {
      const data = await meliRequest("/items", {
        params: {
          ids: batch.join(","),
          include_internal_attributes: true
        },
        operation: "buscar_atributos_de_publicaciones_asociadas",
        maxRetries: 1
      });

      const responses = Array.isArray(data) ? data : [data];

      for (const response of responses) {
        const status = Number(response?.code || response?.status || 200);
        const body = response?.body && typeof response.body === "object" ? response.body : response;
        const itemId = normalizeItemId(firstString(body?.id, body?.item_id));
        if (status >= 200 && status < 300 && itemId) detailsById.set(itemId, body);
      }
    } catch (error) {
      logger.warn({
        item_ids: batch,
        codigo: error.code || "api_error",
        estado_http: error.status || null
      }, "Falló la consulta múltiple de publicaciones asociadas");
    }

    const missingItemIds = batch.filter(itemId => !detailsById.has(itemId));

    const fallbackResults = await mapWithConcurrency(missingItemIds, config.productConcurrency, async itemId => {
      try {
        const data = await meliRequest(`/items/${itemId}`, {
          params: {
            include_internal_attributes: true
          },
          operation: "buscar_atributos_de_publicacion_asociada",
          maxRetries: 1
        });
        return { item_id: itemId, data, error: null };
      } catch (error) {
        return { item_id: itemId, data: null, error };
      }
    });

    for (const result of fallbackResults) {
      if (result.data) {
        detailsById.set(result.item_id, result.data);
      } else if (result.error) {
        errors.push({
          item_id: result.item_id,
          code: result.error.code || "api_error",
          status: result.error.status || null,
          message: result.error.message
        });
      }
    }
  }

  return {
    details: [...detailsById.entries()].map(([item_id, data]) => ({ item_id, data })),
    errors,
    requested: limitedItemIds.length,
    available: detailsById.size,
    truncated: limitedItemIds.length < uniqueItemIds.length
  };
}

async function verifyIdentifierEvidence(catalogProductId, evidenceList) {
  return mapWithConcurrency(evidenceList, config.productConcurrency, async evidence => {
    if (evidence.catalog_direct) {
      evidence.verified = true;
      evidence.verification_status = "catalog_direct";
      evidence.reverse_catalog_product_ids.add(catalogProductId);
      return evidence;
    }

    try {
      const lookup = await searchProductsByEan(evidence.value);
      const reverseIds = lookup.results.map(result => result.catalog_product_id).filter(Boolean);
      for (const reverseId of reverseIds) evidence.reverse_catalog_product_ids.add(reverseId);

      if (reverseIds.includes(catalogProductId)) {
        evidence.verified = true;
        evidence.verification_status = "reverse_match";
      } else if (reverseIds.length) {
        evidence.verification_status = "reverse_other_catalog";
      } else if (lookup.errors.length) {
        evidence.verification_status = "reverse_api_error";
      } else {
        evidence.verification_status = "reverse_no_match";
      }
    } catch (error) {
      evidence.verification_status = "reverse_api_error";
    }

    return evidence;
  });
}

function serializeIdentifierEvidence(evidence) {
  return {
    value: evidence.value,
    type: evidence.type,
    verified: evidence.verified,
    verification_status: evidence.verification_status,
    attribute_ids: [...evidence.attribute_ids],
    sources: [...evidence.sources],
    item_ids: [...evidence.item_ids],
    catalog_product_ids: [...evidence.catalog_product_ids],
    reverse_catalog_product_ids: [...evidence.reverse_catalog_product_ids]
  };
}

function responseFingerprint(data) {
  try {
    return crypto.createHash("sha1").update(JSON.stringify(data)).digest("hex");
  } catch (error) {
    return "";
  }
}

function safeAttemptPreview(data) {
  if (!config.upcAttemptLogBodyChars) return "";
  try {
    return JSON.stringify(data).slice(0, config.upcAttemptLogBodyChars);
  } catch (error) {
    return String(data || "").slice(0, config.upcAttemptLogBodyChars);
  }
}

function countPayloadArrays(payload) {
  const visited = new Set();
  let attributes = 0;
  let variations = 0;
  let pictures = 0;

  function visit(value, depth) {
    if (!value || typeof value !== "object" || visited.has(value) || depth > 8) return;
    visited.add(value);
    if (Array.isArray(value.attributes)) attributes += value.attributes.length;
    if (Array.isArray(value.variations)) variations += value.variations.length;
    if (Array.isArray(value.pictures)) pictures += value.pictures.length;
    for (const child of Object.values(value)) {
      if (child && typeof child === "object") visit(child, depth + 1);
    }
  }

  visit(payload, 0);
  return { attributes, variations, pictures };
}

function summarizeAttemptParams(params) {
  const summary = {};
  if (!params || typeof params !== "object") return summary;
  if (params.ids) summary.ids_count = String(params.ids).split(",").filter(Boolean).length;
  if (params.attributes) summary.attributes = String(params.attributes);
  if (params.include_internal_attributes !== undefined) {
    summary.include_internal_attributes = Boolean(params.include_internal_attributes);
  }
  if (params.limit !== undefined) summary.limit = params.limit;
  if (params.offset !== undefined) summary.offset = params.offset;
  if (params.catalog_product_id) summary.catalog_product_id = params.catalog_product_id;
  if (params.product_identifier) summary.product_identifier = params.product_identifier;
  if (params.site_id) summary.site_id = params.site_id;
  return summary;
}

function recordIdentifierAttempt(attempts, record) {
  attempts.push(record);
  logger.info({
    catalog_product_id: record.catalog_product_id || null,
    item_id: record.item_id || null,
    user_product_id: record.user_product_id || null,
    family_id: record.family_id || null,
    attempt_id: record.attempt_id,
    source: record.source,
    endpoint: record.endpoint,
    authentication: record.authentication,
    parameters: record.parameters,
    http_status: record.http_status,
    inner_status: record.inner_status || null,
    duration_ms: record.duration_ms,
    response_keys: record.response_keys || [],
    attributes_count: record.attributes_count || 0,
    variations_count: record.variations_count || 0,
    pictures_count: record.pictures_count || 0,
    identifiers_found: record.identifiers_found || [],
    response_fingerprint: record.response_fingerprint || "",
    response_duplicate_of: record.response_duplicate_of || null,
    api_error: record.api_error || null,
    response_preview: record.response_preview || "",
    continued: record.continued !== false
  }, "Finalizó un camino del rastreo exhaustivo de identificadores");
}

async function executeMeliIdentifierAttempt(spec, attempts, fingerprints) {
  const startedAt = Date.now();
  const authentication = spec.auth === false ? "public" : "bearer";

  try {
    const data = await meliRequest(spec.endpoint, {
      params: spec.params || {},
      auth: spec.auth !== false,
      operation: `rastrear_identificador_${spec.attemptId}`,
      maxRetries: spec.maxRetries === undefined ? 1 : spec.maxRetries
    });
    const identifiers = extractProductIdentifiers(data, spec.source);
    const fingerprint = responseFingerprint(data);
    const duplicateOf = fingerprint && fingerprints.has(fingerprint) ? fingerprints.get(fingerprint) : null;
    if (fingerprint && !duplicateOf) fingerprints.set(fingerprint, spec.attemptId);
    const counts = countPayloadArrays(data);
    const record = {
      attempt_id: spec.attemptId,
      source: spec.source,
      endpoint: spec.endpoint,
      authentication,
      parameters: summarizeAttemptParams(spec.params),
      catalog_product_id: spec.catalogProductId || null,
      item_id: spec.itemId || null,
      user_product_id: spec.userProductId || null,
      family_id: spec.familyId || null,
      http_status: 200,
      duration_ms: Date.now() - startedAt,
      response_keys: data && typeof data === "object" && !Array.isArray(data) ? Object.keys(data).slice(0, 40) : [],
      attributes_count: counts.attributes,
      variations_count: counts.variations,
      pictures_count: counts.pictures,
      identifiers_found: identifiers.map(identifier => identifier.value),
      response_fingerprint: fingerprint,
      response_duplicate_of: duplicateOf,
      continued: true
    };
    recordIdentifierAttempt(attempts, record);
    return { ok: true, data, identifiers, status: 200, record };
  } catch (error) {
    const record = {
      attempt_id: spec.attemptId,
      source: spec.source,
      endpoint: spec.endpoint,
      authentication,
      parameters: summarizeAttemptParams(spec.params),
      catalog_product_id: spec.catalogProductId || null,
      item_id: spec.itemId || null,
      user_product_id: spec.userProductId || null,
      family_id: spec.familyId || null,
      http_status: error.status || 0,
      duration_ms: Date.now() - startedAt,
      identifiers_found: [],
      api_error: error.code || "api_error",
      response_preview: safeAttemptPreview(error.data || error.message),
      continued: true
    };
    recordIdentifierAttempt(attempts, record);
    return { ok: false, data: null, identifiers: [], status: error.status || 0, error, record };
  }
}

function normalizeUserProductId(value) {
  const text = String(value || "").trim().toUpperCase();
  const match = text.match(/(?:ML[A-Z]U|CBTU|U)\d{3,}/);
  return match ? match[0] : "";
}

function extractReferenceValues(payload) {
  const catalogProductIds = new Set();
  const childCatalogProductIds = new Set();
  const itemIds = new Set();
  const parentItemIds = new Set();
  const userProductIds = new Set();
  const familyIds = new Set();
  const permalinks = new Set();
  const imageUrls = new Set();
  const visited = new Set();

  function addCatalog(value, child = false) {
    const id = normalizeCatalogId(value);
    if (!id) return;
    catalogProductIds.add(id);
    if (child) childCatalogProductIds.add(id);
  }

  function addItem(value, parent = false) {
    const id = normalizeItemId(value);
    if (!id) return;
    itemIds.add(id);
    if (parent) parentItemIds.add(id);
  }

  function visit(value, depth) {
    if (!value || typeof value !== "object" || visited.has(value) || depth > 10) return;
    visited.add(value);

    if (!Array.isArray(value)) {
      for (const [rawKey, child] of Object.entries(value)) {
        const key = String(rawKey).toLowerCase();
        if (["catalog_product_id", "catalogproductid", "product_id"].includes(key)) addCatalog(child);
        if (["children_ids", "child_product_ids"].includes(key) && Array.isArray(child)) {
          for (const entry of child) addCatalog(entry, true);
        }
        if (["item_id", "itemid"].includes(key)) addItem(child);
        if (key === "parent_item_id") addItem(child, true);
        if (["user_product_id", "userproductid"].includes(key)) {
          const id = normalizeUserProductId(child);
          if (id) userProductIds.add(id);
        }
        if (key === "family_id" && child !== null && child !== undefined && String(child).trim()) {
          familyIds.add(String(child).trim());
        }
        if (typeof child === "string" && /^https?:\/\//i.test(child)) {
          const looksLikeImage = /\.(?:jpe?g|png|webp|gif)(?:\?|$)/i.test(child) || /mlstatic\.com/i.test(child);
          if (["secure_url", "secureurl", "image", "image_url", "thumbnail"].includes(key) || (key === "url" && looksLikeImage)) {
            imageUrls.add(child);
          } else if (["permalink", "canonical_url"].includes(key) || (key === "url" && !looksLikeImage)) {
            permalinks.add(child);
          }
        }
      }
    }

    for (const child of Object.values(value)) {
      if (child && typeof child === "object") visit(child, depth + 1);
    }
  }

  visit(payload, 0);
  return {
    catalogProductIds: [...catalogProductIds],
    childCatalogProductIds: [...childCatalogProductIds],
    itemIds: [...itemIds],
    parentItemIds: [...parentItemIds],
    userProductIds: [...userProductIds],
    familyIds: [...familyIds],
    permalinks: [...permalinks],
    imageUrls: [...imageUrls]
  };
}

function extractLabeledIdentifiersFromText(text, source) {
  const identifiers = [];
  const seen = new Set();
  const patterns = [
    /(?:gtin(?:[-_ ]?(?:8|12|13|14))?|ean(?:[-_ ]?(?:8|13))?|upc(?:[-_ ]?a)?|c[oó]digo\s+universal)[^0-9]{0,60}([0-9][0-9\s.-]{6,24}[0-9])/gi,
    /"(?:gtin(?:8|12|13|14)?|ean|upc|productID|barcode)"\s*:\s*"?([0-9]{8,14})"?/gi
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(String(text || ""))) !== null) {
      const value = normalizeEan(match[1]);
      if (!isValidProductIdentifier(value) || seen.has(value)) continue;
      seen.add(value);
      identifiers.push({
        type: classifyProductIdentifier(value),
        attribute_id: "LABELED_TEXT",
        value,
        source
      });
    }
  }

  return identifiers;
}

function collectJsonLdIdentifiers(html, source) {
  const identifiers = [];
  const pattern = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match;

  while ((match = pattern.exec(String(html || ""))) !== null) {
    try {
      const parsed = JSON.parse(match[1].trim());
      identifiers.push(...extractProductIdentifiers(parsed, source));
    } catch (error) {
      identifiers.push(...extractLabeledIdentifiersFromText(match[1], source));
    }
  }

  identifiers.push(...extractLabeledIdentifiersFromText(html, source));
  return identifiers;
}

async function executeWebIdentifierAttempt(spec, attempts, fingerprints) {
  const startedAt = Date.now();

  try {
    const response = await http.get(spec.url, {
      headers: {
        Accept: "text/html,application/xhtml+xml",
        "User-Agent": "Mozilla/5.0 (compatible; MeliIdentifierResolver/4.0)"
      }
    });
    const html = typeof response.data === "string" ? response.data : JSON.stringify(response.data || {});
    const identifiers = response.status >= 200 && response.status < 300
      ? collectJsonLdIdentifiers(html, spec.source)
      : [];
    const fingerprint = responseFingerprint(html);
    const duplicateOf = fingerprint && fingerprints.has(fingerprint) ? fingerprints.get(fingerprint) : null;
    if (fingerprint && !duplicateOf) fingerprints.set(fingerprint, spec.attemptId);
    const record = {
      attempt_id: spec.attemptId,
      source: spec.source,
      endpoint: spec.url,
      authentication: "public_web",
      parameters: {},
      catalog_product_id: spec.catalogProductId || null,
      item_id: spec.itemId || null,
      http_status: response.status,
      duration_ms: Date.now() - startedAt,
      response_keys: [],
      attributes_count: 0,
      variations_count: 0,
      pictures_count: 0,
      identifiers_found: identifiers.map(identifier => identifier.value),
      response_fingerprint: fingerprint,
      response_duplicate_of: duplicateOf,
      response_preview: response.status >= 400 ? html.slice(0, config.upcAttemptLogBodyChars) : "",
      continued: true
    };
    recordIdentifierAttempt(attempts, record);
    return { ok: response.status >= 200 && response.status < 300, identifiers, status: response.status, html, record };
  } catch (error) {
    const record = {
      attempt_id: spec.attemptId,
      source: spec.source,
      endpoint: spec.url,
      authentication: "public_web",
      parameters: {},
      catalog_product_id: spec.catalogProductId || null,
      item_id: spec.itemId || null,
      http_status: error.response?.status || 0,
      duration_ms: Date.now() - startedAt,
      identifiers_found: [],
      api_error: "web_request_error",
      response_preview: safeAttemptPreview(error.response?.data || error.message),
      continued: true
    };
    recordIdentifierAttempt(attempts, record);
    return { ok: false, identifiers: [], status: record.http_status, error, record };
  }
}

function addPayloadToMap(payloadMap, id, data, source, attemptId) {
  if (!id || !data || typeof data !== "object") return;
  if (!payloadMap.has(id)) payloadMap.set(id, []);
  const fingerprint = responseFingerprint(data);
  const entries = payloadMap.get(id);
  if (fingerprint && entries.some(entry => entry.fingerprint === fingerprint)) return;
  entries.push({ data, source, attempt_id: attemptId, fingerprint });
}

function getCatalogWebUrl(catalogProductId) {
  const siteDomains = {
    MLA: "www.mercadolibre.com.ar",
    MLB: "www.mercadolivre.com.br",
    MLM: "www.mercadolibre.com.mx",
    MLC: "www.mercadolibre.cl",
    MCO: "www.mercadolibre.com.co",
    MPE: "www.mercadolibre.com.pe",
    MLU: "www.mercadolibre.com.uy"
  };
  const host = siteDomains[config.meliSiteId] || siteDomains.MLA;
  return `https://${host}/p/${catalogProductId}`;
}

function buildAttemptSummary(attempts) {
  const summary = {
    total: attempts.length,
    succeeded: 0,
    forbidden: 0,
    not_found: 0,
    rate_limited: 0,
    failed: 0,
    public: 0,
    bearer: 0,
    public_web: 0,
    with_identifiers: 0
  };

  for (const attempt of attempts) {
    if (attempt.authentication === "public") summary.public += 1;
    if (attempt.authentication === "bearer") summary.bearer += 1;
    if (attempt.authentication === "public_web") summary.public_web += 1;
    if (attempt.http_status >= 200 && attempt.http_status < 300) summary.succeeded += 1;
    else if (attempt.http_status === 403 || attempt.inner_status === 403) summary.forbidden += 1;
    else if (attempt.http_status === 404 || attempt.inner_status === 404) summary.not_found += 1;
    else if (attempt.http_status === 429 || attempt.inner_status === 429) summary.rate_limited += 1;
    else summary.failed += 1;
    if (Array.isArray(attempt.identifiers_found) && attempt.identifiers_found.length) summary.with_identifiers += 1;
  }

  return summary;
}

async function scanCatalogProductMatrix(rootCatalogProductId, evidenceStore, attempts, fingerprints, verificationRootCatalogProductId = rootCatalogProductId) {
  const queue = [{ id: rootCatalogProductId, depth: 0 }];
  const visitedCatalogProductIds = new Set();
  const itemIds = new Set();
  const rawOffers = [];
  const permalinks = new Set();
  const userProductIds = new Set();
  let rootProduct = null;
  let complete = true;

  while (queue.length && visitedCatalogProductIds.size < config.maxUpcCatalogProducts) {
    const current = queue.shift();
    if (!current || visitedCatalogProductIds.has(current.id) || current.depth > config.maxUpcCatalogDepth) continue;
    visitedCatalogProductIds.add(current.id);
    let currentProductSucceeded = false;
    let currentOffersSucceeded = false;

    for (const auth of [true, false]) {
      const mode = auth ? "auth" : "public";
      const productAttempt = await executeMeliIdentifierAttempt({
        attemptId: `catalog_${current.id}_${mode}`,
        endpoint: `/products/${current.id}`,
        auth,
        source: `catalog_product_api_${mode}`,
        catalogProductId: current.id
      }, attempts, fingerprints);

      if (productAttempt.ok) {
        currentProductSucceeded = true;
        if (current.id === rootCatalogProductId && !rootProduct) rootProduct = productAttempt.data;
        mergeIdentifierEvidence(evidenceStore, productAttempt.identifiers, {
          source: `catalog_product_api_${mode}`,
          catalog_product_id: current.id,
          catalog_direct: current.id === verificationRootCatalogProductId,
          catalog_tree_direct: current.id !== verificationRootCatalogProductId
        });
        const refs = extractReferenceValues(productAttempt.data);
        for (const url of refs.permalinks) permalinks.add(url);
        for (const upId of refs.userProductIds) userProductIds.add(upId);
        if (current.depth < config.maxUpcCatalogDepth) {
          for (const childId of [...refs.childCatalogProductIds, ...refs.catalogProductIds]) {
            if (childId !== current.id && !visitedCatalogProductIds.has(childId)) {
              queue.push({ id: childId, depth: current.depth + 1 });
            }
          }
        }
      }

      let offset = 0;
      let offerRouteComplete = true;
      for (let page = 0; page < config.maxCatalogItemPages; page += 1) {
        const offerAttempt = await executeMeliIdentifierAttempt({
          attemptId: `catalog_items_${current.id}_${mode}_${page + 1}`,
          endpoint: `/products/${current.id}/items`,
          params: { limit: config.catalogItemsPageSize, offset },
          auth,
          source: `catalog_items_api_${mode}`,
          catalogProductId: current.id
        }, attempts, fingerprints);

        if (!offerAttempt.ok) {
          offerRouteComplete = false;
          break;
        }

        const pageRaw = extractResults(offerAttempt.data);
        const paging = extractPaging(offerAttempt.data, offset, config.catalogItemsPageSize, pageRaw.length);
        for (const raw of pageRaw) {
          rawOffers.push(raw);
          const offer = normalizeCatalogOffer(raw, current.id, `catalog_items_api_${mode}`);
          if (offer?.item_id) itemIds.add(offer.item_id);
          if (offer?.link) permalinks.add(offer.link);
          const identifiers = extractProductIdentifiers(raw, `catalog_items_api_${mode}`);
          mergeIdentifierEvidence(evidenceStore, identifiers, {
            source: `catalog_items_api_${mode}`,
            item_id: offer?.item_id || null,
            catalog_product_id: current.id
          });
          const refs = extractReferenceValues(raw);
          for (const itemId of refs.itemIds) itemIds.add(itemId);
          for (const url of refs.permalinks) permalinks.add(url);
          for (const upId of refs.userProductIds) userProductIds.add(upId);
          if (current.depth < config.maxUpcCatalogDepth) {
            for (const catalogId of refs.catalogProductIds) {
              if (catalogId !== current.id && !visitedCatalogProductIds.has(catalogId)) {
                queue.push({ id: catalogId, depth: current.depth + 1 });
              }
            }
          }
        }

        if (!pageRaw.length || !paging.has_more || paging.next_offset <= offset) break;
        offset = paging.next_offset;
        if (page === config.maxCatalogItemPages - 1) offerRouteComplete = false;
      }
      if (offerRouteComplete) currentOffersSucceeded = true;

      let searchOffset = 0;
      for (let page = 0; page < config.maxCatalogItemPages; page += 1) {
        const searchAttempt = await executeMeliIdentifierAttempt({
          attemptId: `site_search_catalog_${current.id}_${mode}_${page + 1}`,
          endpoint: `/sites/${config.meliSiteId}/search`,
          params: { catalog_product_id: current.id, limit: 50, offset: searchOffset },
          auth,
          source: `site_search_catalog_${mode}`,
          catalogProductId: current.id
        }, attempts, fingerprints);

        if (!searchAttempt.ok) break;
        const searchResults = extractResults(searchAttempt.data);
        for (const raw of searchResults) {
          const offer = normalizeCatalogOffer(raw, current.id, `site_search_catalog_${mode}`);
          if (offer?.item_id) itemIds.add(offer.item_id);
          if (offer?.link) permalinks.add(offer.link);
          mergeIdentifierEvidence(evidenceStore, extractProductIdentifiers(raw, `site_search_catalog_${mode}`), {
            source: `site_search_catalog_${mode}`,
            item_id: offer?.item_id || null,
            catalog_product_id: current.id
          });
          const refs = extractReferenceValues(raw);
          for (const itemId of refs.itemIds) itemIds.add(itemId);
          for (const url of refs.permalinks) permalinks.add(url);
          for (const upId of refs.userProductIds) userProductIds.add(upId);
          if (current.depth < config.maxUpcCatalogDepth) {
            for (const catalogId of refs.catalogProductIds) {
              if (catalogId !== current.id && !visitedCatalogProductIds.has(catalogId)) {
                queue.push({ id: catalogId, depth: current.depth + 1 });
              }
            }
          }
        }
        const paging = extractPaging(searchAttempt.data, searchOffset, 50, searchResults.length);
        if (!searchResults.length || !paging.has_more || paging.next_offset <= searchOffset) break;
        searchOffset = paging.next_offset;
      }
    }

    if (!currentProductSucceeded || !currentOffersSucceeded) complete = false;
  }

  if (queue.length) complete = false;

  return {
    rootProduct,
    catalogProductIds: [...visitedCatalogProductIds],
    itemIds: [...itemIds],
    rawOffers,
    permalinks: [...permalinks],
    userProductIds: [...userProductIds],
    complete
  };
}

async function scanItemMatrix(itemIds, evidenceStore, attempts, fingerprints, payloadMap) {
  const uniqueItemIds = [...new Set(itemIds.map(normalizeItemId).filter(Boolean))];
  const limitedItemIds = uniqueItemIds.slice(0, config.maxUpcAssociatedItems);
  const accessibleItemIds = new Set();
  const forbiddenItemIds = new Set();
  const fields = "id,title,catalog_product_id,parent_item_id,user_product_id,family_id,category_id,permalink,attributes,variations,pictures";
  const profiles = [
    { id: "fields_auth", auth: true, params: { attributes: fields } },
    { id: "plain_auth", auth: true, params: {} },
    { id: "internal_auth", auth: true, params: { include_internal_attributes: true } },
    { id: "fields_public", auth: false, params: { attributes: fields } },
    { id: "plain_public", auth: false, params: {} },
    { id: "internal_public", auth: false, params: { include_internal_attributes: true } }
  ];

  for (let index = 0; index < limitedItemIds.length; index += config.upcItemBatchSize) {
    const batch = limitedItemIds.slice(index, index + config.upcItemBatchSize);

    for (const profile of profiles) {
      const attempt = await executeMeliIdentifierAttempt({
        attemptId: `items_bulk_${profile.id}_${Math.floor(index / config.upcItemBatchSize) + 1}`,
        endpoint: "/items",
        params: { ids: batch.join(","), ...profile.params },
        auth: profile.auth,
        source: `items_bulk_${profile.id}`
      }, attempts, fingerprints);

      if (!attempt.ok) {
        if (attempt.status === 403) for (const itemId of batch) forbiddenItemIds.add(itemId);
        continue;
      }

      const responses = Array.isArray(attempt.data) ? attempt.data : [attempt.data];
      for (const response of responses) {
        const innerStatus = Number(response?.code || response?.status || 200);
        const body = response?.body && typeof response.body === "object" ? response.body : response;
        const bodyItemId = normalizeItemId(firstString(body?.id, body?.item_id));
        const matchedItemId = bodyItemId || (batch.length === 1 ? batch[0] : "");
        const identifiers = innerStatus >= 200 && innerStatus < 300
          ? extractProductIdentifiers(body, `items_bulk_${profile.id}`)
          : [];
        recordIdentifierAttempt(attempts, {
          attempt_id: `${attempt.record.attempt_id}_${matchedItemId || "unknown"}_inner`,
          source: `items_bulk_${profile.id}`,
          endpoint: "/items",
          authentication: profile.auth ? "bearer" : "public",
          parameters: summarizeAttemptParams({ ids: batch.join(","), ...profile.params }),
          item_id: matchedItemId || null,
          http_status: attempt.status,
          inner_status: innerStatus,
          duration_ms: 0,
          response_keys: body && typeof body === "object" ? Object.keys(body).slice(0, 40) : [],
          identifiers_found: identifiers.map(identifier => identifier.value),
          response_preview: innerStatus >= 400 ? safeAttemptPreview(body) : "",
          continued: true
        });
        if (!matchedItemId) continue;
        if (innerStatus >= 200 && innerStatus < 300 && body && typeof body === "object") {
          accessibleItemIds.add(matchedItemId);
          addPayloadToMap(payloadMap, matchedItemId, body, `items_bulk_${profile.id}`, attempt.record.attempt_id);
          mergeIdentifierEvidence(evidenceStore, identifiers, {
            source: `items_bulk_${profile.id}`,
            item_id: matchedItemId
          });
        } else if (innerStatus === 403) {
          forbiddenItemIds.add(matchedItemId);
        }
      }
    }
  }

  for (const itemId of limitedItemIds) {
    for (const profile of profiles) {
      const attempt = await executeMeliIdentifierAttempt({
        attemptId: `item_${itemId}_${profile.id}`,
        endpoint: `/items/${itemId}`,
        params: profile.params,
        auth: profile.auth,
        source: `item_api_${profile.id}`,
        itemId
      }, attempts, fingerprints);

      if (attempt.ok) {
        accessibleItemIds.add(itemId);
        addPayloadToMap(payloadMap, itemId, attempt.data, `item_api_${profile.id}`, attempt.record.attempt_id);
        mergeIdentifierEvidence(evidenceStore, attempt.identifiers, {
          source: `item_api_${profile.id}`,
          item_id: itemId
        });
      } else if (attempt.status === 403) {
        forbiddenItemIds.add(itemId);
      }
    }
  }

  return {
    requestedItemIds: limitedItemIds,
    accessibleItemIds: [...accessibleItemIds],
    forbiddenItemIds: [...forbiddenItemIds],
    truncated: limitedItemIds.length < uniqueItemIds.length
  };
}

async function scanDescriptions(itemIds, evidenceStore, attempts, fingerprints) {
  for (const itemId of itemIds) {
    for (const auth of [true, false]) {
      const mode = auth ? "auth" : "public";
      const attempt = await executeMeliIdentifierAttempt({
        attemptId: `description_${itemId}_${mode}`,
        endpoint: `/items/${itemId}/description`,
        auth,
        source: `item_description_${mode}`,
        itemId
      }, attempts, fingerprints);
      if (!attempt.ok) continue;
      const text = firstString(
        attempt.data?.plain_text,
        attempt.data?.text,
        attempt.data?.description,
        JSON.stringify(attempt.data || {})
      );
      const identifiers = extractLabeledIdentifiersFromText(text, `item_description_${mode}`);
      mergeIdentifierEvidence(evidenceStore, identifiers, {
        source: `item_description_${mode}`,
        item_id: itemId
      });
    }
  }
}

async function scanUserProducts(userProductIds, evidenceStore, attempts, fingerprints) {
  const queue = [...new Set(userProductIds.map(normalizeUserProductId).filter(Boolean))];
  const visitedUserProductIds = new Set();
  const accessibleUserProductIds = new Set();
  const visitedFamilyModes = new Set();
  const familyIds = new Set();
  const catalogProductIds = new Set();

  while (queue.length && visitedUserProductIds.size < config.maxUpcUserProducts) {
    const userProductId = queue.shift();
    if (!userProductId || visitedUserProductIds.has(userProductId)) continue;
    visitedUserProductIds.add(userProductId);

    for (const auth of [true, false]) {
      const mode = auth ? "auth" : "public";
      const attempt = await executeMeliIdentifierAttempt({
        attemptId: `user_product_${userProductId}_${mode}`,
        endpoint: `/user-products/${userProductId}`,
        auth,
        source: `user_product_api_${mode}`,
        userProductId
      }, attempts, fingerprints);
      if (!attempt.ok) continue;
      accessibleUserProductIds.add(userProductId);
      mergeIdentifierEvidence(evidenceStore, attempt.identifiers, { source: `user_product_api_${mode}` });
      const refs = extractReferenceValues(attempt.data);
      for (const catalogId of refs.catalogProductIds) catalogProductIds.add(catalogId);
      for (const linkedUserProductId of refs.userProductIds) {
        if (!visitedUserProductIds.has(linkedUserProductId)) queue.push(linkedUserProductId);
      }

      for (const familyId of refs.familyIds) {
        familyIds.add(familyId);
        const familyKey = `${familyId}:${mode}`;
        if (visitedFamilyModes.has(familyKey)) continue;
        visitedFamilyModes.add(familyKey);
        const familyAttempt = await executeMeliIdentifierAttempt({
          attemptId: `user_product_family_${familyId}_${mode}`,
          endpoint: `/sites/${config.meliSiteId}/user-products-families/${familyId}`,
          auth,
          source: `user_product_family_api_${mode}`,
          familyId
        }, attempts, fingerprints);
        if (!familyAttempt.ok) continue;
        mergeIdentifierEvidence(evidenceStore, familyAttempt.identifiers, { source: `user_product_family_api_${mode}` });
        const familyRefs = extractReferenceValues(familyAttempt.data);
        for (const familyUserProductId of familyRefs.userProductIds) {
          if (!visitedUserProductIds.has(familyUserProductId)) queue.push(familyUserProductId);
        }
        const listedIds = Array.isArray(familyAttempt.data?.user_products_ids)
          ? familyAttempt.data.user_products_ids
          : [];
        for (const listedId of listedIds) {
          const normalized = normalizeUserProductId(listedId);
          if (normalized && !visitedUserProductIds.has(normalized)) queue.push(normalized);
        }
      }
    }
  }

  return {
    userProductIds: [...visitedUserProductIds],
    accessibleUserProductIds: [...accessibleUserProductIds],
    familyIds: [...familyIds],
    catalogProductIds: [...catalogProductIds],
    truncated: queue.length > 0
  };
}

async function verifyIdentifierEvidenceExhaustive(catalogProductId, validCatalogProductIds, evidenceList, attempts, fingerprints) {
  const validCatalogIds = new Set([catalogProductId, ...validCatalogProductIds]);
  return mapWithConcurrency(evidenceList, config.productConcurrency, async evidence => {
    if (evidence.catalog_direct) {
      evidence.verified = true;
      evidence.verification_status = "catalog_direct";
      evidence.reverse_catalog_product_ids.add(catalogProductId);
      return evidence;
    }

    if (evidence.catalog_tree_direct) {
      evidence.verified = true;
      evidence.verification_status = "catalog_tree_direct";
      for (const linkedCatalogId of evidence.catalog_product_ids) {
        evidence.reverse_catalog_product_ids.add(linkedCatalogId);
      }
      return evidence;
    }

    let anySuccess = false;
    for (const auth of [true, false]) {
      const mode = auth ? "auth" : "public";
      const attempt = await executeMeliIdentifierAttempt({
        attemptId: `reverse_${evidence.value}_${mode}`,
        endpoint: "/products/search",
        params: {
          site_id: config.meliSiteId,
          product_identifier: evidence.value,
          status: "active"
        },
        auth,
        source: `reverse_product_search_${mode}`,
        catalogProductId
      }, attempts, fingerprints);
      if (!attempt.ok) continue;
      anySuccess = true;
      for (const result of extractResults(attempt.data).map(normalizeCatalogProduct).filter(Boolean)) {
        evidence.reverse_catalog_product_ids.add(result.catalog_product_id);
      }
    }

    const reverseIds = [...evidence.reverse_catalog_product_ids];
    if (reverseIds.some(reverseId => validCatalogIds.has(reverseId))) {
      evidence.verified = true;
      evidence.verification_status = reverseIds.includes(catalogProductId) ? "reverse_match" : "reverse_catalog_tree_match";
    } else if (reverseIds.length) {
      evidence.verification_status = "reverse_other_catalog";
    } else if (anySuccess) {
      evidence.verification_status = "reverse_no_match";
    } else {
      evidence.verification_status = "reverse_api_error";
    }
    return evidence;
  });
}

async function resolveUpcsByMla(entry) {
  const rowNumber = entry && typeof entry === "object" ? entry.row_number || null : null;
  const rawMla = entry && typeof entry === "object" ? entry.mla : entry;
  const input = String(rawMla || "").trim();
  const mla = normalizeMlaId(input);

  if (!mla) {
    return {
      row_number: rowNumber,
      input,
      mla: null,
      title: "",
      catalog_product_id: null,
      primary_identifier: null,
      upc: null,
      upcs: [],
      gtins: [],
      candidate_upcs: [],
      candidate_gtins: [],
      identifiers: [],
      status: "invalid_mla",
      error: "MLA Catalog inválido",
      checked_at: nowIso()
    };
  }

  const evidenceStore = new Map();
  const attempts = [];
  const fingerprints = new Map();
  const payloadMap = new Map();
  const allItemIds = new Set();
  const allPermalinks = new Set();
  const allImageUrls = new Set();
  const allUserProductIds = new Set();

  const catalogScan = await scanCatalogProductMatrix(mla, evidenceStore, attempts, fingerprints);
  const catalogProduct = catalogScan.rootProduct;
  const allCatalogProductIds = new Set(catalogScan.catalogProductIds);
  let catalogScansComplete = catalogScan.complete;

  if (!catalogProduct) {
    const rootAttempts = attempts.filter(attempt => attempt.catalog_product_id === mla && attempt.source.startsWith("catalog_product_api"));
    const rootNotFound = rootAttempts.length > 0 && rootAttempts.every(attempt => attempt.http_status === 404);
    return {
      row_number: rowNumber,
      input,
      mla,
      title: "",
      catalog_product_id: mla,
      primary_identifier: null,
      upc: null,
      upcs: [],
      gtins: [],
      candidate_upcs: [],
      candidate_gtins: [],
      identifiers: [],
      status: rootNotFound ? "item_not_found" : "partial_scan",
      error: rootNotFound ? "El producto MLA Catalog no existe o no está disponible" : "No fue posible consultar el producto de catálogo por ninguna ruta",
      attempt_summary: buildAttemptSummary(attempts),
      attempts: attempts.slice(0, 200),
      attempts_truncated: attempts.length > 200,
      api_http_status: rootNotFound ? 404 : 503,
      retryable: !rootNotFound,
      requires_reauthorization: false,
      checked_at: nowIso()
    };
  }

  for (const itemId of catalogScan.itemIds) allItemIds.add(itemId);
  for (const url of catalogScan.permalinks) allPermalinks.add(url);
  for (const userProductId of catalogScan.userProductIds) allUserProductIds.add(userProductId);

  let itemScan = await scanItemMatrix([...allItemIds], evidenceStore, attempts, fingerprints, payloadMap);
  const visitedItemIds = new Set(itemScan.requestedItemIds);
  const accessibleItemIds = new Set(itemScan.accessibleItemIds);
  const forbiddenItemIds = new Set(itemScan.forbiddenItemIds);
  let relatedItemsTruncated = itemScan.truncated;

  for (let relationDepth = 0; relationDepth < 2; relationDepth += 1) {
    const relatedItemIds = new Set();
    for (const [itemId, payloads] of payloadMap.entries()) {
      for (const payload of payloads) {
        const refs = extractReferenceValues(payload.data);
        for (const parentItemId of refs.parentItemIds) {
          if (!visitedItemIds.has(parentItemId)) relatedItemIds.add(parentItemId);
        }
        for (const linkedItemId of refs.itemIds) {
          if (linkedItemId !== itemId && !visitedItemIds.has(linkedItemId)) relatedItemIds.add(linkedItemId);
        }
        for (const userProductId of refs.userProductIds) allUserProductIds.add(userProductId);
        for (const url of refs.permalinks) allPermalinks.add(url);
        for (const url of refs.imageUrls) allImageUrls.add(url);
      }
    }

    const nextRelatedItems = [...relatedItemIds].slice(0, config.maxUpcRelatedItems);
    if (!nextRelatedItems.length) break;
    if (nextRelatedItems.length < relatedItemIds.size) relatedItemsTruncated = true;
    for (const itemId of nextRelatedItems) {
      visitedItemIds.add(itemId);
      allItemIds.add(itemId);
    }
    const relatedScan = await scanItemMatrix(nextRelatedItems, evidenceStore, attempts, fingerprints, payloadMap);
    for (const itemId of relatedScan.accessibleItemIds) accessibleItemIds.add(itemId);
    for (const itemId of relatedScan.forbiddenItemIds) forbiddenItemIds.add(itemId);
    if (relatedScan.truncated) relatedItemsTruncated = true;
  }

  const referencedCatalogProductIds = new Set();
  for (const payloads of payloadMap.values()) {
    for (const payload of payloads) {
      const refs = extractReferenceValues(payload.data);
      for (const catalogId of [...refs.catalogProductIds, ...refs.childCatalogProductIds]) {
        if (!allCatalogProductIds.has(catalogId)) referencedCatalogProductIds.add(catalogId);
      }
    }
  }

  const remainingCatalogCapacity = Math.max(0, config.maxUpcCatalogProducts - allCatalogProductIds.size);
  const additionalCatalogProductIds = [...referencedCatalogProductIds].slice(0, remainingCatalogCapacity);
  if (additionalCatalogProductIds.length < referencedCatalogProductIds.size) catalogScansComplete = false;

  for (const catalogId of additionalCatalogProductIds) {
    const additionalCatalogScan = await scanCatalogProductMatrix(
      catalogId,
      evidenceStore,
      attempts,
      fingerprints,
      mla
    );
    if (!additionalCatalogScan.complete) catalogScansComplete = false;
    for (const scannedCatalogId of additionalCatalogScan.catalogProductIds) allCatalogProductIds.add(scannedCatalogId);
    for (const url of additionalCatalogScan.permalinks) allPermalinks.add(url);
    for (const userProductId of additionalCatalogScan.userProductIds) allUserProductIds.add(userProductId);
    const newItemIds = additionalCatalogScan.itemIds.filter(itemId => !visitedItemIds.has(itemId));
    for (const itemId of newItemIds) {
      visitedItemIds.add(itemId);
      allItemIds.add(itemId);
    }
    if (newItemIds.length) {
      const additionalItemScan = await scanItemMatrix(newItemIds, evidenceStore, attempts, fingerprints, payloadMap);
      for (const itemId of additionalItemScan.accessibleItemIds) accessibleItemIds.add(itemId);
      for (const itemId of additionalItemScan.forbiddenItemIds) forbiddenItemIds.add(itemId);
      if (additionalItemScan.truncated) relatedItemsTruncated = true;
    }
  }

  for (const [itemId, payloads] of payloadMap.entries()) {
    for (const payload of payloads) {
      const refs = extractReferenceValues(payload.data);
      for (const userProductId of refs.userProductIds) allUserProductIds.add(userProductId);
      for (const url of refs.permalinks) allPermalinks.add(url);
      for (const url of refs.imageUrls) allImageUrls.add(url);
      mergeIdentifierEvidence(evidenceStore, extractProductIdentifiers(payload.data, payload.source), {
        source: payload.source,
        item_id: itemId
      });
    }
  }

  const userProductScan = await scanUserProducts([...allUserProductIds], evidenceStore, attempts, fingerprints);
  await scanDescriptions([...visitedItemIds], evidenceStore, attempts, fingerprints);

  const webTargets = [{
    url: getCatalogWebUrl(mla),
    source: "catalog_public_web",
    catalogProductId: mla,
    itemId: null
  }];
  for (const url of allPermalinks) {
    webTargets.push({ url, source: "item_public_web", catalogProductId: mla, itemId: null });
  }
  const uniqueWebTargets = [...new Map(webTargets.map(target => [target.url, target])).values()]
    .slice(0, config.maxUpcWebPages);

  for (let index = 0; index < uniqueWebTargets.length; index += 1) {
    const target = uniqueWebTargets[index];
    const webAttempt = await executeWebIdentifierAttempt({
      attemptId: `public_web_${index + 1}`,
      ...target
    }, attempts, fingerprints);
    if (webAttempt.ok) {
      mergeIdentifierEvidence(evidenceStore, webAttempt.identifiers, { source: target.source });
    }
  }

  const evidence = await verifyIdentifierEvidenceExhaustive(
    mla,
    [...allCatalogProductIds],
    [...evidenceStore.values()],
    attempts,
    fingerprints
  );
  const serializedIdentifiers = evidence
    .sort((a, b) => {
      if (a.verified !== b.verified) return a.verified ? -1 : 1;
      if (a.type === "UPC" && b.type !== "UPC") return -1;
      if (a.type !== "UPC" && b.type === "UPC") return 1;
      return a.value.localeCompare(b.value);
    })
    .map(serializeIdentifierEvidence);

  const verifiedIdentifiers = serializedIdentifiers.filter(identifier => identifier.verified);
  const candidateIdentifiers = serializedIdentifiers.filter(identifier => !identifier.verified);
  const primaryIdentifier = verifiedIdentifiers.find(identifier => identifier.type === "UPC") || verifiedIdentifiers[0] || null;
  const primaryUpc = verifiedIdentifiers.find(identifier => identifier.type === "UPC") || null;
  const itemScanComplete = !relatedItemsTruncated && [...visitedItemIds].every(itemId => accessibleItemIds.has(itemId));
  const userProductScanComplete = !userProductScan.truncated && userProductScan.userProductIds.every(
    userProductId => userProductScan.accessibleUserProductIds.includes(userProductId)
  );
  const scanComplete = catalogScansComplete && itemScanComplete && userProductScanComplete;
  let status = "identifier_not_available";
  let error = "";
  let warning = "";

  if (verifiedIdentifiers.length) {
    status = "ok";
    if (!scanComplete) warning = "Se encontraron identificadores verificados, pero no se pudieron revisar todas las publicaciones asociadas";
  } else if (candidateIdentifiers.length) {
    status = "identifier_candidates";
    warning = "Se encontraron identificadores en publicaciones asociadas, pero MercadoLibre no confirmó su relación inversa con el producto de catálogo";
  } else if (!scanComplete) {
    status = "partial_scan";
    error = "No se encontraron identificadores y no fue posible revisar todas las publicaciones asociadas";
  } else {
    error = "MercadoLibre no expone un UPC, EAN o GTIN verificable en el producto de catálogo ni en sus publicaciones asociadas";
  }

  logger.info({
    catalog_product_id: mla,
    productos_catalogo_consultados: allCatalogProductIds.size,
    publicaciones_asociadas: visitedItemIds.size,
    publicaciones_consultadas: accessibleItemIds.size,
    publicaciones_con_acceso_denegado: [...forbiddenItemIds].filter(itemId => !accessibleItemIds.has(itemId)).length,
    user_products_consultados: userProductScan.userProductIds.length,
    familias_user_products_consultadas: userProductScan.familyIds.length,
    paginas_web_consultadas: uniqueWebTargets.length,
    imagenes_publicas_detectadas: allImageUrls.size,
    identificadores_verificados: verifiedIdentifiers.map(identifier => identifier.value),
    identificadores_candidatos: candidateIdentifiers.map(identifier => identifier.value),
    intentos: buildAttemptSummary(attempts),
    recorrido_completo: scanComplete,
    estado: status
  }, "Finalizó el rastreo exhaustivo de identificadores por producto de catálogo");

  return {
    row_number: rowNumber,
    input,
    mla,
    title: firstString(catalogProduct?.name, catalogProduct?.title),
    catalog_product_id: mla,
    primary_identifier: primaryIdentifier ? primaryIdentifier.value : null,
    upc: primaryUpc ? primaryUpc.value : null,
    upcs: verifiedIdentifiers.filter(identifier => identifier.type === "UPC").map(identifier => identifier.value),
    gtins: verifiedIdentifiers.map(identifier => identifier.value),
    candidate_upcs: candidateIdentifiers.filter(identifier => identifier.type === "UPC").map(identifier => identifier.value),
    candidate_gtins: candidateIdentifiers.map(identifier => identifier.value),
    identifiers: serializedIdentifiers,
    catalog_products_scanned: [...allCatalogProductIds],
    associated_items_found: visitedItemIds.size,
    associated_items_scanned: accessibleItemIds.size,
    access_denied_items: [...forbiddenItemIds].filter(itemId => !accessibleItemIds.has(itemId)),
    user_products_scanned: userProductScan.userProductIds,
    user_product_families_scanned: userProductScan.familyIds,
    public_web_pages_scanned: uniqueWebTargets.length,
    public_images_detected: allImageUrls.size,
    attempt_summary: buildAttemptSummary(attempts),
    attempts: attempts.slice(0, 200),
    attempts_truncated: attempts.length > 200,
    scan_complete: scanComplete,
    status,
    error,
    warning,
    api_http_status: 200,
    retryable: !scanComplete,
    requires_reauthorization: false,
    checked_at: nowIso()
  };
}

async function notifyN8nJobCreated(job) {
  if (!config.n8nWebhookUrl) {
    throw new Error("missing_n8n_webhook_url");
  }

  const payload = {
    job_id: job.job_id,
    job_type: job.job_type,
    sheet_url: job.sheet_url,
    sheet_name: job.sheet_name,
    email: job.email || "",
    created_at: job.created_at
  };

  const response = await http.post(config.n8nWebhookUrl, payload, {
    headers: {
      "Content-Type": "application/json",
      "X-App-Secret": config.n8nSharedSecret
    }
  });

  if (response.status >= 400) {
    throw new Error(`n8n_webhook_error_${response.status}`);
  }

  return response.data;
}

function countBatchResults(results) {
  const summary = {
    processed: results.length,
    ok: 0,
    full_ok: 0,
    partial_ok: 0,
    catalog_only: 0,
    product_not_found: 0,
    offers_not_found: 0,
    invalid_ean: 0,
    api_errors: 0,
    other_errors: 0
  };

  for (const result of results) {
    if (result.status === "ok") {
      summary.ok += 1;
      summary.full_ok += 1;
    } else if (result.status === "partial_ok") {
      summary.ok += 1;
      summary.partial_ok += 1;
    } else if (result.status === "catalog_only") {
      summary.catalog_only += 1;
    } else if (result.status === "product_not_found") {
      summary.product_not_found += 1;
    } else if (result.status === "offers_not_found") {
      summary.offers_not_found += 1;
    } else if (result.status === "invalid_ean") {
      summary.invalid_ean += 1;
    } else if (String(result.status || "").startsWith("api_")) {
      summary.api_errors += 1;
    } else {
      summary.other_errors += 1;
    }
  }

  return summary;
}

async function mapWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const workerCount = Math.min(Math.max(1, concurrency), items.length);

  async function runWorker() {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index]);
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => runWorker()));
  return results;
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "meli-monitor-service",
    mode: "mercadolibre_api_only",
    health: "/health",
    meli_status: "/meli/status",
    oauth_start: "/auth/mercadolibre/start",
    ean_job_start: "/jobs",
    upc_job_start: "/upc-jobs",
    ean_queue: "/monitor/queue",
    upc_queue: "/lookup-upcs/queue",
    upc_lookup: "/lookup-upcs"
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "meli-monitor-service",
    mode: "mercadolibre_api_only",
    time: nowIso(),
    site_id: config.meliSiteId,
    auth_mode: config.meliAuthMode,
    credentials_configured: hasMeliCredentials(),
    access_token_present: hasMeliToken(),
    refresh_token_present: Boolean(meliTokens.refresh_token),
    token_expires_at: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null,
    token_expired: tokenExpired(),
    api_verified: apiVerificationCache.ok,
    global_selling_verified: Boolean(apiVerificationCache.global_selling_verified),
    automatic_refresh_available: Boolean(meliTokens.refresh_token),
    api_status: apiVerificationCache.status,
    api_user_id: apiVerificationCache.user_id || null,
    api_error: apiVerificationCache.error || "",
    database_ready: databaseReady,
    batch_callback_configured: Boolean(config.n8nBatchResultsWebhookUrl)
  });
});

app.get("/meli/status", async (req, res) => {
  const verification = await verifyMeliApiConnection(true);

  return res.status(verification.ok ? 200 : 503).json({
    ok: verification.ok,
    ready: verification.ok,
    mode: "mercadolibre_api_only",
    auth_mode: config.meliAuthMode,
    credentials_configured: hasMeliCredentials(),
    access_token_present: hasMeliToken(),
    refresh_token_present: Boolean(meliTokens.refresh_token),
    token_expires_at: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null,
    token_expired: tokenExpired(),
    api_verified: verification.ok,
    global_selling_verified: Boolean(verification.global_selling_verified),
    automatic_refresh_available: Boolean(meliTokens.refresh_token),
    api_status: verification.status,
    api_user_id: verification.user_id || null,
    api_error: verification.error || "",
    oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
  });
});

app.post("/meli/test-product", requireN8n, async (req, res) => {
  const parsed = testProductSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      ok: false,
      error: "invalid_payload",
      details: parsed.error.flatten()
    });
  }

  const verification = await verifyMeliApiConnection(true);

  if (!verification.ok) {
    return res.status(503).json({
      ok: false,
      error: "meli_api_not_ready",
      api_status: verification.status,
      api_error: verification.error,
      oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
    });
  }

  const result = await resolveProduct({
    row_number: 1,
    ean: parsed.data.ean,
    brand: parsed.data.brand,
    name: parsed.data.name
  });

  return res.status(["ok", "partial_ok"].includes(result.status) ? 200 : 404).json({
    ok: ["ok", "partial_ok"].includes(result.status),
    result
  });
});


app.post("/monitor/queue", requireN8n, async (req, res) => {
  try {
    const parsed = monitorSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ ok: false, error: "invalid_payload", details: parsed.error.flatten() });
    }

    const body = parsed.data;
    if (body.products.length > config.maxProductsPerRequest) {
      return res.status(400).json({ ok: false, error: "too_many_products", max: config.maxProductsPerRequest });
    }

    const batchIndex = Number(body.batch_index || 0);
    const totalBatches = Number(body.total_batches || 0);
    const totalProducts = Number(body.total_products || body.products.length);
    const queued = await enqueuePersistentBatch({
      jobId: body.job_id,
      jobType: "ean_to_mla",
      batchIndex,
      totalBatches,
      totalProducts,
      payload: { products: body.products }
    });

    setImmediate(() => runBatchWorkerCycle().catch(() => {}));

    return res.status(202).json({
      ok: true,
      accepted: true,
      duplicate: queued.duplicate,
      batch: {
        batch_id: queued.batch.batch_id,
        batch_index: Number(queued.batch.batch_index),
        total_batches: Number(queued.batch.total_batches),
        status: queued.batch.status
      },
      job: publicJob(await getPersistentJob(body.job_id))
    });
  } catch (error) {
    logger.error({ error: error.message, codigo: error.code || "queue_error" }, "No se pudo encolar una tanda EAN a MLA");
    return res.status(error.status && error.status >= 400 && error.status < 600 ? error.status : 500).json({
      ok: false,
      error: error.code || "queue_error",
      message: error.message
    });
  }
});

app.post("/lookup-upcs/queue", requireN8n, async (req, res) => {
  try {
    const parsed = upcLookupSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ ok: false, error: "invalid_payload", details: parsed.error.flatten() });
    }

    const body = parsed.data;
    if (!body.job_id) {
      return res.status(400).json({ ok: false, error: "job_id_required" });
    }

    const inputs = body.products.length
      ? body.products
      : [...new Set(body.mlas.map(value => String(value).trim()))].map((mla, index) => ({ row_number: index + 1, mla }));
    const batchIndex = Number(body.batch_index || 0);
    const totalBatches = Number(body.total_batches || 0);
    const totalProducts = Number(body.total_products || inputs.length);
    const queued = await enqueuePersistentBatch({
      jobId: body.job_id,
      jobType: "mla_to_upc",
      batchIndex,
      totalBatches,
      totalProducts,
      payload: { products: inputs }
    });

    setImmediate(() => runBatchWorkerCycle().catch(() => {}));

    return res.status(202).json({
      ok: true,
      accepted: true,
      duplicate: queued.duplicate,
      batch: {
        batch_id: queued.batch.batch_id,
        batch_index: Number(queued.batch.batch_index),
        total_batches: Number(queued.batch.total_batches),
        status: queued.batch.status
      },
      job: publicJob(await getPersistentJob(body.job_id))
    });
  } catch (error) {
    logger.error({ error: error.message, codigo: error.code || "queue_error" }, "No se pudo encolar una tanda MLA a UPC");
    return res.status(error.status && error.status >= 400 && error.status < 600 ? error.status : 500).json({
      ok: false,
      error: error.code || "queue_error",
      message: error.message
    });
  }
});

app.post("/lookup-upcs", requireWpOrN8n, async (req, res) => {
  try {
    const parsed = upcLookupSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        ok: false,
        error: "invalid_payload",
        details: parsed.error.flatten()
      });
    }

    const verification = await verifyMeliApiConnection(false);

    if (!verification.ok) {
      return res.status(503).json({
        ok: false,
        error: "meli_api_not_ready",
        api_status: verification.status,
        api_error: verification.error,
        oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
      });
    }

    const body = parsed.data;
    const inputs = body.products.length
      ? body.products
      : [...new Set(body.mlas.map(value => String(value).trim()))];
    let job = body.job_id ? await getPersistentJob(body.job_id) : null;

    if (body.job_id && !job) {
      job = createEmptyJob({
        job_id: body.job_id,
        job_type: "mla_to_upc",
        status: "processing",
        total: Number(body.total_products || inputs.length)
      });
      job.started_at = nowIso();
      jobs.set(job.job_id, job);
      await saveJob(job);
    }

    if (job) {
      job.job_type = "mla_to_upc";
      job.status = "processing";
      job.total = Number(body.total_products || job.total || inputs.length);
      job.started_at = job.started_at || nowIso();
      job.finished_at = null;
      job.error = "";
    }

    const results = await mapWithConcurrency(inputs, config.productConcurrency, resolveUpcsByMla);
    const apiErrors = results.filter(result => String(result.status || "").startsWith("api_")).length;
    const summary = {
      requested: inputs.length,
      processed: results.length,
      found: results.filter(result => result.status === "ok").length,
      without_identifier: results.filter(result => ["identifier_not_available", "identifier_candidates", "partial_scan"].includes(result.status)).length,
      with_candidates: results.filter(result => result.status === "identifier_candidates").length,
      partial_scans: results.filter(result => result.status === "partial_scan").length,
      invalid: results.filter(result => result.status === "invalid_mla").length,
      not_found: results.filter(result => result.status === "item_not_found").length,
      api_errors: apiErrors,
      errors: results.filter(result => !["ok", "identifier_not_available", "identifier_candidates", "invalid_mla", "item_not_found"].includes(result.status)).length
    };

    if (job) {
      job.processed += summary.processed;
      job.ok += summary.found;
      job.not_found += summary.not_found;
      job.no_offers += summary.without_identifier;
      job.api_errors += summary.api_errors;
      job.errors += summary.errors;
      await saveJob(job);
    }

    logger.info({
      job_id: body.job_id || null,
      indice_tanda: Number(body.batch_index || 0),
      total_tandas: Number(body.total_batches || 0),
      solicitados: summary.requested,
      procesados: summary.processed,
      identificadores_encontrados: summary.found,
      sin_identificador: summary.without_identifier,
      con_candidatos: summary.with_candidates,
      recorridos_parciales: summary.partial_scans,
      mla_invalidos: summary.invalid,
      publicaciones_no_encontradas: summary.not_found,
      errores: summary.errors
    }, "Finalizó la consulta de UPC, EAN y GTIN por MLA");

    return res.json({
      ok: true,
      job: job ? publicJob(job) : null,
      summary,
      results
    });
  } catch (error) {
    logger.error({
      codigo: error.code || "internal_error",
      estado_http: error.status || null,
      error: error.message
    }, "Falló la consulta de identificadores por MLA");

    return res.status(error.status && error.status >= 400 && error.status < 600 ? error.status : 500).json({
      ok: false,
      error: error.code || "internal_error",
      message: error.message
    });
  }
});

app.post("/jobs", requireWp, async (req, res) => {
  try {
    const parsed = jobSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        ok: false,
        error: "invalid_payload",
        details: parsed.error.flatten()
      });
    }

    const body = parsed.data;

    if (!isGoogleSheetUrl(body.sheet_url)) {
      return res.status(400).json({
        ok: false,
        error: "invalid_sheet_url"
      });
    }

    if (config.requireApiPreflight) {
      const verification = await verifyMeliApiConnection(true);

      if (!verification.ok) {
        logger.error({
          estado_api: verification.status,
          error_api: verification.error
        }, "El job fue rechazado porque la API de MercadoLibre no está disponible");

        return res.status(503).json({
          ok: false,
          error: "meli_api_not_ready",
          api_status: verification.status,
          api_error: verification.error,
          oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
        });
      }
    }

    const job = createEmptyJob({
      job_id: safeJobId(),
      job_type: "ean_to_mla",
      sheet_url: body.sheet_url,
      sheet_name: body.sheet_name || "",
      email: body.email || "",
      status: "pending"
    });

    jobs.set(job.job_id, job);
    await saveJob(job);

    try {
      await notifyN8nJobCreated(job);
      job.status = "sent_to_n8n";
      await saveJob(job);
    } catch (error) {
      job.status = "n8n_error";
      job.error = error.message;
      await saveJob(job);
      logger.error({ job_id: job.job_id, error: error.message }, "No se pudo iniciar el workflow de n8n");
      return res.status(502).json({
        ok: false,
        error: "n8n_webhook_failed",
        job: publicJob(job)
      });
    }

    logger.info({
      job_id: job.job_id,
      sheet_name: job.sheet_name
    }, "El job fue creado y enviado a n8n");

    return res.json({
      ok: true,
      job: publicJob(job)
    });
  } catch (error) {
    logger.error({ error: error.message }, "Falló la creación del job");
    return res.status(500).json({
      ok: false,
      error: "internal_error"
    });
  }
});

app.post("/upc-jobs", requireWp, async (req, res) => {
  try {
    const parsed = jobSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        ok: false,
        error: "invalid_payload",
        details: parsed.error.flatten()
      });
    }

    const body = parsed.data;

    if (!isGoogleSheetUrl(body.sheet_url)) {
      return res.status(400).json({
        ok: false,
        error: "invalid_sheet_url"
      });
    }

    if (config.requireApiPreflight) {
      const verification = await verifyMeliApiConnection(true);

      if (!verification.ok) {
        logger.error({
          estado_api: verification.status,
          error_api: verification.error
        }, "El job MLA a UPC fue rechazado porque la API de MercadoLibre no está disponible");

        return res.status(503).json({
          ok: false,
          error: "meli_api_not_ready",
          api_status: verification.status,
          api_error: verification.error,
          oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
        });
      }
    }

    const job = createEmptyJob({
      job_id: safeJobId(),
      job_type: "mla_to_upc",
      sheet_url: body.sheet_url,
      sheet_name: body.sheet_name || "",
      email: body.email || "",
      status: "pending"
    });

    jobs.set(job.job_id, job);
    await saveJob(job);

    try {
      await notifyN8nJobCreated(job);
      job.status = "sent_to_n8n";
      await saveJob(job);
    } catch (error) {
      job.status = "n8n_error";
      job.error = error.message;
      await saveJob(job);
      logger.error({ job_id: job.job_id, error: error.message }, "No se pudo iniciar el workflow MLA a UPC de n8n");
      return res.status(502).json({
        ok: false,
        error: "n8n_webhook_failed",
        job: publicJob(job)
      });
    }

    logger.info({
      job_id: job.job_id,
      job_type: job.job_type,
      sheet_name: job.sheet_name
    }, "El job MLA a UPC fue creado y enviado a n8n");

    return res.json({
      ok: true,
      job: publicJob(job)
    });
  } catch (error) {
    logger.error({ error: error.message }, "Falló la creación del job MLA a UPC");
    return res.status(500).json({
      ok: false,
      error: "internal_error"
    });
  }
});

app.get("/jobs/:jobId", requireWp, async (req, res) => {
  const job = await getPersistentJob(req.params.jobId);

  if (!job) {
    return res.status(404).json({
      ok: false,
      error: "job_not_found"
    });
  }

  return res.json({
    ok: true,
    job: publicJob(job)
  });
});

app.post("/monitor", requireN8n, async (req, res) => {
  try {
    const parsed = monitorSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        ok: false,
        error: "invalid_payload",
        details: parsed.error.flatten()
      });
    }

    const body = parsed.data;

    if (body.products.length > config.maxProductsPerRequest) {
      return res.status(400).json({
        ok: false,
        error: "too_many_products",
        max: config.maxProductsPerRequest
      });
    }

    const verification = await verifyMeliApiConnection(false);

    if (!verification.ok) {
      logger.error({
        job_id: body.job_id,
        indice_tanda: Number(body.batch_index || 0),
        estado_api: verification.status,
        error_api: verification.error
      }, "La tanda fue rechazada porque la API de MercadoLibre no está disponible");

      return res.status(503).json({
        ok: false,
        error: "meli_api_not_ready",
        api_status: verification.status,
        api_error: verification.error,
        oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
      });
    }

    let job = await getPersistentJob(body.job_id);

    if (!job) {
      job = createEmptyJob({
        job_id: body.job_id,
        status: "processing",
        total: Number(body.total_products || body.products.length)
      });
      job.started_at = nowIso();
      jobs.set(job.job_id, job);
      await saveJob(job);
    }

    job.status = "processing";
    job.total = Number(body.total_products || job.total || body.products.length);
    job.started_at = job.started_at || nowIso();
    job.finished_at = null;
    job.error = "";

    const batchIndex = Number(body.batch_index || 0);
    const totalBatches = Number(body.total_batches || 0);
    const startedAt = Date.now();

    logger.info({
      job_id: job.job_id,
      indice_tanda: batchIndex,
      total_tandas: totalBatches,
      productos_en_tanda: body.products.length,
      total_productos: job.total,
      api_verificada: true,
      api_user_id: verification.user_id || null
    }, "Comienza el procesamiento de una tanda mediante la API de MercadoLibre");

    const results = await mapWithConcurrency(body.products, config.productConcurrency, async row => {
      try {
        return await resolveProduct(row);
      } catch (error) {
        const ean = normalizeEan(row.ean);
        logger.error({
          job_id: job.job_id,
          row_number: row.row_number,
          ean,
          error: error.message
        }, "Falló inesperadamente el procesamiento de un producto");
        return resultError(row, ean, "unexpected_error", error.message);
      }
    });

    const summary = countBatchResults(results);

    job.processed += summary.processed;
    job.ok += summary.ok;
    job.not_found += summary.product_not_found;
    job.no_offers += summary.offers_not_found + summary.catalog_only;
    job.api_errors += summary.api_errors;
    job.errors += summary.catalog_only + summary.product_not_found + summary.offers_not_found + summary.invalid_ean + summary.api_errors + summary.other_errors;
    await saveJob(job);

    logger.info({
      job_id: job.job_id,
      indice_tanda: batchIndex,
      total_tandas: totalBatches,
      procesados: summary.processed,
      correctos: summary.ok,
      correctos_completos: summary.full_ok,
      correctos_parciales: summary.partial_ok,
      solo_catalogo: summary.catalog_only,
      productos_no_encontrados: summary.product_not_found,
      productos_sin_ofertas: summary.offers_not_found,
      ean_invalidos: summary.invalid_ean,
      errores_api: summary.api_errors,
      otros_errores: summary.other_errors,
      duracion_ms: Date.now() - startedAt,
      progreso_job: `${job.processed}/${job.total}`
    }, "Finalizó el procesamiento de una tanda mediante la API de MercadoLibre");

    return res.json({
      ok: true,
      job: publicJob(job),
      batch_summary: summary,
      results
    });
  } catch (error) {
    logger.error({
      codigo: error.code || "internal_error",
      estado_http: error.status || null,
      error: error.message
    }, "Falló el endpoint de monitoreo");

    return res.status(error.status && error.status >= 400 && error.status < 600 ? error.status : 500).json({
      ok: false,
      error: error.code || "internal_error",
      message: error.message
    });
  }
});

app.post("/n8n/callback", requireN8n, async (req, res) => {
  const parsed = callbackSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      ok: false,
      error: "invalid_payload",
      details: parsed.error.flatten()
    });
  }

  const body = parsed.data;
  const job = await getPersistentJob(body.job_id);

  if (!job) {
    return res.status(404).json({
      ok: false,
      error: "job_not_found"
    });
  }

  job.status = body.status;
  job.updated_rows = job.ok === 0 ? 0 : Math.min(body.updated_rows, job.ok);
  job.finished_at = nowIso();

  if (body.error) {
    job.error = body.error;
  } else if (job.status === "failed") {
    job.error = "El procesamiento finalizó con un error";
  } else {
    job.error = "";
  }

  jobs.set(job.job_id, job);
  await saveJob(job);

  logger.info({
    job_id: job.job_id,
    estado_final: job.status,
    procesados: job.processed,
    correctos: job.ok,
    no_encontrados: job.not_found,
    sin_ofertas: job.no_offers,
    errores_api: job.api_errors,
    errores: job.errors,
    filas_actualizadas: job.updated_rows
  }, "El job finalizó y n8n ejecutó el callback legacy");

  return res.json({
    ok: true,
    job: publicJob(job)
  });
});

app.get("/auth/mercadolibre/start", (req, res) => {
  if (!hasMeliCredentials()) {
    logger.error({
      client_id_configurado: Boolean(config.meliClientId),
      client_secret_configurado: Boolean(config.meliClientSecret),
      redirect_uri_configurada: Boolean(config.meliRedirectUri)
    }, "No se puede iniciar OAuth porque faltan credenciales de MercadoLibre");

    return res.status(500).json({
      ok: false,
      error: "missing_meli_credentials"
    });
  }

  const state = crypto.randomBytes(24).toString("hex");

  authStates.set(state, {
    created_at: Date.now()
  });

  const authUrl = new URL(`${getMeliAuthBase()}/authorization`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", config.meliClientId);
  authUrl.searchParams.set("redirect_uri", config.meliRedirectUri);
  authUrl.searchParams.set("state", state);

  logger.info({
    redirect_uri: config.meliRedirectUri,
    site_id: config.meliSiteId
  }, "Se inició el flujo OAuth de MercadoLibre");

  return res.redirect(authUrl.toString());
});

app.get("/auth/mercadolibre/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");

    if (!code || !state) {
      return res.status(400).send("Faltan code o state.");
    }

    const savedState = authStates.get(state);

    if (!savedState) {
      logger.warn({}, "MercadoLibre devolvió un state OAuth inválido");
      return res.status(400).send("State inválido.");
    }

    authStates.delete(state);

    if (Date.now() - savedState.created_at > 1000 * 60 * 10) {
      logger.warn({}, "MercadoLibre devolvió un state OAuth vencido");
      return res.status(400).send("State vencido.");
    }

    await exchangeMeliToken({
      grant_type: "authorization_code",
      client_id: config.meliClientId,
      client_secret: config.meliClientSecret,
      code,
      redirect_uri: config.meliRedirectUri
    });

    const verification = await verifyMeliApiConnection(true);

    if (!verification.ok) {
      return res.status(500).send(`OAuth completado, pero no se pudo validar la API: ${verification.error}`);
    }

    logger.info({
      user_id: verification.user_id || null
    }, "MercadoLibre quedó conectado y la API fue verificada");

    return res.send("MercadoLibre conectado correctamente. La API fue verificada. Ya podés cerrar esta pestaña.");
  } catch (error) {
    logger.error({
      codigo: error.code || "oauth_error",
      estado_http: error.status || null,
      error: error.message
    }, "Falló el callback OAuth de MercadoLibre");

    return res.status(500).send("Error conectando MercadoLibre. Revisá los Deploy Logs de Railway.");
  }
});

app.get("/debug/meli-token", (req, res) => {
  if (process.env.ENABLE_DEBUG_ENDPOINTS !== "true") {
    return res.status(404).json({
      ok: false,
      error: "not_found"
    });
  }

  return res.json({
    ok: true,
    mode: "mercadolibre_api_only",
    auth_mode: config.meliAuthMode,
    credentials_configured: hasMeliCredentials(),
    connected: hasMeliToken(),
    expires_at: meliTokens.expires_at || null,
    expires_at_iso: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null,
    expired: tokenExpired(),
    user_id: meliTokens.user_id || null,
    has_refresh_token: Boolean(meliTokens.refresh_token),
    api_verification: apiVerificationCache
  });
});

app.post("/debug/resolve", async (req, res) => {
  if (process.env.ENABLE_DEBUG_ENDPOINTS !== "true") {
    return res.status(404).json({
      ok: false,
      error: "not_found"
    });
  }

  try {
    const verification = await verifyMeliApiConnection(true);

    if (!verification.ok) {
      return res.status(503).json({
        ok: false,
        error: "meli_api_not_ready",
        api_status: verification.status,
        api_error: verification.error
      });
    }

    const row = {
      row_number: Number(req.body.row_number || 1),
      ean: req.body.ean,
      brand: req.body.brand || "",
      name: req.body.name || ""
    };

    const result = await resolveProduct(row);

    return res.status(["ok", "partial_ok"].includes(result.status) ? 200 : 404).json({
      ok: ["ok", "partial_ok"].includes(result.status),
      result
    });
  } catch (error) {
    logger.error({
      codigo: error.code || "debug_error",
      estado_http: error.status || null,
      error: error.message
    }, "Falló la resolución de prueba de un producto");

    return res.status(500).json({
      ok: false,
      error: error.code || "internal_error",
      message: error.message
    });
  }
});

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "not_found"
  });
});

app.use((error, req, res, next) => {
  logger.error({ error: error.message }, "Ocurrió un error no controlado en Express");
  res.status(500).json({
    ok: false,
    error: "internal_error"
  });
});

async function startService() {
  try {
    await initializeDatabase();
    if (databaseReady) {
      await loadMeliTokensFromDatabase();
    } else {
      logger.warn({}, "DATABASE_URL no está configurada. Los endpoints legacy seguirán disponibles, pero la cola asíncrona permanecerá deshabilitada.");
    }
  } catch (error) {
    databaseReady = false;
    logger.error({ error: error.message }, "No se pudo inicializar PostgreSQL. Los endpoints legacy seguirán disponibles, pero la cola asíncrona permanecerá deshabilitada.");
  }

  app.listen(config.port, async () => {
    logger.info({
      port: config.port,
      site_id: config.meliSiteId,
      auth_mode: config.meliAuthMode,
      modo: "mercadolibre_api_only_async_jobs",
      database_ready: databaseReady,
      batch_callback_configured: Boolean(config.n8nBatchResultsWebhookUrl),
      credenciales_configuradas: hasMeliCredentials(),
      access_token_presente: hasMeliToken(),
      refresh_token_presente: Boolean(meliTokens.refresh_token),
      concurrencia: config.meliConcurrency,
      concurrencia_productos: config.productConcurrency,
      intervalo_minimo_ms: config.meliMinTimeMs,
      max_intentos_tanda: config.batchMaxAttempts,
      max_intentos_callback: config.callbackMaxAttempts || "sin_limite",
      preflight_obligatorio: config.requireApiPreflight,
      tamano_pagina_catalogo: config.catalogItemsPageSize,
      maximo_paginas_catalogo: config.maxCatalogItemPages,
      cache_resultados_exitosos: config.cacheSuccessfulResults,
      logs_muestra_catalogo: config.logCatalogSamples,
      anticipacion_renovacion_ms: config.tokenRefreshLeadMs,
      intervalo_revision_token_ms: config.tokenCheckIntervalMs
    }, "Microservicio iniciado con cola persistente de PostgreSQL");

    const verification = await verifyMeliApiConnection(true);

    if (!verification.ok) {
      logger.warn({
        estado_api: verification.status,
        error_api: verification.error,
        oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
      }, "El microservicio inició, pero la API de MercadoLibre todavía no está lista");
    }

    setInterval(() => {
      checkAndRefreshMeliToken().catch(error => {
        logger.error({ error: error.message }, "Falló la revisión programada del token de MercadoLibre");
      });
    }, config.tokenCheckIntervalMs).unref();

    setInterval(() => {
      runBatchWorkerCycle().catch(error => {
        logger.error({ error: error.message }, "Falló la ejecución programada del worker de tandas");
      });
    }, config.batchWorkerIntervalMs).unref();

    setInterval(() => {
      runCallbackWorkerCycle().catch(error => {
        logger.error({ error: error.message }, "Falló la ejecución programada del worker de callbacks");
      });
    }, config.callbackWorkerIntervalMs).unref();

    setImmediate(() => runBatchWorkerCycle().catch(() => {}));
    setImmediate(() => runCallbackWorkerCycle().catch(() => {}));
  });
}

startService().catch(error => {
  logger.fatal({ error: error.message }, "Falló el arranque del microservicio");
  process.exit(1);
});
