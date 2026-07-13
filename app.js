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
  meliClientId: process.env.MELI_CLIENT_ID || "",
  meliClientSecret: process.env.MELI_CLIENT_SECRET || "",
  meliRedirectUri: process.env.MELI_REDIRECT_URI || "",
  meliSiteId: process.env.MELI_SITE_ID || "MLA",
  allowedOrigins: (process.env.ALLOWED_ORIGINS || "").split(",").map(value => value.trim()).filter(Boolean),
  maxProductsPerRequest: Number(process.env.MAX_PRODUCTS_PER_JOB || 100),
  meliConcurrency: Number(process.env.MELI_CONCURRENCY || 2),
  meliMinTimeMs: Number(process.env.MELI_MIN_TIME_MS || 700),
  cacheTtlMs: Number(process.env.CACHE_TTL_MS || 1000 * 60 * 60 * 6),
  httpTimeoutMs: Number(process.env.HTTP_TIMEOUT_MS || 20000),
  maxApiDiagnosticLogs: Number(process.env.MAX_API_DIAGNOSTIC_LOGS || 20),
  requireApiPreflight: String(process.env.REQUIRE_API_PREFLIGHT || "true") === "true",
  enableSiteEanFallback: String(process.env.ENABLE_SITE_EAN_FALLBACK || "false") === "true",
  enableCatalogSearchFallback: String(process.env.ENABLE_CATALOG_SEARCH_FALLBACK || "false") === "true",
  catalogItemsPageSize: Math.max(1, Math.min(50, Number(process.env.MELI_CATALOG_ITEMS_PAGE_SIZE || 50))),
  maxCatalogItemPages: Math.max(1, Math.min(20, Number(process.env.MELI_MAX_CATALOG_ITEM_PAGES || 10))),
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
  status: "not_checked",
  error: ""
};
let apiDiagnosticCount = 0;
let lastTokenRefreshWarningAt = 0;

const meliLimiter = new Bottleneck({
  maxConcurrent: config.meliConcurrency,
  minTime: config.meliMinTimeMs
});

const http = axios.create({
  timeout: config.httpTimeoutMs,
  headers: {
    "User-Agent": "MeliMonitorService/3.0",
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
    error: job.error
  };
}

function createEmptyJob(data) {
  return {
    job_id: data.job_id,
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
    error: ""
  };
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

function getMeliAuthBase() {
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
    status: "token_updated",
    error: ""
  };

  logger.info({
    user_id: meliTokens.user_id || null,
    expires_at: new Date(meliTokens.expires_at).toISOString(),
    refresh_token_presente: Boolean(meliTokens.refresh_token),
    campos_respuesta: Object.keys(data).filter(key => !["access_token", "refresh_token"].includes(key))
  }, "El token OAuth de MercadoLibre fue actualizado correctamente");

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

      if (response.status === 429 && attempt <= maxRetries + 1) {
        const retryAfter = Number(response.headers["retry-after"] || 2);
        logger.warn({
          operacion: operation,
          endpoint: path,
          estado_http: response.status,
          espera_segundos: retryAfter,
          intento: attempt
        }, "La API de MercadoLibre aplicó un límite de solicitudes");
        await sleep(Math.max(1, retryAfter) * 1000);
        if (attempt <= maxRetries + 1) continue;
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

    apiVerificationCache = {
      checked_at: Date.now(),
      ok: true,
      user_id: userId,
      status: "connected",
      error: ""
    };

    logger.info({
      user_id: userId || null,
      sitio: config.meliSiteId
    }, "La conexión con la API de MercadoLibre fue validada correctamente");

    return apiVerificationCache;
  } catch (error) {
    apiVerificationCache = {
      checked_at: Date.now(),
      ok: false,
      user_id: meliTokens.user_id || "",
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
  const status = data.sold === null || data.sold === undefined ? "partial_ok" : "ok";
  return {
    row_number: row.row_number,
    ean,
    catalog_product_id: data.catalog_product_id || null,
    item_id: data.item_id || null,
    min_price: data.min_price === undefined ? null : data.min_price,
    link: data.link || data.item_id || null,
    mla: data.item_id || null,
    sold: data.sold === undefined ? null : data.sold,
    sold_source: data.sold_source || "not_available",
    sold_start_time: data.sold_start_time || null,
    source: data.source || "mercadolibre_api",
    status,
    error: "",
    warning: status === "partial_ok" ? "MercadoLibre no informó la cantidad vendida para la publicación de menor precio" : "",
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

  if (config.enableSiteEanFallback) {
    const fallbackPath = `/sites/${config.meliSiteId}/search`;
    try {
      const data = await meliRequest(fallbackPath, {
        params: {
          q: ean,
          limit: config.catalogItemsPageSize
        },
        operation: "buscar_publicaciones_publicas_por_ean",
        maxRetries: 1,
        auth: false
      });

      const rawResults = extractResults(data);
      const results = rawResults
        .map(raw => ({
          catalog_product_id: normalizeCatalogId(raw.catalog_product_id),
          title: firstString(raw.title, raw.name),
          raw
        }))
        .filter(result => result.catalog_product_id);

      logger.info({
        ean,
        endpoint: fallbackPath,
        resultados_publicos: rawResults.length,
        productos_catalogo_encontrados: results.length
      }, "Finalizó la búsqueda pública alternativa por UPC/EAN");

      if (results.length) {
        return {
          results,
          endpoint: fallbackPath,
          operation: "buscar_publicaciones_publicas_por_ean",
          errors
        };
      }
    } catch (error) {
      errors.push(error);
      logger.warn({
        ean,
        endpoint: fallbackPath,
        codigo: error.code || "api_error",
        estado_http: error.status || null
      }, "Falló la búsqueda pública alternativa por UPC/EAN");
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

async function fetchCatalogSearchOffers(catalogProductId) {
  if (!config.enableCatalogSearchFallback) {
    return { offers: [], endpoint: null, errors: [], pages_read: 0 };
  }

  const path = `/sites/${config.meliSiteId}/search`;
  const offers = [];
  const errors = [];
  const seenItemIds = new Set();
  let offset = 0;
  let pagesRead = 0;

  for (let page = 0; page < config.maxCatalogItemPages; page += 1) {
    try {
      const data = await meliRequest(path, {
        params: {
          catalog_product_id: catalogProductId,
          limit: config.catalogItemsPageSize,
          offset
        },
        operation: "buscar_publicaciones_publicas_por_producto_catalogo",
        maxRetries: 1,
        auth: false
      });

      const pageRaw = extractResults(data);
      const pageOffers = pageRaw
        .map(raw => normalizeCatalogOffer(raw, catalogProductId, "public_catalog_search_api"))
        .filter(Boolean);

      for (const offer of pageOffers) {
        if (seenItemIds.has(offer.item_id)) continue;
        seenItemIds.add(offer.item_id);
        offers.push(offer);
      }

      const paging = extractPaging(data, offset, config.catalogItemsPageSize, pageRaw.length);
      pagesRead += 1;

      logger.info({
        catalog_product_id: catalogProductId,
        endpoint: path,
        pagina: page + 1,
        offset,
        recibidos: pageRaw.length,
        normalizados: pageOffers.length,
        total_acumulado: offers.length,
        paging
      }, "Se obtuvo una página de la búsqueda pública por producto de catálogo");

      if (pageRaw.length === 0 || !paging.has_more || paging.next_offset <= offset) break;
      offset = paging.next_offset;
    } catch (error) {
      errors.push(error);
      logger.warn({
        catalog_product_id: catalogProductId,
        endpoint: path,
        pagina: page + 1,
        offset,
        codigo: error.code || "api_error",
        estado_http: error.status || null
      }, "Falló la búsqueda pública por producto de catálogo");
      break;
    }
  }

  return { offers, endpoint: path, errors, pages_read: pagesRead };
}


async function fetchSelectedItemSold(catalogProductId, selectedItemId) {
  const path = `/items/${selectedItemId}`;
  const params = {
    attributes: "id,sold_quantity,start_time"
  };

  const parseResponse = (data, authenticated) => {
    const sold = normalizeSold(firstPath(data, ["sold_quantity", "soldQuantity", "sold"]));
    const startTime = firstString(data?.start_time, data?.startTime) || null;

    logger.info({
      catalog_product_id: catalogProductId,
      selected_item_id: selectedItemId,
      endpoint: path,
      requested_attributes: params.attributes,
      authenticated,
      http_status: 200,
      sold_quantity: sold,
      start_time: startTime,
      response_keys: data && typeof data === "object" ? Object.keys(data).slice(0, 20) : []
    }, "Consulta mínima de sold_quantity para la publicación seleccionada");

    return {
      sold,
      sold_source: sold !== null
        ? authenticated ? "item_minimal_attributes_authenticated" : "item_minimal_attributes_public"
        : "not_available",
      start_time: startTime,
      endpoint: path,
      http_status: 200,
      authenticated
    };
  };

  let publicError = null;

  try {
    const data = await meliRequest(path, {
      params,
      operation: "obtener_sold_quantity_minimo_publico",
      maxRetries: 1,
      auth: false
    });

    return parseResponse(data, false);
  } catch (error) {
    publicError = error;

    logger.warn({
      catalog_product_id: catalogProductId,
      selected_item_id: selectedItemId,
      endpoint: path,
      requested_attributes: params.attributes,
      authenticated: false,
      http_status: error.status || null,
      code: error.code || "api_error",
      retryable: Boolean(error.retryable)
    }, "La consulta pública mínima de sold_quantity no pudo completarse");
  }

  const shouldTryAuthenticated = [401, 403].includes(Number(publicError?.status || 0)) || [
    "api_unauthorized",
    "api_forbidden",
    "api_not_authenticated",
    "api_reauthorization_required"
  ].includes(publicError?.code);

  if (shouldTryAuthenticated && hasMeliToken()) {
    try {
      const data = await meliRequest(path, {
        params,
        operation: "obtener_sold_quantity_minimo_autenticado",
        maxRetries: 1,
        auth: true
      });

      return parseResponse(data, true);
    } catch (error) {
      logger.warn({
        catalog_product_id: catalogProductId,
        selected_item_id: selectedItemId,
        endpoint: path,
        requested_attributes: params.attributes,
        authenticated: true,
        http_status: error.status || null,
        code: error.code || "api_error",
        retryable: Boolean(error.retryable)
      }, "La consulta autenticada mínima de sold_quantity no pudo completarse");

      return {
        sold: null,
        sold_source: error.status === 403 ? "item_endpoint_forbidden" : "not_available",
        start_time: null,
        endpoint: path,
        http_status: error.status || null,
        authenticated: true
      };
    }
  }

  return {
    sold: null,
    sold_source: publicError?.status === 403 ? "item_endpoint_forbidden" : "not_available",
    start_time: null,
    endpoint: path,
    http_status: publicError?.status || null,
    authenticated: false
  };
}

function mergeOffers(...lists) {
  const byItemId = new Map();

  for (const list of lists) {
    for (const offer of list || []) {
      if (!offer || !offer.item_id) continue;
      const existing = byItemId.get(offer.item_id);
      if (!existing) {
        byItemId.set(offer.item_id, offer);
        continue;
      }

      byItemId.set(offer.item_id, {
        ...existing,
        price: existing.price !== null ? existing.price : offer.price,
        currency_id: existing.currency_id || offer.currency_id,
        status: existing.status || offer.status,
        link: existing.link || offer.link,
        sold: existing.sold !== null ? existing.sold : offer.sold,
        sold_source: existing.sold !== null ? existing.sold_source : offer.sold_source,
        source: `${existing.source}+${offer.source}`,
        raw: existing.raw
      });
    }
  }

  return [...byItemId.values()];
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

  const cacheKey = `api-v4-sold-diagnostic:${config.meliSiteId}:ean:${ean}`;
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
  let fallbackResult = { offers: [], endpoint: null, errors: [], pages_read: 0 };
  let offers = catalogResult.offers;
  let offersEndpoint = catalogResult.endpoint;

  if (!pickBestOffer(offers) && config.enableCatalogSearchFallback) {
    fallbackResult = await fetchCatalogSearchOffers(catalogProductId);
    accumulatedErrors.push(...fallbackResult.errors);
    offers = mergeOffers(catalogResult.offers, fallbackResult.offers);
    if (fallbackResult.offers.length) offersEndpoint = fallbackResult.endpoint;
  }

  const best = pickBestOffer(offers);
  const itemCandidates = offers.filter(offer => offer.item_id);
  const firstItem = itemCandidates[0] || null;

  logger.info({
    row_number: row.row_number,
    ean,
    catalog_product_id: catalogProductId,
    publicaciones_catalogo: catalogResult.offers.length,
    publicaciones_fallback: fallbackResult.offers.length,
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
    let soldResult = {
      sold: best.sold,
      sold_source: best.sold_source,
      start_time: null,
      endpoint: null,
      http_status: null
    };

    if (best.sold === null || best.sold === undefined) {
      soldResult = await fetchSelectedItemSold(catalogProductId, best.item_id);
    }

    const result = buildResolvedResult(row, ean, {
      catalog_product_id: catalogProductId,
      item_id: best.item_id,
      min_price: best.price,
      link: best.item_id,
      sold: soldResult.sold,
      sold_source: soldResult.sold_source,
      sold_start_time: soldResult.start_time,
      source: best.source,
      api_endpoint: offersEndpoint
    });

    logger.info({
      row_number: row.row_number,
      ean,
      catalog_product_id: catalogProductId,
      item_id: result.item_id,
      meli_price: result.min_price,
      sold: result.sold,
      sold_source: result.sold_source,
      sold_start_time: result.sold_start_time,
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

async function notifyN8nJobCreated(job) {
  if (!config.n8nWebhookUrl) {
    throw new Error("missing_n8n_webhook_url");
  }

  const payload = {
    job_id: job.job_id,
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

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "meli-monitor-service",
    mode: "mercadolibre_api_only",
    health: "/health",
    meli_status: "/meli/status",
    oauth_start: "/auth/mercadolibre/start"
  });
});

app.get("/health", async (req, res) => {
  const verification = await verifyMeliApiConnection(false);

  res.status(verification.ok ? 200 : 503).json({
    ok: verification.ok,
    service: "meli-monitor-service",
    mode: "mercadolibre_api_only",
    time: nowIso(),
    site_id: config.meliSiteId,
    credentials_configured: hasMeliCredentials(),
    access_token_present: hasMeliToken(),
    refresh_token_present: Boolean(meliTokens.refresh_token),
    token_expires_at: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null,
    token_expired: tokenExpired(),
    api_verified: verification.ok,
    automatic_refresh_available: Boolean(meliTokens.refresh_token),
    api_status: verification.status,
    api_user_id: verification.user_id || null,
    api_error: verification.error || ""
  });
});

app.get("/meli/status", async (req, res) => {
  const verification = await verifyMeliApiConnection(true);

  return res.status(verification.ok ? 200 : 503).json({
    ok: verification.ok,
    ready: verification.ok,
    mode: "mercadolibre_api_only",
    credentials_configured: hasMeliCredentials(),
    access_token_present: hasMeliToken(),
    refresh_token_present: Boolean(meliTokens.refresh_token),
    token_expires_at: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null,
    token_expired: tokenExpired(),
    api_verified: verification.ok,
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
      sheet_url: body.sheet_url,
      sheet_name: body.sheet_name || "",
      email: body.email || "",
      status: "pending"
    });

    jobs.set(job.job_id, job);

    try {
      await notifyN8nJobCreated(job);
      job.status = "sent_to_n8n";
    } catch (error) {
      job.status = "n8n_error";
      job.error = error.message;
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

app.get("/jobs/:jobId", requireWp, (req, res) => {
  const job = jobs.get(req.params.jobId);

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

    let job = jobs.get(body.job_id);

    if (!job) {
      job = createEmptyJob({
        job_id: body.job_id,
        status: "processing",
        total: Number(body.total_products || body.products.length)
      });
      job.started_at = nowIso();
      jobs.set(job.job_id, job);
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

    const results = [];

    for (const row of body.products) {
      try {
        const result = await resolveProduct(row);
        results.push(result);
      } catch (error) {
        const ean = normalizeEan(row.ean);
        results.push(resultError(row, ean, "unexpected_error", error.message));
        logger.error({
          job_id: job.job_id,
          row_number: row.row_number,
          ean,
          error: error.message
        }, "Falló inesperadamente el procesamiento de un producto");
      }
    }

    const summary = countBatchResults(results);

    job.processed += summary.processed;
    job.ok += summary.ok;
    job.not_found += summary.product_not_found;
    job.no_offers += summary.offers_not_found + summary.catalog_only;
    job.api_errors += summary.api_errors;
    job.errors += summary.catalog_only + summary.product_not_found + summary.offers_not_found + summary.invalid_ean + summary.api_errors + summary.other_errors;

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

app.post("/n8n/callback", requireN8n, (req, res) => {
  const parsed = callbackSchema.safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      ok: false,
      error: "invalid_payload",
      details: parsed.error.flatten()
    });
  }

  const body = parsed.data;
  const job = jobs.get(body.job_id);

  if (!job) {
    return res.status(404).json({
      ok: false,
      error: "job_not_found"
    });
  }

  const requestedStatus = body.status;
  job.status = requestedStatus === "completed" && job.processed > 0 && job.ok === 0 ? "failed" : requestedStatus;
  job.updated_rows = job.ok === 0 ? 0 : Math.min(body.updated_rows, job.ok);
  job.finished_at = nowIso();

  if (body.error) {
    job.error = body.error;
  } else if (job.status === "failed" && job.ok === 0) {
    job.error = "El monitoreo finalizó sin productos resueltos correctamente";
  }

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
  }, "El job finalizó y n8n ejecutó el callback");

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

app.listen(config.port, async () => {
  logger.info({
    port: config.port,
    site_id: config.meliSiteId,
    modo: "mercadolibre_api_only",
    credenciales_configuradas: hasMeliCredentials(),
    access_token_presente: hasMeliToken(),
    refresh_token_presente: Boolean(meliTokens.refresh_token),
    concurrencia: config.meliConcurrency,
    intervalo_minimo_ms: config.meliMinTimeMs,
    preflight_obligatorio: config.requireApiPreflight,
    fallback_publico_por_ean: config.enableSiteEanFallback,
    fallback_publico_por_catalogo: config.enableCatalogSearchFallback,
    tamano_pagina_catalogo: config.catalogItemsPageSize,
    maximo_paginas_catalogo: config.maxCatalogItemPages,
    cache_resultados_exitosos: config.cacheSuccessfulResults,
    logs_muestra_catalogo: config.logCatalogSamples,
    anticipacion_renovacion_ms: config.tokenRefreshLeadMs,
    intervalo_revision_token_ms: config.tokenCheckIntervalMs
  }, "Microservicio iniciado en modo exclusivo API de MercadoLibre");

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
});
