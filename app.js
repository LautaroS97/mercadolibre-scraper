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
  maxApiDiagnosticLogs: Number(process.env.MAX_API_DIAGNOSTIC_LOGS || 10),
  requireApiPreflight: String(process.env.REQUIRE_API_PREFLIGHT || "true") === "true",
  enableNameFallback: String(process.env.ENABLE_NAME_FALLBACK || "true") === "true",
  maxSearchResults: Number(process.env.MELI_MAX_SEARCH_RESULTS || 50)
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

const meliLimiter = new Bottleneck({
  maxConcurrent: config.meliConcurrency,
  minTime: config.meliMinTimeMs
});

const http = axios.create({
  timeout: config.httpTimeoutMs,
  headers: {
    "User-Agent": "MeliMonitorService/2.0",
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
  return Date.now() > meliTokens.expires_at - 1000 * 60 * 5;
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
    refresh_token_presente: Boolean(meliTokens.refresh_token)
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

function parsePrice(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const clean = String(value)
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

function resultError(row, ean, status, error, details = {}) {
  return {
    row_number: row.row_number,
    ean,
    catalog_product_id: details.catalog_product_id || null,
    item_id: details.item_id || null,
    min_price: null,
    link: null,
    sold: null,
    sold_source: "not_available",
    source: "mercadolibre_api",
    status,
    error: error ? String(error).slice(0, 500) : "",
    api_http_status: details.api_http_status || null,
    api_endpoint: details.api_endpoint || null,
    retryable: Boolean(details.retryable),
    requires_reauthorization: Boolean(details.requires_reauthorization),
    checked_at: nowIso()
  };
}

function buildOkResult(row, ean, data) {
  return {
    row_number: row.row_number,
    ean,
    catalog_product_id: data.catalog_product_id || null,
    item_id: data.item_id || null,
    min_price: data.min_price === undefined ? null : data.min_price,
    link: data.link || null,
    sold: data.sold === undefined ? null : data.sold,
    sold_source: data.sold_source || "not_available",
    source: data.source || "mercadolibre_api",
    status: "ok",
    error: "",
    api_http_status: 200,
    api_endpoint: data.api_endpoint || null,
    retryable: false,
    requires_reauthorization: false,
    checked_at: nowIso()
  };
}

function normalizeSearchItem(raw) {
  if (!raw || typeof raw !== "object") return null;

  const itemId = normalizeItemId(firstString(raw.id, raw.item_id, raw.itemId));
  const catalogProductId = normalizeCatalogId(firstString(raw.catalog_product_id, raw.catalogProductId, raw.product_id));
  const price = parsePrice(raw.price ?? raw.amount ?? raw.current_price);
  const link = firstString(raw.permalink, raw.link, raw.url);
  const sold = typeof raw.sold_quantity === "number" ? raw.sold_quantity : null;
  const title = firstString(raw.title, raw.name);

  if (!itemId && !catalogProductId && price === null && !link) return null;

  return {
    item_id: itemId || null,
    catalog_product_id: catalogProductId || null,
    price,
    link: link || null,
    sold,
    sold_source: sold !== null ? "api_reference" : "not_available",
    title,
    raw
  };
}

async function searchApi(path, params, operation) {
  const data = await meliRequest(path, {
    params,
    operation,
    maxRetries: 1
  });
  return extractResults(data).map(normalizeSearchItem).filter(Boolean);
}

async function searchProductsByEan(ean) {
  const attempts = [
    {
      path: "/products/search",
      operation: "buscar_producto_por_identificador",
      params: {
        site_id: config.meliSiteId,
        product_identifier: ean,
        status: "active"
      }
    },
    {
      path: "/marketplace/products/search",
      operation: "buscar_producto_marketplace_por_identificador",
      params: {
        site_id: config.meliSiteId,
        product_identifier: ean,
        status: "active"
      }
    },
    {
      path: `/sites/${config.meliSiteId}/search`,
      operation: "buscar_publicaciones_por_ean",
      params: {
        q: ean,
        limit: config.maxSearchResults
      }
    }
  ];

  const errors = [];

  for (const attempt of attempts) {
    try {
      const results = await searchApi(attempt.path, attempt.params, attempt.operation);

      logger.debug({
        ean,
        operacion: attempt.operation,
        endpoint: attempt.path,
        cantidad_resultados: results.length
      }, "Finalizó un intento de búsqueda del producto mediante la API");

      if (results.length) {
        return {
          results,
          endpoint: attempt.path,
          operation: attempt.operation,
          errors
        };
      }
    } catch (error) {
      errors.push(error);
      logger.warn({
        ean,
        operacion: attempt.operation,
        endpoint: attempt.path,
        codigo: error.code || "api_error",
        estado_http: error.status || null,
        reintentable: Boolean(error.retryable),
        requiere_reautorizacion: Boolean(error.requires_reauthorization)
      }, "Falló un método de búsqueda del producto mediante la API");

      if (error.code === "api_unauthorized" || error.code === "api_not_authenticated" || error.code === "api_reauthorization_required") {
        throw error;
      }
    }
  }

  return {
    results: [],
    endpoint: null,
    operation: null,
    errors
  };
}

async function searchProductsByName(row) {
  if (!config.enableNameFallback) return { results: [], endpoint: null, operation: null, errors: [] };

  const query = `${row.brand || ""} ${row.name || ""}`.replace(/\s+/g, " ").trim();
  if (query.length < 3) return { results: [], endpoint: null, operation: null, errors: [] };

  const path = `/sites/${config.meliSiteId}/search`;

  try {
    const results = await searchApi(path, {
      q: query,
      limit: config.maxSearchResults
    }, "buscar_publicaciones_por_nombre");

    logger.debug({
      row_number: row.row_number,
      consulta: query.slice(0, 200),
      cantidad_resultados: results.length
    }, "Finalizó la búsqueda alternativa por marca y nombre");

    return {
      results,
      endpoint: path,
      operation: "buscar_publicaciones_por_nombre",
      errors: []
    };
  } catch (error) {
    logger.warn({
      row_number: row.row_number,
      codigo: error.code || "api_error",
      estado_http: error.status || null
    }, "Falló la búsqueda alternativa por marca y nombre");

    return {
      results: [],
      endpoint: path,
      operation: "buscar_publicaciones_por_nombre",
      errors: [error]
    };
  }
}

async function getItemDetail(itemId) {
  if (!itemId) return null;

  try {
    const item = await meliRequest(`/items/${itemId}`, {
      params: { include_attributes: "all" },
      operation: "obtener_detalle_publicacion",
      maxRetries: 1
    });

    return {
      item_id: normalizeItemId(item.id || itemId) || itemId,
      catalog_product_id: normalizeCatalogId(item.catalog_product_id) || null,
      price: parsePrice(item.price),
      link: firstString(item.permalink),
      sold: typeof item.sold_quantity === "number" ? item.sold_quantity : null,
      sold_source: typeof item.sold_quantity === "number" ? "api_reference" : "not_available",
      source: "api_item_detail"
    };
  } catch (error) {
    logger.warn({
      item_id: itemId,
      codigo: error.code || "api_error",
      estado_http: error.status || null
    }, "No se pudo obtener el detalle de una publicación");
    return null;
  }
}

async function findOffersByCatalogApi(catalogProductId) {
  if (!catalogProductId) return { offers: [], errors: [] };

  const attempts = [
    {
      path: `/products/${catalogProductId}/items`,
      operation: "buscar_ofertas_por_producto_catalogo",
      params: { limit: config.maxSearchResults }
    },
    {
      path: `/sites/${config.meliSiteId}/search`,
      operation: "buscar_publicaciones_por_catalog_product_id",
      params: {
        catalog_product_id: catalogProductId,
        limit: config.maxSearchResults
      }
    }
  ];

  const errors = [];

  for (const attempt of attempts) {
    try {
      const results = await searchApi(attempt.path, attempt.params, attempt.operation);
      if (results.length) {
        return {
          offers: results,
          endpoint: attempt.path,
          errors
        };
      }
    } catch (error) {
      errors.push(error);
      logger.warn({
        catalog_product_id: catalogProductId,
        operacion: attempt.operation,
        endpoint: attempt.path,
        codigo: error.code || "api_error",
        estado_http: error.status || null
      }, "Falló un método de búsqueda de ofertas mediante la API");

      if (error.code === "api_unauthorized" || error.code === "api_not_authenticated" || error.code === "api_reauthorization_required") {
        throw error;
      }
    }
  }

  return { offers: [], endpoint: null, errors };
}

async function enrichOffers(offers) {
  const enriched = [];

  for (const offer of offers) {
    if (offer.item_id) {
      const detail = await getItemDetail(offer.item_id);
      enriched.push({
        item_id: offer.item_id,
        catalog_product_id: offer.catalog_product_id || detail?.catalog_product_id || null,
        price: detail && detail.price !== null ? detail.price : offer.price,
        link: detail && detail.link ? detail.link : offer.link,
        sold: detail && detail.sold !== null ? detail.sold : offer.sold,
        sold_source: detail && detail.sold !== null ? detail.sold_source : offer.sold_source,
        source: detail ? "api_item_detail" : "api_search"
      });
    } else {
      enriched.push({
        item_id: null,
        catalog_product_id: offer.catalog_product_id || null,
        price: offer.price,
        link: offer.link,
        sold: offer.sold,
        sold_source: offer.sold_source,
        source: "api_search"
      });
    }
  }

  return enriched;
}

function pickBestOffer(offers) {
  return offers
    .filter(offer => offer && offer.price !== null && offer.price !== undefined && offer.link)
    .sort((a, b) => Number(a.price) - Number(b.price))[0] || null;
}

function firstCriticalApiError(errors) {
  const list = (errors || []).filter(Boolean);
  return list.find(error => [
    "api_unauthorized",
    "api_not_authenticated",
    "api_reauthorization_required",
    "api_forbidden",
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

  const cacheKey = `api:${config.meliSiteId}:ean:${ean}`;
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

  let eanSearch;

  try {
    eanSearch = await searchProductsByEan(ean);
  } catch (error) {
    return resultError(row, ean, error.code || "api_error", error.message, {
      api_http_status: error.status,
      api_endpoint: error.endpoint,
      retryable: error.retryable,
      requires_reauthorization: error.requires_reauthorization
    });
  }

  let candidates = eanSearch.results;
  let sourceEndpoint = eanSearch.endpoint;
  let lookupSource = "api_ean_search";
  const accumulatedErrors = [...eanSearch.errors];

  if (!candidates.length) {
    const nameSearch = await searchProductsByName(row);
    accumulatedErrors.push(...nameSearch.errors);
    candidates = nameSearch.results;
    sourceEndpoint = nameSearch.endpoint;
    lookupSource = "api_name_search";
  }

  if (!candidates.length) {
    const critical = firstCriticalApiError(accumulatedErrors);

    if (critical) {
      logApiDiagnostic({
        row_number: row.row_number,
        ean,
        codigo: critical.code,
        estado_http: critical.status || null,
        endpoint: critical.endpoint || null,
        reintentable: Boolean(critical.retryable)
      }, "La búsqueda del producto no pudo completarse por un error de la API");

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
      nombre: String(row.name || "").slice(0, 200),
      busqueda_por_nombre_habilitada: config.enableNameFallback
    }, "La API no encontró coincidencias para el producto");

    return resultError(row, ean, "product_not_found", "La API de MercadoLibre no encontró coincidencias para el producto", {
      api_endpoint: sourceEndpoint
    });
  }

  const catalogProductId = candidates.map(candidate => candidate.catalog_product_id).find(Boolean) || null;
  let offers = candidates;
  let offersEndpoint = sourceEndpoint;

  if (catalogProductId) {
    try {
      const catalogOffers = await findOffersByCatalogApi(catalogProductId);
      accumulatedErrors.push(...catalogOffers.errors);
      if (catalogOffers.offers.length) {
        offers = catalogOffers.offers;
        offersEndpoint = catalogOffers.endpoint;
        lookupSource = "api_catalog_offers";
      }
    } catch (error) {
      return resultError(row, ean, error.code || "api_error", error.message, {
        catalog_product_id: catalogProductId,
        api_http_status: error.status,
        api_endpoint: error.endpoint,
        retryable: error.retryable,
        requires_reauthorization: error.requires_reauthorization
      });
    }
  }

  const enrichedOffers = await enrichOffers(offers.slice(0, config.maxSearchResults));
  const best = pickBestOffer(enrichedOffers);

  if (!best) {
    const critical = firstCriticalApiError(accumulatedErrors);

    if (critical) {
      return resultError(row, ean, critical.code || "api_error", critical.message, {
        catalog_product_id: catalogProductId,
        api_http_status: critical.status,
        api_endpoint: critical.endpoint,
        retryable: critical.retryable,
        requires_reauthorization: critical.requires_reauthorization
      });
    }

    logApiDiagnostic({
      row_number: row.row_number,
      ean,
      catalog_product_id: catalogProductId,
      candidatos_encontrados: candidates.length,
      ofertas_evaluadas: enrichedOffers.length
    }, "La API encontró el producto, pero no devolvió una oferta válida con precio y enlace");

    return resultError(row, ean, "offers_not_found", "La API encontró coincidencias, pero no una oferta válida con precio y enlace", {
      catalog_product_id: catalogProductId,
      api_endpoint: offersEndpoint
    });
  }

  const result = buildOkResult(row, ean, {
    catalog_product_id: best.catalog_product_id || catalogProductId,
    item_id: best.item_id || null,
    min_price: best.price,
    link: best.link,
    sold: best.sold,
    sold_source: best.sold_source,
    source: best.source || lookupSource,
    api_endpoint: offersEndpoint || sourceEndpoint
  });

  cacheSet(cacheKey, result);
  return result;
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
    product_not_found: 0,
    offers_not_found: 0,
    invalid_ean: 0,
    api_errors: 0,
    other_errors: 0
  };

  for (const result of results) {
    if (result.status === "ok") summary.ok += 1;
    else if (result.status === "product_not_found") summary.product_not_found += 1;
    else if (result.status === "offers_not_found") summary.offers_not_found += 1;
    else if (result.status === "invalid_ean") summary.invalid_ean += 1;
    else if (String(result.status || "").startsWith("api_")) summary.api_errors += 1;
    else summary.other_errors += 1;
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

  return res.status(result.status === "ok" ? 200 : 404).json({
    ok: result.status === "ok",
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
    job.no_offers += summary.offers_not_found;
    job.api_errors += summary.api_errors;
    job.errors += summary.invalid_ean + summary.api_errors + summary.other_errors;

    logger.info({
      job_id: job.job_id,
      indice_tanda: batchIndex,
      total_tandas: totalBatches,
      procesados: summary.processed,
      correctos: summary.ok,
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

  job.status = body.status;
  job.updated_rows = body.updated_rows;
  job.finished_at = nowIso();

  if (body.error) {
    job.error = body.error;
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

    return res.status(result.status === "ok" ? 200 : 404).json({
      ok: result.status === "ok",
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
    busqueda_alternativa_por_nombre: config.enableNameFallback
  }, "Microservicio iniciado en modo exclusivo API de MercadoLibre");

  const verification = await verifyMeliApiConnection(true);

  if (!verification.ok) {
    logger.warn({
      estado_api: verification.status,
      error_api: verification.error,
      oauth_start_url: `${config.appBaseUrl}/auth/mercadolibre/start`
    }, "El microservicio inició, pero la API de MercadoLibre todavía no está lista");
  }
});
