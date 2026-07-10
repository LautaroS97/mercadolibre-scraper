require("dotenv").config();

const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
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
    "*.token"
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
  allowedOrigins: (process.env.ALLOWED_ORIGINS || "").split(",").map(v => v.trim()).filter(Boolean),
  enableScrapingFallback: String(process.env.ENABLE_SCRAPING_FALLBACK || "true") === "true",
  maxProductsPerJob: Number(process.env.MAX_PRODUCTS_PER_JOB || 100),
  meliConcurrency: Number(process.env.MELI_CONCURRENCY || 2),
  meliMinTimeMs: Number(process.env.MELI_MIN_TIME_MS || 700),
  cacheTtlMs: Number(process.env.CACHE_TTL_MS || 1000 * 60 * 60 * 6),
  httpTimeoutMs: Number(process.env.HTTP_TIMEOUT_MS || 20000),
  logProductDetails: String(process.env.LOG_PRODUCT_DETAILS || "false") === "true",
  logHttpDetails: String(process.env.LOG_HTTP_DETAILS || "true") === "true"
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

const meliLimiter = new Bottleneck({
  maxConcurrent: config.meliConcurrency,
  minTime: config.meliMinTimeMs
});

const http = axios.create({
  timeout: config.httpTimeoutMs,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; MeliMonitorService/1.0)",
    "Accept-Language": "es-AR,es;q=0.9,en;q=0.8"
  },
  validateStatus: status => status >= 200 && status < 500
});

app.set("trust proxy", 1);

app.use(helmet());

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (!config.allowedOrigins.length) return callback(null, true);
    if (config.allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed"));
  }
}));

app.use(express.json({ limit: "2mb" }));

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 120,
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

function nowIso() {
  return new Date().toISOString();
}

function logProduct(level, data, message) {
  const selectedLevel = config.logProductDetails ? level : "debug";
  logger[selectedLevel](data, message);
}

function summarizeResponseData(data) {
  if (data === null || data === undefined) return { type: "empty" };
  if (Array.isArray(data)) return { type: "array", length: data.length };
  if (typeof data === "string") {
    return {
      type: "string",
      length: data.length,
      preview: data.slice(0, 180).replace(/\s+/g, " ")
    };
  }
  if (typeof data === "object") {
    return {
      type: "object",
      keys: Object.keys(data).slice(0, 20)
    };
  }
  return { type: typeof data, value: String(data).slice(0, 180) };
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
    errors: job.errors,
    created_at: job.created_at,
    started_at: job.started_at,
    finished_at: job.finished_at,
    error: job.error
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

function getSiteDomain() {
  const map = {
    MLA: "com.ar",
    MLB: "com.br",
    MLM: "com.mx",
    MLC: "cl",
    MCO: "com.co",
    MPE: "com.pe",
    MLU: "com.uy"
  };
  return map[config.meliSiteId] || "com.ar";
}

function getMeliAuthUrl() {
  if (config.meliSiteId === "MLB") return "https://auth.mercadolivre.com.br";
  return "https://auth.mercadolibre.com.ar";
}

function getMeliPublicBase() {
  return `https://www.mercadolibre.${getSiteDomain()}`;
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

async function exchangeMeliToken(payload) {
  const response = await http.post("https://api.mercadolibre.com/oauth/token", new URLSearchParams(payload).toString(), {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    }
  });

  if (response.status < 200 || response.status >= 300) {
    const message = response.data && typeof response.data === "object" ? JSON.stringify(response.data) : String(response.data || "");
    throw new Error(`meli_oauth_error_${response.status}_${message}`);
  }

  const data = response.data;

  meliTokens = {
    access_token: data.access_token || "",
    refresh_token: data.refresh_token || meliTokens.refresh_token || "",
    expires_at: Date.now() + Number(data.expires_in || 10800) * 1000,
    user_id: data.user_id ? String(data.user_id) : meliTokens.user_id || ""
  };

  return meliTokens;
}

async function refreshMeliToken() {
  if (!meliTokens.refresh_token) {
    throw new Error("meli_auth_required");
  }

  if (refreshPromise) return refreshPromise;

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
    throw new Error("meli_auth_required");
  }

  if (tokenWillExpireSoon() && hasMeliCredentials()) {
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

    let headers = {
      Accept: "application/json"
    };

    if (auth) {
      const token = await ensureMeliToken();
      headers.Authorization = `Bearer ${token}`;
    }

    const makeRequest = async () => {
      return http.request({
        method,
        url: `https://api.mercadolibre.com${path}`,
        params,
        data,
        headers
      });
    };

    let response = await makeRequest();

    if (config.logHttpDetails) {
      logger.info({
        metodo: method,
        endpoint: path,
        estado_http: response.status,
        parametros: params,
        autenticado: auth,
        respuesta: summarizeResponseData(response.data)
      }, "Respuesta recibida desde la API de MercadoLibre");
    }

    if (response.status === 401 && auth && hasMeliCredentials() && meliTokens.refresh_token) {
      logger.warn({ endpoint: path }, "La API devolvió 401; se intentará renovar el token y repetir la solicitud");
      await refreshMeliToken();
      headers.Authorization = `Bearer ${meliTokens.access_token}`;
      response = await makeRequest();
      logger.info({ endpoint: path, estado_http: response.status }, "Solicitud repetida después de renovar el token");
    }

    if (response.status === 429) {
      logger.warn({ endpoint: path }, "La API devolvió 429; se esperarán 2 segundos antes de reintentar");
      await sleep(2000);
      response = await makeRequest();
      logger.info({ endpoint: path, estado_http: response.status }, "Solicitud repetida después del límite de velocidad");
    }

    if (response.status >= 400) {
      logger.error({
        endpoint: path,
        estado_http: response.status,
        respuesta: summarizeResponseData(response.data)
      }, "La API de MercadoLibre devolvió un error");
      const err = new Error(`meli_api_error_${response.status}`);
      err.status = response.status;
      err.data = response.data;
      throw err;
    }

    return response.data;
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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

function getItemIdFromUrl(url) {
  try {
    const decoded = decodeURIComponent(String(url || ""));
    const match = decoded.match(/item_id:([A-Z]{3}\d+)/i) || decoded.match(/\/(ML[A-Z]?\d{5,})/i);
    return match ? match[1].toUpperCase() : "";
  } catch {
    return "";
  }
}

function resultError(row, ean, status, error) {
  return {
    row_number: row.row_number,
    ean,
    catalog_product_id: null,
    item_id: null,
    min_price: null,
    link: null,
    sold: null,
    sold_source: "not_available",
    source: "none",
    status,
    error: error ? String(error).slice(0, 500) : "",
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
    source: data.source || "api",
    status: "ok",
    error: "",
    checked_at: nowIso()
  };
}

async function findCatalogByIdentifier(ean, row) {
  const attempts = [];

  attempts.push({ nombre: "products_search_por_identificador", ejecutar: async () => {
    const data = await meliRequest("/products/search", {
      params: {
        site_id: config.meliSiteId,
        product_identifier: ean,
        status: "active"
      }
    });
    return extractResults(data);
  }});

  attempts.push({ nombre: "marketplace_products_search_por_identificador", ejecutar: async () => {
    const data = await meliRequest("/marketplace/products/search", {
      params: {
        site_id: config.meliSiteId,
        product_identifier: ean,
        status: "active"
      }
    });
    return extractResults(data);
  }});

  attempts.push({ nombre: "sites_search_por_ean", ejecutar: async () => {
    const data = await meliRequest(`/sites/${config.meliSiteId}/search`, {
      params: {
        q: ean,
        limit: 10
      }
    });
    return extractResults(data);
  }});

  if (row.name) {
    attempts.push({ nombre: "sites_search_por_marca_y_nombre", ejecutar: async () => {
      const data = await meliRequest(`/sites/${config.meliSiteId}/search`, {
        params: {
          q: `${row.brand || ""} ${row.name || ""}`.trim(),
          limit: 10
        }
      });
      return extractResults(data);
    }});
  }

  for (const attempt of attempts) {
    try {
      logProduct("info", {
        job_id: row.job_id || null,
        fila: row.row_number,
        ean,
        intento: attempt.nombre
      }, "Comienza un intento de búsqueda por API");

      const results = await attempt.ejecutar();

      logProduct("info", {
        job_id: row.job_id || null,
        fila: row.row_number,
        ean,
        intento: attempt.nombre,
        cantidad_resultados: results.length
      }, "Finalizó un intento de búsqueda por API");

      for (const item of results) {
        const catalogId = firstString(
          item.catalog_product_id,
          item.catalogProductId,
          item.id && String(item.id).startsWith("ML") ? item.id : "",
          item.product_id
        );

        const itemId = firstString(item.id && !String(item.id).startsWith("MLA1") ? item.id : "", item.item_id);

        if (catalogId) {
          logProduct("info", {
            job_id: row.job_id || null,
            fila: row.row_number,
            ean,
            intento: attempt.nombre,
            catalog_product_id: normalizeCatalogId(catalogId),
            item_id: normalizeItemId(itemId) || null
          }, "La API encontró un producto de catálogo");
          return {
            catalog_product_id: normalizeCatalogId(catalogId),
            item_id: normalizeItemId(itemId),
            raw: item
          };
        }
      }
    } catch (error) {
      logger.warn({
        job_id: row.job_id || null,
        fila: row.row_number,
        ean,
        intento: attempt.nombre,
        error: error.message,
        estado_http: error.status || null,
        respuesta: summarizeResponseData(error.data)
      }, "Falló un intento de búsqueda por API");
    }
  }

  logProduct("warn", {
    job_id: row.job_id || null,
    fila: row.row_number,
    ean,
    intentos_realizados: attempts.map(attempt => attempt.nombre)
  }, "La API no encontró un producto de catálogo para el EAN");

  return null;
}

async function getItemDetail(itemId) {
  if (!itemId) return null;

  try {
    const item = await meliRequest(`/items/${itemId}`, {
      params: {
        include_attributes: "all"
      }
    });

    return {
      item_id: item.id || itemId,
      price: parsePrice(item.price),
      link: item.permalink || "",
      sold: typeof item.sold_quantity === "number" ? item.sold_quantity : null,
      sold_source: typeof item.sold_quantity === "number" ? "api_reference" : "not_available",
      raw: item
    };
  } catch (error) {
    logger.warn({ itemId, err: error.message }, "item_detail_failed");
    return null;
  }
}

async function findOffersByCatalogApi(catalogProductId) {
  if (!catalogProductId) return [];

  const attempts = [];

  attempts.push(async () => {
    const data = await meliRequest(`/products/${catalogProductId}/items`, {
      params: {
        limit: 50
      }
    });
    return extractResults(data);
  });

  attempts.push(async () => {
    const data = await meliRequest(`/sites/${config.meliSiteId}/search`, {
      params: {
        catalog_product_id: catalogProductId,
        limit: 50
      }
    });
    return extractResults(data);
  });

  attempts.push(async () => {
    const data = await meliRequest(`/sites/${config.meliSiteId}/search`, {
      params: {
        q: catalogProductId,
        limit: 50
      }
    });
    return extractResults(data);
  });

  let rawOffers = [];

  for (const attempt of attempts) {
    try {
      const results = await attempt();
      if (results.length) {
        rawOffers = results;
        break;
      }
    } catch (error) {
      logger.warn({ catalogProductId, err: error.message }, "offers_attempt_failed");
    }
  }

  const offers = [];

  for (const raw of rawOffers) {
    const itemId = normalizeItemId(firstString(raw.id, raw.item_id, raw.itemId));
    const price = parsePrice(raw.price || raw.amount || raw.current_price);
    const link = firstString(raw.permalink, raw.link, raw.url);
    const sold = typeof raw.sold_quantity === "number" ? raw.sold_quantity : null;

    if (itemId) {
      const detail = await getItemDetail(itemId);
      offers.push({
        item_id: itemId,
        price: detail && detail.price !== null ? detail.price : price,
        link: detail && detail.link ? detail.link : link,
        sold: detail && detail.sold !== null ? detail.sold : sold,
        sold_source: detail && detail.sold !== null ? detail.sold_source : sold !== null ? "api_reference" : "not_available",
        source: "api"
      });
    } else if (price !== null || link) {
      offers.push({
        item_id: null,
        price,
        link,
        sold,
        sold_source: sold !== null ? "api_reference" : "not_available",
        source: "api"
      });
    }
  }

  return offers.filter(o => o.price !== null && o.link);
}

function pickBestOffer(offers) {
  return offers
    .filter(o => o && o.price !== null && o.price !== undefined && o.link)
    .sort((a, b) => Number(a.price) - Number(b.price))[0] || null;
}

async function scrapeCatalogByEan(ean) {
  const base = getMeliPublicBase();
  const url = `${base}/catalogo/explorar?q=${encodeURIComponent(ean)}`;

  logger.info({ ean, url }, "Comienza la búsqueda pública del producto por EAN");

  const response = await http.get(url, {
    headers: {
      Accept: "text/html"
    }
  });

  const html = String(response.data || "");
  const contentType = response.headers && response.headers["content-type"] ? response.headers["content-type"] : "";

  logger.info({
    ean,
    url,
    estado_http: response.status,
    tipo_contenido: contentType,
    longitud_html: html.length
  }, "MercadoLibre respondió a la búsqueda pública por EAN");

  if (response.status >= 400) {
    logger.warn({ ean, url, estado_http: response.status }, "La búsqueda pública devolvió un estado HTTP de error");
    return null;
  }

  const $ = cheerio.load(response.data);
  let catalogId = "";

  $("a").each((_, el) => {
    if (catalogId) return;
    const href = $(el).attr("href") || "";
    const match = href.match(/\/p\/(ML[A-Z]?\d+)/i);
    if (match) catalogId = match[1].toUpperCase();
  });

  if (!catalogId) {
    const match = html.match(/\/p\/(ML[A-Z]?\d+)/i);
    if (match) catalogId = match[1].toUpperCase();
  }

  if (!catalogId) {
    const title = $("title").text().replace(/\s+/g, " ").trim().slice(0, 200);
    const possibleBlock = /captcha|robot|access denied|forbidden|demasiadas solicitudes|unusual traffic/i.test(`${title} ${html.slice(0, 5000)}`);

    logger.warn({
      ean,
      url,
      estado_http: response.status,
      tipo_contenido: contentType,
      longitud_html: html.length,
      titulo: title,
      posible_bloqueo: possibleBlock
    }, "La búsqueda pública respondió, pero no se encontró un identificador de catálogo en el HTML");

    return null;
  }

  logger.info({ ean, catalog_product_id: catalogId }, "La búsqueda pública encontró un producto de catálogo");

  return {
    catalog_product_id: catalogId,
    source: "html"
  };
}

async function scrapeOffersByCatalog(catalogProductId) {
  const base = getMeliPublicBase();
  const urls = [
    `${base}/p/${catalogProductId}/s`,
    `${base}/p/${catalogProductId}`
  ];

  for (const url of urls) {
    try {
      const response = await http.get(url, {
        headers: {
          Accept: "text/html"
        }
      });

      if (response.status >= 400) continue;

      const $ = cheerio.load(response.data);
      const offers = [];

      $("a").each((_, el) => {
        const href = $(el).attr("href") || "";
        const text = $(el).text().replace(/\s+/g, " ").trim();
        const itemId = getItemIdFromUrl(href);
        const priceMatch = text.match(/\$[\s]*[\d.,]+/);
        const price = priceMatch ? parsePrice(priceMatch[0]) : null;

        if (href && itemId && price !== null) {
          offers.push({
            item_id: itemId,
            price,
            link: href.startsWith("http") ? href : `${base}${href}`,
            sold: null,
            sold_source: "not_available",
            source: "html"
          });
        }
      });

      const scriptText = $("script").map((_, el) => $(el).html() || "").get().join("\n");
      const itemMatches = [...scriptText.matchAll(/MLA\d{6,}|MLB\d{6,}|MLM\d{6,}|MLC\d{6,}|MCO\d{6,}|MPE\d{6,}|MLU\d{6,}/g)];
      const priceMatches = [...scriptText.matchAll(/"price"\s*:\s*([0-9.]+)/g)];

      if (!offers.length && itemMatches.length && priceMatches.length) {
        const itemId = itemMatches[0][0];
        const price = parsePrice(priceMatches[0][1]);
        offers.push({
          item_id: itemId,
          price,
          link: `${base}/p/${catalogProductId}?pdp_filters=item_id%3A${itemId}`,
          sold: null,
          sold_source: "not_available",
          source: "html"
        });
      }

      const cleanOffers = offers.filter(o => o.price !== null && o.link);
      if (cleanOffers.length) return cleanOffers;
    } catch (error) {
      logger.warn({ catalogProductId, err: error.message }, "scrape_offers_failed");
    }
  }

  return [];
}

async function resolveProduct(row) {
  const ean = normalizeEan(row.ean);

  logProduct("info", {
    job_id: row.job_id || null,
    fila: row.row_number,
    ean,
    marca: row.brand || "",
    nombre: row.name || "",
    api_conectada: hasMeliToken(),
    fallback_scraping_habilitado: config.enableScrapingFallback
  }, "Comienza la resolución de un producto");

  if (!isValidEan(ean)) {
    logProduct("warn", { job_id: row.job_id || null, fila: row.row_number, ean }, "El EAN fue rechazado por formato inválido");
    return resultError(row, ean, "invalid_ean", "EAN inválido");
  }

  const cacheKey = `ean:${ean}`;
  const cached = cacheGet(cacheKey);

  if (cached) {
    logProduct("info", { job_id: row.job_id || null, fila: row.row_number, ean }, "Se utilizará un resultado almacenado en caché");
    return {
      ...cached,
      row_number: row.row_number,
      checked_at: nowIso(),
      source: `${cached.source || "cache"}_cache`
    };
  }

  let catalog = null;

  if (hasMeliToken()) {
    try {
      logProduct("info", { job_id: row.job_id || null, fila: row.row_number, ean }, "Se intentará buscar el catálogo mediante la API oficial");
      catalog = await findCatalogByIdentifier(ean, row);
    } catch (error) {
      logger.warn({ job_id: row.job_id || null, fila: row.row_number, ean, error: error.message }, "Falló la búsqueda de catálogo mediante la API oficial");
    }
  } else {
    logProduct("warn", { job_id: row.job_id || null, fila: row.row_number, ean }, "La búsqueda por API fue omitida porque no hay un token de MercadoLibre disponible");
  }

  if (!catalog && config.enableScrapingFallback) {
    try {
      logProduct("info", { job_id: row.job_id || null, fila: row.row_number, ean }, "Se intentará buscar el catálogo mediante scraping público");
      catalog = await scrapeCatalogByEan(ean);
    } catch (error) {
      logger.warn({ job_id: row.job_id || null, fila: row.row_number, ean, error: error.message }, "Falló la búsqueda de catálogo mediante scraping público");
    }
  } else if (!catalog) {
    logProduct("warn", { job_id: row.job_id || null, fila: row.row_number, ean }, "El scraping público está deshabilitado y la API no encontró un catálogo");
  }

  if (!catalog || !catalog.catalog_product_id) {
    logProduct("warn", {
      job_id: row.job_id || null,
      fila: row.row_number,
      ean,
      api_conectada: hasMeliToken(),
      fallback_scraping_habilitado: config.enableScrapingFallback
    }, "No se encontró un producto de catálogo después de completar todos los métodos disponibles");
    return resultError(row, ean, "not_found", "No se encontró producto de catálogo");
  }

  let offers = [];

  if (hasMeliToken()) {
    try {
      offers = await findOffersByCatalogApi(catalog.catalog_product_id);
    } catch (error) {
      logger.warn({ ean, catalogProductId: catalog.catalog_product_id, err: error.message }, "api_offers_lookup_failed");
    }
  }

  if (!offers.length && config.enableScrapingFallback) {
    try {
      offers = await scrapeOffersByCatalog(catalog.catalog_product_id);
    } catch (error) {
      logger.warn({ ean, catalogProductId: catalog.catalog_product_id, err: error.message }, "html_offers_lookup_failed");
    }
  }

  const best = pickBestOffer(offers);

  if (!best) {
    logProduct("warn", {
      job_id: row.job_id || null,
      fila: row.row_number,
      ean,
      catalog_product_id: catalog.catalog_product_id,
      cantidad_ofertas: offers.length
    }, "Se encontró el catálogo, pero no hubo ofertas válidas con precio y enlace");
    return resultError(row, ean, "no_offers", "No se encontraron ofertas con precio y link");
  }

  const result = buildOkResult(row, ean, {
    catalog_product_id: catalog.catalog_product_id,
    item_id: best.item_id || null,
    min_price: best.price,
    link: best.link,
    sold: best.sold,
    sold_source: best.sold_source,
    source: best.source || catalog.source || "api"
  });

  cacheSet(cacheKey, result);

  logProduct("info", {
    job_id: row.job_id || null,
    fila: row.row_number,
    ean,
    catalog_product_id: result.catalog_product_id,
    item_id: result.item_id,
    precio_minimo: result.min_price,
    vendidos: result.sold,
    fuente: result.source
  }, "El producto fue resuelto correctamente");

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

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "meli-monitor-service",
    health: "/health"
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "meli-monitor-service",
    time: nowIso(),
    meli_auth: hasMeliToken() ? "connected" : "not_connected",
    scraping_fallback: config.enableScrapingFallback
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

    const job = {
      job_id: safeJobId(),
      sheet_url: body.sheet_url,
      sheet_name: body.sheet_name || "",
      email: body.email || "",
      status: "pending",
      total: 0,
      processed: 0,
      ok: 0,
      errors: 0,
      created_at: nowIso(),
      started_at: null,
      finished_at: null,
      error: ""
    };

    jobs.set(job.job_id, job);

    try {
      await notifyN8nJobCreated(job);
      job.status = "sent_to_n8n";
    } catch (error) {
      job.status = "n8n_error";
      job.error = error.message;
      logger.error({ job_id: job.job_id, err: error.message }, "n8n_job_create_failed");
      return res.status(502).json({
        ok: false,
        error: "n8n_webhook_failed",
        job: publicJob(job)
      });
    }

    return res.json({
      ok: true,
      job: publicJob(job)
    });
  } catch (error) {
    logger.error({ err: error.message }, "create_job_failed");
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

    if (body.products.length > config.maxProductsPerJob) {
      return res.status(400).json({
        ok: false,
        error: "too_many_products",
        max: config.maxProductsPerJob
      });
    }

    let job = jobs.get(body.job_id);

    if (!job) {
      job = {
        job_id: body.job_id,
        sheet_url: "",
        sheet_name: "",
        email: "",
        status: "processing",
        total: body.products.length,
        processed: 0,
        ok: 0,
        errors: 0,
        created_at: nowIso(),
        started_at: nowIso(),
        finished_at: null,
        error: ""
      };

      jobs.set(job.job_id, job);
    }

    job.status = "processing";
    job.total = Number(body.total_products || job.total || body.products.length);
    job.processed = Number(job.processed || 0);
    job.ok = Number(job.ok || 0);
    job.errors = Number(job.errors || 0);
    job.started_at = job.started_at || nowIso();
    job.finished_at = null;
    job.error = "";

    logger.info({
      job_id: body.job_id,
      indice_tanda: body.batch_index || null,
      total_tandas: body.total_batches || null,
      productos_en_tanda: body.products.length,
      total_productos: body.total_products || null,
      api_conectada: hasMeliToken(),
      fallback_scraping_habilitado: config.enableScrapingFallback
    }, "Comienza el procesamiento de una tanda");

    const results = [];

    for (const row of body.products) {
      try {
        const result = await resolveProduct({ ...row, job_id: body.job_id });
        results.push(result);

        job.processed += 1;

        if (result.status === "ok") {
          job.ok += 1;
        } else {
          job.errors += 1;
        }
      } catch (error) {
        const ean = normalizeEan(row.ean);
        const result = resultError(row, ean, "unexpected_error", error.message);
        results.push(result);

        job.processed += 1;
        job.errors += 1;

        logger.error({ job_id: job.job_id, row_number: row.row_number, ean, err: error.message }, "product_failed");
      }
    }

    job.status = "processing";
    job.finished_at = null;

    const batchOk = results.filter(result => result.status === "ok").length;
    const batchNotFound = results.filter(result => result.status === "not_found").length;
    const batchNoOffers = results.filter(result => result.status === "no_offers").length;
    const batchInvalid = results.filter(result => result.status === "invalid_ean").length;
    const batchUnexpected = results.filter(result => result.status === "unexpected_error").length;

    logger.info({
      job_id: body.job_id,
      indice_tanda: body.batch_index || null,
      productos_en_tanda: body.products.length,
      correctos: batchOk,
      no_encontrados: batchNotFound,
      sin_ofertas: batchNoOffers,
      ean_invalidos: batchInvalid,
      errores_inesperados: batchUnexpected,
      progreso_total: job.processed,
      correctos_totales: job.ok,
      errores_totales: job.errors
    }, "Finalizó el procesamiento de una tanda");

    return res.json({
      ok: true,
      job: publicJob(job),
      results
    });
  } catch (error) {
    logger.error({ err: error.message }, "monitor_failed");
    return res.status(500).json({
      ok: false,
      error: "internal_error"
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
  job.finished_at = nowIso();

  logger.info({
    job_id: body.job_id,
    estado_final: body.status,
    filas_actualizadas: body.updated_rows,
    procesados: job.processed,
    correctos: job.ok,
    errores: job.errors,
    error_reportado: body.error || ""
  }, "n8n informó la finalización del job");

  if (body.error) {
    job.error = body.error;
  }

  return res.json({
    ok: true,
    job: publicJob(job)
  });
});

app.get("/auth/mercadolibre/start", (req, res) => {
  if (!hasMeliCredentials()) {
    return res.status(500).json({
      ok: false,
      error: "missing_meli_credentials"
    });
  }

  const state = crypto.randomBytes(24).toString("hex");

  authStates.set(state, {
    created_at: Date.now()
  });

  const authUrl = new URL(`${getMeliAuthUrl()}/authorization`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", config.meliClientId);
  authUrl.searchParams.set("redirect_uri", config.meliRedirectUri);
  authUrl.searchParams.set("state", state);

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
      return res.status(400).send("State inválido.");
    }

    authStates.delete(state);

    if (Date.now() - savedState.created_at > 1000 * 60 * 10) {
      return res.status(400).send("State vencido.");
    }

    await exchangeMeliToken({
      grant_type: "authorization_code",
      client_id: config.meliClientId,
      client_secret: config.meliClientSecret,
      code,
      redirect_uri: config.meliRedirectUri
    });

    return res.send("MercadoLibre conectado correctamente. Ya podés cerrar esta pestaña.");
  } catch (error) {
    logger.error({ err: error.message }, "meli_callback_failed");
    return res.status(500).send("Error conectando MercadoLibre.");
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
    connected: hasMeliToken(),
    expires_at: meliTokens.expires_at || null,
    expires_at_iso: meliTokens.expires_at ? new Date(meliTokens.expires_at).toISOString() : null,
    user_id: meliTokens.user_id || null,
    has_refresh_token: Boolean(meliTokens.refresh_token)
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
    const row = {
      row_number: Number(req.body.row_number || 1),
      ean: req.body.ean,
      brand: req.body.brand || "",
      name: req.body.name || ""
    };

    const result = await resolveProduct(row);

    return res.json({
      ok: true,
      result
    });
  } catch (error) {
    logger.error({ err: error.message }, "debug_resolve_failed");
    return res.status(500).json({
      ok: false,
      error: error.message
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
  logger.error({ err: error.message }, "unhandled_error");
  res.status(500).json({
    ok: false,
    error: "internal_error"
  });
});

app.listen(config.port, () => {
  logger.info({
    port: config.port,
    site: config.meliSiteId,
    scraping_fallback: config.enableScrapingFallback,
    api_conectada: hasMeliToken(),
    log_detalle_productos: config.logProductDetails,
    log_detalle_http: config.logHttpDetails
  }, "Microservicio de monitoreo de MercadoLibre iniciado");
});