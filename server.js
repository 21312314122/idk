const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const compression = require("compression");
const dns = require("dns").promises;
const net = require("net");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(compression());
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "1h"
}));

/*
 * Small in-memory cache.
 *
 * This means repeated visits to the same page don't always
 * require a brand-new request to the target website.
 */
const pageCache = new Map();

const CACHE_TIME = 30 * 1000;
const MAX_CACHE_ITEMS = 100;

const hostSafetyCache = new Map();

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = parts;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 0
  );
}

function isPrivateIPv6(ip) {
  const value = ip.toLowerCase();

  return (
    value === "::1" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:")
  );
}

async function isSafeHost(hostname) {
  const cached = hostSafetyCache.get(hostname);

  if (cached && cached.expires > Date.now()) {
    return cached.value;
  }

  const host = hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    return false;
  }

  let safe = false;

  if (net.isIP(host) === 4) {
    safe = !isPrivateIPv4(host);
  } else if (net.isIP(host) === 6) {
    safe = !isPrivateIPv6(host);
  } else {
    try {
      const addresses = await dns.lookup(host, {
        all: true
      });

      safe = addresses.length > 0 &&
        addresses.every(address => {
          if (address.family === 4) {
            return !isPrivateIPv4(address.address);
          }

          if (address.family === 6) {
            return !isPrivateIPv6(address.address);
          }

          return false;
        });
    } catch {
      safe = false;
    }
  }

  hostSafetyCache.set(hostname, {
    value: safe,
    expires: Date.now() + 5 * 60 * 1000
  });

  return safe;
}

async function validateUrl(rawUrl) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL.");
  }

  if (
    url.protocol !== "http:" &&
    url.protocol !== "https:"
  ) {
    throw new Error("Only HTTP and HTTPS URLs are allowed.");
  }

  if (!(await isSafeHost(url.hostname))) {
    throw new Error("That host is not allowed.");
  }

  return url;
}

function proxyUrl(target) {
  return "/proxy?url=" + encodeURIComponent(target);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/*
 * Rewrite the page intelligently.
 *
 * IMPORTANT:
 *
 * Navigation:
 *   goes through our proxy.
 *
 * Images:
 *   load directly from the original website.
 *
 * CSS:
 *   loads directly from the original website.
 *
 * JavaScript:
 *   loads directly from the original website.
 *
 * This is much faster than proxying every asset.
 */
function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, {
    decodeEntities: false
  });

  $("base").remove();

  /*
   * Links.
   */
  $("a[href]").each((_, element) => {
    const href = $(element).attr("href");

    if (!href) return;

    if (
      href.startsWith("#") ||
      href.startsWith("mailto:") ||
      href.startsWith("tel:") ||
      href.startsWith("javascript:")
    ) {
      return;
    }

    try {
      const absolute = new URL(href, baseUrl).href;

      $(element).attr(
        "href",
        proxyUrl(absolute)
      );
    } catch {}
  });

  /*
   * Forms.
   */
  $("form[action]").each((_, element) => {
    const action = $(element).attr("action");

    if (!action) return;

    try {
      const absolute = new URL(action, baseUrl).href;

      $(element).attr(
        "action",
        proxyUrl(absolute)
      );
    } catch {}
  });

  /*
   * Images load directly from the original server.
   */
  $("img[src]").each((_, element) => {
    const src = $(element).attr("src");

    if (!src) return;

    try {
      const absolute = new URL(src, baseUrl).href;

      $(element).attr("src", absolute);
    } catch {}
  });

  /*
   * Scripts load directly.
   */
  $("script[src]").each((_, element) => {
    const src = $(element).attr("src");

    if (!src) return;

    try {
      const absolute = new URL(src, baseUrl).href;

      $(element).attr("src", absolute);
    } catch {}
  });

  /*
   * CSS loads directly.
   */
  $("link[href]").each((_, element) => {
    const href = $(element).attr("href");

    if (!href) return;

    try {
      const absolute = new URL(href, baseUrl).href;

      $(element).attr("href", absolute);
    } catch {}
  });

  /*
   * Video/audio.
   */
  $("video[src], audio[src], source[src]").each(
    (_, element) => {
      const src = $(element).attr("src");

      if (!src) return;

      try {
        const absolute = new URL(src, baseUrl).href;

        $(element).attr("src", absolute);
      } catch {}
    }
  );

  /*
   * Preload resources directly.
   */
  $("link[rel='preload']").each((_, element) => {
    const href = $(element).attr("href");

    if (!href) return;

    try {
      const absolute = new URL(href, baseUrl).href;

      $(element).attr("href", absolute);
    } catch {}
  });

  /*
   * Proxy toolbar.
   */
  if ($("body").length) {
    $("body").prepend(`
      <div style="
        position:sticky;
        top:0;
        z-index:999999;
        height:42px;
        display:flex;
        align-items:center;
        gap:10px;
        padding:0 14px;
        background:#111827;
        color:white;
        font-family:Arial,sans-serif;
        font-size:14px;
        box-shadow:0 1px 4px rgba(0,0,0,.25);
      ">
        <strong>Proxy</strong>

        <span style="
          opacity:.75;
          overflow:hidden;
          text-overflow:ellipsis;
          white-space:nowrap;
          max-width:70%;
        ">
          ${escapeHtml(baseUrl)}
        </span>

        <a
          href="/"
          style="
            margin-left:auto;
            color:#93c5fd;
            text-decoration:none;
          "
        >
          Home
        </a>
      </div>
    `);
  }

  return $.html();
}

/*
 * Homepage.
 */
app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/*
 * Main proxy.
 */
app.get("/proxy", async (req, res) => {
  try {
    const requestedUrl = req.query.url;

    if (
      !requestedUrl ||
      typeof requestedUrl !== "string"
    ) {
      return res.status(400).send("Missing URL.");
    }

    const target = await validateUrl(requestedUrl);

    const cacheKey = target.href;

    /*
     * Check page cache.
     */
    const cached = pageCache.get(cacheKey);

    if (
      cached &&
      cached.expires > Date.now()
    ) {
      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=15"
      );

      return res.send(cached.html);
    }

    /*
     * Fetch target.
     */
    const response = await axios.get(
      target.href,
      {
        proxy: false,
        responseType: "text",

        timeout: 10000,

        maxRedirects: 5,

        headers: {
          "User-Agent":
            "Mozilla/5.0 (compatible; FastWebProxy/2.0)",
          "Accept":
            "text/html,application/xhtml+xml"
        },

        maxContentLength:
          8 * 1024 * 1024,

        maxBodyLength:
          8 * 1024 * 1024,

        validateStatus: status =>
          status >= 200 &&
          status < 400
      }
    );

    const contentType =
      response.headers["content-type"] || "";

    /*
     * HTML.
     */
    if (contentType.includes("text/html")) {
      const rewritten = rewriteHtml(
        response.data,
        target.href
      );

      /*
       * Keep cache small.
       */
      if (pageCache.size >= MAX_CACHE_ITEMS) {
        const firstKey =
          pageCache.keys().next().value;

        pageCache.delete(firstKey);
      }

      pageCache.set(cacheKey, {
        html: rewritten,
        expires:
          Date.now() + CACHE_TIME
      });

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=15"
      );

      return res.send(rewritten);
    }

    /*
     * Other content.
     */
    res.setHeader(
      "Content-Type",
      contentType || "application/octet-stream"
    );

    res.setHeader(
      "Cache-Control",
      "public, max-age=3600"
    );

    return res.send(response.data);

  } catch (error) {
    console.error(error);

    const message =
      error.message ||
      "Unable to retrieve that website.";

    res.status(500).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <title>Proxy Error</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background:#0f172a;
              color:white;
              padding:40px;
            }

            .box {
              max-width:700px;
              margin:auto;
              background:#1e293b;
              padding:25px;
              border-radius:14px;
            }

            a {
              color:#60a5fa;
            }
          </style>
        </head>

        <body>
          <div class="box">
            <h1>Proxy Error</h1>

            <p>
              ${escapeHtml(message)}
            </p>

            <a href="/">
              Back to proxy
            </a>
          </div>
        </body>
      </html>
    `);
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Fast proxy running on port ${PORT}`
  );
});
