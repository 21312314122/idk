const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const compression = require("compression");
const dns = require("dns").promises;
const net = require("net");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================
   BASIC SETUP
========================================= */

app.use(compression());

app.use(
  express.static(path.join(__dirname, "public"), {
    maxAge: "1h"
  })
);

/* =========================================
   CACHE
========================================= */

const cache = new Map();

const MAX_CACHE_ITEMS = 300;

function getCache(key) {
  const item = cache.get(key);

  if (!item) {
    return null;
  }

  if (item.expires < Date.now()) {
    cache.delete(key);
    return null;
  }

  return item;
}

function setCache(key, data, contentType, ttl) {
  if (cache.size >= MAX_CACHE_ITEMS) {
    const firstKey = cache.keys().next().value;

    if (firstKey) {
      cache.delete(firstKey);
    }
  }

  cache.set(key, {
    data,
    contentType,
    expires: Date.now() + ttl
  });
}

/* =========================================
   HOST SAFETY
========================================= */

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(Number.isNaN)
  ) {
    return true;
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
  const host = hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    return false;
  }

  if (net.isIP(host) === 4) {
    return !isPrivateIPv4(host);
  }

  if (net.isIP(host) === 6) {
    return !isPrivateIPv6(host);
  }

  try {
    const results = await dns.lookup(host, {
      all: true
    });

    if (!results.length) {
      return false;
    }

    return results.every(result => {
      if (result.family === 4) {
        return !isPrivateIPv4(result.address);
      }

      if (result.family === 6) {
        return !isPrivateIPv6(result.address);
      }

      return false;
    });
  } catch {
    return false;
  }
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
    throw new Error(
      "Only HTTP and HTTPS URLs are allowed."
    );
  }

  const safe = await isSafeHost(
    url.hostname
  );

  if (!safe) {
    throw new Error(
      "That host is not allowed."
    );
  }

  return url;
}

/* =========================================
   HELPERS
========================================= */

function proxyUrl(target) {
  return (
    "/proxy?url=" +
    encodeURIComponent(target)
  );
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* =========================================
   HTML REWRITING
========================================= */

function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, {
    decodeEntities: false
  });

  $("base").remove();

  /* Links */

  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");

    if (!href) {
      return;
    }

    if (
      href.startsWith("#") ||
      href.startsWith("mailto:") ||
      href.startsWith("tel:") ||
      href.startsWith("javascript:")
    ) {
      return;
    }

    try {
      const absolute = new URL(
        href,
        baseUrl
      ).href;

      $(el).attr(
        "href",
        proxyUrl(absolute)
      );
    } catch {}
  });

  /* Forms */

  $("form[action]").each((_, el) => {
    const action = $(el).attr("action");

    if (!action) {
      return;
    }

    try {
      const absolute = new URL(
        action,
        baseUrl
      ).href;

      $(el).attr(
        "action",
        proxyUrl(absolute)
      );
    } catch {}
  });

  /* Images */

  $("img[src]").each((_, el) => {
    const src = $(el).attr("src");

    if (!src) {
      return;
    }

    try {
      const absolute = new URL(
        src,
        baseUrl
      ).href;

      $(el).attr(
        "src",
        proxyUrl(absolute)
      );
    } catch {}
  });

  /* Scripts */

  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");

    if (!src) {
      return;
    }

    try {
      const absolute = new URL(
        src,
        baseUrl
      ).href;

      $(el).attr(
        "src",
        proxyUrl(absolute)
      );
    } catch {}
  });

  /* Stylesheets */

  $("link[href]").each((_, el) => {
    const href = $(el).attr("href");

    if (!href) {
      return;
    }

    try {
      const absolute = new URL(
        href,
        baseUrl
      ).href;

      $(el).attr(
        "href",
        proxyUrl(absolute)
      );
    } catch {}
  });

  /* Videos */

  $("video[src], source[src]").each(
    (_, el) => {
      const src = $(el).attr("src");

      if (!src) {
        return;
      }

      try {
        const absolute = new URL(
          src,
          baseUrl
        ).href;

        $(el).attr(
          "src",
          proxyUrl(absolute)
        );
      } catch {}
    }
  );

  /* srcset */

  $("[srcset]").each((_, el) => {
    const srcset =
      $(el).attr("srcset");

    if (!srcset) {
      return;
    }

    const rewritten = srcset
      .split(",")
      .map(part => {
        const pieces =
          part.trim().split(/\s+/);

        const src = pieces.shift();

        try {
          const absolute = new URL(
            src,
            baseUrl
          ).href;

          return [
            proxyUrl(absolute),
            ...pieces
          ].join(" ");
        } catch {
          return part.trim();
        }
      })
      .join(", ");

    $(el).attr(
      "srcset",
      rewritten
    );
  });

  /* Proxy toolbar */

  if ($("body").length) {
    $("body").prepend(`
      <div style="
        position:sticky;
        top:0;
        left:0;
        right:0;
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
        box-shadow:0 1px 5px rgba(0,0,0,.25);
      ">

        <strong>FastProxy</strong>

        <span style="
          overflow:hidden;
          text-overflow:ellipsis;
          white-space:nowrap;
          opacity:.8;
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

/* =========================================
   HOME
========================================= */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =========================================
   HEALTH CHECK
========================================= */

/*
 * Your frontend uses this endpoint
 * to measure which proxy server is fastest.
 */

app.get("/health", (req, res) => {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "*"
  );

  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  res.json({
    status: "ok",
    server: "FastProxy",
    timestamp: Date.now()
  });
});

/* =========================================
   PROXY
========================================= */

app.get("/proxy", async (req, res) => {
  try {
    const requestedUrl =
      req.query.url;

    if (
      !requestedUrl ||
      typeof requestedUrl !== "string"
    ) {
      return res
        .status(400)
        .send("Missing URL.");
    }

    const target =
      await validateUrl(
        requestedUrl
      );

    const cacheKey =
      target.href;

    /* Check cache */

    const cached =
      getCache(cacheKey);

    if (cached) {
      res.setHeader(
        "Content-Type",
        cached.contentType
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=60"
      );

      res.setHeader(
        "X-FastProxy-Cache",
        "HIT"
      );

      return res.send(
        cached.data
      );
    }

    /* Fetch target */

    const response =
      await axios.get(
        target.href,
        {
          proxy: false,

          responseType:
            "arraybuffer",

          timeout: 12000,

          maxRedirects: 5,

          headers: {
            "User-Agent":
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/150 Safari/537.36",

            "Accept":
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",

            "Accept-Language":
              "en-US,en;q=0.9",

            "Referer":
              target.origin + "/"
          },

          maxContentLength:
            15 * 1024 * 1024,

          maxBodyLength:
            15 * 1024 * 1024,

          validateStatus:
            status =>
              status >= 200 &&
              status < 400
        }
      );

    const contentType =
      response.headers[
        "content-type"
      ] ||
      "application/octet-stream";

    /* HTML */

    if (
      contentType.includes(
        "text/html"
      ) ||
      contentType.includes(
        "application/xhtml+xml"
      )
    ) {
      const html =
        Buffer
          .from(response.data)
          .toString("utf8");

      const rewritten =
        rewriteHtml(
          html,
          target.href
        );

      /*
       * HTML gets a short cache.
       */

      setCache(
        cacheKey,
        rewritten,
        "text/html; charset=utf-8",
        30 * 1000
      );

      res.setHeader(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      res.setHeader(
        "Cache-Control",
        "public, max-age=30"
      );

      res.setHeader(
        "X-FastProxy-Cache",
        "MISS"
      );

      return res.send(
        rewritten
      );
    }

    /*
     * Images, CSS, JS, fonts,
     * videos, etc.
     */

    setCache(
      cacheKey,
      response.data,
      contentType,
      5 * 60 * 1000
    );

    res.setHeader(
      "Content-Type",
      contentType
    );

    res.setHeader(
      "Cache-Control",
      "public, max-age=300"
    );

    res.setHeader(
      "X-FastProxy-Cache",
      "MISS"
    );

    return res.send(
      response.data
    );

  } catch (error) {

    console.error(
      "Proxy error:",
      error.message
    );

    const message =
      error.message ||
      "Unable to retrieve that website.";

    return res
      .status(500)
      .send(`
        <!DOCTYPE html>

        <html>

        <head>

          <meta charset="UTF-8">

          <title>
            FastProxy Error
          </title>

          <style>

            body {
              margin:0;
              padding:40px;
              font-family:Arial,sans-serif;
              background:#0f172a;
              color:white;
            }

            .box {
              max-width:700px;
              margin:auto;
              padding:25px;
              border-radius:16px;
              background:#1e293b;
              box-shadow:
                0 20px 60px
                rgba(0,0,0,.3);
            }

            a {
              color:#60a5fa;
            }

          </style>

        </head>

        <body>

          <div class="box">

            <h1>
              FastProxy Error
            </h1>

            <p>
              ${escapeHtml(message)}
            </p>

            <a href="/">
              Back to FastProxy
            </a>

          </div>

        </body>

        </html>
      `);
  }
});

/* =========================================
   START SERVER
========================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `FastProxy running on port ${PORT}`
    );

    console.log(
      `Health endpoint: /health`
    );
  }
);
