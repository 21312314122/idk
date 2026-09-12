const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const compression = require("compression");
const dns = require("dns").promises;
const net = require("net");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================================
   APP SETUP
========================================================= */

app.disable("x-powered-by");

app.use(compression());

app.use(
  express.static(path.join(__dirname, "public"), {
    maxAge: "1h"
  })
);

/* =========================================================
   CACHE
========================================================= */

const cache = new Map();

const MAX_CACHE_ITEMS = 300;

const HTML_CACHE_TIME = 30 * 1000;
const ASSET_CACHE_TIME = 5 * 60 * 1000;

function getCache(key) {
  const item = cache.get(key);

  if (!item) {
    return null;
  }

  if (item.expires <= Date.now()) {
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

/* =========================================================
   SSRF / LOCAL HOST PROTECTION
========================================================= */

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
      "Only HTTP and HTTPS URLs are supported."
    );
  }

  const safe = await isSafeHost(url.hostname);

  if (!safe) {
    throw new Error(
      "That website is not allowed."
    );
  }

  return url;
}

/* =========================================================
   HELPERS
========================================================= */

function makeProxyUrl(url) {
  return (
    "/proxy?url=" +
    encodeURIComponent(url)
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

function resolveUrl(value, baseUrl) {
  try {
    return new URL(value, baseUrl).href;
  } catch {
    return null;
  }
}

/* =========================================================
   REWRITE HTML
========================================================= */

function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, {
    decodeEntities: false
  });

  /*
   * Remove <base> so the browser doesn't bypass
   * the rewritten URLs.
   */
  $("base").remove();

  /* -------------------------------------------------------
     LINKS
  ------------------------------------------------------- */

  $("a[href]").each((_, element) => {
    const value = $(element).attr("href");

    if (!value) return;

    if (
      value.startsWith("#") ||
      value.startsWith("mailto:") ||
      value.startsWith("tel:") ||
      value.startsWith("javascript:") ||
      value.startsWith("data:")
    ) {
      return;
    }

    const absolute = resolveUrl(
      value,
      baseUrl
    );

    if (absolute) {
      $(element).attr(
        "href",
        makeProxyUrl(absolute)
      );
    }
  });

  /* -------------------------------------------------------
     FORMS
  ------------------------------------------------------- */

  $("form[action]").each((_, element) => {
    const value = $(element).attr("action");

    if (!value) return;

    const absolute = resolveUrl(
      value,
      baseUrl
    );

    if (absolute) {
      $(element).attr(
        "action",
        makeProxyUrl(absolute)
      );
    }
  });

  /* -------------------------------------------------------
     IMAGES
  ------------------------------------------------------- */

  $(
    "img[src], image[href], image[xlink\\:href]"
  ).each((_, element) => {

    const attribute =
      $(element).attr("src") !== undefined
        ? "src"
        : $(element).attr("href") !== undefined
          ? "href"
          : "xlink:href";

    const value =
      $(element).attr(attribute);

    if (!value) return;

    if (
      value.startsWith("data:") ||
      value.startsWith("blob:")
    ) {
      return;
    }

    const absolute = resolveUrl(
      value,
      baseUrl
    );

    if (absolute) {
      $(element).attr(
        attribute,
        makeProxyUrl(absolute)
      );
    }
  });

  /* -------------------------------------------------------
     SCRIPTS
  ------------------------------------------------------- */

  $("script[src]").each((_, element) => {
    const value = $(element).attr("src");

    if (!value) return;

    const absolute = resolveUrl(
      value,
      baseUrl
    );

    if (absolute) {
      $(element).attr(
        "src",
        makeProxyUrl(absolute)
      );
    }
  });

  /* -------------------------------------------------------
     STYLESHEETS / FAVICONS
  ------------------------------------------------------- */

  $("link[href]").each((_, element) => {
    const value = $(element).attr("href");

    if (!value) return;

    const absolute = resolveUrl(
      value,
      baseUrl
    );

    if (absolute) {
      $(element).attr(
        "href",
        makeProxyUrl(absolute)
      );
    }
  });

  /* -------------------------------------------------------
     VIDEO / AUDIO / SOURCE
  ------------------------------------------------------- */

  $(
    "video[src], audio[src], source[src], track[src]"
  ).each((_, element) => {

    const value = $(element).attr("src");

    if (!value) return;

    const absolute = resolveUrl(
      value,
      baseUrl
    );

    if (absolute) {
      $(element).attr(
        "src",
        makeProxyUrl(absolute)
      );
    }
  });

  /* -------------------------------------------------------
     OBJECT / EMBED
  ------------------------------------------------------- */

  $(
    "object[data], embed[src]"
  ).each((_, element) => {

    const attribute =
      $(element).attr("data") !== undefined
        ? "data"
        : "src";

    const value =
      $(element).attr(attribute);

    if (!value) return;

    const absolute = resolveUrl(
      value,
      baseUrl
    );

    if (absolute) {
      $(element).attr(
        attribute,
        makeProxyUrl(absolute)
      );
    }
  });

  /* -------------------------------------------------------
     SRCSET
  ------------------------------------------------------- */

  $("[srcset]").each((_, element) => {
    const value = $(element).attr("srcset");

    if (!value) return;

    const rewritten = value
      .split(",")
      .map(item => {

        const pieces =
          item.trim().split(/\s+/);

        const source =
          pieces.shift();

        if (!source) {
          return item;
        }

        const absolute =
          resolveUrl(
            source,
            baseUrl
          );

        if (!absolute) {
          return item;
        }

        return [
          makeProxyUrl(absolute),
          ...pieces
        ].join(" ");
      })
      .join(", ");

    $(element).attr(
      "srcset",
      rewritten
    );
  });

  /* -------------------------------------------------------
     ADD FASTPROXY TOOLBAR
  ------------------------------------------------------- */

  if ($("body").length) {

    $("body").prepend(`
      <div
        style="
          position:sticky;
          top:0;
          z-index:2147483647;
          display:flex;
          align-items:center;
          gap:10px;
          height:42px;
          padding:0 14px;
          background:#111827;
          color:white;
          font-family:Arial,sans-serif;
          font-size:14px;
          box-shadow:0 1px 5px rgba(0,0,0,.25);
        "
      >

        <strong>
          ⚡ FastProxy
        </strong>

        <span
          style="
            opacity:.75;
            overflow:hidden;
            white-space:nowrap;
            text-overflow:ellipsis;
            max-width:70%;
          "
        >
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

/* =========================================================
   HOME PAGE
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", (req, res) => {

  res.setHeader(
    "Access-Control-Allow-Origin",
    "*"
  );

  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  res.status(200).json({
    status: "ok",
    server: "FastProxy",
    uptime: process.uptime(),
    timestamp: Date.now()
  });

});

/* =========================================================
   PROXY
========================================================= */

app.get("/proxy", async (req, res) => {

  const started =
    performance.now();

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

    /* -------------------------------------------------------
       CACHE HIT
    ------------------------------------------------------- */

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

    /* -------------------------------------------------------
       REQUEST
    ------------------------------------------------------- */

    const response =
      await axios.get(
        target.href,
        {
          proxy: false,

          responseType:
            "arraybuffer",

          timeout:
            15000,

          /*
           * Follow normal website redirects.
           */
          maxRedirects:
            10,

          headers: {

            /*
             * Browser-like headers.
             */
            "User-Agent":
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",

            "Accept":
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",

            "Accept-Language":
              "en-US,en;q=0.9",

            "Accept-Encoding":
              "gzip, deflate, br",

            "Cache-Control":
              "no-cache",

            "Upgrade-Insecure-Requests":
              "1",

            "Referer":
              target.origin + "/"
          },

          maxContentLength:
            20 * 1024 * 1024,

          maxBodyLength:
            20 * 1024 * 1024,

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

    /* -------------------------------------------------------
       LOG
    ------------------------------------------------------- */

    console.log(
      `[${Math.round(performance.now() - started)}ms]`,
      response.status,
      target.href,
      contentType
    );

    /* -------------------------------------------------------
       HTML
    ------------------------------------------------------- */

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

      setCache(
        cacheKey,
        rewritten,
        "text/html; charset=utf-8",
        HTML_CACHE_TIME
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

      res.setHeader(
        "X-FastProxy-Time",
        Math.round(
          performance.now() - started
        )
      );

      return res.send(
        rewritten
      );
    }

    /* -------------------------------------------------------
       OTHER RESOURCES
       images / css / js / fonts / video / etc.
    ------------------------------------------------------- */

    setCache(
      cacheKey,
      response.data,
      contentType,
      ASSET_CACHE_TIME
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

    res.setHeader(
      "X-FastProxy-Time",
      Math.round(
        performance.now() - started
      )
    );

    return res.send(
      response.data
    );

  } catch (error) {

    console.error(
      "FASTPROXY ERROR:",
      error.message
    );

    /*
     * Axios timeout.
     */
    if (
      error.code === "ECONNABORTED"
    ) {

      return res
        .status(504)
        .send(`
          <h1>FastProxy Timeout</h1>
          <p>
            The website took too long to respond.
          </p>
          <p>
            <a href="/">Back to FastProxy</a>
          </p>
        `);

    }

    let message =
      error.message ||
      "Unable to load the website.";

    /*
     * Friendly error page.
     */

    return res
      .status(502)
      .send(`
        <!DOCTYPE html>

        <html>

        <head>

          <meta charset="UTF-8">

          <meta
            name="viewport"
            content="width=device-width,initial-scale=1"
          >

          <title>
            FastProxy Error
          </title>

          <style>

            body {
              margin:0;
              min-height:100vh;
              display:flex;
              align-items:center;
              justify-content:center;
              padding:20px;
              background:#070b14;
              color:white;
              font-family:Arial,sans-serif;
            }

            .box {
              width:min(650px,100%);
              padding:30px;
              border-radius:20px;
              background:#111827;
              border:1px solid #273449;
              box-shadow:
                0 30px 80px
                rgba(0,0,0,.4);
            }

            h1 {
              margin-top:0;
            }

            p {
              color:#94a3b8;
              line-height:1.6;
            }

            a {
              color:#93c5fd;
            }

          </style>

        </head>

        <body>

          <div class="box">

            <h1>
              ⚡ FastProxy
            </h1>

            <p>
              ${escapeHtml(message)}
            </p>

            <p>
              <a href="/">
                Return to FastProxy
              </a>
            </p>

          </div>

        </body>

        </html>
      `);
  }
});

/* =========================================================
   START
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `FastProxy running on port ${PORT}`
    );

    console.log(
      `Health: http://localhost:${PORT}/health`
    );

  }
);
