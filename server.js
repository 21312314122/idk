const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const net = require("net");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));

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
  const normalized = ip.toLowerCase();

  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
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
    const result = await dns.lookup(host);

    if (result.family === 4) {
      return !isPrivateIPv4(result.address);
    }

    if (result.family === 6) {
      return !isPrivateIPv6(result.address);
    }

    return false;
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

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS URLs are allowed.");
  }

  if (!(await isSafeHost(url.hostname))) {
    throw new Error("That host is not allowed.");
  }

  return url;
}

function makeProxyUrl(target) {
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

function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, {
    decodeEntities: false
  });

  $("base").remove();

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
      $(element).attr("href", makeProxyUrl(absolute));
    } catch {}
  });

  $("form[action]").each((_, element) => {
    const action = $(element).attr("action");

    if (!action) return;

    try {
      const absolute = new URL(action, baseUrl).href;
      $(element).attr("action", makeProxyUrl(absolute));
    } catch {}
  });

  $("img[src]").each((_, element) => {
    const src = $(element).attr("src");

    if (!src) return;

    try {
      const absolute = new URL(src, baseUrl).href;
      $(element).attr("src", makeProxyUrl(absolute));
    } catch {}
  });

  $("script[src]").each((_, element) => {
    const src = $(element).attr("src");

    if (!src) return;

    try {
      const absolute = new URL(src, baseUrl).href;
      $(element).attr("src", makeProxyUrl(absolute));
    } catch {}
  });

  $('link[href]').each((_, element) => {
    const href = $(element).attr("href");

    if (!href) return;

    try {
      const absolute = new URL(href, baseUrl).href;
      $(element).attr("href", makeProxyUrl(absolute));
    } catch {}
  });

  if ($("body").length) {
    $("body").prepend(`
      <div style="
        position:sticky;
        top:0;
        z-index:999999;
        padding:8px 12px;
        background:#111827;
        color:white;
        font-family:Arial,sans-serif;
        font-size:14px;
        border-bottom:1px solid #374151;
      ">
        Proxy:
        <strong>${escapeHtml(baseUrl)}</strong>
        &nbsp;
        <a href="/" style="color:#93c5fd;">Home</a>
      </div>
    `);
  }

  return $.html();
}
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});
‹
app.get("/proxy", async (req, res) => {
  try {
    const requestedUrl = req.query.url;

    if (!requestedUrl || typeof requestedUrl !== "string") {
      return res.status(400).send("Missing URL.");
    }

    const target = await validateUrl(requestedUrl);

    const response = await axios.get(target.href, {
      proxy: false,
      responseType: "text",
      timeout: 15000,
      maxRedirects: 5,

      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; SimpleWebProxy/1.0)"
      },

      maxContentLength: 5 * 1024 * 1024,
      maxBodyLength: 5 * 1024 * 1024,

      validateStatus: status => status >= 200 && status < 400
    });

    const contentType =
      response.headers["content-type"] || "";

    if (!contentType.includes("text/html")) {
      res.setHeader("Content-Type", contentType);
      return res.send(response.data);
    }

    const output = rewriteHtml(
      response.data,
      target.href
    );

    res.setHeader(
      "Content-Type",
      "text/html; charset=utf-8"
    );

    res.send(output);

  } catch (error) {
    console.error(error);

    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Proxy Error</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            background: #f3f4f6;
            padding: 40px;
          }

          .box {
            max-width: 700px;
            margin: auto;
            background: white;
            padding: 25px;
            border-radius: 12px;
          }

          a {
            color: #2563eb;
          }
        </style>
      </head>

      <body>
        <div class="box">
          <h1>Proxy Error</h1>
          <p>${escapeHtml(error.message)}</p>
          <p><a href="/">Go Home</a></p>
        </div>
      </body>
      </html>
    `);
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Proxy server running on port ${PORT}`);
});
