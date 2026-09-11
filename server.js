```js
const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const net = require("net");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));

/*
 * Convert a hostname/IP into an address and reject private/local targets.
 * This helps prevent the proxy from being used for SSRF attacks.
 */
function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b, c] = parts;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 0)
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
  const lower = hostname.toLowerCase();

  // Reject obvious local names.
  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".local")
  ) {
    return false;
  }

  // If the hostname is already an IP address.
  if (net.isIP(lower) === 4) {
    return !isPrivateIPv4(lower);
  }

  if (net.isIP(lower) === 6) {
    return !isPrivateIPv6(lower);
  }

  try {
    const result = await dns.lookup(lower);

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

/*
 * Validate a URL before fetching it.
 */
async function validateUrl(rawUrl) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are allowed.");
  }

  const safe = await isSafeHost(url.hostname);

  if (!safe) {
    throw new Error("That host is not allowed.");
  }

  return url;
}

/*
 * Turn a target URL into a proxy URL.
 */
function proxyUrl(targetUrl) {
  return `/proxy?url=${encodeURIComponent(targetUrl)}`;
}

/*
 * Rewrite URLs inside HTML so navigation stays inside our proxy.
 */
function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, {
    decodeEntities: false
  });

  // Remove potentially dangerous elements for this basic demo.
  $("base").remove();

  /*
   * Rewrite links.
   */
  $("a[href]").each((_, element) => {
    const value = $(element).attr("href");

    if (!value) return;

    if (
      value.startsWith("#") ||
      value.startsWith("mailto:") ||
      value.startsWith("tel:") ||
      value.startsWith("javascript:")
    ) {
      return;
    }

    try {
      const absolute = new URL(value, baseUrl).href;
      $(element).attr("href", proxyUrl(absolute));
    } catch {
      // Leave invalid URLs alone.
    }
  });

  /*
   * Rewrite forms.
   */
  $("form[action]").each((_, element) => {
    const value = $(element).attr("action");

    if (!value) return;

    try {
      const absolute = new URL(value, baseUrl).href;
      $(element).attr("action", proxyUrl(absolute));
    } catch {
      // Ignore invalid actions.
    }
  });

  /*
   * Rewrite images.
   */
  $("img[src]").each((_, element) => {
    const value = $(element).attr("src");

    if (!value) return;

    try {
      const absolute = new URL(value, baseUrl).href;
      $(element).attr("src", proxyUrl(absolute));
    } catch {
      // Ignore invalid URLs.
    }
  });

  /*
   * Rewrite scripts.
   */
  $("script[src]").each((_, element) => {
    const value = $(element).attr("src");

    if (!value) return;

    try {
      const absolute = new URL(value, baseUrl).href;
      $(element).attr("src", proxyUrl(absolute));
    } catch {
      // Ignore invalid URLs.
    }
  });

  /*
   * Rewrite stylesheets.
   */
  $('link[href]').each((_, element) => {
    const value = $(element).attr("href");

    if (!value) return;

    try {
      const absolute = new URL(value, baseUrl).href;
      $(element).attr("href", proxyUrl(absolute));
    } catch {
      // Ignore invalid URLs.
    }
  });

  /*
   * Rewrite inline src attributes where useful.
   */
  $("[srcset]").each((_, element) => {
    const value = $(element).attr("srcset");

    if (!value) return;

    const rewritten = value
      .split(",")
      .map(part => {
        const bits = part.trim().split(/\s+/);
        const src = bits.shift();

        try {
          const absolute = new URL(src, baseUrl).href;
          return [proxyUrl(absolute), ...bits].join(" ");
        } catch {
          return part.trim();
        }
      })
      .join(", ");

    $(element).attr("srcset", rewritten);
  });

  /*
   * Add a small toolbar so users can easily return to the proxy UI.
   */
  $("body").prepend(`
    <div style="
      position: sticky;
      top: 0;
      z-index: 999999;
      padding: 8px 12px;
      background: #111827;
      color: white;
      font-family: Arial, sans-serif;
      font-size: 14px;
      border-bottom: 1px solid #374151;
    ">
      Proxying:
      <strong>${escapeHtml(baseUrl)}</strong>
      &nbsp;
      <a
        href="/"
        style="color:#93c5fd;"
      >
        Back
      </a>
    </div>
  `);

  return $.html();
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/*
 * Proxy endpoint.
 *
 * Example:
 * /proxy?url=https%3A%2F%2Fexample.com
 */
app.get("/proxy", async (req, res) => {
  try {
    const rawUrl = req.query.url;

    if (!rawUrl || typeof rawUrl !== "string") {
      return res.status(400).send("Missing URL.");
    }

    const target = await validateUrl(rawUrl);

    const response = await axios.get(target.href, {
      responseType: "text",

      // Prevent Axios from using HTTP_PROXY/HTTPS_PROXY automatically.
      proxy: false,

      timeout: 15000,

      maxRedirects: 5,

      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; SimpleEducationalProxy/1.0)"
      },

      /*
       * Only allow reasonably small HTML documents in this demo.
       */
      maxContentLength: 5 * 1024 * 1024,
      maxBodyLength: 5 * 1024 * 1024,

      validateStatus: status => status >= 200 && status < 400
    });

    const contentType =
      response.headers["content-type"] || "text/html";

    /*
     * Only rewrite HTML.
     */
    if (!contentType.includes("text/html")) {
      res.setHeader("Content-Type", contentType);

      return res.send(response.data);
    }

    const rewritten = rewriteHtml(
      response.data,
      target.href
    );

    res.setHeader("Content-Type", "text/html; charset=utf-8");

    return res.send(rewritten);
  } catch (error) {
    console.error(error);

    const message =
      error.message || "Unable to retrieve that website.";

    return res.status(500).send(`
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

            .card {
              max-width: 700px;
              margin: auto;
              background: white;
              padding: 25px;
              border-radius: 12px;
              box-shadow: 0 8px 30px rgba(0,0,0,.08);
            }

            code {
              background: #f3f4f6;
              padding: 3px 6px;
              border-radius: 4px;
            }

            a {
              color: #2563eb;
            }
          </style>
        </head>

        <body>
          <div class="card">
            <h1>Proxy Error</h1>
            <p>${escapeHtml(message)}</p>
            <p><a href="/">Return to the proxy</a></p>
          </div>
        </body>
      </html>
    `);
  }
});

app.listen(PORT, () => {
  console.log(`Proxy running at http://localhost:${PORT}`);
});
```
