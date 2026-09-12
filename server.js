const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const compression = require("compression");
const httpProxy = require("http-proxy");
const dns = require("dns").promises;
const net = require("net");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================================================
   SETUP
========================================================= */

app.disable("x-powered-by");

app.use(compression());

app.use(
  express.static(
    path.join(__dirname, "public"),
    {
      maxAge: "1h"
    }
  )
);

/*
 * IMPORTANT:
 *
 * We intentionally do NOT use express.json()
 * or express.urlencoded() here.
 *
 * Game POST requests need their raw request
 * body streamed directly to the destination.
 */

/* =========================================================
   HTTP PROXY
========================================================= */

const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  xfwd: true,
  secure: false,
  selfHandleResponse: false,

  /*
   * Remove the original website's cookie domain
   * so cookies belong to the proxy instead.
   */
  cookieDomainRewrite: "",

  /*
   * Make paths work regardless of the original
   * website's cookie path.
   */
  cookiePathRewrite: "/"
});

proxy.on(
  "error",
  (error, req, res) => {

    console.error(
      "Proxy error:",
      error.message
    );

    if (
      res &&
      !res.headersSent
    ) {
      res.writeHead(
        502,
        {
          "Content-Type":
            "text/plain; charset=utf-8"
        }
      );

      res.end(
        "FastProxy could not connect to the website."
      );
    }
  }
);

/*
 * Rewrite headers from proxied sites.
 *
 * This removes frame restrictions that would otherwise
 * prevent pages from being displayed inside FastProxy.
 */
proxy.on(
  "proxyRes",
  (proxyRes) => {

    delete proxyRes.headers[
      "x-frame-options"
    ];

    delete proxyRes.headers[
      "content-security-policy"
    ];

    delete proxyRes.headers[
      "content-security-policy-report-only"
    ];

    delete proxyRes.headers[
      "cross-origin-opener-policy"
    ];

    delete proxyRes.headers[
      "cross-origin-embedder-policy"
    ];

  }
);

/* =========================================================
   CACHE
========================================================= */

const cache = new Map();

const MAX_CACHE_ITEMS = 250;

const HTML_CACHE_TTL =
  30 * 1000;

const SMALL_ASSET_TTL =
  5 * 60 * 1000;

const MAX_CACHED_ASSET =
  5 * 1024 * 1024;

/*
 * Only allow a reasonable amount of cached data.
 */
let cachedBytes = 0;

const MAX_CACHE_BYTES =
  60 * 1024 * 1024;

function cacheGet(key) {

  const item =
    cache.get(key);

  if (!item) {
    return null;
  }

  if (
    item.expires <= Date.now()
  ) {

    removeCache(key);

    return null;
  }

  return item;
}

function cacheSet(
  key,
  data,
  contentType,
  ttl
) {

  const size =
    Buffer.isBuffer(data)
      ? data.length
      : Buffer.byteLength(
          String(data)
        );

  if (
    size > MAX_CACHED_ASSET ||
    size > MAX_CACHE_BYTES
  ) {
    return;
  }

  /*
   * Remove old entries if necessary.
   */
  while (
    cachedBytes + size >
      MAX_CACHE_BYTES ||
    cache.size >=
      MAX_CACHE_ITEMS
  ) {

    const firstKey =
      cache.keys().next().value;

    if (!firstKey) {
      break;
    }

    removeCache(firstKey);
  }

  cache.set(
    key,
    {
      data,
      contentType,
      expires:
        Date.now() + ttl,
      size
    }
  );

  cachedBytes += size;
}

function removeCache(key) {

  const item =
    cache.get(key);

  if (!item) {
    return;
  }

  cachedBytes -=
    item.size || 0;

  cache.delete(key);
}

/* =========================================================
   HOST SAFETY
========================================================= */

function isPrivateIPv4(ip) {

  const parts =
    ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(Number.isNaN)
  ) {
    return true;
  }

  const [a, b] =
    parts;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 &&
      b >= 16 &&
      b <= 31) ||
    (a === 192 &&
      b === 168) ||
    a === 0
  );
}

function isPrivateIPv6(ip) {

  const value =
    ip.toLowerCase();

  return (
    value === "::1" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:")
  );
}

async function isSafeHostname(
  hostname
) {

  const host =
    hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    return false;
  }

  /*
   * Direct IP.
   */
  if (
    net.isIP(host) === 4
  ) {
    return !isPrivateIPv4(host);
  }

  if (
    net.isIP(host) === 6
  ) {
    return !isPrivateIPv6(host);
  }

  /*
   * Resolve hostname.
   */
  try {

    const results =
      await dns.lookup(
        host,
        {
          all: true
        }
      );

    if (!results.length) {
      return false;
    }

    return results.every(
      result => {

        if (
          result.family === 4
        ) {
          return !isPrivateIPv4(
            result.address
          );
        }

        if (
          result.family === 6
        ) {
          return !isPrivateIPv6(
            result.address
          );
        }

        return false;
      }
    );

  } catch {

    return false;

  }
}

/* =========================================================
   URL VALIDATION
========================================================= */

async function validateHttpUrl(
  raw
) {

  let url;

  try {

    url =
      new URL(raw);

  } catch {

    throw new Error(
      "Invalid website URL."
    );

  }

  if (
    url.protocol !== "http:" &&
    url.protocol !== "https:"
  ) {

    throw new Error(
      "Only HTTP and HTTPS URLs are allowed."
    );

  }

  if (
    !(await isSafeHostname(
      url.hostname
    ))
  ) {

    throw new Error(
      "That website address is not allowed."
    );

  }

  return url;
}

async function validateWsUrl(
  raw
) {

  let url;

  try {

    url =
      new URL(raw);

  } catch {

    throw new Error(
      "Invalid WebSocket URL."
    );

  }

  if (
    url.protocol !== "ws:" &&
    url.protocol !== "wss:"
  ) {

    throw new Error(
      "Invalid WebSocket protocol."
    );

  }

  if (
    !(await isSafeHostname(
      url.hostname
    ))
  ) {

    throw new Error(
      "That WebSocket host is not allowed."
    );

  }

  return url;
}

/* =========================================================
   HELPERS
========================================================= */

function resolveUrl(
  value,
  base
) {

  try {

    return new URL(
      value,
      base
    ).href;

  } catch {

    return null;

  }
}

function makeProxyUrl(
  target
) {

  return (
    "/proxy?url=" +
    encodeURIComponent(
      target
    )
  );
}

function makeWsProxyUrl(
  target
) {

  const protocol =
    locationPlaceholder();

  return (
    protocol +
    "/ws?url=" +
    encodeURIComponent(
      target
    )
  );
}

/*
 * Used only when generating browser-side
 * WebSocket URLs.
 */
function locationPlaceholder() {

  /*
   * This value gets replaced by the
   * browser-injected script.
   */
  return "__FASTPROXY_PROTOCOL__";

}

function escapeHtml(
  value
) {

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );

}

/* =========================================================
   CSS REWRITE
========================================================= */

function rewriteCss(
  css,
  baseUrl
) {

  return css.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (
      match,
      quote,
      value
    ) => {

      const trimmed =
        value.trim();

      if (
        trimmed.startsWith("data:") ||
        trimmed.startsWith("blob:") ||
        trimmed.startsWith("#")
      ) {
        return match;
      }

      const absolute =
        resolveUrl(
          trimmed,
          baseUrl
        );

      if (!absolute) {
        return match;
      }

      return (
        'url("' +
        makeProxyUrl(
          absolute
        ) +
        '")'
      );

    }
  );

}

/* =========================================================
   GAME RUNTIME
========================================================= */

function gameRuntime(
  baseUrl
) {

  const escapedBase =
    JSON.stringify(
      baseUrl
    );

  return `
<script>
(() => {

  const FASTPROXY_BASE =
    ${escapedBase};

  const FASTPROXY_ORIGIN =
    window.location.origin;

  window.__FASTPROXY_BASE__ =
    FASTPROXY_BASE;


  function notify(type, data = {}) {

    try {

      window.parent.postMessage(
        {
          source: "fastproxy",
          type,
          ...data
        },
        "*"
      );

    } catch {}

  }


  function isAlreadyProxied(url) {

    try {

      const parsed =
        new URL(
          url,
          window.location.href
        );

      return (
        parsed.origin ===
          FASTPROXY_ORIGIN &&
        (
          parsed.pathname ===
            "/proxy" ||
          parsed.pathname ===
            "/ws"
        )
      );

    } catch {

      return false;

    }
  }


  function toAbsolute(
    input
  ) {

    try {

      return new URL(
        input,
        FASTPROXY_BASE
      ).href;

    } catch {

      return null;

    }

  }


  function toProxy(
    input
  ) {

    if (
      typeof input !==
      "string"
    ) {

      return input;

    }

    if (
      isAlreadyProxied(
        input
      )
    ) {

      return input;

    }

    const absolute =
      toAbsolute(input);

    if (!absolute) {

      return input;

    }

    /*
     * Do not proxy browser-local
     * data/blob URLs.
     */
    if (
      absolute.startsWith(
        "data:"
      ) ||
      absolute.startsWith(
        "blob:"
      )
    ) {

      return absolute;

    }

    notify(
      "request",
      {
        url: absolute
      }
    );

    return (
      "/proxy?url=" +
      encodeURIComponent(
        absolute
      )
    );

  }


  /*
   * FETCH
   */

  const originalFetch =
    window.fetch.bind(
      window
    );


  window.fetch =
    function(
      input,
      init
    ) {

      let url =
        input;


      if (
        input &&
        typeof input.url ===
          "string"
      ) {

        url =
          input.url;

      }


      if (
        typeof url ===
        "string"
      ) {

        const rewritten =
          toProxy(url);

        if (
          input instanceof
          Request
        ) {

          input =
            new Request(
              rewritten,
              input
            );

        } else {

          input =
            rewritten;

        }

      }


      notify(
        "fetch"
      );

      return originalFetch(
        input,
        init
      );

    };


  /*
   * XMLHttpRequest
   */

  const originalOpen =
    XMLHttpRequest
      .prototype
      .open;


  XMLHttpRequest
    .prototype
    .open =
    function(
      method,
      url,
      ...rest
    ) {

      if (
        typeof url ===
        "string"
      ) {

        url =
          toProxy(url);

      }

      notify(
        "xhr"
      );

      return originalOpen.call(
        this,
        method,
        url,
        ...rest
      );

    };


  /*
   * WebSocket
   */

  const OriginalWebSocket =
    window.WebSocket;


  window.WebSocket =
    function(
      url,
      protocols
    ) {

      let wsUrl =
        url;


      try {

        const parsed =
          new URL(
            url,
            FASTPROXY_BASE
          );


        if (
          parsed.protocol ===
            "ws:" ||
          parsed.protocol ===
            "wss:"
        ) {

          const browserProtocol =
            location.protocol ===
              "https:"
              ? "wss:"
              : "ws:";


          wsUrl =
            browserProtocol +
            "//" +
            location.host +
            "/ws?url=" +
            encodeURIComponent(
              parsed.href
            );

        }

      } catch {}


      notify(
        "websocket"
      );


      if (
        protocols !==
        undefined
      ) {

        return new OriginalWebSocket(
          wsUrl,
          protocols
        );

      }

      return new OriginalWebSocket(
        wsUrl
      );

    };


  window.WebSocket.prototype =
    OriginalWebSocket.prototype;


  /*
   * EventSource
   */

  if (
    window.EventSource
  ) {

    const OriginalEventSource =
      window.EventSource;


    window.EventSource =
      function(url, options) {

        return new OriginalEventSource(
          toProxy(url),
          options
        );

      };


    window.EventSource.prototype =
      OriginalEventSource.prototype;

  }


  /*
   * sendBeacon
   */

  if (
    navigator.sendBeacon
  ) {

    const originalBeacon =
      navigator.sendBeacon.bind(
        navigator
      );


    navigator.sendBeacon =
      function(
        url,
        data
      ) {

        notify(
          "beacon"
        );

        return originalBeacon(
          toProxy(url),
          data
        );

      };

  }


  /*
   * Make relative forms use the proxy.
   */

  document.addEventListener(
    "submit",
    event => {

      const form =
        event.target;

      if (
        !form ||
        !form.action
      ) {
        return;
      }

      try {

        const absolute =
          new URL(
            form.action,
            FASTPROXY_BASE
          ).href;


        form.action =
          toProxy(
            absolute
          );

      } catch {}

    },
    true
  );


  notify(
    "runtime-ready"
  );

})();
</script>
`;

}

/* =========================================================
   HTML REWRITE
========================================================= */

function rewriteHtml(
  html,
  baseUrl
) {

  const $ =
    cheerio.load(
      html,
      {
        decodeEntities: false
      }
    );

  /*
   * Remove base tag because our runtime
   * handles URL resolution itself.
   */
  $("base").remove();


  /*
   * Links
   */

  $("a[href]").each(
    (_, element) => {

      const href =
        $(element).attr(
          "href"
        );

      if (!href) {
        return;
      }

      if (
        href.startsWith("#") ||
        href.startsWith("mailto:") ||
        href.startsWith("tel:") ||
        href.startsWith(
          "javascript:"
        ) ||
        href.startsWith(
          "data:"
        )
      ) {
        return;
      }

      const absolute =
        resolveUrl(
          href,
          baseUrl
        );

      if (absolute) {

        $(element).attr(
          "href",
          makeProxyUrl(
            absolute
          )
        );

      }

    }
  );


  /*
   * Images
   */

  $("img[src]").each(
    (_, element) => {

      const src =
        $(element).attr(
          "src"
        );

      if (!src) {
        return;
      }

      if (
        src.startsWith("data:") ||
        src.startsWith("blob:")
      ) {
        return;
      }

      const absolute =
        resolveUrl(
          src,
          baseUrl
        );

      if (absolute) {

        $(element).attr(
          "src",
          makeProxyUrl(
            absolute
          )
        );

      }

    }
  );


  /*
   * Image srcset
   */

  $("[srcset]").each(
    (_, element) => {

      const value =
        $(element).attr(
          "srcset"
        );

      if (!value) {
        return;
      }

      const rewritten =
        value
          .split(",")
          .map(
            part => {

              const pieces =
                part.trim()
                  .split(/\s+/);

              const source =
                pieces.shift();

              if (!source) {
                return part;
              }

              const absolute =
                resolveUrl(
                  source,
                  baseUrl
                );

              if (!absolute) {
                return part;
              }

              return [
                makeProxyUrl(
                  absolute
                ),
                ...pieces
              ].join(" ");

            }
          )
          .join(", ");


      $(element).attr(
        "srcset",
        rewritten
      );

    }
  );


  /*
   * Scripts
   */

  $("script[src]").each(
    (_, element) => {

      const src =
        $(element).attr(
          "src"
        );

      if (!src) {
        return;
      }

      const absolute =
        resolveUrl(
          src,
          baseUrl
        );

      if (absolute) {

        $(element).attr(
          "src",
          makeProxyUrl(
            absolute
          )
        );

      }

    }
  );


  /*
   * Stylesheets
   */

  $("link[href]").each(
    (_, element) => {

      const href =
        $(element).attr(
          "href"
        );

      if (!href) {
        return;
      }

      const absolute =
        resolveUrl(
          href,
          baseUrl
        );

      if (absolute) {

        $(element).attr(
          "href",
          makeProxyUrl(
            absolute
          )
        );

      }

    }
  );


  /*
   * Media
   */

  $(
    "video[src],audio[src],source[src],track[src]"
  ).each(
    (_, element) => {

      const src =
        $(element).attr(
          "src"
        );

      if (!src) {
        return;
      }

      const absolute =
        resolveUrl(
          src,
          baseUrl
        );

      if (absolute) {

        $(element).attr(
          "src",
          makeProxyUrl(
            absolute
          )
        );

      }

    }
  );


  /*
   * Inline styles
   */

  $("[style]").each(
    (_, element) => {

      const style =
        $(element).attr(
          "style"
        );

      if (!style) {
        return;
      }

      $(element).attr(
        "style",
        rewriteCss(
          style,
          baseUrl
        )
      );

    }
  );


  /*
   * Inject Game Mode runtime
   * before website scripts run.
   */

  const runtime =
    gameRuntime(
      baseUrl
    );


  if (
    $("head").length
  ) {

    $("head").prepend(
      runtime
    );

  } else if (
    $("body").length
  ) {

    $("body").prepend(
      runtime
    );

  }


  return $.html();

}

/* =========================================================
   HOME
========================================================= */

app.get(
  "/",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );

  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/health",
  (req, res) => {

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
      mode: "game",
      uptime:
        Math.round(
          process.uptime()
        ),
      timestamp:
        Date.now()
    });

  }
);

/* =========================================================
   PROXY REQUEST
========================================================= */

app.all(
  "/proxy",
  async (req, res) => {

    const rawUrl =
      req.query.url;


    if (
      !rawUrl ||
      typeof rawUrl !==
        "string"
    ) {

      return res
        .status(400)
        .send(
          "Missing URL."
        );

    }


    let target;

    try {

      target =
        await validateHttpUrl(
          rawUrl
        );

    } catch (error) {

      return res
        .status(400)
        .send(
          escapeHtml(
            error.message
          )
        );

    }


    /*
     * HTML requests are fetched by Node
     * because we need to rewrite the HTML.
     */
    if (
      (
        req.method ===
          "GET" ||
        req.method ===
          "HEAD"
      ) &&
      !req.headers.range
    ) {

      const cacheKey =
        target.href;


      const cached =
        cacheGet(
          cacheKey
        );


      if (cached) {

        res.setHeader(
          "Content-Type",
          cached.contentType
        );

        res.setHeader(
          "Cache-Control",
          "public, max-age=30"
        );

        res.setHeader(
          "X-FastProxy-Cache",
          "HIT"
        );

        return res.send(
          cached.data
        );

      }


      try {

        const response =
          await axios.get(
            target.href,
            {
              proxy: false,

              responseType:
                "arraybuffer",

              timeout:
                15000,

              maxRedirects:
                10,

              headers: {

                "User-Agent":
                  req.headers[
                    "user-agent"
                  ] ||
                  "Mozilla/5.0",

                "Accept":
                  req.headers[
                    "accept"
                  ] ||
                  "text/html,*/*;q=0.8",

                "Accept-Language":
                  req.headers[
                    "accept-language"
                  ] ||
                  "en-US,en;q=0.9",

                "Referer":
                  target.origin +
                  "/"

              },

              maxContentLength:
                20 *
                1024 *
                1024,

              validateStatus:
                () => true

            }
          );


        const contentType =
          response.headers[
            "content-type"
          ] || "";


        /*
         * If the target returned an error,
         * show an accurate error page.
         */
        if (
          response.status >= 400
        ) {

          return res
            .status(
              response.status
            )
            .send(`
              <!DOCTYPE html>
              <html>
              <body style="
                margin:0;
                padding:40px;
                font-family:Arial;
                background:#070b14;
                color:white;
              ">

                <h1>
                  FastProxy
                </h1>

                <h2>
                  Website returned
                  ${response.status}
                </h2>

                <p style="
                  color:#94a3b8;
                ">
                  ${escapeHtml(
                    target.href
                  )}
                </p>

                <a
                  href="/"
                  style="
                    color:#93c5fd;
                  "
                >
                  Back to FastProxy
                </a>

              </body>
              </html>
            `);

        }


        /*
         * HTML rewrite
         */
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
              .from(
                response.data
              )
              .toString(
                "utf8"
              );


          const rewritten =
            rewriteHtml(
              html,
              target.href
            );


          cacheSet(
            cacheKey,
            rewritten,
            "text/html; charset=utf-8",
            HTML_CACHE_TTL
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


          /*
           * Forward safe cookies.
           */
          if (
            response.headers[
              "set-cookie"
            ]
          ) {

            res.setHeader(
              "Set-Cookie",
              response.headers[
                "set-cookie"
              ].map(
                cookie =>
                  cookie
                    .replace(
                      /Domain=[^;]+;?\s*/gi,
                      ""
                    )
                    .replace(
                      /Path=[^;]+/gi,
                      "Path=/"
                    )
              )
            );

          }


          return res.send(
            rewritten
          );

        }


        /*
         * Small assets can be cached.
         */
        const buffer =
          Buffer.from(
            response.data
          );


        if (
          buffer.length <=
          MAX_CACHED_ASSET
        ) {

          cacheSet(
            cacheKey,
            buffer,
            contentType ||
              "application/octet-stream",
            SMALL_ASSET_TTL
          );

        }


        res.setHeader(
          "Content-Type",
          contentType ||
            "application/octet-stream"
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
          buffer
        );


      } catch (error) {

        console.error(
          "GET proxy:",
          error.message
        );

        /*
         * If direct fetching fails,
         * fall through to the streaming
         * proxy below.
         */

      }

    }


    /*
     * STREAMING PROXY
     *
     * This handles:
     *
     * POST
     * PUT
     * PATCH
     * DELETE
     * OPTIONS
     * Range requests
     * large game files
     * API traffic
     */

    try {

      /*
       * Avoid leaking FastProxy's own cookies
       * to the target website.
       */
      delete req.headers.cookie;


      /*
       * Preserve the original target path.
       */
      req.url =
        target.pathname +
        target.search;


      proxy.web(
        req,
        res,
        {
          target:
            target.origin,

          changeOrigin:
            true,

          secure:
            true,

          ignorePath:
            false,

          cookieDomainRewrite:
            "",

          cookiePathRewrite:
            "/"
        }
      );


    } catch (error) {

      console.error(
        "Streaming proxy:",
        error.message
      );

      if (
        !res.headersSent
      ) {

        res.status(
          502
        ).send(
          "FastProxy streaming error."
        );

      }

    }

  }
);

/* =========================================================
   WEBSOCKET PROXY
========================================================= */

const server =
  app.listen(
    PORT,
    "0.0.0.0",
    () => {

      console.log(
        `FastProxy Game Mode running on port ${PORT}`
      );

      console.log(
        `Health endpoint: /health`
      );

    }
  );


server.on(
  "upgrade",
  async (
    req,
    socket,
    head
  ) => {

    try {

      const parsed =
        new URL(
          req.url,
          "http://localhost"
        );


      if (
        parsed.pathname !==
        "/ws"
      ) {

        socket.destroy();

        return;
      }


      const rawTarget =
        parsed.searchParams.get(
          "url"
        );


      if (!rawTarget) {

        socket.destroy();

        return;

      }


      const target =
        await validateWsUrl(
          rawTarget
        );


      /*
       * Never pass the FastProxy cookie
       * header to the destination.
       */
      delete req.headers.cookie;


      /*
       * Replace request path with
       * the real WebSocket path.
       */
      req.url =
        target.pathname +
        target.search;


      proxy.ws(
        req,
        socket,
        head,
        {
          target:
            target.href,

          changeOrigin:
            true,

          secure:
            true,

          ws:
            true
        }
      );


    } catch (
      error
    ) {

      console.error(
        "WebSocket proxy:",
        error.message
      );

      socket.destroy();

    }

  }
);
