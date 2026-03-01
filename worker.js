const MODE_READER = "reader";
const MODE_MIRROR = "mirror";
const THEME_AUTO = "auto";
const THEME_LIGHT = "light";
const THEME_DARK = "dark";
const FETCH_TIMEOUT_MS = 15_000;
const MAX_HTML_BYTES = 2_000_000;
const MIN_CONTENT_TEXT_LENGTH = 200;
const BODY_TOO_LARGE_ERROR = "BODY_TOO_LARGE";
const FETCH_HEADERS = {
  "User-Agent": "ReadableProxy/1.1",
  Accept: "text/html,application/xhtml+xml",
};
const HTML_CONTENT_TYPES = ["text/html", "application/xhtml+xml"];
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "0.0.0.0",
  "127.0.0.1",
  "255.255.255.255",
  "::1",
  "[::1]",
  "::",
  "[::]",
]);
const BLOCKED_HOST_SUFFIXES = [".localhost", ".local", ".localdomain", ".internal", ".home.arpa"];
const UI_CHROME_PATTERNS = [
  /\bsave this story\b/i,
  /\bshare (this )?(story|article)\b/i,
  /\bsubscribe\b/i,
  /\bsign (in|up)\b/i,
  /\bread more\b/i,
  /\badvertisement\b/i,
  /\bcookie(s)?\b/i,
];

export default {
  async fetch(request) {
    const requestUrl = new URL(request.url);
    const parsed = parseProxyRequest(requestUrl);
    if (parsed.error) return textResponse(parsed.error.message, parsed.error.status);

    const { targetUrl, mode, theme } = parsed;

    if (!targetUrl) {
      return new Response(renderLandingPage({ requestUrl, theme }), {
        headers: hardenedHeaders("text/html; charset=utf-8"),
      });
    }

    if (!isSafeTargetUrl(targetUrl)) return textResponse("Blocked target URL", 400);

    let upstreamResponse;
    try {
      upstreamResponse = await fetchWithTimeout(targetUrl);
    } catch (error) {
      if (isAbortError(error)) return textResponse("Target fetch timed out", 504);
      return textResponse("Failed to fetch target URL", 502);
    }

    if (!isHtmlResponse(upstreamResponse)) {
      return textResponse("Not HTML", 415);
    }

    if (mode === MODE_MIRROR) {
      return mirrorNoJs(upstreamResponse);
    }

    const mirrorFallbackResponse = upstreamResponse.clone();

    let html;
    try {
      html = await readTextBodyWithLimit(upstreamResponse, MAX_HTML_BYTES);
    } catch (error) {
      if (isBodyTooLargeError(error)) return mirrorNoJs(mirrorFallbackResponse);
      return textResponse("Failed to parse target page", 502);
    }

    const cleanedHtml = stripDangerous(html);
    const title = extractTitle(cleanedHtml) || targetUrl.hostname;
    const chunk = selectContentChunk(cleanedHtml);

    if (!hasMeaningfulText(chunk, MIN_CONTENT_TEXT_LENGTH)) {
      return mirrorNoJs(mirrorFallbackResponse);
    }

    const articleHtml = toReadableHtml(chunk, targetUrl);
    if (!hasMeaningfulText(articleHtml, MIN_CONTENT_TEXT_LENGTH)) {
      return mirrorNoJs(mirrorFallbackResponse);
    }

    const outputHtml = renderReaderPage({
      title,
      sourceUrl: targetUrl.toString(),
      bodyHtml: articleHtml,
      mode,
      theme,
      requestUrl,
    });

    return new Response(outputHtml, {
      headers: hardenedHeaders("text/html; charset=utf-8"),
    });
  },
};

function parseProxyRequest(requestUrl) {
  const target = requestUrl.searchParams.get("url");
  const mode = normalizeMode(requestUrl.searchParams.get("mode"));
  const theme = normalizeTheme(requestUrl.searchParams.get("theme"));

  if (!target) return { targetUrl: null, mode, theme };

  let targetUrl;
  try {
    targetUrl = new URL(target);
  } catch {
    return { error: { message: "Bad URL", status: 400 } };
  }

  if (!isSupportedProtocol(targetUrl.protocol)) {
    return { error: { message: "Bad URL scheme", status: 400 } };
  }

  return { targetUrl, mode, theme };
}

function normalizeMode(rawMode) {
  const mode = (rawMode || MODE_READER).toLowerCase();
  return mode === MODE_MIRROR ? MODE_MIRROR : MODE_READER;
}

function normalizeTheme(rawTheme) {
  const theme = (rawTheme || THEME_AUTO).toLowerCase();
  if (theme === THEME_LIGHT || theme === THEME_DARK) return theme;
  return THEME_AUTO;
}

function isSupportedProtocol(protocol) {
  return protocol === "http:" || protocol === "https:";
}

function isSafeTargetUrl(targetUrl) {
  if (targetUrl.username || targetUrl.password) return false;

  const hostname = normalizeHostname(targetUrl.hostname);
  if (!hostname) return false;

  if (isBlockedHostname(hostname)) return false;
  if (isPrivateIpv4(hostname)) return false;
  if (isPrivateIpv6(hostname)) return false;

  return true;
}

function normalizeHostname(hostname) {
  return hostname.toLowerCase().replace(/\.+$/, "");
}

function isBlockedHostname(hostname) {
  if (BLOCKED_HOSTNAMES.has(hostname)) return true;
  return BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

function isPrivateIpv4(hostname) {
  const parts = hostname.split(".");
  if (parts.length !== 4) return false;

  const octets = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    const value = Number.parseInt(part, 10);
    if (value < 0 || value > 255) return false;
    octets.push(value);
  }

  const [a, b, c] = octets;

  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a >= 224) return true;

  return false;
}

function isPrivateIpv6(hostname) {
  const host = normalizeIpv6Host(hostname);
  if (!host.includes(":")) return false;

  if (host === "::1" || host === "::") return true;
  if (host.startsWith("fc") || host.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(host)) return true;
  if (host.startsWith("ff")) return true;

  if (host.startsWith("::ffff:")) {
    const mappedIpv4 = host.slice("::ffff:".length);
    return isPrivateIpv4(mappedIpv4);
  }

  return false;
}

function normalizeIpv6Host(hostname) {
  const trimmed = hostname.trim().toLowerCase();
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

async function fetchWithTimeout(targetUrl) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    return await fetch(targetUrl.toString(), {
      redirect: "follow",
      headers: FETCH_HEADERS,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

function isAbortError(error) {
  if (!(error instanceof Error)) return false;
  return error.name === "AbortError";
}

function isHtmlResponse(response) {
  const contentType = (response.headers.get("content-type") || "").toLowerCase();
  return HTML_CONTENT_TYPES.some((type) => contentType.includes(type));
}

async function readTextBodyWithLimit(response, maxBytes) {
  if (!response.body) {
    const text = await response.text();
    if (byteLength(text) > maxBytes) throw new Error(BODY_TOO_LARGE_ERROR);
    return text;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    bytesRead += value.byteLength;
    if (bytesRead > maxBytes) {
      await reader.cancel();
      throw new Error(BODY_TOO_LARGE_ERROR);
    }

    text += decoder.decode(value, { stream: true });
  }

  text += decoder.decode();
  return text;
}

function byteLength(value) {
  return new TextEncoder().encode(value).byteLength;
}

function isBodyTooLargeError(error) {
  if (!(error instanceof Error)) return false;
  return error.message === BODY_TOO_LARGE_ERROR;
}

function selectContentChunk(html) {
  return (
    extractTagChunk(html, "article") || extractTagChunk(html, "main") || extractBestBlock(html)
  );
}

function hasMeaningfulText(html, minimumLength) {
  return stripTags(html).trim().length >= minimumLength;
}

function hardenedHeaders(contentType) {
  const headers = new Headers();
  headers.set("content-type", contentType);
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "no-referrer");
  headers.set("cache-control", "no-store");
  headers.set(
    "content-security-policy",
    "default-src 'none'; img-src https: data:; style-src 'unsafe-inline'; " +
      "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; script-src 'unsafe-inline'",
  );
  return headers;
}

function textResponse(message, status = 200) {
  return new Response(message, {
    status,
    headers: hardenedHeaders("text/plain; charset=utf-8"),
  });
}

function renderLandingPage({ requestUrl, theme }) {
  const searchAction = escapeHtml(requestUrl.pathname || "/");
  const lightThemeUrl = buildAppUrl(requestUrl, { theme: THEME_LIGHT });
  const darkThemeUrl = buildAppUrl(requestUrl, { theme: THEME_DARK });

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Reader</title>
  <style>${sharedAppCss()}</style>
</head>
<body data-theme="${escapeHtml(theme)}">
  <div class="page page-home">
    <header class="header-row">
      <h1 class="brand">Reader</h1>
      <div class="theme-toggle" role="group" aria-label="Theme">
        <a class="icon-btn ${theme === THEME_LIGHT ? "is-active" : ""}" href="${escapeHtml(lightThemeUrl)}" aria-label="Light mode">
          ${sunIconSvg()}
        </a>
        <a class="icon-btn ${theme === THEME_DARK ? "is-active" : ""}" href="${escapeHtml(darkThemeUrl)}" aria-label="Dark mode">
          ${moonIconSvg()}
        </a>
      </div>
    </header>
    <form class="search-form" method="get" action="${searchAction}">
      <input type="url" name="url" placeholder="Paste a URL to read..." required />
      <input type="hidden" name="mode" value="${MODE_READER}" />
      <input type="hidden" name="theme" value="${escapeHtml(theme)}" />
      <button class="search-btn" type="submit" aria-label="Open URL">
        ${searchIconSvg()}
      </button>
    </form>
  </div>
</body>
</html>`;
}

function renderReaderPage({ title, sourceUrl, bodyHtml, mode, theme, requestUrl }) {
  const searchAction = escapeHtml(requestUrl.pathname || "/");
  const readerSelected = mode === MODE_READER ? " selected" : "";
  const mirrorSelected = mode === MODE_MIRROR ? " selected" : "";
  const initialThemeIcon = theme === THEME_DARK ? sunIconSvg() : moonIconSvg();

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>${sharedAppCss()}</style>
</head>
<body data-theme="${escapeHtml(theme)}" data-font="serif" data-text-size="md">
  <div class="page page-reader">
    <div class="corner-controls" aria-label="Reader controls">
      <button class="icon-btn" id="shareButton" type="button" aria-label="Share article link">
        ${shareIconSvg()}
      </button>
      <button class="icon-btn" id="themeToggle" type="button" aria-label="Toggle light and dark mode">
        <span id="themeIcon">${initialThemeIcon}</span>
      </button>
      <button class="icon-btn" id="fontToggle" type="button" aria-label="Toggle serif and sans-serif fonts">
        <span class="font-icon font-icon-serif" id="fontIcon">T</span>
      </button>
      <button class="icon-btn" id="sizeToggle" type="button" aria-label="Change text size">
        <span class="size-icon size-md" id="sizeIcon">A</span>
      </button>
      <button class="icon-btn" id="settingsToggle" type="button" aria-label="Open reader settings">
        ${settingsIconSvg()}
      </button>
    </div>
    <header>
      <div class="header-row header-row-article">
        <h1>${escapeHtml(title)}</h1>
      </div>
      <div class="meta">
        Source:
        <a rel="noreferrer noopener" href="${escapeHtml(sourceUrl)}">${escapeHtml(sourceUrl)}</a>
      </div>
    </header>
    <main>${bodyHtml}</main>
  </div>
  <div class="share-toast" id="shareToast" hidden aria-live="polite"></div>
  <div class="settings-overlay" id="settingsOverlay" hidden>
    <div class="settings-view" role="dialog" aria-modal="true" aria-label="Reader settings">
      <div class="settings-head">
        <h2>Settings</h2>
        <button class="icon-btn close-btn" id="settingsClose" type="button" aria-label="Close settings">
          ${closeIconSvg()}
        </button>
      </div>
      <form class="settings-form" method="get" action="${searchAction}" id="settingsForm">
        <label for="readerUrlInput">Page URL</label>
        <div class="search-form search-form-overlay">
          <input id="readerUrlInput" type="url" name="url" value="${escapeHtml(sourceUrl)}" required />
          <button class="search-btn" type="submit" aria-label="Open URL">
            ${searchIconSvg()}
          </button>
        </div>
        <label for="modeSelect">Opening style</label>
        <div class="select-wrap">
          <select id="modeSelect" name="mode">
            <option value="${MODE_READER}"${readerSelected}>Reader</option>
            <option value="${MODE_MIRROR}"${mirrorSelected}>Mirror (no JS)</option>
          </select>
        </div>
        <input id="themeField" type="hidden" name="theme" value="${escapeHtml(theme)}" />
      </form>
      <a class="btn settings-original-btn" href="${escapeHtml(sourceUrl)}" rel="noreferrer noopener">Open original</a>
    </div>
  </div>
  <script>${readerUiScript()}</script>
</body>
</html>`;
}

function buildAppUrl(requestUrl, { url, mode, theme }) {
  const out = new URL(requestUrl.toString());
  out.search = "";

  if (url) out.searchParams.set("url", url);
  if (mode) out.searchParams.set("mode", mode);
  if (theme && theme !== THEME_AUTO) out.searchParams.set("theme", theme);

  return `${out.pathname}${out.search}`;
}

function searchIconSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="m21 21-4.35-4.35m1.85-5.15a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

function sunIconSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 3v2.25M12 18.75V21M4.72 4.72 6.3 6.3M17.7 17.7l1.58 1.58M3 12h2.25M18.75 12H21M4.72 19.28 6.3 17.7M17.7 6.3l1.58-1.58M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

function moonIconSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M21.75 15.5A9.75 9.75 0 0 1 8.5 2.25a9.75 9.75 0 1 0 13.25 13.25Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

function shareIconSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 15.75V3.75m0 0 3.75 3.75M12 3.75 8.25 7.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M4.5 12.75v5.625c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V12.75" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

function settingsIconSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path stroke-linecap="round" stroke="currentColor" stroke-linejoin="round" stroke-width="1.5" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z"/>
  <path stroke-linecap="round" stroke="currentColor" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/>
</svg>`;
}

function closeIconSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="m6 6 12 12M18 6 6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

function readerUiScript() {
  return `
  (() => {
    const THEME_LIGHT = "light";
    const THEME_DARK = "dark";
    const FONT_SERIF = "serif";
    const FONT_SANS = "sans";
    const TEXT_SIZES = ["sm", "md", "lg"];
    const STORAGE_KEY = "reader-ui-v1";

    const body = document.body;
    const themeToggle = document.getElementById("themeToggle");
    const themeIcon = document.getElementById("themeIcon");
    const shareButton = document.getElementById("shareButton");
    const shareToast = document.getElementById("shareToast");
    const fontToggle = document.getElementById("fontToggle");
    const fontIcon = document.getElementById("fontIcon");
    const sizeToggle = document.getElementById("sizeToggle");
    const sizeIcon = document.getElementById("sizeIcon");
    const settingsToggle = document.getElementById("settingsToggle");
    const settingsOverlay = document.getElementById("settingsOverlay");
    const settingsClose = document.getElementById("settingsClose");
    const settingsForm = document.getElementById("settingsForm");
    const themeField = document.getElementById("themeField");
    const shareUrl = window.location.href;
    const shareTitle = (document.querySelector("h1")?.textContent || "Reader").trim();
    let toastTimer = null;

    const state = {
      theme: body.dataset.theme === THEME_LIGHT || body.dataset.theme === THEME_DARK
        ? body.dataset.theme
        : (window.matchMedia("(prefers-color-scheme: dark)").matches ? THEME_DARK : THEME_LIGHT),
      font: FONT_SERIF,
      textSize: "md",
    };

    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
      if (parsed && (parsed.theme === THEME_LIGHT || parsed.theme === THEME_DARK)) {
        state.theme = parsed.theme;
      }
      if (parsed && (parsed.font === FONT_SERIF || parsed.font === FONT_SANS)) {
        state.font = parsed.font;
      }
      if (parsed && TEXT_SIZES.includes(parsed.textSize)) {
        state.textSize = parsed.textSize;
      }
    } catch {}

    function saveState() {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
      } catch {}
    }

    function moonSvg() {
      return '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M21.75 15.5A9.75 9.75 0 0 1 8.5 2.25a9.75 9.75 0 1 0 13.25 13.25Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    }

    function sunSvg() {
      return '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3v2.25M12 18.75V21M4.72 4.72 6.3 6.3M17.7 17.7l1.58 1.58M3 12h2.25M18.75 12H21M4.72 19.28 6.3 17.7M17.7 6.3l1.58-1.58M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    }

    function applyState() {
      body.dataset.theme = state.theme;
      body.dataset.font = state.font;
      body.dataset.textSize = state.textSize;

      if (themeField) {
        themeField.value = state.theme;
      }

      if (themeIcon) {
        themeIcon.innerHTML = state.theme === THEME_DARK ? sunSvg() : moonSvg();
      }

      if (fontIcon) {
        fontIcon.textContent = state.font === FONT_SERIF ? "T" : "t";
        fontIcon.className = state.font === FONT_SERIF ? "font-icon font-icon-serif" : "font-icon font-icon-cursive";
      }

      if (sizeIcon) {
        const sizeClass = state.textSize === "sm" ? "size-sm" : state.textSize === "lg" ? "size-lg" : "size-md";
        sizeIcon.className = "size-icon " + sizeClass;
      }
    }

    function setOverlayOpen(isOpen) {
      if (!settingsOverlay) return;
      settingsOverlay.hidden = !isOpen;
      body.classList.toggle("settings-open", isOpen);
    }

    function showShareToast(message) {
      if (!shareToast) return;

      shareToast.textContent = message;
      shareToast.hidden = false;
      shareToast.classList.add("is-visible");

      if (toastTimer) {
        clearTimeout(toastTimer);
      }

      toastTimer = setTimeout(() => {
        shareToast.classList.remove("is-visible");
        shareToast.hidden = true;
      }, 1400);
    }

    async function copyText(text) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch {}

      try {
        const input = document.createElement("textarea");
        input.value = text;
        input.setAttribute("readonly", "");
        input.style.position = "fixed";
        input.style.top = "-9999px";
        document.body.appendChild(input);
        input.select();
        const copied = document.execCommand("copy");
        document.body.removeChild(input);
        return copied;
      } catch {
        return false;
      }
    }

    if (shareButton) {
      shareButton.addEventListener("click", async () => {
        if (navigator.share) {
          try {
            await navigator.share({ title: shareTitle, url: shareUrl });
            return;
          } catch (error) {
            if (error && typeof error === "object" && error.name === "AbortError") {
              return;
            }
          }
        }

        const copied = await copyText(shareUrl);
        showShareToast(copied ? "Link copied" : "Could not copy link");
      });
    }

    if (themeToggle) {
      themeToggle.addEventListener("click", () => {
        state.theme = state.theme === THEME_DARK ? THEME_LIGHT : THEME_DARK;
        applyState();
        saveState();
      });
    }

    if (fontToggle) {
      fontToggle.addEventListener("click", () => {
        state.font = state.font === FONT_SERIF ? FONT_SANS : FONT_SERIF;
        applyState();
        saveState();
      });
    }

    if (sizeToggle) {
      sizeToggle.addEventListener("click", () => {
        const index = TEXT_SIZES.indexOf(state.textSize);
        const next = (index + 1) % TEXT_SIZES.length;
        state.textSize = TEXT_SIZES[next];
        applyState();
        saveState();
      });
    }

    if (settingsToggle) {
      settingsToggle.addEventListener("click", () => setOverlayOpen(true));
    }

    if (settingsClose) {
      settingsClose.addEventListener("click", () => setOverlayOpen(false));
    }

    if (settingsOverlay) {
      settingsOverlay.addEventListener("click", (event) => {
        if (event.target === settingsOverlay) {
          setOverlayOpen(false);
        }
      });
    }

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && settingsOverlay && !settingsOverlay.hidden) {
        setOverlayOpen(false);
      }
    });

    if (settingsForm) {
      settingsForm.addEventListener("submit", () => {
        if (themeField) themeField.value = state.theme;
      });
    }

    applyState();
    saveState();
  })();
  `;
}

function sharedAppCss() {
  return `
  :root{
    color-scheme: light dark;
    --bg:#ffffff;
    --ink:#111827;
    --muted:#4b5563;
    --line:#d9dee7;
    --soft:#edf1f6;
    --soft-2:#f8fafc;
    --accent:#0a66ff;
    --accent-ink:#ffffff;
    --code-bg:#eef3fb;
    --quote-line:#b6c5de;
    --reader-font-serif:"Iowan Old Style","Palatino Linotype","Book Antiqua",Palatino,serif;
    --reader-font-sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --reader-font-current:var(--reader-font-serif);
    --reader-size:19.5px;
    --reader-line:1.78;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0a0a0d;
      --ink:#e7ebf2;
      --muted:#a0abbb;
      --line:#2a3342;
      --soft:#1a2029;
      --soft-2:#161c24;
      --accent:#6ea8ff;
      --accent-ink:#0f172a;
      --code-bg:#111923;
      --quote-line:#5f78a0;
    }
  }
  body[data-theme="${THEME_LIGHT}"]{
    color-scheme: light;
    --bg:#ffffff;
    --ink:#111827;
    --muted:#4b5563;
    --line:#d9dee7;
    --soft:#edf1f6;
    --soft-2:#f8fafc;
    --accent:#0a66ff;
    --accent-ink:#ffffff;
    --code-bg:#eef3fb;
    --quote-line:#b6c5de;
  }
  body[data-theme="${THEME_DARK}"]{
    color-scheme: dark;
    --bg:#0a0a0d;
    --ink:#e7ebf2;
    --muted:#a0abbb;
    --line:#2a3342;
    --soft:#1a2029;
    --soft-2:#161c24;
    --accent:#6ea8ff;
    --accent-ink:#0f172a;
    --code-bg:#111923;
    --quote-line:#5f78a0;
  }
  body[data-font="serif"]{
    --reader-font-current:var(--reader-font-serif);
  }
  body[data-font="sans"]{
    --reader-font-current:var(--reader-font-sans);
  }
  body[data-text-size="sm"]{
    --reader-size:18px;
  }
  body[data-text-size="md"]{
    --reader-size:19.5px;
  }
  body[data-text-size="lg"]{
    --reader-size:21.5px;
  }
  *{box-sizing:border-box}
  html, body{height:100%}
  body{
    margin:0;
    color:var(--ink);
    background:var(--bg);
    font:400 16px/1.45 var(--reader-font-sans);
  }
  body.settings-open{overflow:hidden}
  .page{
    width:min(88ch, calc(100% - 2.6rem));
    margin:0 auto;
    padding:1.6rem 0 2.8rem;
  }
  .page-home{
    width:min(42rem, calc(100% - 2rem));
    padding-top:18vh;
  }
  header{
    margin-top: 4rem;
  }
  .header-row{
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:1rem;
  }
  h1, .brand{
    font:600 clamp(1.7rem, 3vw, 2.5rem)/1.15 "SF Pro Display","Avenir Next","Segoe UI",sans-serif;
    letter-spacing:.01em;
    margin:0 0 .65rem 0;
  }
  .header-row-article{
    padding-right:12.5rem;
  }
  .theme-toggle{
    display:flex;
    align-items:center;
    gap:.45rem;
  }
  .icon-btn{
    display:grid;
    place-items:center;
    width:2.35rem;
    height:2.35rem;
    border-radius:999px;
    border:1px solid var(--line);
    color:var(--muted);
    background:var(--soft);
    text-decoration:none;
    padding:0;
    font:inherit;
  }
  button.icon-btn{cursor:pointer}
  .icon-btn:hover{color:var(--ink); border-color:var(--accent)}
  .icon-btn.is-active{
    color:var(--accent-ink);
    background:var(--accent);
    border-color:var(--accent);
  }
  .icon-btn svg, .search-btn svg{width:1.15rem; height:1.15rem}
  #themeIcon{
    display:grid;
    place-items:center;
    width:1.15rem;
    height:1.15rem;
  }
  #themeIcon svg{width:1.15rem; height:1.15rem}
  .font-icon{
    display:block;
    line-height:1;
    font-size:1.2rem;
  }
  .font-icon-serif{
    font-family:Georgia, "Times New Roman", serif;
    font-weight:700;
  }
  .font-icon-cursive{
    font-family:"Snell Roundhand", "Segoe Script", "Apple Chancery", cursive;
    font-style:italic;
    font-size:1.25rem;
  }
  .size-icon{
    display:block;
    line-height:1;
    font-family:Georgia, "Times New Roman", serif;
    font-weight:600;
  }
  .size-icon.size-sm{font-size:.88rem}
  .size-icon.size-md{font-size:1.05rem}
  .size-icon.size-lg{font-size:1.24rem}
  .corner-controls{
    position:fixed;
    top:.95rem;
    right:1rem;
    display:flex;
    gap:.45rem;
    z-index:25;
  }
  .share-toast{
    position:fixed;
    left:50%;
    bottom:1.2rem;
    transform:translateX(-50%);
    z-index:48;
    color:var(--accent-ink);
    background:var(--accent);
    border-radius:999px;
    padding:.52rem .85rem;
    font:600 .83rem/1 "SF Pro Text","Avenir Next","Segoe UI",sans-serif;
    letter-spacing:.01em;
    opacity:0;
    transition:opacity .16s ease-out;
    pointer-events:none;
  }
  .share-toast.is-visible{opacity:1}
  .share-toast[hidden]{display:none !important}
  .search-form{
    display:flex;
    align-items:center;
    gap:.35rem;
    margin:.35rem 0 .85rem;
    padding:.3rem;
    border-radius:999px;
    border:1px solid var(--line);
    background:linear-gradient(180deg, var(--soft-2), var(--soft));
    box-shadow:0 10px 28px rgba(10,18,35,.11);
  }
  .search-form input{
    flex:1;
    min-width:0;
    border:0;
    outline:0;
    color:var(--ink);
    background:transparent;
    font:500 1rem/1.25 "SF Pro Text","Avenir Next","Segoe UI",sans-serif;
    padding:.72rem 1rem;
  }
  .search-form input::placeholder{color:var(--muted)}
  .search-btn{
    display:grid;
    place-items:center;
    width:2.7rem;
    height:2.7rem;
    border:0;
    border-radius:999px;
    cursor:pointer;
    background:var(--accent);
    color:var(--accent-ink);
  }
  .meta{
    color:var(--muted);
    font:500 .94rem/1.35 "SF Pro Text","Avenir Next","Segoe UI",sans-serif;
    margin-top:.2rem;
    margin-bottom:1.5rem;
    word-break:break-word;
  }
  .btn{
    display:inline-block;
    color:var(--ink);
    text-decoration:none;
    font:600 .84rem/1 "SF Pro Text","Avenir Next","Segoe UI",sans-serif;
    letter-spacing:.02em;
    padding:.52rem .72rem;
    border:1px solid var(--line);
    border-radius:999px;
    background:var(--soft);
  }
  .btn:hover{border-color:var(--accent); color:var(--accent)}
  .btn.is-active{
    color:var(--accent-ink);
    background:var(--accent);
    border-color:var(--accent);
  }
  .settings-original-btn{
    align-self:flex-start;
  }
  .settings-overlay{
    position:fixed;
    inset:0;
    z-index:40;
    background:color-mix(in oklab, var(--bg) 84%, black 16%);
    padding:1rem;
  }
  .settings-overlay[hidden]{display:none !important}
  .settings-view{
    width:100%;
    height:100%;
    overflow:auto;
    padding:clamp(1rem, 4vw, 2rem);
    display:flex;
    flex-direction:column;
    gap:1rem;
  }
  .settings-head{
    display:flex;
    align-items:center;
    justify-content:flex-start;
    gap:.75rem;
  }
  .settings-head h2{
    margin:0;
    font:600 clamp(1.2rem, 2.4vw, 1.65rem)/1.2 "SF Pro Display","Avenir Next","Segoe UI",sans-serif;
  }
  .close-btn{
    position:fixed;
    top:.95rem;
    right:1rem;
    z-index:45;
  }
  .settings-form{
    width:min(48rem, 100%);
    display:flex;
    flex-direction:column;
    gap:.7rem;
  }
  .settings-form label{
    font:600 .92rem/1.3 "SF Pro Text","Avenir Next","Segoe UI",sans-serif;
    letter-spacing:.01em;
    color:var(--muted);
  }
  .search-form-overlay{
    margin:0 0 .35rem;
  }
  .select-wrap{
    position:relative;
    width:min(16rem, 100%);
  }
  .select-wrap::after{
    content:"";
    position:absolute;
    top:50%;
    right:.9rem;
    width:.5rem;
    height:.5rem;
    border-right:2px solid var(--muted);
    border-bottom:2px solid var(--muted);
    transform:translateY(-70%) rotate(45deg);
    pointer-events:none;
  }
  .select-wrap select{
    appearance:none;
    width:100%;
    border:1px solid var(--line);
    border-radius:.78rem;
    background:var(--soft);
    color:var(--ink);
    font:600 .95rem/1.2 "SF Pro Text","Avenir Next","Segoe UI",sans-serif;
    padding:.78rem 2.2rem .78rem .84rem;
    outline:0;
  }
  .select-wrap select:focus{
    border-color:var(--accent);
  }
  main{
    margin-top:.4rem;
    font-family:var(--reader-font-current);
    font-size:var(--reader-size);
    line-height:var(--reader-line);
    text-wrap:pretty;
  }
  main h2, main h3{
    font:600 1.22rem/1.3 "SF Pro Display","Avenir Next","Segoe UI",sans-serif;
    margin:2rem 0 .72rem;
  }
  main p{margin:0 0 1.45rem}
  main a{word-break:break-word; color:var(--accent)}
  main ul, main ol{padding-left:1.35rem; margin:0 0 1.5rem}
  main li{margin:.34rem 0}
  main img{
    display:block;
    max-width:min(100%, 44rem);
    width:auto;
    height:auto;
    max-height:52vh;
    object-fit:contain;
    margin:0 auto 1.5rem;
    border-radius:10px;
  }
  main blockquote{
    margin:0 0 1.55rem;
    padding:.08rem 0 .08rem 1rem;
    border-left:3px solid var(--quote-line);
    color:var(--muted);
  }
  code, pre{font-family:"SF Mono","Menlo","Consolas",monospace}
  pre{
    white-space:pre-wrap;
    word-wrap:break-word;
    padding:1rem;
    border-radius:.6rem;
    background:var(--code-bg);
    border:1px solid var(--line);
    overflow:auto;
    margin:0 0 1.55rem;
  }
  @media (max-width: 720px){
    .page{width:calc(100% - 3rem); padding-top:1.2rem}
    .page-home{padding-top:13vh}
    .header-row{align-items:center}
    .header-row-article{
      padding-right:10.1rem;
    }
    .corner-controls{
      top:.75rem;
      right:.74rem;
      gap:.34rem;
    }
    .icon-btn{
      width:2.15rem;
      height:2.15rem;
    }
    body[data-text-size="sm"]{--reader-size:17.2px}
    body[data-text-size="md"]{--reader-size:18.3px}
    body[data-text-size="lg"]{--reader-size:19.4px}
    .settings-overlay{
      padding:.5rem;
    }
    .settings-view{
      padding:1rem .8rem 1.3rem;
    }
    .close-btn{
      top:.75rem;
      right:.74rem;
    }
  }
  @media print{
    @page{
      size:auto;
      margin:14mm 12mm 16mm;
    }
    :root{
      color-scheme: light;
    }
    body{
      background:#fff !important;
      color:#000 !important;
      font-size:10.5pt !important;
      line-height:1.4 !important;
    }
    .corner-controls,
    .settings-overlay,
    .share-toast{
      display:none !important;
    }
    .page{
      width:100% !important;
      max-width:none !important;
      padding:0 !important;
      margin:0 !important;
    }
    header{
      margin-bottom:.45rem;
    }
    h1{
      font-size:14pt !important;
      line-height:1.2 !important;
      margin:0 0 .2rem !important;
    }
    .meta{
      margin:0 0 .55rem !important;
      font-size:8.7pt !important;
      line-height:1.25 !important;
    }
    .meta a{
      color:#000 !important;
      text-decoration:none;
    }
    main{
      font-size:10.5pt !important;
      line-height:1.42 !important;
      margin-top:0 !important;
    }
    main h2, main h3{
      font-size:11.5pt !important;
      line-height:1.25 !important;
      margin:1.05em 0 .4em !important;
    }
    main p{
      margin:0 0 .75em !important;
    }
    main ul, main ol{
      margin:0 0 .75em !important;
    }
    main pre{
      font-size:9pt !important;
      line-height:1.35 !important;
      margin:0 0 .85em !important;
    }
    main img{
      max-height:95mm !important;
      margin:.2em auto .85em !important;
    }
    main img, main pre, main blockquote{
      break-inside:avoid;
      page-break-inside:avoid;
    }
  }`;
}

function mirrorNoJs(originResponse) {
  const rewriter = new HTMLRewriter()
    .on("script,noscript,template", { element: (element) => element.remove() })
    .on("iframe,object,embed", { element: (element) => element.remove() })
    .on('meta[http-equiv="refresh" i]', { element: (element) => element.remove() })
    .on("base", { element: (element) => element.remove() })
    .on("*", {
      element: (element) => {
        for (const [name] of element.attributes) {
          if (name.toLowerCase().startsWith("on")) element.removeAttribute(name);
        }

        const href = element.getAttribute("href");
        if (href && !isSafeLinkValue(href, false)) {
          element.removeAttribute("href");
        }

        const src = element.getAttribute("src");
        if (src && !isSafeLinkValue(src, true)) {
          element.removeAttribute("src");
        }

        if (element.getAttribute("srcdoc")) {
          element.removeAttribute("srcdoc");
        }
      },
    })
    .on("head", {
      element: (element) => {
        element.append(
          `<meta name="viewport" content="width=device-width, initial-scale=1" />
           <style>
             :root{color-scheme: light dark}
             body{
               margin:0 auto;
               max-width:94ch;
               padding:2rem 1rem 3rem;
               font:18px/1.62 "Iowan Old Style","Palatino Linotype","Book Antiqua",Palatino,serif;
             }
             img{max-width:100%; height:auto}
             pre,code{font-family:"SF Mono","Menlo","Consolas",monospace}
           </style>`,
          { html: true },
        );
      },
    });

  const output = rewriter.transform(originResponse);
  return new Response(output.body, {
    status: output.status,
    headers: hardenedHeaders("text/html; charset=utf-8"),
  });
}

function stripDangerous(html) {
  let output = html;

  output = output.replace(/<!--[\s\S]*?-->/g, "");
  output = output.replace(
    /<(script|style|noscript|template|iframe|object|embed)\b[\s\S]*?<\/\1>/gi,
    "",
  );
  output = output.replace(/<meta\b[^>]*http-equiv\s*=\s*("|')?refresh\1?[^>]*>/gi, "");
  output = output.replace(/<base\b[^>]*>/gi, "");
  output = output.replace(/\son[a-z0-9_-]+\s*=\s*(".*?"|'.*?'|[^\s>]+)/gi, "");
  output = output.replace(/\ssrcdoc\s*=\s*(".*?"|'.*?'|[^\s>]+)/gi, "");
  output = output.replace(
    /\s(?:href|src)\s*=\s*("|')\s*(?:javascript|vbscript|data:text\/html)[\s\S]*?\1/gi,
    "",
  );
  output = output.replace(
    /\s(?:href|src)\s*=\s*(?:javascript|vbscript|data:text\/html)[^\s>]+/gi,
    "",
  );

  return output;
}

function extractTitle(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return "";
  return decodeEntities(stripTags(match[1]).trim());
}

function extractTagChunk(html, tag) {
  const regex = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const match = html.match(regex);
  return match ? match[1] : "";
}

function extractBestBlock(html) {
  const candidates = [];
  const regex = /<(div|section)\b([^>]*)>([\s\S]*?)<\/\1>/gi;

  let match;
  let safety = 0;

  while (safety++ < 2500) {
    match = regex.exec(html);
    if (!match) break;

    const attrs = match[2] || "";
    const inner = match[3] || "";
    const textLength = stripTags(inner).trim().length;
    if (textLength < 400) continue;

    const pCount = (inner.match(/<p\b/gi) || []).length;
    const liCount = (inner.match(/<li\b/gi) || []).length;
    const anchorCount = (inner.match(/<a\b/gi) || []).length;
    const attrLower = attrs.toLowerCase();

    const hasBadSignals =
      /(nav|menu|footer|header|aside|sidebar|cookie|consent|subscribe|signup|login|comment|related|breadcrumb|promo|ad-|ads|banner)/i.test(
        attrLower,
      );
    const hasGoodSignals = /(article|content|post|entry|story|body|main|text)/i.test(attrLower);

    let score = textLength + pCount * 400 + liCount * 130;

    if (anchorCount > (pCount + liCount + 1) * 4) score *= 0.65;
    if (hasBadSignals) score *= 0.35;
    if (hasGoodSignals) score *= 1.15;

    candidates.push({ score, inner });
  }

  if (!candidates.length) return "";
  candidates.sort((a, b) => b.score - a.score);
  return candidates[0].inner;
}

function toReadableHtml(chunk, baseUrl) {
  let output = chunk;

  output = normalizeHeadings(output);
  output = normalizeBlockquotes(output);
  output = normalizePreformatted(output);
  output = normalizeLists(output);

  output = output.replace(/<\/(p|div|section|article|main)>/gi, "\n\n");
  output = output.replace(/<br\s*\/?>/gi, "\n");

  output = stripUnsafeTagsButKeepKnown(output, baseUrl);
  output = splitOutStandaloneImages(output);
  output = output.replace(/\n{3,}/g, "\n\n").trim();

  const parts = output.split(/\n{2,}/);
  const blocks = [];

  for (const part of parts) {
    const candidate = part.trim();
    if (!candidate) continue;

    if (
      /^<(h2|h3|blockquote|pre|ul|ol|img)\b/i.test(candidate) ||
      isStandaloneImageLink(candidate)
    ) {
      blocks.push(candidate);
      continue;
    }

    const inline = stripBlockTags(candidate).trim();
    if (containsAllowedInlineMarkup(inline)) {
      const inlineParts = splitInlineImageBlocks(inline);

      for (const inlinePart of inlineParts) {
        if (isStandaloneImageBlock(inlinePart)) {
          blocks.push(inlinePart);
          continue;
        }

        if (hasMeaningfulInlineContent(inlinePart)) {
          blocks.push(`<p>${inlinePart}</p>`);
        }
      }

      continue;
    }

    const text = sanitizeReadableText(decodeEntities(stripTags(candidate)));
    if (shouldKeepTextBlock(text)) blocks.push(`<p>${escapeHtml(text)}</p>`);
  }

  return blocks.join("\n");
}

function normalizeHeadings(html) {
  return html.replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi, (_, level, inner) => {
    const text = sanitizeReadableText(decodeEntities(stripTags(inner)));
    if (!shouldKeepTextBlock(text)) return "";
    const tag = Number.parseInt(level, 10) <= 2 ? "h2" : "h3";
    return `\n\n<${tag}>${escapeHtml(text)}</${tag}>\n\n`;
  });
}

function normalizeBlockquotes(html) {
  return html.replace(/<blockquote\b[^>]*>([\s\S]*?)<\/blockquote>/gi, (_, inner) => {
    const text = sanitizeReadableText(decodeEntities(stripTags(inner)));
    if (!shouldKeepTextBlock(text)) return "";
    return `\n\n<blockquote>${escapeHtml(text)}</blockquote>\n\n`;
  });
}

function normalizePreformatted(html) {
  return html.replace(/<pre\b[^>]*>([\s\S]*?)<\/pre>/gi, (_, inner) => {
    const withoutCodeTags = inner.replace(/<code\b[^>]*>/gi, "").replace(/<\/code>/gi, "");
    const text = decodeEntities(stripTags(withoutCodeTags)).trim();
    if (!text) return "";
    return `\n\n<pre>${escapeHtml(text)}</pre>\n\n`;
  });
}

function normalizeLists(html) {
  return html.replace(/<(ul|ol)\b[^>]*>([\s\S]*?)<\/\1>/gi, (_, listTag, inner) => {
    const items = [];
    const itemRegex = /<li\b[^>]*>([\s\S]*?)<\/li>/gi;

    let match;
    let safety = 0;
    while (safety++ < 300) {
      match = itemRegex.exec(inner);
      if (!match) break;

      const text = sanitizeReadableText(decodeEntities(stripTags(match[1])));
      if (shouldKeepTextBlock(text)) items.push(`<li>${escapeHtml(text)}</li>`);
    }

    if (!items.length) return "";

    const tag = listTag.toLowerCase();
    return `\n\n<${tag}>${items.join("")}</${tag}>\n\n`;
  });
}

function stripUnsafeTagsButKeepKnown(html, baseUrl) {
  const simpleTags = new Set(["h2", "h3", "blockquote", "pre", "ul", "ol", "li"]);

  return html.replace(/<\/?([a-z0-9]+)\b[^>]*>/gi, (fullTag, rawTag) => {
    const tag = rawTag.toLowerCase();
    const isClosing = fullTag.startsWith("</");

    if (simpleTags.has(tag)) {
      return isClosing ? `</${tag}>` : `<${tag}>`;
    }

    if (tag === "a") {
      if (isClosing) return "</a>";
      const href = getHtmlAttribute(fullTag, "href");
      if (!href) return "";
      const absoluteHref = absolutizeUrl(baseUrl, href);
      if (!absoluteHref || !isSafeLinkValue(absoluteHref, false)) return "";
      return `<a rel="noreferrer noopener" href="${escapeHtml(absoluteHref)}">`;
    }

    if (tag === "img") {
      if (isClosing) return "";
      const src = getHtmlAttribute(fullTag, "src");
      if (!src) return "";
      const absoluteSrc = absolutizeUrl(baseUrl, src);
      if (!absoluteSrc || !isSafeLinkValue(absoluteSrc, true)) return "";
      const alt = getHtmlAttribute(fullTag, "alt");
      if (shouldDropImageTag(fullTag, alt)) return "";
      return `<img src="${escapeHtml(absoluteSrc)}" alt="${escapeHtml(alt)}" />`;
    }

    return "";
  });
}

function stripBlockTags(html) {
  return html.replace(/<\/?(h2|h3|blockquote|pre|ul|ol|li)\b[^>]*>/gi, "");
}

function containsAllowedInlineMarkup(html) {
  return /<(a|img)\b/i.test(html);
}

function hasMeaningfulInlineContent(html) {
  const plainText = sanitizeReadableText(decodeEntities(stripTags(html)));
  if (plainText && shouldKeepTextBlock(plainText)) return true;
  return /<img\b/i.test(html);
}

function splitOutStandaloneImages(html) {
  return html
    .replace(/(<a\b[^>]*>\s*<img\b[^>]*>\s*<\/a>)/gi, "\n\n$1\n\n")
    .replace(/(<img\b[^>]*>)/gi, "\n\n$1\n\n");
}

function splitInlineImageBlocks(html) {
  return splitOutStandaloneImages(html)
    .split(/\n{2,}/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function isStandaloneImageLink(html) {
  return /^<a\b[^>]*>\s*<img\b[^>]*>\s*<\/a>$/i.test(html);
}

function isStandaloneImageBlock(html) {
  return /^<img\b[^>]*>$/i.test(html) || isStandaloneImageLink(html);
}

function sanitizeReadableText(text) {
  let output = text.replace(/([a-z])([A-Z])/g, "$1 $2");
  output = output.replace(/\s+/g, " ").trim();
  output = collapseExactRepeatedSegments(output);
  output = output.replace(/\s+/g, " ").trim();
  return output;
}

function collapseExactRepeatedSegments(text) {
  if (!text || text.length < 8) return text;

  for (let repeat = 4; repeat >= 2; repeat--) {
    if (text.length % repeat !== 0) continue;

    const segmentLength = text.length / repeat;
    const firstSegment = text.slice(0, segmentLength);
    if (!firstSegment.trim()) continue;

    let allMatch = true;
    for (let index = 1; index < repeat; index++) {
      const segment = text.slice(index * segmentLength, (index + 1) * segmentLength);
      if (segment !== firstSegment) {
        allMatch = false;
        break;
      }
    }

    if (allMatch) return firstSegment.trim();
  }

  return text;
}

function shouldKeepTextBlock(text) {
  if (!text) return false;
  return !isLikelyUiChromeText(text);
}

function isLikelyUiChromeText(text) {
  const normalized = text.toLowerCase().trim();
  if (!normalized) return true;

  if (normalized.length <= 80 && UI_CHROME_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return true;
  }

  const words = normalized
    .split(/\s+/)
    .map((word) => word.replace(/[^a-z0-9]/g, ""))
    .filter(Boolean);

  if (words.length >= 4 && words.length <= 10) {
    const uniqueWordCount = new Set(words).size;
    if (uniqueWordCount <= Math.ceil(words.length / 3)) return true;
  }

  return false;
}

function getHtmlAttribute(tagMarkup, attributeName) {
  const regex = new RegExp(`\\b${attributeName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const match = tagMarkup.match(regex);
  if (!match) return "";
  return (match[1] || match[2] || match[3] || "").trim();
}

function getNumericHtmlAttribute(tagMarkup, attributeName) {
  const value = getHtmlAttribute(tagMarkup, attributeName);
  if (!value) return null;

  const numericValue = Number.parseInt(value, 10);
  if (!Number.isFinite(numericValue) || numericValue <= 0) return null;
  return numericValue;
}

function shouldDropImageTag(tagMarkup, altText) {
  const lowerMarkup = tagMarkup.toLowerCase();
  const width = getNumericHtmlAttribute(tagMarkup, "width");
  const height = getNumericHtmlAttribute(tagMarkup, "height");
  const hasUiHints =
    /(avatar|author|profile|headshot|icon|logo|badge|sprite|tracking|pixel|newsletter)/i.test(
      lowerMarkup,
    );

  if (width && height && width <= 64 && height <= 64) return true;
  if (hasUiHints && width && height && width <= 220 && height <= 220) return true;

  const alt = altText.trim().toLowerCase();
  if (hasUiHints && alt && alt.length <= 80) return true;

  return false;
}

function isSafeLinkValue(rawUrl, allowDataImage) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      return true;
    }

    if (!allowDataImage) return false;
    return /^data:image\//i.test(rawUrl);
  } catch {
    return false;
  }
}

function absolutizeUrl(baseUrl, href) {
  try {
    return new URL(href, baseUrl).toString();
  } catch {
    return "";
  }
}

function stripTags(value) {
  return value.replace(/<[^>]+>/g, "");
}

function decodeEntities(value) {
  return value
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, number) => String.fromCharCode(Number.parseInt(number, 10)));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[char];
  });
}
