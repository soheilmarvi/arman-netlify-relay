const ALLOWED_HOSTS = [
  "mozilla.org",
  "mozilla.com",
  "firefox.com",
  "github.com",
  "githubusercontent.com",
  "jsdelivr.net",
];

const DROP_HEADERS = new Set([
  "host", "connection", "content-length", "keep-alive",
  "proxy-authenticate", "proxy-authorization", "te", "trailer",
  "transfer-encoding", "upgrade", "forwarded", "x-forwarded-for",
  "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "true-client-ip",
]);

function fail(status, message) {
  return new Response(message, {
    status,
    headers: {
      "X-Relay-Error": message,
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function healthResponse() {
  return new Response(JSON.stringify({ relay: "arman-vpn", version: 1, ready: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

function statusPage(kind) {
  const states = {
    ready: {
      color: "#10b981",
      badge: "✓ Working",
      title: "Your relay is ready",
      text: "Put this page's address in Arman VPN, including its secret.",
    },
    wrong: {
      color: "#ef4444",
      badge: "✗ Wrong secret",
      title: "This address has no secret, or the wrong one",
      text: "It must include ?secret= followed by the SECRET configured in Netlify.",
    },
    unset: {
      color: "#f59e0b",
      badge: "⚠ Not set up",
      title: "Set a secret first",
      text: "Add the SECRET environment variable in Netlify and redeploy.",
    },
  };
  const state = states[kind];
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Arman VPN relay</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box;background:#eef0fb;color:#1d2040;font:16px/1.6 system-ui}main{max-width:560px;width:100%;background:white;border-radius:20px;padding:32px;box-shadow:0 20px 60px #18204a22;border-top:5px solid ${state.color}}small{color:#68708e;font-weight:700}.badge{display:inline-block;margin-top:22px;padding:5px 12px;border-radius:30px;background:${state.color}20;color:${state.color};font-weight:700}h1{font-size:24px;margin:14px 0 8px}p{color:#626985}</style><main><small>Arman VPN relay · Netlify</small><div class="badge">${state.badge}</div><h1>${state.title}</h1><p>${state.text}</p></main></html>`;
  return new Response(html, {
    status: kind === "ready" ? 200 : kind === "wrong" ? 403 : 503,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export default async function handler(request) {
  const incoming = new URL(request.url);
  const isHealth = incoming.searchParams.get("health") === "1";
  const isBrowser = !incoming.searchParams.has("url") && !isHealth;
  const secret = Netlify.env.get("SECRET") || "";

  if (!secret) return isBrowser ? statusPage("unset") : fail(503, "no secret is set in the relay");
  if (incoming.searchParams.get("secret") !== secret) {
    return isBrowser ? statusPage("wrong") : fail(403, "wrong secret");
  }

  if (isHealth) {
    if (request.method !== "GET") return fail(405, "health requires GET");
    return healthResponse();
  }

  if (isBrowser) return statusPage("ready");

  let target;
  try {
    target = new URL(incoming.searchParams.get("url") || "");
  } catch {
    return fail(400, "url must be an https URL");
  }

  if (target.protocol !== "https:") return fail(400, "url must be an https URL");
  if (target.username || target.password || target.hash || (target.port && target.port !== "443")) {
    return fail(400, "target must not contain credentials, a fragment or a non-HTTPS port");
  }

  const host = target.hostname.toLowerCase();
  if (!ALLOWED_HOSTS.some((domain) => host === domain || host.endsWith(`.${domain}`))) {
    return fail(403, `host not allowed: ${host}`);
  }

  const headers = new Headers();
  for (const [name, value] of request.headers) {
    const lower = name.toLowerCase();
    if (DROP_HEADERS.has(lower) || lower.startsWith("cf-")) continue;
    headers.set(name, value);
  }

  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;

  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers,
      body,
      redirect: "manual",
    });
    const responseHeaders = new Headers(upstream.headers);
    responseHeaders.set("X-Arman-Relay", "1");
    responseHeaders.set("Cache-Control", "no-store");
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  } catch {
    return fail(502, "upstream request failed");
  }
}

export const config = { path: "/*" };
