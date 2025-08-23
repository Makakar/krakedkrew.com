export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") return handleOptions(req, env);

    // Auth
    if (url.pathname === "/auth/login" && req.method === "GET")    return twitchLogin(req, env);
    if (url.pathname === "/auth/callback" && req.method === "GET") return twitchCallback(req, env);
    if (url.pathname === "/auth/logout" && req.method === "POST")  return twitchLogout(req, env);

    // Viewer APIs
    if (url.pathname === "/api/me" && req.method === "GET")        return meSummary(req, env);
    if (url.pathname === "/api/commands" && req.method === "POST") return commandsOut(req, env);

    // Streamer.bot signed ingest
    if (url.pathname === "/api/streamerbot" && req.method === "POST") return streamerbotIn(req, env);

    // Realtime
    if (url.pathname === "/sse" && req.method === "GET")           return ssePublic(req, env);
    if (url.pathname === "/sse/me" && req.method === "GET")        return sseMe(req, env);

    // Static files
    return env.ASSETS.fetch(req);
  }
};

/* ------------------ CORS ------------------ */
function corsHeaders(env) {
  const allowed = (env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim()).filter(Boolean);
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-CSRF-Token, X-SB-Signature",
    "Access-Control-Allow-Credentials": "true",
  };
  return { allowed, headers };
}

function originOK(req, env) {
  const { allowed } = corsHeaders(env);
  const ori = req.headers.get("Origin") || "";
  return !ori || allowed.some(a => matchesOrigin(ori, a));
}
function matchesOrigin(origin, pat) {
  if (pat.includes("*")) {
    const re = new RegExp("^" + pat.replace(/\./g,"\\.").replace(/\*/g,".*") + "$");
    return re.test(origin);
  }
  return origin === pat;
}

function withCors(res, req, env) {
  const { headers } = corsHeaders(env);
  const h = new Headers(res.headers);
  if (originOK(req, env)) {
    const origin = req.headers.get("Origin");
    if (origin) h.set("Access-Control-Allow-Origin", origin);
  }
  for (const [k,v] of Object.entries(headers)) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
}

function handleOptions(req, env) {
  // Preflight
  return withCors(new Response(null, { status: 204 }), req, env);
}

function json(data, status=200) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" }});
}

/* ------------------ Sessions ------------------ */
async function getSession(req, env) {
  const sid = (req.headers.get("Cookie") || "").match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
  if (!sid) return null;
  return await env.SESSIONS.get(`sess:${sid}`, { type: "json" });
}

async function setSession(env, payload) {
  const sid = crypto.randomUUID();
  await env.SESSIONS.put(`sess:${sid}`, JSON.stringify(payload), { expirationTtl: 60*60*24*7 });
  return sid;
}

function clearSessionCookie() {
  return "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}

/* ------------------ Twitch OAuth ------------------ */
async function twitchLogin(req, env) {
  const params = new URLSearchParams({
    client_id: env.TWITCH_CLIENT_ID,
    redirect_uri: env.OAUTH_REDIRECT_URI,
    response_type: "code",
    scope: "openid user:read:email",
  });
  return Response.redirect(`https://id.twitch.tv/oauth2/authorize?${params}`, 302);
}

async function twitchCallback(req, env) {
  const code = new URL(req.url).searchParams.get("code");
  if (!code) return withCors(json({ ok:false, error:"no_code" }, 400), req, env);

  const body = new URLSearchParams({
    client_id: env.TWITCH_CLIENT_ID,
    client_secret: env.TWITCH_CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: env.OAUTH_REDIRECT_URI,
  });
  const r = await fetch("https://id.twitch.tv/oauth2/token", { method: "POST", body });
  if (!r.ok) return withCors(json({ ok:false, error:"token_exchange_failed" }, 500), req, env);
  const tokens = await r.json(); // { access_token, id_token, ... }

  const uRes = await fetch("https://api.twitch.tv/helix/users", {
    headers: { "Authorization": `Bearer ${tokens.access_token}`, "Client-Id": env.TWITCH_CLIENT_ID }
  });
  if (!uRes.ok) return withCors(json({ ok:false, error:"user_fetch_failed" }, 500), req, env);
  const userData = (await uRes.json()).data?.[0];
  if (!userData) return withCors(json({ ok:false, error:"no_user" }, 400), req, env);

  // Upsert identity
  const now = Date.now();
  await env.DB.prepare(
    `INSERT OR REPLACE INTO identities(provider, provider_user_id, user_id, display_name, avatar_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(
    "twitch",
    userData.id,
    userData.id, // use twitch id as user_id
    userData.display_name || userData.login,
    userData.profile_image_url || null,
    now
  ).run();

  // Create session
  const sid = await setSession(env, {
    user_id: userData.id,
    provider: "twitch",
    provider_user_id: userData.id,
    display_name: userData.display_name || userData.login,
    avatar_url: userData.profile_image_url || null
  });

  const h = new Headers({ "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60*60*24*7}`, "Location": "/app/dashboard.html" });
  return new Response(null, { status: 302, headers: h });
}

async function twitchLogout(req, env) {
  const h = new Headers({ "Set-Cookie": clearSessionCookie() });
  return withCors(new Response(null, { status: 200, headers: h }), req, env);
}

/* ------------------ Viewer APIs ------------------ */
async function meSummary(req, env) {
  const s = await getSession(req, env);
  if (!s?.user_id) return withCors(json({ ok:false, error:"unauthorized" }, 401), req, env);

  // current campaign (pick the one active now; fallback to most recent)
  const now = Date.now();
  let campaign = await env.DB.prepare(
    `SELECT * FROM campaigns WHERE (starts_at IS NULL OR starts_at<=?) AND (ends_at IS NULL OR ends_at>=?)
     ORDER BY starts_at DESC LIMIT 1`
  ).bind(now, now).first();

  if (!campaign) {
    campaign = await env.DB.prepare(`SELECT * FROM campaigns ORDER BY starts_at DESC LIMIT 1`).first();
  }

  // points balance
  const p = await env.DB.prepare(`SELECT COALESCE(SUM(points_delta), 0) AS bal FROM points_ledger WHERE user_id=?`).bind(s.user_id).first();
  const pointsBalance = Number(p?.bal || 0);

  // my tickets
  let myTickets = 0;
  if (campaign) {
    const t = await env.DB.prepare(
      `SELECT COALESCE(SUM(tickets_delta), 0) AS bal FROM tickets_ledger WHERE user_id=? AND campaign_id=?`
    ).bind(s.user_id, campaign.campaign_id).first();
    myTickets = Number(t?.bal || 0);
  }

  return withCors(json({
    ok: true,
    user: { id: s.user_id, displayName: s.display_name, avatarUrl: s.avatar_url },
    pointsBalance,
    myTickets,
    giveaway: campaign ? {
      id: campaign.campaign_id,
      title: campaign.title,
      description: campaign.description,
      endsAt: campaign.ends_at ? new Date(campaign.ends_at).toISOString() : null
    } : null
  }), req, env);
}

/* ------------------ Site → Streamer.bot ------------------ */
async function commandsOut(req, env) {
  if (!originOK(req, env)) return withCors(json({ ok:false, error:"bad_origin" }, 403), req, env);

  const s = await getSession(req, env);
  if (!s?.user_id) return withCors(json({ ok:false, error:"unauthorized" }, 401), req, env);

  const text = await req.text();
  let cmd;
  try { cmd = JSON.parse(text); } catch { return withCors(json({ ok:false, error:"bad_json" }, 400), req, env); }

  const allowed = new Set(["tickets.buy","tickets.sell"]);
  if (!allowed.has(cmd.type)) return withCors(json({ ok:false, error:"forbidden_type" }, 403), req, env);

  // Basic validation/clamps
  const maxPerCall = Number(env.MAX_TICKETS_PER_CALL || "10000");
  const qty = Math.max(1, Math.min(Number(cmd.quantity || 0), maxPerCall));

  // Forward to your private SB webhook URL (set in secret STREAMERBOT_WEBHOOK_URL)
  const payload = {
    type: cmd.type,
    quantity: qty,
    userId: s.user_id,
    traceId: crypto.randomUUID()
  };

  const r = await fetch(env.STREAMERBOT_WEBHOOK_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!r.ok) return withCors(json({ ok:false, error:"sb_failed", status: r.status }), req, env);
  return withCors(json({ ok:true }), req, env);
}

/* ------------------ Streamer.bot → Site (signed ingest) ------------------ */
async function hmacHex(secret, body) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

async function streamerbotIn(req, env) {
  const body = await req.text();
  const headerSig = req.headers.get("X-SB-Signature") || "";
  const expected = await hmacHex(env.INGEST_SECRET, body);
  if (headerSig !== expected) return withCors(json({ ok:false, error:"unauthorized" }, 401), req, env);

  // Expected payload from SB (examples):
  // { eventId, userId, pointsDelta?, ticketsDelta?, campaignId?, reason?, metadata? }
  let dto;
  try { dto = JSON.parse(body); } catch { return withCors(json({ ok:false, error:"bad_json" }, 400), req, env); }
  const now = Date.now();
  const ops = [];

  if (typeof dto.pointsDelta === "number" && dto.pointsDelta !== 0) {
    ops.push(
      env.DB.prepare(
        `INSERT INTO points_ledger(event_id, user_id, points_delta, reason, trace_id, created_at, metadata)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(dto.eventId, dto.userId, dto.pointsDelta, dto.reason || "sb", dto.traceId || null, now, dto.metadata ? JSON.stringify(dto.metadata) : null)
    );
  }
  if (typeof dto.ticketsDelta === "number" && dto.ticketsDelta !== 0 && dto.campaignId) {
    ops.push(
      env.DB.prepare(
        `INSERT INTO tickets_ledger(event_id, campaign_id, user_id, tickets_delta, trace_id, created_at, metadata)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(dto.eventId, dto.campaignId, dto.userId, dto.ticketsDelta, dto.traceId || null, now, dto.metadata ? JSON.stringify(dto.metadata) : null)
    );
  }

  if (ops.length === 0) return withCors(json({ ok:false, error:"no_op" }, 400), req, env);

  try {
    await env.DB.batch(ops);
  } catch (e) {
    // Idempotency: if the event_id already exists, treat as OK
    if (!/UNIQUE|PRIMARY KEY|constraint/i.test(String(e?.message || ""))) throw e;
  }

  // Ping SSE bus (public + user-scoped)
  const stub = env.BUS.get(env.BUS.idFromName("global"));
  await stub.fetch("https://bus/publish", {
    method: "POST",
    body: JSON.stringify({
      type: "update",
      userId: dto.userId,
      campaignId: dto.campaignId || null
    })
  });

  return withCors(json({ ok:true }), req, env);
}

/* ------------------ SSE (Durable Object Bus) ------------------ */
export class Bus {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.publicSubs = new Set(); // all listeners
    this.userSubs = new Map();   // userId -> Set(streams)
  }
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/publish" && req.method === "POST") {
      const msg = await req.json();
      // broadcast to everyone
      for (const c of this.publicSubs) c.controller.enqueue(encodeSSE({ event:"tick", data: msg }));
      // and to user-specific
      if (msg.userId && this.userSubs.has(msg.userId)) {
        for (const c of this.userSubs.get(msg.userId)) c.controller.enqueue(encodeSSE({ event:"me", data: msg }));
      }
      return new Response("ok");
    }
    if (url.pathname === "/sse" && req.method === "GET") {
      return this.makeStream(this.publicSubs, null);
    }
    if (url.pathname === "/sse/me" && req.method === "POST") {
      const { userId } = await req.json();
      return this.makeStream(null, userId);
    }
    return new Response("not found", { status:404 });
  }
  makeStream(pool, userId) {
    const ctrl = new TransformStream();
    const controller = ctrl.writable.getWriter();
    const stream = { controller };
    controller.write(encodeSSE({ event:"init", data:{ ok:true }}));

    if (pool) pool.add(stream);
    if (userId) {
      const set = this.userSubs.get(userId) || new Set();
      set.add(stream);
      this.userSubs.set(userId, set);
    }

    const close = () => {
      controller.releaseLock?.();
      if (pool) pool.delete(stream);
      if (userId) {
        const set = this.userSubs.get(userId);
        if (set) { set.delete(stream); if (set.size===0) this.userSubs.delete(userId); }
      }
    };

    return new Response(ctrl.readable, {
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-store, must-revalidate",
        "connection": "keep-alive"
      }
    });
  }
}
function encodeSSE({ event, data }) {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

async function ssePublic(req, env) {
  const stub = env.BUS.get(env.BUS.idFromName("global"));
  return stub.fetch("https://bus/sse");
}
async function sseMe(req, env) {
  const s = await getSession(req, env);
  if (!s?.user_id) return withCors(json({ ok:false, error:"unauthorized" }, 401), req, env);
  const stub = env.BUS.get(env.BUS.idFromName("global"));
  return stub.fetch("https://bus/sse/me", { method: "POST", body: JSON.stringify({ userId: s.user_id }) });
}
