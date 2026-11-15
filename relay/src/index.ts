// The phone-approvals relay (crypto design §11.4).
//
// visipassd keeps one WebSocket open to its tunnel; a paired phone sends the
// requests it would send visipassd directly to /t/<tunnel_id>/v1/..., and the
// relay passes each one down the socket and the daemon's reply back. Everything
// it carries is sealed to or signed by the pairing's keys, so the relay reads
// nothing and can forge nothing; it stores nothing either. It also sends the
// one fixed notification, to a device token visipassd hands it.

import { DurableObject } from "cloudflare:workers";

export interface Env {
  TUNNEL: DurableObjectNamespace<Tunnel>;
  /** The app's bundle id. */
  APNS_TOPIC: string;
  /** Secrets: the APNs key (.p8, PEM), its id and the developer's team id. */
  APNS_KEY?: string;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  /** How long a phone's request waits for visipassd, in ms (tests shorten it). */
  REPLY_MS?: string;
}

const TUNNEL_PATH = /^\/t\/([0-9a-f]{32})(\/.*)$/;

/** The routes visipassd serves a phone; nothing else is passed down. */
const ROUTES: [string, RegExp][] = [
  ["GET", /^\/v1\/pending\/[0-9a-f]{32}$/],
  ["POST", /^\/v1\/pair\/(commit|reveal)$/],
  ["POST", /^\/v1\/answer$/],
  ["POST", /^\/v1\/push$/],
];

/** vp-phone's MAX_MESSAGE. */
const MAX_BODY = 64 * 1024;
const REPLY_MS = 20_000;
const PER_MINUTE = { tunnel: 600, address: 120, push: 6 };

/** The whole notification: no request, agent or computer in it (§11.4). */
const NOTIFICATION = JSON.stringify({
  aps: { alert: { title: "VisiPass", body: "An agent is waiting for you." }, sound: "default" },
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const match = TUNNEL_PATH.exec(new URL(request.url).pathname);
    if (!match) return say(404, "Not a VisiPass relay address.");
    return env.TUNNEL.get(env.TUNNEL.idFromName(match[1])).fetch(request);
  },
} satisfies ExportedHandler<Env>;

/** From visipassd: a reply to request `id`, or a device token to notify. */
type Frame = { id: number; status: number; body: string } | { push: string };

/** One computer's tunnel. */
export class Tunnel extends DurableObject<Env> {
  private next = 0;
  private waiting = new Map<number, (reply: Response) => void>();
  private counts = new Map<string, { start: number; n: number }>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // visipassd's keepalive, answered without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request: Request): Promise<Response> {
    const [, id, path] = TUNNEL_PATH.exec(new URL(request.url).pathname)!;
    return path === "/connect" ? this.takeTunnel(request, id) : this.forward(request, path);
  }

  /** visipassd taking its tunnel: it proves it holds the secret the id is
   *  the hash of. A newer connection replaces an older one. */
  private async takeTunnel(request: Request, id: string): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return say(426, "Connect with a WebSocket.");
    }
    const auth = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.get("Authorization") ?? "");
    if (!auth || (await tunnelId(auth[1])) !== id) {
      return say(403, "Not this tunnel's computer.");
    }
    for (const old of this.ctx.getWebSockets()) old.close(4000, "Replaced by a newer connection.");
    this.answerAll(503, "The computer reconnected; try again.");
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  /** A phone's request, passed down to visipassd. */
  private async forward(request: Request, path: string): Promise<Response> {
    const address = request.headers.get("CF-Connecting-IP") ?? "";
    if (
      !this.allow("tunnel", PER_MINUTE.tunnel) ||
      !this.allow(`address ${address}`, PER_MINUTE.address)
    ) {
      return say(429, "Too many requests. Wait a minute.");
    }
    if (!ROUTES.some(([method, route]) => method === request.method && route.test(path))) {
      return say(404, "Not found.");
    }
    const [socket] = this.ctx.getWebSockets();
    if (!socket) return say(503, "The computer is offline, or VisiPass is locked there.");
    const body = request.method === "POST" ? await readLimited(request, MAX_BODY) : new Uint8Array();
    if (!body) return say(413, "Too large.");

    const id = ++this.next;
    const wait = Number(this.env.REPLY_MS ?? REPLY_MS);
    const reply = new Promise<Response>((resolve) => {
      this.waiting.set(id, resolve);
      setTimeout(() => this.answer(id, say(504, "The computer did not answer in time.")), wait);
    });
    try {
      socket.send(JSON.stringify({ id, method: request.method, path, body: toBase64(body) }));
    } catch {
      this.answer(id, say(503, "The computer is offline, or VisiPass is locked there."));
    }
    return reply;
  }

  async webSocketMessage(_socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") return;
    let frame: Frame;
    try {
      frame = JSON.parse(message);
    } catch {
      return;
    }
    if ("id" in frame && typeof frame.id === "number") {
      const status = Number.isInteger(frame.status) && frame.status >= 200 && frame.status < 600 ? frame.status : 502;
      const body = typeof frame.body === "string" ? fromBase64(frame.body) : null;
      if (!body || body.length > MAX_BODY) {
        this.answer(frame.id, say(502, "The computer's reply was not readable."));
        return;
      }
      this.answer(
        frame.id,
        new Response(body, {
          status,
          headers: {
            "Content-Type": status === 200 ? "application/cbor" : "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
          },
        }),
      );
    } else if ("push" in frame && typeof frame.push === "string" && /^[0-9a-f]{2,200}$/.test(frame.push)) {
      if (this.allow(`push ${frame.push}`, PER_MINUTE.push)) await this.push(frame.push);
    }
  }

  async webSocketClose(): Promise<void> {
    this.answerAll(503, "The computer went offline.");
  }

  async webSocketError(): Promise<void> {
    this.answerAll(503, "The computer went offline.");
  }

  private answer(id: number, reply: Response): void {
    const resolve = this.waiting.get(id);
    if (!resolve) return;
    this.waiting.delete(id);
    resolve(reply);
  }

  private answerAll(status: number, text: string): void {
    for (const id of [...this.waiting.keys()]) this.answer(id, say(status, text));
  }

  /** At most `limit` per minute for `key`. */
  private allow(key: string, limit: number): boolean {
    const now = Date.now();
    if (this.counts.size > 4096) {
      for (const [k, v] of this.counts) if (now - v.start >= 60_000) this.counts.delete(k);
    }
    const count = this.counts.get(key);
    if (!count || now - count.start >= 60_000) {
      this.counts.set(key, { start: now, n: 1 });
      return true;
    }
    count.n += 1;
    return count.n <= limit;
  }

  /** The fixed notification to one device. A development build's token is
   *  good only on Apple's sandbox, which says so; then it is tried there. */
  private async push(token: string): Promise<void> {
    const jwt = await apnsToken(this.env);
    if (!jwt) return;
    for (const host of ["api.push.apple.com", "api.sandbox.push.apple.com"]) {
      const sent = await fetch(`https://${host}/3/device/${token}`, {
        method: "POST",
        headers: {
          authorization: `bearer ${jwt}`,
          "apns-topic": this.env.APNS_TOPIC,
          "apns-push-type": "alert",
          "apns-priority": "10",
          "apns-expiration": String(Math.floor(Date.now() / 1000) + 120),
        },
        body: NOTIFICATION,
      }).catch(() => null);
      if (!sent || sent.status !== 400) return;
      const reason = await sent
        .json<{ reason?: string }>()
        .then((r) => r.reason)
        .catch(() => undefined);
      if (reason !== "BadDeviceToken") return;
    }
  }
}

/** `SHA-256(tunnel_secret)[..16]`, hex: the tunnel's id. */
export async function tunnelId(secretHex: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", fromHex(secretHex));
  return toHex(new Uint8Array(digest).slice(0, 16));
}

let cachedJwt: { jwt: string; at: number } | undefined;

/** APNs's provider token: ES256 over the team and time, reused for 40
 *  minutes (Apple wants a new one between 20 and 60). */
async function apnsToken(env: Env): Promise<string | undefined> {
  if (!env.APNS_KEY || !env.APNS_KEY_ID || !env.APNS_TEAM_ID) return undefined;
  const now = Math.floor(Date.now() / 1000);
  if (cachedJwt && now - cachedJwt.at < 40 * 60) return cachedJwt.jwt;
  const der = fromBase64(env.APNS_KEY.replace(/-----[^-]+-----|\s/g, ""));
  if (!der) return undefined;
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
  ]);
  const part = (value: object) => base64url(new TextEncoder().encode(JSON.stringify(value)));
  const signed = `${part({ alg: "ES256", kid: env.APNS_KEY_ID })}.${part({ iss: env.APNS_TEAM_ID, iat: now })}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signed),
  );
  cachedJwt = { jwt: `${signed}.${base64url(new Uint8Array(signature))}`, at: now };
  return cachedJwt.jwt;
}

function say(status: number, text: string): Response {
  return new Response(text, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

/** The body, or null if it is over `limit` bytes. */
async function readLimited(request: Request, limit: number): Promise<Uint8Array | null> {
  if (Number(request.headers.get("Content-Length") ?? 0) > limit) return null;
  if (!request.body) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = request.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    body.set(chunk, at);
    at += chunk.length;
  }
  return body;
}

function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(text);
}

function fromBase64(text: string): Uint8Array | null {
  try {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function base64url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16));
}
