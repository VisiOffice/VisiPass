import { SELF } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { tunnelId } from "../src/index";

const SECRET = "11".repeat(32);
const OTHER = "22".repeat(32);
const PAIRING = "ab".repeat(16);

async function base(secret = SECRET) {
  return `https://relay.visipass.app/t/${await tunnelId(secret)}`;
}

type Down = { id: number; method: string; path: string; body: string };

/** visipassd's end of the tunnel. */
async function connect(secret = SECRET) {
  const response = await SELF.fetch(`${await base(secret)}/connect`, {
    headers: { Upgrade: "websocket", Authorization: `Bearer ${secret}` },
  });
  expect(response.status).toBe(101);
  const socket = response.webSocket!;
  socket.accept();
  const frames: Down[] = [];
  const waiters: ((frame: Down) => void)[] = [];
  socket.addEventListener("message", (event) => {
    const frame = JSON.parse(event.data as string);
    const waiter = waiters.shift();
    waiter ? waiter(frame) : frames.push(frame);
  });
  return {
    socket,
    next: () =>
      new Promise<Down>((resolve) => {
        const frame = frames.shift();
        frame ? resolve(frame) : waiters.push(resolve);
      }),
    reply: (id: number, status: number, body: Uint8Array | string) =>
      socket.send(
        JSON.stringify({ id, status, body: btoa(typeof body === "string" ? body : String.fromCharCode(...body)) }),
      ),
  };
}

afterEach(() => vi.restoreAllMocks());

describe("the tunnel", () => {
  it("answers only tunnel addresses", async () => {
    expect((await SELF.fetch("https://relay.visipass.app/")).status).toBe(404);
    expect((await SELF.fetch("https://relay.visipass.app/t/xyz/v1/answer", { method: "POST" })).status).toBe(404);
  });

  it("says when the computer is offline", async () => {
    const response = await SELF.fetch(`${await base(OTHER)}/v1/pending/${PAIRING}`);
    expect(response.status).toBe(503);
    expect(await response.text()).toMatch(/offline/);
  });

  it("is taken only by the computer holding its secret", async () => {
    const url = `${await base()}/connect`;
    const wrong = await SELF.fetch(url, { headers: { Upgrade: "websocket", Authorization: `Bearer ${OTHER}` } });
    expect(wrong.status).toBe(403);
    const none = await SELF.fetch(url, { headers: { Upgrade: "websocket" } });
    expect(none.status).toBe(403);
    const plain = await SELF.fetch(url, { headers: { Authorization: `Bearer ${SECRET}` } });
    expect(plain.status).toBe(426);
  });

  it("passes a phone's request down and the computer's reply back, unchanged", async () => {
    const computer = await connect();
    const sent = new Uint8Array([0x82, 0x01, 0xff, 0x00]);
    const asked = SELF.fetch(`${await base()}/v1/answer`, { method: "POST", body: sent });
    const down = await computer.next();
    expect(down).toMatchObject({ method: "POST", path: "/v1/answer" });
    expect(Uint8Array.from(atob(down.body), (c) => c.charCodeAt(0))).toEqual(sent);

    computer.reply(down.id, 200, new Uint8Array([1, 2, 3]));
    const reply = await asked;
    expect(reply.status).toBe(200);
    expect(new Uint8Array(await reply.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));

    const pending = SELF.fetch(`${await base()}/v1/pending/${PAIRING}`);
    const get = await computer.next();
    expect(get).toMatchObject({ method: "GET", path: `/v1/pending/${PAIRING}`, body: "" });
    computer.reply(get.id, 423, "VisiPass is locked.");
    const locked = await pending;
    expect(locked.status).toBe(423);
    expect(await locked.text()).toBe("VisiPass is locked.");
  });

  it("passes down only visipassd's routes", async () => {
    const computer = await connect();
    for (const [method, path] of [
      ["GET", "/v1/answer"],
      ["POST", "/v1/pending/" + PAIRING],
      ["GET", "/v1/pending/../../etc"],
      ["POST", "/v1/answer/"],
      ["GET", "/v1/pending/" + PAIRING.toUpperCase()],
      ["DELETE", "/v1/answer"],
    ]) {
      const response = await SELF.fetch(`${await base()}${path}`, { method });
      expect(response.status, `${method} ${path}`).toBe(404);
    }
    // Nothing reached the computer.
    const asked = SELF.fetch(`${await base()}/v1/pair/commit`, { method: "POST", body: "x" });
    expect((await computer.next()).path).toBe("/v1/pair/commit");
    computer.socket.close();
    expect((await asked).status).toBe(503);
  });

  it("refuses bodies over 64 KiB", async () => {
    await connect();
    const response = await SELF.fetch(`${await base()}/v1/answer`, {
      method: "POST",
      body: new Uint8Array(64 * 1024 + 1),
    });
    expect(response.status).toBe(413);
  });

  it("gives up when the computer does not answer", async () => {
    const computer = await connect();
    const asked = SELF.fetch(`${await base()}/v1/answer`, { method: "POST", body: "x" });
    await computer.next();
    expect((await asked).status).toBe(504);
  });

  it("hands requests to the newest connection", async () => {
    const first = await connect();
    const closed = new Promise((resolve) => first.socket.addEventListener("close", resolve));
    const second = await connect();
    await closed;
    const asked = SELF.fetch(`${await base()}/v1/answer`, { method: "POST", body: "x" });
    const down = await second.next();
    second.reply(down.id, 200, "");
    expect((await asked).status).toBe(200);
  });

  it("rate-limits each address, whatever it asks", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 125; i++) {
      const path = i % 2 ? "/v1/pair/commit" : "/nothing";
      const response = await SELF.fetch(`${await base(OTHER)}${path}`, {
        method: "POST",
        headers: { "CF-Connecting-IP": "192.0.2.7" },
      });
      statuses.push(response.status);
    }
    expect(new Set(statuses.slice(0, 120))).toEqual(new Set([404, 503]));
    expect(statuses.slice(120)).toEqual([429, 429, 429, 429, 429]);
    const elsewhere = await SELF.fetch(`${await base(OTHER)}/v1/pair/commit`, {
      method: "POST",
      headers: { "CF-Connecting-IP": "192.0.2.8" },
    });
    expect(elsewhere.status).toBe(503);
  });
});

describe("notifications", () => {
  it("sends only the fixed notification, signed with the APNs key, and limits each device", async () => {
    const sent: { url: string; init: RequestInit }[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      sent.push({ url: String(input), init: init! });
      return new Response(null, { status: 200 });
    });
    const computer = await connect();
    const token = "cd".repeat(32);
    for (let i = 0; i < 8; i++) computer.socket.send(JSON.stringify({ push: token }));
    // A round trip so the pushes above have been handled.
    const asked = SELF.fetch(`${await base()}/v1/answer`, { method: "POST", body: "x" });
    const down = await computer.next();
    computer.reply(down.id, 200, "");
    await asked;

    const pushes = sent.filter((s) => s.url.includes("push.apple.com"));
    expect(pushes).toHaveLength(6);
    expect(pushes[0].url).toBe(`https://api.push.apple.com/3/device/${token}`);
    const headers = pushes[0].init.headers as Record<string, string>;
    expect(headers["apns-topic"]).toBe("app.visipass.ios");
    expect(headers.authorization).toMatch(/^bearer [\w-]+\.[\w-]+\.[\w-]+$/);
    expect(JSON.parse(pushes[0].init.body as string)).toEqual({
      aps: { alert: { title: "VisiPass", body: "An agent is waiting for you." }, sound: "default" },
    });
  });

  it("tries Apple's sandbox for a development build's token", async () => {
    const urls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      urls.push(String(input));
      return String(input).includes("sandbox")
        ? new Response(null, { status: 200 })
        : Response.json({ reason: "BadDeviceToken" }, { status: 400 });
    });
    const computer = await connect();
    computer.socket.send(JSON.stringify({ push: "ef".repeat(32) }));
    const asked = SELF.fetch(`${await base()}/v1/answer`, { method: "POST", body: "x" });
    const down = await computer.next();
    computer.reply(down.id, 200, "");
    await asked;
    expect(urls.filter((u) => u.includes("apple"))).toEqual([
      `https://api.push.apple.com/3/device/${"ef".repeat(32)}`,
      `https://api.sandbox.push.apple.com/3/device/${"ef".repeat(32)}`,
    ]);
  });
});
