// Runs in the page's own world, at document start, in the top frame only: puts
// VisiPass in front of navigator.credentials for passkeys (WebAuthn).
//
// It holds no secret and decides nothing. A request goes to VisiPass's content
// script (inline.js) as a JSON string on a DOM event; that script shows its own
// card or menu, and only a real click there makes visipassd sign. The private
// key never leaves visipassd. Whenever VisiPass has nothing to offer (not
// running, no passkey for this site, an algorithm it does not make, or the
// human picks "Use another device"), the browser's own WebAuthn runs instead.
(() => {
  const credentials = navigator.credentials;
  if (!credentials || typeof PublicKeyCredential === "undefined" || window.__visipassPasskeys) return;
  Object.defineProperty(window, "__visipassPasskeys", { value: true });

  const original = {
    create: credentials.create.bind(credentials),
    get: credentials.get.bind(credentials),
  };
  const REQUEST = "visipass-passkey-request";
  const ANSWER = "visipass-passkey-answer";
  const ES256 = -7;

  const b64 = (source) => {
    const bytes = ArrayBuffer.isView(source)
      ? new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
      : new Uint8Array(source);
    let text = "";
    for (const b of bytes) text += String.fromCharCode(b);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const unb64 = (text) => {
    const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  };

  let counter = 0;
  const waiting = new Map();
  document.addEventListener(ANSWER, (e) => {
    let answer;
    try {
      answer = JSON.parse(e.detail);
    } catch {
      return;
    }
    const pending = waiting.get(answer.id);
    if (!pending) return;
    waiting.delete(answer.id);
    pending(answer);
  });

  // Asks VisiPass's content script; resolves with its answer or, when it does
  // not answer in time (not loaded, or VisiPass not running), with fallback.
  function ask(request, signal) {
    const id = `${Date.now()}-${++counter}`;
    return new Promise((resolve, reject) => {
      const done = (answer) => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", aborted);
        resolve(answer);
      };
      const aborted = () => {
        waiting.delete(id);
        clearTimeout(timer);
        document.dispatchEvent(new CustomEvent(REQUEST, { detail: JSON.stringify({ id, kind: "cancel" }) }));
        reject(signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
      };
      // The content script acknowledges at once; the human then has as long as they need.
      let timer = setTimeout(() => {
        waiting.delete(id);
        done({ fallback: true });
      }, 1500);
      waiting.set(id, (answer) => {
        if (answer.ack) {
          clearTimeout(timer);
          timer = null;
          waiting.set(id, done);
          return;
        }
        done(answer);
      });
      if (signal) {
        if (signal.aborted) return aborted();
        signal.addEventListener("abort", aborted, { once: true });
      }
      document.dispatchEvent(new CustomEvent(REQUEST, { detail: JSON.stringify({ ...request, id }) }));
    });
  }

  const own = (target, values) => {
    for (const [name, value] of Object.entries(values)) {
      Object.defineProperty(target, name, { value, enumerable: true, configurable: true });
    }
    return target;
  };

  // A PublicKeyCredential the page can use as the browser's own: the real
  // prototypes, with the values as own properties.
  function credential(id, response, extensions, json) {
    const rawId = unb64(id);
    const result = Object.create(PublicKeyCredential.prototype);
    own(result, {
      id,
      rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => extensions,
      toJSON: () => ({
        id,
        rawId: id,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: json,
        clientExtensionResults: extensions,
      }),
    });
    return result;
  }

  function registration(r) {
    const response = Object.create(AuthenticatorAttestationResponse.prototype);
    own(response, {
      clientDataJSON: unb64(r.client_data_json),
      attestationObject: unb64(r.attestation_object),
      getTransports: () => ["internal", "hybrid"],
      getAuthenticatorData: () => unb64(r.authenticator_data),
      getPublicKey: () => unb64(r.public_key),
      getPublicKeyAlgorithm: () => r.public_key_algorithm,
    });
    return credential(
      r.credential_id,
      response,
      { credProps: { rk: true } },
      {
        clientDataJSON: r.client_data_json,
        attestationObject: r.attestation_object,
        authenticatorData: r.authenticator_data,
        transports: ["internal", "hybrid"],
        publicKey: r.public_key,
        publicKeyAlgorithm: r.public_key_algorithm,
      },
    );
  }

  function assertion(r) {
    const response = Object.create(AuthenticatorAssertionResponse.prototype);
    own(response, {
      clientDataJSON: unb64(r.client_data_json),
      authenticatorData: unb64(r.authenticator_data),
      signature: unb64(r.signature),
      userHandle: r.user_handle ? unb64(r.user_handle) : null,
    });
    return credential(
      r.credential_id,
      response,
      {},
      {
        clientDataJSON: r.client_data_json,
        authenticatorData: r.authenticator_data,
        signature: r.signature,
        userHandle: r.user_handle || undefined,
      },
    );
  }

  function failed(answer) {
    return new DOMException(answer.message || "The operation either timed out or was not allowed.", answer.error || "NotAllowedError");
  }

  async function create(options) {
    const key = options?.publicKey;
    // Only passkeys VisiPass can make: ES256, kept on this device's vault.
    const algorithms = (key?.pubKeyCredParams || []).map((p) => p.alg);
    if (
      !key ||
      options.mediation === "conditional" ||
      (algorithms.length && !algorithms.includes(ES256)) ||
      key.authenticatorSelection?.authenticatorAttachment === "cross-platform"
    ) {
      return original.create(options);
    }
    const answer = await ask(
      {
        kind: "create",
        rp_id: key.rp?.id || location.hostname,
        rp_name: String(key.rp?.name || ""),
        challenge: b64(key.challenge),
        user_handle: b64(key.user.id),
        user_name: String(key.user.name || ""),
        user_display_name: String(key.user.displayName || ""),
        exclude: (key.excludeCredentials || []).map((c) => b64(c.id)),
      },
      options.signal,
    );
    if (answer.fallback) return original.create(options);
    if (answer.error) throw failed(answer);
    return registration(answer.result);
  }

  async function get(options) {
    const key = options?.publicKey;
    if (!key) return original.get(options);
    const answer = await ask(
      {
        kind: options.mediation === "conditional" ? "conditional" : "get",
        rp_id: key.rpId || location.hostname,
        challenge: b64(key.challenge),
        allow: (key.allowCredentials || []).map((c) => b64(c.id)),
      },
      options.signal,
    );
    if (answer.fallback) return original.get(options);
    if (answer.error) throw failed(answer);
    return assertion(answer.result);
  }

  // Native-looking functions: some sites check toString().
  const native = (fn, name) => {
    Object.defineProperty(fn, "name", { value: name });
    Object.defineProperty(fn, "toString", { value: () => `function ${name}() { [native code] }` });
    return fn;
  };
  const proto = Object.getPrototypeOf(credentials);
  Object.defineProperty(proto, "create", {
    value: native(function create_(options) {
      return create(options);
    }, "create"),
    configurable: true,
    writable: true,
  });
  Object.defineProperty(proto, "get", {
    value: native(function get_(options) {
      return get(options);
    }, "get"),
    configurable: true,
    writable: true,
  });
  // Tell sites a passkey can be made and used here, and offered in autofill.
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = native(
    () => Promise.resolve(true),
    "isUserVerifyingPlatformAuthenticatorAvailable",
  );
  PublicKeyCredential.isConditionalMediationAvailable = native(() => Promise.resolve(true), "isConditionalMediationAvailable");
})();
