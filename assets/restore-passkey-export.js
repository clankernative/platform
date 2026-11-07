// Browser presentation only. Produces candidate public configuration locally;
// it never submits a key, enrolls an admin, signs an approval or calls a server.
const text = new TextEncoder();
const require = ok => { if (!ok) throw new Error('passkey_candidate_refused'); };
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const bytes = (value, min, max) => {
  require(value instanceof ArrayBuffer || ArrayBuffer.isView(value));
  const result = value instanceof ArrayBuffer ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  require(result.length >= min && result.length <= max);
  return result.slice();
};
const base64url = value => btoa(String.fromCharCode(...value)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
const from64 = value => {
  require(typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value));
  const result = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='), c => c.charCodeAt(0));
  require(result.length === 32 && base64url(result) === value);
  return result;
};

function site(origin) {
  const url = new URL(origin);
  const labels = url.hostname.split('.');
  require(url.protocol === 'https:' && url.origin === origin && url.hostname.length <= 253
    && labels.length >= 2 && labels.every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s))
    && /[a-z]/.test(labels.at(-1)));
  return {origin, rp: url.hostname};
}

function identity(email, subject) {
  require(typeof email === 'string' && typeof subject === 'string'
    && text.encode(email).length <= 256 && email.length >= 3
    && email.replace(/[A-Z]/g, c => c.toLowerCase()) === email
    && !/[\s\p{Cc}]/u.test(email) && email.split('@').length === 2 && email.split('@').every(Boolean)
    && !email.startsWith('domain:') && !email.startsWith('credential_client:')
    && text.encode(subject).length >= 1 && text.encode(subject).length <= 1024 && !/\p{Cc}/u.test(subject));
  return {email, subject};
}

function cosePoint(cose) {
  require(cose.length === 77 && cose[0] === 0xa5);
  const seen = new Set(), point = new Uint8Array(65); point[0] = 4;
  let at = 1;
  for (let i = 0; i < 5; i++) {
    const label = cose[at++];
    require(!seen.has(label)); seen.add(label);
    if (label === 1 || label === 3 || label === 0x20) {
      require(cose[at++] === (label === 1 ? 2 : label === 3 ? 0x26 : 1));
    } else {
      require((label === 0x21 || label === 0x22) && cose[at++] === 0x58 && cose[at++] === 0x20);
      require(at + 32 <= cose.length);
      point.set(cose.slice(at, at + 32), label === 0x21 ? 1 : 33); at += 32;
    }
  }
  require(seen.size === 5 && at === cose.length);
  return point;
}

// These checks validate an export, not an attestation or an authenticated admin.
// Config review and the later assertion verifier remain the trust boundaries.
export async function publicCandidate(credential, saved, crypto = globalThis.crypto) {
  const selected = site(saved.origin), actor = identity(saved.email, saved.subject);
  const handle = bytes(saved.handle, 32, 32), challenge = bytes(saved.challenge, 32, 32);
  require(credential?.type === 'public-key' && credential.response?.getPublicKeyAlgorithm() === -7);
  const id = bytes(credential.rawId, 1, 1023);
  const auth = bytes(credential.response.getAuthenticatorData(), 133, 1155);
  const clientBytes = bytes(credential.response.clientDataJSON, 1, 4096);
  const spki = bytes(credential.response.getPublicKey(), 1, 256);
  const flags = auth[32], length = (auth[53] << 8) | auth[54];
  require((flags & 0x45) === 0x45 && (flags & ~0x5d) === 0
    && (!(flags & 0x10) || (flags & 0x08)) && length === id.length && auth.length === 55 + length + 77
    && equal(auth.slice(55, 55 + length), id));
  const client = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(clientBytes));
  require(client && !Array.isArray(client) && Object.keys(client).every(k => ['type', 'challenge', 'origin', 'crossOrigin'].includes(k))
    && client.type === 'webauthn.create' && client.origin === selected.origin
    && client.challenge === base64url(challenge) && (client.crossOrigin === undefined || client.crossOrigin === false));
  const cose = auth.slice(55 + length), point = cosePoint(cose);
  const key = await crypto.subtle.importKey('spki', spki, {name: 'ECDSA', namedCurve: 'P-256'}, true, ['verify']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  require(jwk.kty === 'EC' && jwk.crv === 'P-256'
    && equal(point.slice(1, 33), from64(jwk.x)) && equal(point.slice(33), from64(jwk.y))
    && equal(auth.slice(0, 32), new Uint8Array(await crypto.subtle.digest('SHA-256', text.encode(selected.rp)))));
  return {...actor, credential_id: Array.from(id), user_handle: Array.from(handle),
    cose_key: Array.from(cose), backup_eligible: Boolean(flags & 0x08), rp_id: selected.rp, origin: selected.origin};
}

export function mount(document, window, navigator, crypto = globalThis.crypto) {
  const root = document.getElementById('restore-passkey-export');
  const button = document.getElementById('create-passkey');
  const output = document.getElementById('public-key-record');
  const status = document.getElementById('passkey-status');
  if (!root || !button || !output || !status) return;
  let busy = false;
  button.addEventListener('click', async () => {
    if (busy) return;
    busy = true; button.disabled = true; output.value = ''; status.textContent = 'Creating a passkey…';
    try {
      const selected = site(root.dataset.origin);
      const actor = identity(root.dataset.email, root.dataset.subject);
      require(window.isSecureContext && window.top === window.self && window.location.origin === selected.origin);
      const saved = {...actor, origin: selected.origin,
        handle: crypto.getRandomValues(new Uint8Array(32)), challenge: crypto.getRandomValues(new Uint8Array(32))};
      // Freeze independent copies before invoking the browser; no identity or
      // handle can be replaced by a later DOM edit or returned credential field.
      const credential = await navigator.credentials.create({publicKey: {
        challenge: saved.challenge.slice(), rp: {id: selected.rp, name: 'Restore passkey'},
        user: {id: saved.handle.slice(), name: actor.email, displayName: actor.email},
        pubKeyCredParams: [{type: 'public-key', alg: -7}],
        authenticatorSelection: {residentKey: 'required', userVerification: 'required'},
        timeout: 120000, attestation: 'none',
      }});
      const record = await publicCandidate(credential, saved, crypto);
      require(root.isConnected && root.dataset.origin === saved.origin
        && root.dataset.email === saved.email && root.dataset.subject === saved.subject
        && window.location.origin === saved.origin);
      output.value = JSON.stringify(record, null, 2);
      status.textContent = 'Public record ready. A reviewed configuration change is still required.';
    } catch {
      output.value = ''; status.textContent = 'No public record exported. Retry with a supported user-verifying authenticator.';
    } finally { busy = false; button.disabled = false; }
  });
}

if (typeof document !== 'undefined') mount(document, window, navigator);
