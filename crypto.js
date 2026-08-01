// crypto.js — all encryption for the app. Nothing here ever leaves the device.
// A password is turned into an AES-256 key via PBKDF2. The key only ever
// lives in memory for the current session; it is never written to storage.

const Crypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function randomBytes(len) {
    return crypto.getRandomValues(new Uint8Array(len));
  }

  function toB64(bytes) {
    let s = '';
    bytes.forEach((b) => (s += String.fromCharCode(b)));
    return btoa(s);
  }

  function fromB64(str) {
    const s = atob(str);
    return new Uint8Array([...s].map((c) => c.charCodeAt(0)));
  }

  async function deriveKey(password, saltB64) {
    const salt = fromB64(saltB64);
    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    // extractable: true — needed so the key can be wrapped for optional
    // biometric unlock (see app.js). The raw bits never leave the device;
    // they're only ever re-encrypted locally with a biometric-derived key.
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptJSON(key, obj) {
    const iv = randomBytes(12);
    const data = enc.encode(JSON.stringify(obj));
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { iv: toB64(iv), data: toB64(new Uint8Array(cipherBuf)) };
  }

  async function decryptJSON(key, payload) {
    const iv = fromB64(payload.iv);
    const data = fromB64(payload.data);
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return JSON.parse(dec.decode(plainBuf));
  }

  function newSalt() {
    return toB64(randomBytes(16));
  }

  return { deriveKey, encryptJSON, decryptJSON, newSalt, toB64, fromB64, randomBytes };
})();
