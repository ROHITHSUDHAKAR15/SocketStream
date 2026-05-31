/*
 * SSCrypto - all key material and message encryption live in the browser.
 *
 * Identity:   RSA-OAEP-2048 (SHA-256) keypair, generated client-side.
 * Messages:   hybrid encryption - a fresh AES-256-GCM content key per message,
 *             wrapped to the recipient's RSA public key. Blob layout (then base64):
 *                 [ RSA-wrapped AES key | 256 bytes ][ IV | 12 bytes ][ GCM ciphertext ]
 * Key custody: the private key is exported (PKCS8), encrypted with a key derived
 *             from the account password (PBKDF2-SHA256, 200k iters -> AES-GCM), and
 *             kept in localStorage. The server never receives it. After login the
 *             unwrapped key is held in sessionStorage for the chat tab only.
 *
 * The server is a relay: it stores public keys and ciphertext, nothing else.
 */
const SSCrypto = (() => {
  const subtle = window.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITERS = 200000;
  const RSA_WRAPPED_KEY_BYTES = 256; // RSA-2048 OAEP output

  // --- base64 <-> bytes ----------------------------------------------------
  function bytesToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // --- identity keypair ----------------------------------------------------
  async function generateIdentity() {
    const pair = await subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["encrypt", "decrypt"]
    );
    const spki = await subtle.exportKey("spki", pair.publicKey);
    return { publicKeyB64: bytesToB64(spki), privateKey: pair.privateKey };
  }

  async function importPublicKey(b64) {
    return subtle.importKey("spki", b64ToBytes(b64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
  }
  async function importPrivateKeyPkcs8(b64) {
    return subtle.importKey("pkcs8", b64ToBytes(b64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
  }
  async function exportPrivateKeyPkcs8B64(privateKey) {
    return bytesToB64(await subtle.exportKey("pkcs8", privateKey));
  }

  // --- password-derived wrapping key ---------------------------------------
  async function deriveWrapKey(password, salt) {
    const base = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // Wrap a private key with the password. Returns a serialisable blob.
  async function wrapPrivateKey(privateKey, password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await deriveWrapKey(password, salt);
    const pkcs8 = await subtle.exportKey("pkcs8", privateKey);
    const data = await subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, pkcs8);
    return { v: 1, salt: bytesToB64(salt), iv: bytesToB64(iv), data: bytesToB64(data) };
  }

  // Returns the unwrapped CryptoKey, or throws if the password is wrong.
  async function unwrapPrivateKey(blob, password) {
    const salt = b64ToBytes(blob.salt);
    const iv = b64ToBytes(blob.iv);
    const wrapKey = await deriveWrapKey(password, salt);
    const pkcs8 = await subtle.decrypt({ name: "AES-GCM", iv }, wrapKey, b64ToBytes(blob.data));
    return subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
  }

  // --- hybrid message encryption ------------------------------------------
  async function encryptFor(recipientPublicKeyB64, plaintext) {
    const pubKey = await importPublicKey(recipientPublicKeyB64);
    const aesKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(plaintext));
    const rawAes = await subtle.exportKey("raw", aesKey);
    const wrappedKey = await subtle.encrypt({ name: "RSA-OAEP" }, pubKey, rawAes);

    const blob = new Uint8Array(RSA_WRAPPED_KEY_BYTES + iv.length + ct.byteLength);
    blob.set(new Uint8Array(wrappedKey), 0);
    blob.set(iv, RSA_WRAPPED_KEY_BYTES);
    blob.set(new Uint8Array(ct), RSA_WRAPPED_KEY_BYTES + iv.length);
    return bytesToB64(blob);
  }

  async function decrypt(privateKey, ciphertextB64) {
    const blob = b64ToBytes(ciphertextB64);
    const wrappedKey = blob.slice(0, RSA_WRAPPED_KEY_BYTES);
    const iv = blob.slice(RSA_WRAPPED_KEY_BYTES, RSA_WRAPPED_KEY_BYTES + 12);
    const ct = blob.slice(RSA_WRAPPED_KEY_BYTES + 12);
    const rawAes = await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrappedKey);
    const aesKey = await subtle.importKey("raw", rawAes, { name: "AES-GCM" }, false, ["decrypt"]);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    return dec.decode(pt);
  }

  // --- local custody helpers ----------------------------------------------
  const lsKey = (u) => `ss_pk_${u}`;     // localStorage: password-wrapped private key
  const ssKey = (u) => `ss_sk_${u}`;     // sessionStorage: unwrapped PKCS8 (this tab only)

  function storeWrapped(username, blob) {
    localStorage.setItem(lsKey(username), JSON.stringify(blob));
  }
  function loadWrapped(username) {
    const raw = localStorage.getItem(lsKey(username));
    return raw ? JSON.parse(raw) : null;
  }
  function hasWrapped(username) {
    return !!localStorage.getItem(lsKey(username));
  }
  async function cacheUnlocked(username, privateKey) {
    sessionStorage.setItem(ssKey(username), await exportPrivateKeyPkcs8B64(privateKey));
  }
  async function loadUnlocked(username) {
    const b64 = sessionStorage.getItem(ssKey(username));
    return b64 ? importPrivateKeyPkcs8(b64) : null;
  }
  function clearSession(username) {
    sessionStorage.removeItem(ssKey(username));
  }

  return {
    bytesToB64, b64ToBytes,
    generateIdentity, encryptFor, decrypt,
    wrapPrivateKey, unwrapPrivateKey,
    storeWrapped, loadWrapped, hasWrapped,
    cacheUnlocked, loadUnlocked, clearSession,
  };
})();
