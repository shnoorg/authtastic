// ! START COPY/PASTE -- from MDN: https://developer.mozilla.org/en-US/docs/Glossary/Base64#the_unicode_problem
export function base64ToBytes(base64) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.codePointAt(0));
}

export function bytesToBase64(bytes) {
  const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join('');
  return btoa(binString);
}

function bytesToArrayBuffer(bytes) {
  const buf = new ArrayBuffer(bytes.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i += 1) {
    bufView[i] = bytes[i];
  }
  return buf;
}
// ! END COPY/PASTE

// ? Would prefer to use X25519 but browsers do not consistently support natively

export async function generateEcdhP384Keys() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey({
    name: 'ECDH',
    namedCurve: 'P-384',
  }, true, ['deriveKey']);

  const raw_pub_key = await crypto.subtle.exportKey('raw', publicKey);
  const b64_pub_key = bytesToBase64(new Uint8Array(raw_pub_key));

  const raw_priv_key = await crypto.subtle.exportKey('pkcs8', privateKey);
  const b64_priv_key = bytesToBase64(new Uint8Array(raw_priv_key));

  return [b64_pub_key, b64_priv_key];
}

export async function deriveAes256GcmKeyFromEcdhP384Keys(b64_pub_key, b64_priv_key, use) {
  const pub_key_bytes = base64ToBytes(b64_pub_key);
  const pub_key = await crypto.subtle.importKey('raw', bytesToArrayBuffer(pub_key_bytes), {
    name: 'ECDH',
    namedCurve: 'P-384',
  }, false, ['deriveKey']);

  const priv_key_bytes = base64ToBytes(b64_priv_key);
  const priv_key = await crypto.subtle.importKey('pkcs8', bytesToArrayBuffer(priv_key_bytes), {
    name: 'ECDH',
    namedCurve: 'P-384',
  }, false, ['deriveKey']);

  return crypto.subtle.deriveKey({
    name: 'ECDH',
    public: pub_key,

  }, priv_key, { name: 'AES-GCM', length: 256 }, false, [use]);
}

// ? Would prefer to use XChaCha20Poly1305 but browsers do not support natively

export async function encryptAes256Gcm(key, plaintext) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext),
  );

  const b64_ct = bytesToBase64(new Uint8Array(ciphertext));
  const b64_iv = bytesToBase64(iv);

  return [b64_ct, b64_iv];
}

export async function decryptAes256Gcm(key, iv, ciphertext) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(iv),
    },
    key,
    bytesToArrayBuffer(base64ToBytes(ciphertext)),
  );

  const dec = new TextDecoder();
  return dec.decode(plaintext);
}
