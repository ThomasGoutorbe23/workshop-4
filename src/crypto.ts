import { webcrypto } from "crypto";

// ============
// === UTILS ===
// ============

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ======================
// === RSA KEY PAIR ====
// ======================

export async function generateRsaKeyPair(): Promise<{
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
}> {
  return await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
  ) as { publicKey: webcrypto.CryptoKey; privateKey: webcrypto.CryptoKey };
}

export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exported);
}

export async function exportPrvKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(exported);
}

export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyData = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
      "spki",
      keyData,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"]
  );
}

export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyData = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
      "pkcs8",
      keyData,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
  );
}

export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  const key = await importPubKey(strPublicKey);
  const data = base64ToArrayBuffer(b64Data);
  const encrypted = await webcrypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      key,
      data
  );
  return arrayBufferToBase64(encrypted);
}

export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  const decrypted = await webcrypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64ToArrayBuffer(data)
  );
  return arrayBufferToBase64(decrypted);
}

// ========================
// === SYMMETRIC AES KEY ==
// ========================

export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey(
      {
        name: "AES-CBC",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
  );
}

export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(exported);
}

export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyData = base64ToArrayBuffer(strKey);
  if (keyData.byteLength !== 32) {
    throw new Error("Invalid key length for AES-256");
  }
  return await webcrypto.subtle.importKey(
      "raw",
      keyData,
      { name: "AES-CBC" },
      true,
      ["encrypt", "decrypt"]
  );
}

export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encoded = new TextEncoder().encode(data);
  const encrypted = await webcrypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      key,
      encoded
  );
  return arrayBufferToBase64(iv) + ":" + arrayBufferToBase64(encrypted);
}

export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
  const key = await importSymKey(strKey);
  const [ivBase64, cipherBase64] = encryptedData.split(":");
  const iv = base64ToArrayBuffer(ivBase64);
  const encrypted = base64ToArrayBuffer(cipherBase64);
  const decrypted = await webcrypto.subtle.decrypt(
      { name: "AES-CBC", iv: new Uint8Array(iv) },
      key,
      encrypted
  );
  return new TextDecoder().decode(decrypted);
}


