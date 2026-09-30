// Sample code for pqc-kit tests. Not meant to be run.
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { secp256k1 } from "@noble/curves/secp256k1";

export function keys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return { publicKey, privateKey, ec };
}

export function hashPassword(pw: string, salt: Buffer) {
  return crypto.pbkdf2Sync(pw, salt, 100000, 32, "sha512");
}

export function etag(body: string) {
  return crypto.createHash("sha1").update(body).digest("hex");
}

export function encrypt(key: Buffer, iv: Buffer, data: Buffer) {
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}

export function legacy(key: Buffer, iv: Buffer, data: Buffer) {
  return crypto.createCipheriv("des-ede3-cbc", key, iv).update(data);
}

export function token(payload: object, key: string) {
  return jwt.sign(payload, key, { algorithm: "ES256" });
}

export async function browserKeys() {
  return crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
}

export const tlsOptions = { minVersion: "TLSv1", ecdhCurve: "X25519MLKEM768:X25519:P-256" };

export const pq = ml_kem768.keygen();
export const wallet = secp256k1;
