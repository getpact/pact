import { generateAesKey } from "@getpact/crypto";
import { describe, expect, it } from "vitest";
import { unwrapSecret, wrapSecret } from "../index.js";

describe("vault envelope", () => {
  it("round-trips a secret through MEK + per-secret DEK", async () => {
    const mek = await generateAesKey();
    const plaintext = new TextEncoder().encode("placeholder-secret-value");
    const wrapped = await wrapSecret(mek, plaintext);
    const out = await unwrapSecret(mek, wrapped);
    expect(new TextDecoder().decode(out)).toBe("placeholder-secret-value");
  });

  it("ciphertext does not contain plaintext", async () => {
    const mek = await generateAesKey();
    const plaintext = new TextEncoder().encode("super-secret-marker-xyz");
    const wrapped = await wrapSecret(mek, plaintext);
    expect(wrapped.ciphertext).not.toContain("super-secret-marker");
    expect(wrapped.dekCiphertext).not.toContain("super-secret-marker");
  });

  it("uses fresh DEK per call", async () => {
    const mek = await generateAesKey();
    const plaintext = new TextEncoder().encode("same plaintext");
    const a = await wrapSecret(mek, plaintext);
    const b = await wrapSecret(mek, plaintext);
    expect(a.dekCiphertext).not.toBe(b.dekCiphertext);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("wrong MEK fails to unwrap", async () => {
    const mekA = await generateAesKey();
    const mekB = await generateAesKey();
    const wrapped = await wrapSecret(mekA, new TextEncoder().encode("data"));
    await expect(unwrapSecret(mekB, wrapped)).rejects.toThrow();
  });
});
