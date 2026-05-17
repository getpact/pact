import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

describe("holder key persistence", () => {
  let tmp: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    originalHome = process.env.HOME;
    tmp = mkdtempSync(join(tmpdir(), "pact-holder-"));
    process.env.HOME = tmp;
    vi.resetModules();
  });

  afterEach(() => {
    if (originalHome) {
      process.env.HOME = originalHome;
    } else {
      delete process.env.HOME;
    }
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns null when no key on disk", async () => {
    const { loadHolderKey } = await import("../holder-key.js");
    const key = await loadHolderKey();
    expect(key).toBeNull();
  });

  it("generates and persists with 0600 perms in 0700 directory", async () => {
    const { loadOrCreateHolderKey, holderKeyPath } = await import("../holder-key.js");
    const key = await loadOrCreateHolderKey();
    expect(key.publicJwk.kty).toBe("OKP");
    expect(key.publicJwk.crv).toBe("Ed25519");
    expect(key.publicJwk.x).toMatch(/^[A-Za-z0-9_-]+$/);

    const path = holderKeyPath();
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(join(tmp, ".pact")).mode & 0o777).toBe(0o700);
  });

  it("loads the same key across calls (no regeneration)", async () => {
    const { loadOrCreateHolderKey } = await import("../holder-key.js");
    const first = await loadOrCreateHolderKey();
    const second = await loadOrCreateHolderKey();
    expect(second.publicJwk.x).toBe(first.publicJwk.x);
  });

  it("private key actually signs (round-trip with public key)", async () => {
    const { loadOrCreateHolderKey } = await import("../holder-key.js");
    const key = await loadOrCreateHolderKey();
    const data = new TextEncoder().encode("hello");
    const sig = new Uint8Array(
      await crypto.subtle.sign("Ed25519", key.privateKey, data as BufferSource),
    );
    const ok = await crypto.subtle.verify(
      "Ed25519",
      key.publicKey,
      sig as BufferSource,
      data as BufferSource,
    );
    expect(ok).toBe(true);
  });
});
