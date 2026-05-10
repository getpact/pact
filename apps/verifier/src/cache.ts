export type RevocationCache = {
  get: (key: string) => Promise<boolean | null>;
  set: (key: string, revoked: boolean, ttlSeconds: number) => Promise<void>;
};

export type KVNamespace = {
  get: (key: string) => Promise<string | null>;
  put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
};

export const inMemoryRevocationCache = (): RevocationCache => {
  const store = new Map<string, { revoked: boolean; expiresAt: number }>();
  return {
    get: async (key) => {
      const e = store.get(key);
      if (!e) return null;
      if (Date.now() > e.expiresAt) {
        store.delete(key);
        return null;
      }
      return e.revoked;
    },
    set: async (key, revoked, ttlSeconds) => {
      store.set(key, { revoked, expiresAt: Date.now() + ttlSeconds * 1000 });
    },
  };
};

export const kvRevocationCache = (kv: KVNamespace): RevocationCache => ({
  get: async (key) => {
    const v = await kv.get(key);
    if (v === null) return null;
    return v === "revoked";
  },
  set: async (key, revoked, ttlSeconds) => {
    await kv.put(key, revoked ? "revoked" : "ok", { expirationTtl: ttlSeconds });
  },
});

export const cacheKey = (workspaceId: string, jti: string): string => `rev:${workspaceId}:${jti}`;
