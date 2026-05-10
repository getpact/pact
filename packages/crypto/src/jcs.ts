import canonicalize from "canonicalize";

export const jcsCanonicalize = (value: unknown): string => {
  const result = canonicalize(value);
  if (result === undefined) throw new Error("value is not JCS canonicalizable");
  return result;
};

export const jcsBytes = (value: unknown): Uint8Array =>
  new TextEncoder().encode(jcsCanonicalize(value));
