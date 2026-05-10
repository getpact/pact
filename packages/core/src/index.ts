export type WorkspaceId = string & { readonly _brand: "WorkspaceId" };
export type UserId = string & { readonly _brand: "UserId" };
export type TokenId = string & { readonly _brand: "TokenId" };
export type GroupId = string & { readonly _brand: "GroupId" };
export type RoleId = string & { readonly _brand: "RoleId" };

export type Email = string & { readonly _brand: "Email" };

export const canonicalizeEmail = (raw: string): Email => raw.trim().toLowerCase() as Email;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const isUuid = (value: unknown): value is string =>
  typeof value === "string" && UUID_RE.test(value);
