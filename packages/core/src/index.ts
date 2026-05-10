export type WorkspaceId = string & { readonly _brand: "WorkspaceId" };
export type UserId = string & { readonly _brand: "UserId" };
export type TokenId = string & { readonly _brand: "TokenId" };
export type GroupId = string & { readonly _brand: "GroupId" };
export type RoleId = string & { readonly _brand: "RoleId" };

export type Email = string & { readonly _brand: "Email" };

export const canonicalizeEmail = (raw: string): Email => raw.trim().toLowerCase() as Email;
