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

export class PactError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
    this.name = new.target.name;
  }
}

export class AuthError extends PactError {
  constructor(message: string) {
    super("auth", message, 401);
  }
}

export class AuthzError extends PactError {
  constructor(message: string) {
    super("forbidden", message, 403);
  }
}

export class NotFoundError extends PactError {
  constructor(message: string) {
    super("not_found", message, 404);
  }
}

export class ValidationError extends PactError {
  constructor(message: string) {
    super("invalid_request", message, 400);
  }
}

export class ConflictError extends PactError {
  constructor(message: string) {
    super("conflict", message, 409);
  }
}
