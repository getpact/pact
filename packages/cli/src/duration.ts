const DURATION_RE = /^(\d+)\s*(s|m|h|d|w)$/i;
const MAX_DAYS = 3650;

export type DurationUnit = "s" | "m" | "h" | "d" | "w";

export type ParsedDuration = {
  amount: number;
  unit: DurationUnit;
  seconds: number;
};

const unitSeconds: Record<DurationUnit, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
};

const parseRaw = (input: string, flagLabel: string): ParsedDuration => {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error(`${flagLabel} must not be empty`);
  }
  const numericOnly = /^-?\d+$/.test(trimmed);
  if (numericOnly) {
    const raw = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(raw) || raw <= 0) {
      throw new Error(`${flagLabel} must be a positive integer with a unit`);
    }
    return { amount: raw, unit: "s", seconds: raw };
  }
  const match = DURATION_RE.exec(trimmed);
  if (!match) {
    throw new Error(`invalid ${flagLabel} '${input}'; use a value like 7d, 24h, 30m, 1w, or 3600`);
  }
  const amount = Number.parseInt(match[1] ?? "0", 10);
  if (!Number.isFinite(amount) || amount <= 0) {
    throw new Error(`${flagLabel} must be a positive integer with a unit`);
  }
  const unit = ((match[2] ?? "").toLowerCase() as DurationUnit) ?? "s";
  const seconds = amount * unitSeconds[unit];
  const days = seconds / 86400;
  if (days > MAX_DAYS) {
    throw new Error(`${flagLabel} '${input}' exceeds maximum of ${MAX_DAYS} days`);
  }
  return { amount, unit, seconds };
};

const intervalUnitWords: Record<DurationUnit, string> = {
  s: "seconds",
  m: "minutes",
  h: "hours",
  d: "days",
  w: "days",
};

/**
 * Parses a duration like `7d`, `24h`, `30m`, `1w`, or `45s` into a
 * Postgres-friendly interval string such as `"7 days"`. Used by `pact admin`
 * subcommands that feed the value to a SQL interval cast. Bare integers are
 * rejected for the SQL form to preserve the existing admin contract.
 */
export const parseDuration = (input: string, flagLabel = "--older-than"): string => {
  const trimmed = input.trim();
  if (/^-?\d+$/.test(trimmed)) {
    throw new Error(`invalid ${flagLabel} '${input}'; use a value like 7d, 24h, 30m, 1w`);
  }
  const parsed = parseRaw(input, flagLabel);
  if (parsed.unit === "w") {
    return `${parsed.amount * 7} days`;
  }
  return `${parsed.amount} ${intervalUnitWords[parsed.unit]}`;
};

/**
 * Parses a duration like `7d`, `1h`, `30m`, or a bare integer count of seconds
 * (`3600`) into an absolute second count. Used by mint-style commands where the
 * underlying API expects `ttl_seconds`.
 */
export const parseDurationToSeconds = (input: string, flagLabel = "--ttl"): number => {
  return parseRaw(input, flagLabel).seconds;
};
