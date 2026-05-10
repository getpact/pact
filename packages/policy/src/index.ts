import { z } from "zod";

export const subjectSchema = z.object({
  kind: z.enum(["group", "role", "user"]),
  value: z.string().min(1),
});

export const policyRuleSchema = z.object({
  subject: subjectSchema,
  effect: z.enum(["allow", "deny"]),
  action: z.string().optional(),
  resource: z.string().optional(),
});

export const policySchema = z.object({
  rules: z.array(policyRuleSchema),
});

export type Subject = z.infer<typeof subjectSchema>;
export type PolicyRule = z.infer<typeof policyRuleSchema>;
export type Policy = z.infer<typeof policySchema>;

export const parsePolicy = (input: unknown): Policy => policySchema.parse(input);

export const tryParsePolicy = (input: unknown): Policy | null => {
  const result = policySchema.safeParse(input);
  return result.success ? result.data : null;
};

export type TokenClaims = {
  sub: string;
  email: string;
  groups: string[];
  roles: string[];
};

export type EvaluateInput = {
  token: TokenClaims;
  action: string;
  resource: string;
  policy: Policy;
};

export type EvaluateResult = {
  allow: boolean;
  reasons: string[];
};

const subjectMatches = (subject: Subject, token: TokenClaims): boolean => {
  switch (subject.kind) {
    case "group":
      return token.groups.includes(subject.value);
    case "role":
      return token.roles.includes(subject.value);
    case "user":
      return token.email === subject.value || token.sub === subject.value;
  }
};

const patternMatches = (pattern: string | undefined, value: string): boolean => {
  if (pattern === undefined || pattern === "*") return true;
  if (pattern.endsWith(":*")) {
    return value.startsWith(pattern.slice(0, -1));
  }
  return pattern === value;
};

const ruleApplies = (rule: PolicyRule, input: EvaluateInput): boolean =>
  subjectMatches(rule.subject, input.token) &&
  patternMatches(rule.action, input.action) &&
  patternMatches(rule.resource, input.resource);

export const evaluate = (input: EvaluateInput): EvaluateResult => {
  const matched = input.policy.rules.filter((r) => ruleApplies(r, input));
  const denies = matched.filter((r) => r.effect === "deny");
  if (denies.length > 0) {
    return {
      allow: false,
      reasons: denies.map((r) => `deny by ${r.subject.kind}:${r.subject.value}`),
    };
  }
  const allows = matched.filter((r) => r.effect === "allow");
  if (allows.length > 0) {
    return {
      allow: true,
      reasons: allows.map((r) => `allow by ${r.subject.kind}:${r.subject.value}`),
    };
  }
  return { allow: false, reasons: ["default deny"] };
};
