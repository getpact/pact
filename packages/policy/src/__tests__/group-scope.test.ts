import { describe, expect, it } from "vitest";
import { matchGroupInPredicate, scopeAllowsGroupIn } from "../index.js";

describe("group_in scope predicate", () => {
  it("returns null when the value is not a string array", () => {
    expect(matchGroupInPredicate("eng", { groups: ["eng"] })).toBeNull();
    expect(matchGroupInPredicate({ value: "eng" }, { groups: ["eng"] })).toBeNull();
    expect(matchGroupInPredicate(undefined, { groups: ["eng"] })).toBeNull();
  });

  it("returns false when the list is empty", () => {
    expect(matchGroupInPredicate([], { groups: ["eng"] })).toBe(false);
  });

  it("matches when subject is in at least one of the listed groups", () => {
    expect(matchGroupInPredicate(["eng"], { groups: ["eng"] })).toBe(true);
    expect(matchGroupInPredicate(["sales", "eng"], { groups: ["finance", "eng"] })).toBe(true);
  });

  it("denies when subject is in none of the listed groups", () => {
    expect(matchGroupInPredicate(["eng"], { groups: ["sales"] })).toBe(false);
    expect(matchGroupInPredicate(["eng"], { groups: [] })).toBe(false);
  });

  it("scopeAllowsGroupIn passes scopes without a group_in key through", () => {
    expect(scopeAllowsGroupIn({ doc_id: "abc" }, { groups: [] })).toBe(true);
  });

  it("scopeAllowsGroupIn denies an empty group_in array even when subject has groups", () => {
    expect(scopeAllowsGroupIn({ group_in: [] }, { groups: ["eng"] })).toBe(false);
  });

  it("scopeAllowsGroupIn allows when actor is in the listed group", () => {
    expect(scopeAllowsGroupIn({ group_in: ["eng"] }, { groups: ["eng"] })).toBe(true);
  });

  it("scopeAllowsGroupIn denies when actor is not in the listed group", () => {
    expect(scopeAllowsGroupIn({ group_in: ["eng"] }, { groups: ["sales"] })).toBe(false);
  });
});
