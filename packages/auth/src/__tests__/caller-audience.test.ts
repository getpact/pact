import { describe, expect, it } from "vitest";
import { callerAudience } from "../index.js";

describe("callerAudience", () => {
  it("returns email then groups", () => {
    expect(callerAudience({ email: "alice@example.com", groups: ["eng", "ops"] })).toEqual([
      "alice@example.com",
      "eng",
      "ops",
    ]);
  });

  it("trims whitespace and drops empties", () => {
    expect(
      callerAudience({ email: "  bob@example.com  ", groups: ["  eng  ", "", "ops"] }),
    ).toEqual(["bob@example.com", "eng", "ops"]);
  });

  it("dedups duplicates across email and groups", () => {
    expect(
      callerAudience({ email: "alice@example.com", groups: ["alice@example.com", "eng", "eng"] }),
    ).toEqual(["alice@example.com", "eng"]);
  });

  it("handles missing email", () => {
    expect(callerAudience({ groups: ["eng"] })).toEqual(["eng"]);
  });

  it("handles missing groups", () => {
    expect(callerAudience({ email: "alice@example.com" })).toEqual(["alice@example.com"]);
  });

  it("returns empty for empty input", () => {
    expect(callerAudience({})).toEqual([]);
  });

  it("ignores non-array groups", () => {
    expect(callerAudience({ email: "alice@example.com", groups: undefined })).toEqual([
      "alice@example.com",
    ]);
  });
});
