import { describe, expect, it } from "vitest";
import { evaluatePassword, strengthColor } from "./password";

describe("evaluatePassword", () => {
  it("returns score 0 for empty input", () => {
    expect(evaluatePassword("").score).toBe(0);
  });

  it("returns score 0 for very short input", () => {
    expect(evaluatePassword("abc").score).toBe(0);
  });

  it("returns score 1 for minimal length + 1 class", () => {
    expect(evaluatePassword("aaaaaaaa").score).toBe(1);
  });

  it("returns score 2 for 12 chars + 2 classes", () => {
    expect(evaluatePassword("aaaaaaaa1234").score).toBe(2);
  });

  it("returns score 3 for 16 chars + 3 classes", () => {
    expect(evaluatePassword("aaaaAAAA12345678").score).toBe(3);
  });

  it("returns score 4 for 20 chars + 4 classes", () => {
    expect(evaluatePassword("Aa1!Aa1!Aa1!Aa1!Aa1!").score).toBe(4);
  });

  it("returns a score in the [0,4] range for any input", () => {
    // Audit E P0-7: the label is no longer baked into the eval --
    // PasswordField resolves it via t(`password.strength.${score}`).
    // This test stays as a contract guard on the score range.
    for (const pwd of [
      "",
      "a",
      "aaaaaaaa",
      "aaaaaaaa1234",
      "aaaaAAAA12345678",
      "Aa1!Aa1!Aa1!Aa1!Aa1!",
    ]) {
      const { score } = evaluatePassword(pwd);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(4);
    }
  });
});

describe("strengthColor", () => {
  it("returns the primary token for strong scores", () => {
    expect(strengthColor(3)).toContain("primary");
    expect(strengthColor(4)).toContain("primary");
  });

  it("returns the destructive token for weak scores", () => {
    expect(strengthColor(0)).toContain("destructive");
    expect(strengthColor(1)).toContain("destructive");
  });

  it("returns an amber-ish hue for the middle score", () => {
    const colour = strengthColor(2);
    expect(colour).toContain("oklch");
  });
});
