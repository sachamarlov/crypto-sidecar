/**
 * Lightweight password strength evaluator for the lock + create-user
 * forms. Mirrors the CLI / TUI zxcvbn semantic in spirit (length +
 * entropy classes), but the server-side `assert_strong` in
 * :mod:`guardiabox.security.password` is the authoritative gate --
 * the client evaluation is purely a UX hint.
 *
 * Score band -> i18n key mapping (audit E P0-7 fix: previously the
 * labels were hard-coded French literals, breaking NFR-6 EN coverage):
 *
 * | Length / classes | Score | i18n key                |
 * | ---------------- | ----- | ----------------------- |
 * | < 8              | 0     | password.strength.0     |
 * | 8..11 + 1 class  | 1     | password.strength.1     |
 * | 12..15 + 2 cls   | 2     | password.strength.2     |
 * | 16+ + 3 classes  | 3     | password.strength.3     |
 * | 20+ + 4 classes  | 4     | password.strength.4     |
 *
 * The label is resolved by `PasswordField` via `t("password.strength.${score}")`.
 */

export type PasswordScore = 0 | 1 | 2 | 3 | 4;

export interface PasswordEval {
  score: PasswordScore;
}

const CHAR_CLASSES: ReadonlyArray<RegExp> = [/[a-z]/u, /[A-Z]/u, /[0-9]/u, /[^A-Za-z0-9]/u];

export function evaluatePassword(password: string): PasswordEval {
  if (password.length === 0) {
    return { score: 0 };
  }
  const classes = CHAR_CLASSES.filter((re) => re.test(password)).length;
  let score: PasswordScore = 0;
  if (password.length >= 20 && classes >= 4) {
    score = 4;
  } else if (password.length >= 16 && classes >= 3) {
    score = 3;
  } else if (password.length >= 12 && classes >= 2) {
    score = 2;
  } else if (password.length >= 8 && classes >= 1) {
    score = 1;
  } else {
    score = 0;
  }
  return { score };
}

/** Hex colour (oklch fallback) keyed to score for the strength bar. */
export function strengthColor(score: PasswordScore): string {
  if (score >= 3) return "var(--color-primary)";
  if (score === 2) return "oklch(0.75 0.18 70)";
  return "var(--color-destructive)";
}
