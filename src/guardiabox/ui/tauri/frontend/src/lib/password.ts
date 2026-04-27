/**
 * Lightweight password strength evaluator for the lock + create-user
 * forms. Mirrors the CLI / TUI zxcvbn semantic in spirit (length +
 * entropy classes), but the server-side `assert_strong` in
 * :mod:`guardiabox.security.password` is the authoritative gate --
 * the client evaluation is purely a UX hint.
 *
 * Score band -> label mapping aligns with the TUI strength bar:
 *
 * | Length / classes | Score | Label             |
 * | ---------------- | ----- | ----------------- |
 * | < 8              | 0     | Très faible       |
 * | 8..11 + 1 class  | 1     | Faible            |
 * | 12..15 + 2 cls   | 2     | Moyen             |
 * | 16+ + 3 classes  | 3     | Bon               |
 * | 20+ + 4 classes  | 4     | Excellent         |
 */

export interface PasswordEval {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
}

const CHAR_CLASSES: ReadonlyArray<RegExp> = [
  /[a-z]/u,
  /[A-Z]/u,
  /[0-9]/u,
  /[^A-Za-z0-9]/u,
];

const LABEL_BY_SCORE: Record<0 | 1 | 2 | 3 | 4, string> = {
  0: "Très faible",
  1: "Faible",
  2: "Moyen",
  3: "Bon",
  4: "Excellent",
};

export function evaluatePassword(password: string): PasswordEval {
  if (password.length === 0) {
    return { score: 0, label: LABEL_BY_SCORE[0] };
  }
  const classes = CHAR_CLASSES.filter((re) => re.test(password)).length;
  let score: 0 | 1 | 2 | 3 | 4 = 0;
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
  return { score, label: LABEL_BY_SCORE[score] };
}

/** Hex colour (oklch fallback) keyed to score for the strength bar. */
export function strengthColor(score: 0 | 1 | 2 | 3 | 4): string {
  if (score >= 3) return "var(--color-primary)";
  if (score === 2) return "oklch(0.75 0.18 70)";
  return "var(--color-destructive)";
}
