/**
 * Strip ``undefined`` values from an object.
 *
 * Audit E P1-11 / ε-13: TypeScript's ``exactOptionalPropertyTypes``
 * (enabled in tsconfig.json) refuses ``{ key: undefined }`` literals;
 * absent keys are required for optional properties. Hand-rolled
 * conditional spreads (``actionFilter ? { action: actionFilter,
 * limit } : { limit }``) repeat the workaround at every call site.
 * This helper centralises it.
 */

export function dropUndefined<T extends Record<string, unknown>>(
  obj: T,
): { [K in keyof T]: T[K] extends undefined ? never : T[K] } {
  const result: Record<string, unknown> = {};
  for (const key in obj) {
    const value = obj[key];
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result as { [K in keyof T]: T[K] extends undefined ? never : T[K] };
}
