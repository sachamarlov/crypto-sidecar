/**
 * Sidecar error taxonomy.
 *
 * Two distinct categories surface to the UI:
 *
 * * `SidecarHttpError` -- the sidecar responded with a non-2xx status
 *   and an `ErrorBody` (or a parseable status text). This covers
 *   anti-oracle 422 (ADR-0015 / ADR-0016 sec C), 401 session expired,
 *   429 rate-limited, 4xx pre-KDF parse failures, and 5xx server.
 *
 * * `SidecarUnreachableError` -- the sidecar was not reachable at all.
 *   Three sub-stages let the UI offer actionable copy: `handshake`
 *   (the Rust-side `get_sidecar_connection` did not resolve within
 *   10s), `fetch` (the loopback HTTP request itself threw a
 *   `TypeError` -- port closed, AV blocked, sidecar crashed), and
 *   `timeout` (the request was aborted by the caller).
 *
 * The split is the audit B P0-2 fix: a single `errors.network` toast
 * blanket-covered every diagnostic and made every Phase I CORS / port
 * regression invisible to the reviewer.
 */

export class SidecarHttpError extends Error {
  public readonly status: number;
  public readonly detail: string;

  constructor(status: number, detail: string) {
    super(`sidecar HTTP ${status}: ${detail}`);
    this.status = status;
    this.detail = detail;
  }
}

export type SidecarUnreachableStage = "handshake" | "fetch" | "timeout";

export class SidecarUnreachableError extends Error {
  public readonly stage: SidecarUnreachableStage;

  constructor(stage: SidecarUnreachableStage) {
    super(`sidecar unreachable at stage=${stage}`);
    this.stage = stage;
  }
}
