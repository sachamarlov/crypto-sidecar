/**
 * Thin typed HTTP client for the GuardiaBox sidecar.
 *
 * Every request is decorated with the launch token
 * (`X-GuardiaBox-Token`) and -- when the vault is unlocked -- with
 * the active session id (`X-GuardiaBox-Session`). The session id is
 * read at call time from the Jotai store so a freshly-locked vault
 * never sees its session leak into in-flight requests.
 *
 * Anti-oracle preservation (ADR-0016 sec C): the client surfaces
 * server errors verbatim by reading the `detail` field from the
 * sidecar's `ErrorBody`. The decrypt + accept toasts in the
 * UI layer rely on this string being constant on every post-KDF
 * failure -- the client must not paraphrase it.
 *
 * Error taxonomy (audit B P0-2): two distinct classes surface --
 * `SidecarHttpError` for non-2xx HTTP responses, and
 * `SidecarUnreachableError` for handshake / fetch / timeout
 * failures (port closed, AV blocked, sidecar crashed, abort). Both
 * live in `./errors` to break the circular import with sidecar.ts.
 */

import { sessionIdAtom } from "@/stores/lock";
import { getDefaultStore } from "jotai";
import { SidecarHttpError, SidecarUnreachableError } from "./errors";
import { baseUrl, getSidecarConnection } from "./sidecar";
import type { ErrorBody } from "./types";

// Re-export so existing call sites keep working without churn.
export { SidecarHttpError, SidecarUnreachableError } from "./errors";

interface RequestInitWithBody extends Omit<RequestInit, "body" | "headers"> {
  body?: unknown;
  headers?: Record<string, string>;
}

async function request<T>(path: string, init: RequestInitWithBody = {}): Promise<T> {
  const conn = await getSidecarConnection();
  const url = `${baseUrl(conn)}${path}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-GuardiaBox-Token": conn.token,
    ...(init.headers ?? {}),
  };
  // Inject session header if the user has unlocked the vault.
  const sessionId = getDefaultStore().get(sessionIdAtom);
  if (sessionId !== null) {
    headers["X-GuardiaBox-Session"] = sessionId;
  }
  // exactOptionalPropertyTypes refuses { body: undefined } and forbids
  // spreading our `unknown` body straight into RequestInit. Build the
  // fetch init explicitly: drop body from the spread, JSON-encode if
  // present, otherwise leave the key absent.
  const { body: rawBody, headers: _h, method: _m, ...rest } = init;
  const fetchInit: RequestInit = {
    ...rest,
    method: init.method ?? "GET",
    headers,
  };
  if (rawBody !== undefined) {
    fetchInit.body = JSON.stringify(rawBody);
  }
  let response: Response;
  try {
    response = await fetch(url, fetchInit);
  } catch (err) {
    // Native fetch throws on network failures (port closed, AV
    // blocking, ECONNREFUSED) as `TypeError: Failed to fetch`.
    // AbortError surfaces when the caller passes an AbortSignal.
    // Both collapse to SidecarUnreachableError so the UI helper
    // can dispatch a typed toast instead of "Failed to fetch".
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new SidecarUnreachableError("timeout");
    }
    if (err instanceof TypeError) {
      throw new SidecarUnreachableError("fetch");
    }
    throw err;
  }
  if (response.status === 204) {
    return undefined as T;
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as ErrorBody;
      detail = body.detail ?? detail;
    } catch {
      /* fall through with statusText */
    }
    throw new SidecarHttpError(response.status, detail);
  }
  return (await response.json()) as T;
}

/** GET helper. */
export function get<T>(path: string, init: RequestInitWithBody = {}): Promise<T> {
  return request<T>(path, { ...init, method: "GET" });
}

/** POST helper -- body is JSON-serialised. */
export function post<T>(path: string, body?: unknown, init: RequestInitWithBody = {}): Promise<T> {
  return request<T>(path, { ...init, method: "POST", body });
}

/** DELETE helper. */
export function del<T>(path: string, init: RequestInitWithBody = {}): Promise<T> {
  return request<T>(path, { ...init, method: "DELETE" });
}
