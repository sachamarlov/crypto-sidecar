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
 */

import { getDefaultStore } from "jotai";
import { sessionIdAtom } from "@/stores/lock";
import { baseUrl, getSidecarConnection } from "./sidecar";
import type { ErrorBody } from "./types";

export class SidecarHttpError extends Error {
  public readonly status: number;
  public readonly detail: string;

  constructor(status: number, detail: string) {
    super(`sidecar HTTP ${status}: ${detail}`);
    this.status = status;
    this.detail = detail;
  }
}

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
  const response = await fetch(url, {
    ...init,
    method: init.method ?? "GET",
    headers,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  });
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
