/**
 * Tauri command bridge -- retrieves the (port, token) pair the
 * sidecar produces at launch. Wraps `invoke('get_sidecar_connection')`
 * so the rest of the app never imports `@tauri-apps/api` directly.
 *
 * The Rust side returns `null` until the spawn handshake completes;
 * the React boot loop polls every 200 ms until the connection
 * resolves. After that, the URL is cached for the session.
 */

import { invoke } from "@tauri-apps/api/core";
import { SidecarUnreachableError } from "./errors";
import type { SidecarConnection } from "./types";

let cached: SidecarConnection | null = null;

/**
 * Get the active sidecar connection. Polls the Tauri command until
 * the handshake is complete. Throws `SidecarUnreachableError` with
 * `stage="handshake"` after 10 s so the UI helper can surface a
 * typed toast (audit B P0-2).
 */
export async function getSidecarConnection(): Promise<SidecarConnection> {
  if (cached !== null) {
    return cached;
  }
  const maxWaitMs = 10_000;
  const intervalMs = 200;
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const conn = await invoke<SidecarConnection | null>("get_sidecar_connection");
      if (conn !== null && conn !== undefined) {
        cached = conn;
        return conn;
      }
    } catch {
      // The Tauri command may not be registered in dev mode (web
      // browser preview). Caller-side fallback below.
    }
    await sleep(intervalMs);
  }
  throw new SidecarUnreachableError("handshake");
}

/**
 * Reset the cached connection -- exposed for tests and for the
 * (unlikely) case where the sidecar restarts mid-session.
 */
export function resetSidecarConnection(): void {
  cached = null;
}

/** Build the loopback HTTP base URL from a connection. */
export function baseUrl(conn: SidecarConnection): string {
  return `http://127.0.0.1:${conn.port}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
