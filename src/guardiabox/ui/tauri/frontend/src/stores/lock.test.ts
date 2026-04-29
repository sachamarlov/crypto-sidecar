import { createStore } from "jotai";
import { describe, expect, it } from "vitest";
import { activeUserIdAtom, expiresAtMsAtom, isUnlockedAtom, sessionIdAtom } from "./lock";

describe("lock atoms", () => {
  it("isUnlocked is false by default", () => {
    const store = createStore();
    expect(store.get(isUnlockedAtom)).toBe(false);
  });

  it("isUnlocked is true when session_id and expiresAt > now", () => {
    const store = createStore();
    store.set(sessionIdAtom, "session-abc");
    store.set(expiresAtMsAtom, Date.now() + 60_000);
    expect(store.get(isUnlockedAtom)).toBe(true);
  });

  it("isUnlocked is false when expiresAt is in the past", () => {
    const store = createStore();
    store.set(sessionIdAtom, "session-abc");
    store.set(expiresAtMsAtom, Date.now() - 60_000);
    expect(store.get(isUnlockedAtom)).toBe(false);
  });

  it("isUnlocked is false when sessionId is null even if expiresAt is set", () => {
    const store = createStore();
    store.set(sessionIdAtom, null);
    store.set(expiresAtMsAtom, Date.now() + 60_000);
    expect(store.get(isUnlockedAtom)).toBe(false);
  });

  it("activeUserIdAtom defaults to null", () => {
    const store = createStore();
    expect(store.get(activeUserIdAtom)).toBeNull();
  });

  it("activeUserIdAtom can be set + read independently of sessionId", () => {
    const store = createStore();
    store.set(activeUserIdAtom, "user-uuid");
    expect(store.get(activeUserIdAtom)).toBe("user-uuid");
    expect(store.get(isUnlockedAtom)).toBe(false);
  });
});
