/**
 * TanStack Query hooks over the sidecar API.
 *
 * Read hooks use `useQuery` with sensible cache keys; mutations use
 * `useMutation` and invalidate the relevant queries on success.
 *
 * No optimistic updates yet -- the sidecar is fast enough on
 * loopback that the latency hide is unnecessary; adding it would
 * complicate the anti-oracle path on /decrypt and /accept.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationOptions, UseQueryOptions } from "@tanstack/react-query";
import { del, get, post } from "./client";
import type {
  AcceptRequest,
  AcceptResponse,
  AuditListResponse,
  AuditVerifyResponse,
  DecryptRequest,
  DecryptResponse,
  DoctorResponse,
  EncryptRequest,
  EncryptResponse,
  InitRequest,
  InitResponse,
  InspectRequest,
  InspectResponse,
  ReadyResponse,
  SecureDeleteRequest,
  SecureDeleteResponse,
  ShareRequest,
  ShareResponse,
  UnlockRequest,
  UnlockResponse,
  UserCreateRequest,
  UserView,
  UsersList,
  VaultStatusResponse,
  VersionResponse,
} from "./types";

// ---------------------------------------------------------------------------
// Health / status
// ---------------------------------------------------------------------------

export function useReadyz(options?: Omit<UseQueryOptions<ReadyResponse>, "queryKey" | "queryFn">) {
  return useQuery<ReadyResponse>({
    queryKey: ["readyz"],
    queryFn: () => get<ReadyResponse>("/readyz"),
    staleTime: 10_000,
    ...options,
  });
}

export function useVersion(
  options?: Omit<UseQueryOptions<VersionResponse>, "queryKey" | "queryFn">,
) {
  return useQuery<VersionResponse>({
    queryKey: ["version"],
    queryFn: () => get<VersionResponse>("/version"),
    staleTime: 60_000,
    ...options,
  });
}

export function useVaultStatus(
  options?: Omit<UseQueryOptions<VaultStatusResponse>, "queryKey" | "queryFn">,
) {
  return useQuery<VaultStatusResponse>({
    queryKey: ["vault", "status"],
    queryFn: () => get<VaultStatusResponse>("/api/v1/vault/status"),
    staleTime: 5_000,
    ...options,
  });
}

// ---------------------------------------------------------------------------
// Init / unlock / lock
// ---------------------------------------------------------------------------

export function useInit(options?: UseMutationOptions<InitResponse, Error, InitRequest>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: InitRequest) => post<InitResponse>("/api/v1/init", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["readyz"] });
      void qc.invalidateQueries({ queryKey: ["vault", "status"] });
    },
    ...options,
  });
}

export function useUnlock(options?: UseMutationOptions<UnlockResponse, Error, UnlockRequest>) {
  return useMutation({
    mutationFn: (body: UnlockRequest) => post<UnlockResponse>("/api/v1/vault/unlock", body),
    ...options,
  });
}

export function useLock(options?: UseMutationOptions<void, Error, { session_id: string }>) {
  return useMutation({
    mutationFn: (body: { session_id: string }) => post<void>("/api/v1/vault/lock", body),
    ...options,
  });
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export function useUsers(options?: Omit<UseQueryOptions<UsersList>, "queryKey" | "queryFn">) {
  return useQuery<UsersList>({
    queryKey: ["users"],
    queryFn: () => get<UsersList>("/api/v1/users"),
    ...options,
  });
}

export function useCreateUser(options?: UseMutationOptions<UserView, Error, UserCreateRequest>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UserCreateRequest) => post<UserView>("/api/v1/users", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["users"] });
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
    ...options,
  });
}

export function useDeleteUser(options?: UseMutationOptions<void, Error, string>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (userId: string) => del<void>(`/api/v1/users/${userId}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["users"] });
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
    ...options,
  });
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditFilter {
  actor_user_id?: string;
  action?: string;
  limit?: number;
}

export function useAudit(filter: AuditFilter = {}) {
  const params = new URLSearchParams();
  if (filter.actor_user_id) params.set("actor_user_id", filter.actor_user_id);
  if (filter.action) params.set("action", filter.action);
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  const qs = params.toString();
  const path = qs.length === 0 ? "/api/v1/audit" : `/api/v1/audit?${qs}`;

  return useQuery<AuditListResponse>({
    queryKey: ["audit", filter],
    queryFn: () => get<AuditListResponse>(path),
  });
}

export function useAuditVerify() {
  return useMutation({
    mutationFn: () => get<AuditVerifyResponse>("/api/v1/audit/verify"),
  });
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt / Inspect / Secure-delete
// ---------------------------------------------------------------------------

export function useEncrypt(options?: UseMutationOptions<EncryptResponse, Error, EncryptRequest>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: EncryptRequest) => post<EncryptResponse>("/api/v1/encrypt", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
    ...options,
  });
}

export function useDecrypt(options?: UseMutationOptions<DecryptResponse, Error, DecryptRequest>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DecryptRequest) => post<DecryptResponse>("/api/v1/decrypt", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
    ...options,
  });
}

export function useInspect(options?: UseMutationOptions<InspectResponse, Error, InspectRequest>) {
  return useMutation({
    mutationFn: (body: InspectRequest) => post<InspectResponse>("/api/v1/inspect", body),
    ...options,
  });
}

export function useSecureDelete(
  options?: UseMutationOptions<SecureDeleteResponse, Error, SecureDeleteRequest>,
) {
  return useMutation({
    mutationFn: (body: SecureDeleteRequest) =>
      post<SecureDeleteResponse>("/api/v1/secure-delete", body),
    ...options,
  });
}

// ---------------------------------------------------------------------------
// Share / Accept
// ---------------------------------------------------------------------------

export function useShare(options?: UseMutationOptions<ShareResponse, Error, ShareRequest>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ShareRequest) => post<ShareResponse>("/api/v1/share", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
    ...options,
  });
}

export function useAccept(options?: UseMutationOptions<AcceptResponse, Error, AcceptRequest>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AcceptRequest) => post<AcceptResponse>("/api/v1/accept", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["audit"] });
    },
    ...options,
  });
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

export function useDoctor(verifyAudit = false, reportSsd = false) {
  const params = new URLSearchParams();
  if (verifyAudit) params.set("verify_audit", "true");
  if (reportSsd) params.set("report_ssd", "true");
  const qs = params.toString();
  const path = qs.length === 0 ? "/api/v1/doctor" : `/api/v1/doctor?${qs}`;

  return useQuery<DoctorResponse>({
    queryKey: ["doctor", { verifyAudit, reportSsd }],
    queryFn: () => get<DoctorResponse>(path),
  });
}
