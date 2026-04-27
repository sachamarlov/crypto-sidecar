/**
 * Hand-written TypeScript views over the Phase G sidecar Pydantic
 * schemas. A future codegen pipeline (`openapi-typescript` against
 * the FastAPI `/openapi.json` dump) replaces this file -- tracked
 * as a follow-up; the contract here is the ground truth until then.
 */

/** Common shape returned by the sidecar on every error. */
export interface ErrorBody {
  detail: string;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string;
}

export interface ReadyResponse {
  ready: boolean;
  vault_initialized: boolean;
  reason: string | null;
}

export interface VersionResponse {
  version: string;
  python_version: string;
  platform: string;
  machine: string;
}

// ---------------------------------------------------------------------------
// Vault unlock / lock / status
// ---------------------------------------------------------------------------

export interface UnlockRequest {
  admin_password: string;
}

export interface UnlockResponse {
  session_id: string;
  expires_in_seconds: number;
}

export interface LockRequest {
  session_id: string;
}

export interface VaultStatusResponse {
  active_sessions: number;
  vault_initialized: boolean;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

export type Kdf = "pbkdf2" | "argon2id";

export interface InitRequest {
  admin_password: string;
  kdf?: Kdf;
}

export interface InitResponse {
  data_dir: string;
  db_path: string;
  admin_config_path: string;
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export interface UserView {
  user_id: string;
  username: string;
  has_keystore: boolean;
}

export interface UsersList {
  users: UserView[];
}

export interface UserCreateRequest {
  username: string;
  password: string;
  kdf?: Kdf;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditEntryView {
  sequence: number;
  timestamp: string;
  actor_user_id: string | null;
  actor_username: string | null;
  action: string;
  target: string | null;
  metadata: Record<string, string> | null;
}

export interface AuditListResponse {
  entries: AuditEntryView[];
}

export interface AuditVerifyResponse {
  ok: boolean;
  first_bad_sequence: number | null;
  entries_checked: number;
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

export interface EncryptRequest {
  path: string;
  password: string;
  kdf?: Kdf;
  dest?: string;
  force?: boolean;
}

export interface EncryptResponse {
  output_path: string;
  plaintext_size: number;
  ciphertext_size: number;
  kdf_id: number;
  elapsed_ms: number;
}

export interface DecryptRequest {
  path: string;
  password: string;
  dest?: string;
  force?: boolean;
}

export interface DecryptResponse {
  output_path: string;
  plaintext_size: number;
  ciphertext_size: number;
  kdf_id: number;
  elapsed_ms: number;
}

// ---------------------------------------------------------------------------
// Share / Accept
// ---------------------------------------------------------------------------

export interface ShareRequest {
  source_path: string;
  sender_user_id: string;
  sender_password: string;
  recipient_user_id: string;
  output_path: string;
  expires_days?: number;
  force?: boolean;
}

export interface ShareResponse {
  output_path: string;
  sender_user_id: string;
  recipient_user_id: string;
}

export interface AcceptRequest {
  source_path: string;
  recipient_user_id: string;
  recipient_password: string;
  sender_user_id: string;
  output_path: string;
  force?: boolean;
}

export interface AcceptResponse {
  output_path: string;
  plaintext_size: number;
}

// ---------------------------------------------------------------------------
// Inspect
// ---------------------------------------------------------------------------

export interface InspectRequest {
  path: string;
}

export interface InspectResponse {
  path: string;
  version: number;
  kdf_id: number;
  kdf_name: string;
  kdf_params_summary: string;
  salt_hex: string;
  base_nonce_hex: string;
  header_size: number;
  ciphertext_size: number;
}

// ---------------------------------------------------------------------------
// Secure delete
// ---------------------------------------------------------------------------

export interface SecureDeleteRequest {
  path: string;
  passes?: number;
  confirm_ssd?: boolean;
}

export interface SecureDeleteResponse {
  path: string;
  method: string;
  passes: number;
  is_ssd: boolean | null;
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

export interface SsdReport {
  is_ssd: boolean | null;
  recommendation: string;
}

export interface AuditVerifyView {
  ok: boolean;
  first_bad_sequence: number | null;
  entries_checked: number;
}

export interface DoctorResponse {
  data_dir: string;
  db_exists: boolean;
  admin_config_exists: boolean;
  sqlcipher_available: boolean;
  ssd_report: SsdReport | null;
  audit_chain: AuditVerifyView | null;
}

// ---------------------------------------------------------------------------
// Sidecar connection (Tauri command)
// ---------------------------------------------------------------------------

export interface SidecarConnection {
  port: number;
  token: string;
}
