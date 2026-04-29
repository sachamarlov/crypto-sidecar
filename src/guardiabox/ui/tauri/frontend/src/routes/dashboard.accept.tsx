import { SidecarHttpError } from "@/api/client";
import { useAccept, useUsers } from "@/api/queries";
import { PasswordField } from "@/components/PasswordField";
import { toastSidecarError } from "@/lib/sidecarErrors";
import { activeUserIdAtom } from "@/stores/lock";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { open, save } from "@tauri-apps/plugin-dialog";
import { useAtomValue } from "jotai";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export const Route = createFileRoute("/dashboard/accept")({
  component: AcceptModal,
});

function AcceptModal(): React.ReactElement {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const usersQuery = useUsers();
  const acceptMutation = useAccept();
  const activeUserId = useAtomValue(activeUserIdAtom);

  const [tokenPath, setTokenPath] = useState("");
  const [outputPath, setOutputPath] = useState("");
  const [senderId, setSenderId] = useState("");
  const [password, setPassword] = useState("");

  const otherUsers = usersQuery.data?.users.filter((u) => u.user_id !== activeUserId) ?? [];

  const onPickToken = async (): Promise<void> => {
    const picked = await open({
      multiple: false,
      directory: false,
      filters: [{ name: ".gbox-share", extensions: ["gbox-share"] }],
    });
    if (typeof picked === "string") setTokenPath(picked);
  };

  const onPickOutput = async (): Promise<void> => {
    const picked = await save({ defaultPath: outputPath });
    if (typeof picked === "string") setOutputPath(picked);
  };

  const onSubmit = (e: FormEvent): void => {
    e.preventDefault();
    if (activeUserId === null) {
      toast.error(t("errors.session_required"));
      return;
    }
    acceptMutation.mutate(
      {
        source_path: tokenPath,
        recipient_user_id: activeUserId,
        recipient_password: password,
        sender_user_id: senderId,
        output_path: outputPath,
      },
      {
        onSuccess: (r) => {
          toast.success(t("accept.success", { path: r.output_path }));
          setPassword("");
          void navigate({ to: "/dashboard" });
        },
        onError: (err) => {
          if (err instanceof SidecarHttpError && err.status === 422) {
            // Anti-oracle: integrity / signature / unwrap all share
            // the same constant 'share verification failed' toast.
            // The 'share expired' branch is allowed to differ
            // because it is raised AFTER signature verifies (the
            // attacker has to forge a valid signature, which is
            // impossible against the sender's public key).
            if (err.detail === "share expired") {
              toast.error(t("accept.expired"));
            } else {
              toast.error(t("accept.anti_oracle_failure"));
            }
            return;
          }
          // Pre-KDF parse failures (400/409) and unreachable errors
          // route through the central typed-toast helper.
          toastSidecarError(err, t);
        },
      },
    );
  };

  return (
    <article className="mx-auto flex w-full max-w-xl flex-col gap-5 rounded-xl border border-border bg-card p-6">
      <h2 className="font-semibold text-xl">{t("accept.title")}</h2>
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        <label className="flex flex-col gap-1.5">
          <span className="font-medium text-sm">{t("accept.source_label")}</span>
          <span className="flex gap-2">
            <input
              type="text"
              value={tokenPath}
              onChange={(e) => setTokenPath(e.target.value)}
              className="h-10 flex-1 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              required
            />
            <button
              type="button"
              onClick={() => void onPickToken()}
              className="h-10 rounded-md border border-input px-3 text-sm hover:bg-accent"
            >
              {t("encrypt.path_pick")}
            </button>
          </span>
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="font-medium text-sm">{t("accept.sender_label")}</span>
          <select
            value={senderId}
            onChange={(e) => setSenderId(e.target.value)}
            required
            className="h-10 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <option value="" disabled>
              --
            </option>
            {otherUsers.map((u) => (
              <option key={u.user_id} value={u.user_id}>
                {u.username}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="font-medium text-sm">{t("encrypt.path_label")}</span>
          <span className="flex gap-2">
            <input
              type="text"
              value={outputPath}
              onChange={(e) => setOutputPath(e.target.value)}
              className="h-10 flex-1 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              required
            />
            <button
              type="button"
              onClick={() => void onPickOutput()}
              className="h-10 rounded-md border border-input px-3 text-sm hover:bg-accent"
            >
              {t("encrypt.path_pick")}
            </button>
          </span>
        </label>

        <PasswordField value={password} onChange={setPassword} showStrength={false} />

        <button
          type="submit"
          disabled={acceptMutation.isPending}
          className="h-10 rounded-md bg-primary font-medium text-primary-foreground text-sm hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60"
        >
          {acceptMutation.isPending ? t("common.loading") : t("accept.submit")}
        </button>
      </form>
    </article>
  );
}
