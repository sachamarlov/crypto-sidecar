import { useShare, useUsers } from "@/api/queries";
import { PasswordField } from "@/components/PasswordField";
import { toastSidecarError } from "@/lib/sidecarErrors";
import { cn } from "@/lib/utils";
import { activeUserIdAtom } from "@/stores/lock";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { open, save } from "@tauri-apps/plugin-dialog";
import { useAtomValue } from "jotai";
import { ShieldAlert } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export const Route = createFileRoute("/dashboard/share")({
  component: ShareModal,
});

type Step = "form" | "confirm";

function ShareModal(): React.ReactElement {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const usersQuery = useUsers();
  const shareMutation = useShare();
  const activeUserId = useAtomValue(activeUserIdAtom);

  const [step, setStep] = useState<Step>("form");
  const [sourcePath, setSourcePath] = useState("");
  const [outputPath, setOutputPath] = useState("");
  const [recipientId, setRecipientId] = useState("");
  const [expiresDays, setExpiresDays] = useState(0);
  const [password, setPassword] = useState("");

  const otherUsers = usersQuery.data?.users.filter((u) => u.user_id !== activeUserId) ?? [];

  const onPickSource = async (): Promise<void> => {
    const picked = await open({
      multiple: false,
      directory: false,
      filters: [{ name: ".crypt", extensions: ["crypt"] }],
    });
    if (typeof picked === "string") {
      setSourcePath(picked);
      if (outputPath.length === 0) {
        setOutputPath(`${picked}.gbox-share`);
      }
    }
  };

  const onPickOutput = async (): Promise<void> => {
    const picked = await save({
      defaultPath: outputPath,
      filters: [{ name: ".gbox-share", extensions: ["gbox-share"] }],
    });
    if (typeof picked === "string") {
      setOutputPath(picked);
    }
  };

  const onSubmit = (e: FormEvent): void => {
    e.preventDefault();
    if (activeUserId === null) {
      toast.error(t("errors.session_required"));
      return;
    }
    if (step === "form") {
      setStep("confirm");
      return;
    }
    shareMutation.mutate(
      {
        source_path: sourcePath,
        sender_user_id: activeUserId,
        sender_password: password,
        recipient_user_id: recipientId,
        output_path: outputPath,
        expires_days: expiresDays,
      },
      {
        onSuccess: (resp) => {
          toast.success(t("share.success", { path: resp.output_path }));
          setPassword("");
          void navigate({ to: "/dashboard" });
        },
        onError: (err) => toastSidecarError(err, t),
      },
    );
  };

  return (
    <article className="mx-auto flex w-full max-w-xl flex-col gap-5 rounded-xl border border-border bg-card p-6">
      <h2 className="font-semibold text-xl">{t("share.title")}</h2>

      <p className="text-muted-foreground text-sm">
        {step === "form" ? t("share.preview_step") : t("share.commit_step")}
      </p>

      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        {step === "form" ? (
          <>
            <label className="flex flex-col gap-1.5">
              <span className="font-medium text-sm">{t("share.source_label")}</span>
              <span className="flex gap-2">
                <input
                  type="text"
                  value={sourcePath}
                  onChange={(e) => setSourcePath(e.target.value)}
                  className="h-10 flex-1 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  required
                />
                <button
                  type="button"
                  onClick={() => void onPickSource()}
                  className="h-10 rounded-md border border-input px-3 text-sm hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {t("encrypt.path_pick")}
                </button>
              </span>
            </label>

            <label className="flex flex-col gap-1.5">
              <span className="font-medium text-sm">{t("share.recipient_label")}</span>
              <select
                value={recipientId}
                onChange={(e) => setRecipientId(e.target.value)}
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
              <span className="font-medium text-sm">{t("share.expires_label")}</span>
              <input
                type="number"
                min={0}
                max={3650}
                value={expiresDays}
                onChange={(e) => setExpiresDays(Number(e.target.value))}
                className="h-10 w-32 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              />
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

            <button
              type="submit"
              disabled={
                sourcePath.length === 0 || recipientId.length === 0 || outputPath.length === 0
              }
              className="h-10 rounded-md bg-primary font-medium text-primary-foreground text-sm hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60"
            >
              {t("share.preview_button")}
            </button>
          </>
        ) : (
          <>
            <p className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-amber-200/90 text-xs">
              <ShieldAlert className="h-4 w-4 flex-shrink-0" aria-hidden />
              <span>{t("share.fingerprint_warning")}</span>
            </p>
            <PasswordField value={password} onChange={setPassword} showStrength={false} />
            <button
              type="submit"
              disabled={shareMutation.isPending || password.length === 0}
              className={cn(
                "h-10 rounded-md bg-primary font-medium text-primary-foreground text-sm",
                "hover:bg-primary/90",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                "disabled:cursor-not-allowed disabled:opacity-60",
              )}
            >
              {shareMutation.isPending ? t("common.loading") : t("share.commit_button")}
            </button>
            <button
              type="button"
              onClick={() => setStep("form")}
              className="text-muted-foreground text-xs hover:text-foreground"
            >
              {t("common.back")}
            </button>
          </>
        )}
      </form>
    </article>
  );
}
