import { SidecarHttpError } from "@/api/client";
import { useDecrypt } from "@/api/queries";
import { PasswordField } from "@/components/PasswordField";
import { cn } from "@/lib/utils";
import { open } from "@tauri-apps/plugin-dialog";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export const Route = createFileRoute("/dashboard/decrypt")({
  component: DecryptModal,
});

function DecryptModal(): React.ReactElement {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const decryptMutation = useDecrypt();

  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");

  const onPick = async (): Promise<void> => {
    try {
      const picked = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "GuardiaBox container", extensions: ["crypt"] }],
      });
      if (typeof picked === "string") {
        setPath(picked);
      }
    } catch {
      /* cancelled */
    }
  };

  const onSubmit = (e: FormEvent): void => {
    e.preventDefault();
    decryptMutation.mutate(
      { path, password },
      {
        onSuccess: (response) => {
          toast.success(t("decrypt.success", { path: response.output_path }));
          setPassword("");
          void navigate({ to: "/dashboard" });
        },
        onError: (err) => {
          // Anti-oracle (ADR-0015 / ADR-0016 sec C):
          // post-KDF failures collapse to the constant toast
          // string. ShareExpiredError style differentiation does
          // not apply here (decrypt has no expiry concept).
          if (err instanceof SidecarHttpError && err.status === 422) {
            toast.error(t("decrypt.anti_oracle_failure"));
          } else if (err instanceof SidecarHttpError) {
            toast.error(err.detail);
          } else {
            toast.error(t("errors.network"));
          }
        },
      },
    );
  };

  return (
    <article className="mx-auto flex w-full max-w-xl flex-col gap-5 rounded-xl border border-border bg-card p-6">
      <h2 className="font-semibold text-xl">{t("decrypt.title")}</h2>

      <p className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-amber-200/90 text-xs">
        <ShieldAlert className="h-4 w-4 flex-shrink-0" aria-hidden />
        <span>{t("decrypt.info_anti_oracle")}</span>
      </p>

      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        <label className="flex flex-col gap-1.5">
          <span className="font-medium text-sm">{t("decrypt.path_label")}</span>
          <span className="flex gap-2">
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              className="h-10 flex-1 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              required
            />
            <button
              type="button"
              onClick={() => void onPick()}
              className="h-10 rounded-md border border-input bg-background px-3 text-sm hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {t("decrypt.path_pick")}
            </button>
          </span>
        </label>

        <PasswordField value={password} onChange={setPassword} showStrength={false} />

        <button
          type="submit"
          disabled={decryptMutation.isPending || path.length === 0 || password.length === 0}
          className={cn(
            "h-10 rounded-md bg-primary font-medium text-primary-foreground text-sm",
            "hover:bg-primary/90",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            "disabled:cursor-not-allowed disabled:opacity-60",
          )}
        >
          {decryptMutation.isPending ? t("common.loading") : t("decrypt.submit")}
        </button>
      </form>
    </article>
  );
}
