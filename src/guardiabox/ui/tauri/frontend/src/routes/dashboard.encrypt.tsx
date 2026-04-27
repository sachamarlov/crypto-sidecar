import { SidecarHttpError } from "@/api/client";
import { useEncrypt } from "@/api/queries";
import type { Kdf } from "@/api/types";
import { PasswordField } from "@/components/PasswordField";
import { cn } from "@/lib/utils";
import { open } from "@tauri-apps/plugin-dialog";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export const Route = createFileRoute("/dashboard/encrypt")({
  component: EncryptModal,
});

function EncryptModal(): React.ReactElement {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const encryptMutation = useEncrypt();

  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [kdf, setKdf] = useState<Kdf>("pbkdf2");

  const onPick = async (): Promise<void> => {
    try {
      const picked = await open({ multiple: false, directory: false });
      if (typeof picked === "string") {
        setPath(picked);
      }
    } catch {
      /* user cancelled */
    }
  };

  const onSubmit = (e: FormEvent): void => {
    e.preventDefault();
    if (path.length === 0) {
      toast.error(t("encrypt.error_path_required"));
      return;
    }
    if (password !== confirm) {
      toast.error(t("errors.weak_password"));
      return;
    }
    encryptMutation.mutate(
      { path, password, kdf },
      {
        onSuccess: (response) => {
          toast.success(t("encrypt.success", { path: response.output_path }));
          setPassword("");
          setConfirm("");
          void navigate({ to: "/dashboard" });
        },
        onError: (err) => {
          if (err instanceof SidecarHttpError) {
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
      <h2 className="font-semibold text-xl">{t("encrypt.title")}</h2>
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        <label className="flex flex-col gap-1.5">
          <span className="font-medium text-sm">{t("encrypt.path_label")}</span>
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
              {t("encrypt.path_pick")}
            </button>
          </span>
        </label>

        <fieldset className="flex flex-col gap-2">
          <legend className="font-medium text-sm">{t("encrypt.kdf_label")}</legend>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name="kdf"
              value="pbkdf2"
              checked={kdf === "pbkdf2"}
              onChange={() => setKdf("pbkdf2")}
            />
            {t("encrypt.kdf_pbkdf2")}
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name="kdf"
              value="argon2id"
              checked={kdf === "argon2id"}
              onChange={() => setKdf("argon2id")}
            />
            {t("encrypt.kdf_argon2id")}
          </label>
        </fieldset>

        <PasswordField value={password} onChange={setPassword} />
        <PasswordField
          value={confirm}
          onChange={setConfirm}
          placeholder={t("password.confirm_placeholder")}
          showStrength={false}
        />

        <button
          type="submit"
          disabled={encryptMutation.isPending || path.length === 0 || password.length < 12}
          className={cn(
            "h-10 rounded-md bg-primary font-medium text-primary-foreground text-sm",
            "hover:bg-primary/90",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            "disabled:cursor-not-allowed disabled:opacity-60",
          )}
        >
          {encryptMutation.isPending ? t("common.loading") : t("encrypt.submit")}
        </button>
      </form>
    </article>
  );
}
