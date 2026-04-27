import { SidecarHttpError } from "@/api/client";
import { useCreateUser, useDeleteUser, useUsers } from "@/api/queries";
import { PasswordField } from "@/components/PasswordField";
import { createFileRoute } from "@tanstack/react-router";
import { Trash2, UserPlus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export const Route = createFileRoute("/dashboard/users")({
  component: UsersModal,
});

function UsersModal(): React.ReactElement {
  const { t } = useTranslation();
  const usersQuery = useUsers();
  const createMutation = useCreateUser();
  const deleteMutation = useDeleteUser();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");

  const onCreate = (e: FormEvent): void => {
    e.preventDefault();
    if (password !== confirm) {
      toast.error(t("errors.weak_password"));
      return;
    }
    createMutation.mutate(
      { username, password, kdf: "pbkdf2" },
      {
        onSuccess: () => {
          toast.success(t("users.create_success", { username }));
          setUsername("");
          setPassword("");
          setConfirm("");
        },
        onError: (err) => {
          if (err instanceof SidecarHttpError && err.status === 409) {
            toast.error(t("users.duplicate_username"));
          } else if (err instanceof SidecarHttpError && err.status === 400) {
            toast.error(t("errors.weak_password"));
          } else {
            toast.error(t("errors.network"));
          }
        },
      },
    );
  };

  const onDelete = (userId: string): void => {
    if (!window.confirm(t("users.delete_confirm_subtitle"))) return;
    deleteMutation.mutate(userId, {
      onSuccess: () => toast.success(t("users.delete_success")),
      onError: () => toast.error(t("errors.network")),
    });
  };

  return (
    <article className="flex flex-col gap-6">
      <h2 className="font-semibold text-xl">{t("users.title")}</h2>

      <section className="rounded-xl border border-border bg-card p-5">
        <h3 className="mb-4 flex items-center gap-2 font-medium text-sm">
          <UserPlus className="h-4 w-4 text-primary" aria-hidden />
          {t("users.create_title")}
        </h3>
        <form onSubmit={onCreate} className="flex flex-col gap-3">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder={t("users.username_label")}
            required
            minLength={1}
            maxLength={128}
            aria-label={t("users.username_label")}
            className="h-10 rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
          <PasswordField value={password} onChange={setPassword} />
          <PasswordField
            value={confirm}
            onChange={setConfirm}
            placeholder={t("password.confirm_placeholder")}
            showStrength={false}
          />
          <button
            type="submit"
            disabled={
              createMutation.isPending ||
              username.length === 0 ||
              password.length < 12 ||
              password !== confirm
            }
            className="h-10 rounded-md bg-primary font-medium text-primary-foreground text-sm hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60"
          >
            {createMutation.isPending ? t("common.loading") : t("users.create_submit")}
          </button>
        </form>
      </section>

      <section>
        <h3 className="mb-3 font-medium text-sm">{t("dashboard.users_section")}</h3>
        {usersQuery.isLoading ? (
          <p className="text-muted-foreground text-sm">{t("common.loading")}</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {usersQuery.data?.users.map((u) => (
              <li
                key={u.user_id}
                className="flex items-center justify-between rounded-md border border-border bg-card px-4 py-2 text-sm"
              >
                <span className="flex flex-col">
                  <span className="font-medium">{u.username}</span>
                  <span className="font-mono text-muted-foreground text-xs">
                    {u.user_id}
                  </span>
                </span>
                <button
                  type="button"
                  onClick={() => onDelete(u.user_id)}
                  disabled={deleteMutation.isPending}
                  aria-label={t("users.delete_button")}
                  className="flex items-center gap-1 rounded-md border border-destructive/40 bg-destructive/10 px-2 py-1 text-destructive text-xs hover:bg-destructive/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive disabled:opacity-60"
                >
                  <Trash2 className="h-3.5 w-3.5" aria-hidden />
                  {t("common.delete")}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </article>
  );
}
