import { useUsers } from "@/api/queries";
import { activeUserIdAtom } from "@/stores/lock";
import { cn } from "@/lib/utils";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useAtom } from "jotai";
import { CheckCircle2, UserCircle2 } from "lucide-react";
import { useTranslation } from "react-i18next";

export const Route = createFileRoute("/dashboard/")({
  component: DashboardHome,
});

function DashboardHome(): React.ReactElement {
  const { t } = useTranslation();
  const usersQuery = useUsers();
  const [activeUserId, setActiveUserId] = useAtom(activeUserIdAtom);

  if (usersQuery.isLoading) {
    return <p className="text-muted-foreground">{t("common.loading")}</p>;
  }

  const users = usersQuery.data?.users ?? [];

  if (users.length === 0) {
    return (
      <section className="flex flex-col items-start gap-4">
        <h2 className="font-semibold text-2xl">{t("dashboard.empty.title")}</h2>
        <p className="text-muted-foreground">{t("dashboard.empty.subtitle")}</p>
        <Link
          to="/dashboard/users"
          className="rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground text-sm hover:bg-primary/90"
        >
          {t("dashboard.actions.users")}
        </Link>
      </section>
    );
  }

  return (
    <section className="flex flex-col gap-4">
      <h2 className="font-semibold text-xl">{t("dashboard.users_section")}</h2>
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {users.map((user) => {
          const active = user.user_id === activeUserId;
          return (
            <li key={user.user_id}>
              <button
                type="button"
                onClick={() => setActiveUserId(user.user_id)}
                className={cn(
                  "flex w-full items-center justify-between rounded-lg border bg-card p-4 text-left transition-colors",
                  active
                    ? "border-primary bg-primary/5"
                    : "border-border hover:border-primary/40",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                )}
                aria-pressed={active}
              >
                <span className="flex items-center gap-3">
                  <UserCircle2 className="h-7 w-7 text-foreground/70" aria-hidden />
                  <span>
                    <span className="block font-medium">{user.username}</span>
                    <span className="block text-muted-foreground text-xs">
                      {user.user_id.slice(0, 8)}…
                    </span>
                  </span>
                </span>
                {active ? <CheckCircle2 className="h-5 w-5 text-primary" aria-hidden /> : null}
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
