import { useLock, useUsers } from "@/api/queries";
import { AuthGuard } from "@/components/AuthGuard";
import { useAutoLock } from "@/hooks/useAutoLock";
import { useLanguageStore } from "@/stores/language";
import { activeUserIdAtom, expiresAtMsAtom, sessionIdAtom } from "@/stores/lock";
import { cn } from "@/lib/utils";
import { createFileRoute, Link, Outlet, useNavigate } from "@tanstack/react-router";
import { useAtom, useAtomValue } from "jotai";
import {
  Activity,
  FileLock,
  FileText,
  Inbox,
  LockKeyhole,
  Settings,
  Share2,
  Users,
} from "lucide-react";
import { useTranslation } from "react-i18next";

export const Route = createFileRoute("/dashboard")({
  component: DashboardLayout,
});

function DashboardLayout(): React.ReactElement {
  return (
    <AuthGuard>
      <DashboardChrome />
    </AuthGuard>
  );
}

function DashboardChrome(): React.ReactElement {
  const { t } = useTranslation();
  useAutoLock();

  const navigate = useNavigate();
  const language = useLanguageStore((s) => s.language);
  const setLanguage = useLanguageStore((s) => s.setLanguage);

  const [sessionId, setSessionId] = useAtom(sessionIdAtom);
  const [, setExpiresAt] = useAtom(expiresAtMsAtom);
  const activeUserId = useAtomValue(activeUserIdAtom);

  const usersQuery = useUsers();
  const lockMutation = useLock();

  const onLock = (): void => {
    if (sessionId !== null) {
      lockMutation.mutate({ session_id: sessionId });
    }
    setSessionId(null);
    setExpiresAt(null);
    void navigate({ to: "/lock" });
  };

  const activeUser =
    usersQuery.data?.users.find((u) => u.user_id === activeUserId) ?? null;

  const navItems: Array<{
    to: string;
    label: string;
    icon: React.ReactNode;
  }> = [
    { to: "/dashboard/encrypt", label: t("dashboard.actions.encrypt"), icon: <FileLock className="h-4 w-4" /> },
    { to: "/dashboard/decrypt", label: t("dashboard.actions.decrypt"), icon: <FileText className="h-4 w-4" /> },
    { to: "/dashboard/share", label: t("dashboard.actions.share"), icon: <Share2 className="h-4 w-4" /> },
    { to: "/dashboard/accept", label: t("dashboard.actions.accept"), icon: <Inbox className="h-4 w-4" /> },
    { to: "/dashboard/history", label: t("dashboard.actions.history"), icon: <Activity className="h-4 w-4" /> },
    { to: "/dashboard/users", label: t("dashboard.actions.users"), icon: <Users className="h-4 w-4" /> },
    { to: "/dashboard/settings", label: t("dashboard.actions.settings"), icon: <Settings className="h-4 w-4" /> },
  ];

  return (
    <div className="grid min-h-screen grid-rows-[auto_1fr] bg-background text-foreground">
      <header className="flex items-center justify-between border-border border-b bg-card/40 px-6 py-3 backdrop-blur-sm">
        <div className="flex items-center gap-2">
          <LockKeyhole className="h-5 w-5 text-primary" aria-hidden />
          <span className="font-semibold tracking-tight">{t("app.name")}</span>
          {activeUser !== null ? (
            <span className="ml-3 text-muted-foreground text-sm">
              / {activeUser.username}
            </span>
          ) : null}
        </div>
        <div className="flex items-center gap-2 text-sm">
          <button
            type="button"
            onClick={() => setLanguage(language === "fr" ? "en" : "fr")}
            className="rounded-md border border-input px-2 py-1 text-xs hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={t("common.language")}
          >
            {language === "fr" ? "EN" : "FR"}
          </button>
          <button
            type="button"
            onClick={onLock}
            className={cn(
              "rounded-md border border-destructive/40 bg-destructive/10 px-3 py-1.5 text-destructive text-xs font-medium",
              "hover:bg-destructive/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-destructive",
            )}
          >
            {t("dashboard.actions.lock")}
          </button>
        </div>
      </header>

      <div className="grid grid-cols-[16rem_1fr]">
        <nav
          aria-label={t("dashboard.title")}
          className="border-border border-r bg-card/20 p-4"
        >
          <ul className="flex flex-col gap-1">
            {navItems.map((item) => (
              <li key={item.to}>
                <Link
                  to={item.to}
                  className={cn(
                    "flex items-center gap-2 rounded-md px-3 py-2 text-sm",
                    "hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  )}
                  activeProps={{ className: "bg-accent text-accent-foreground" }}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <main className="overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
