import { useInit, useReadyz, useUnlock } from "@/api/queries";
import { SidecarHttpError } from "@/api/client";
import { PasswordField } from "@/components/PasswordField";
import { useLanguageStore } from "@/stores/language";
import { expiresAtMsAtom, isUnlockedAtom, sessionIdAtom } from "@/stores/lock";
import { cn } from "@/lib/utils";
import { createFileRoute, Navigate, useNavigate } from "@tanstack/react-router";
import { motion, useReducedMotion } from "framer-motion";
import { useAtom, useAtomValue } from "jotai";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export const Route = createFileRoute("/lock")({
  component: LockScreen,
});

function LockScreen(): React.ReactElement {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const unlocked = useAtomValue(isUnlockedAtom);
  const [, setSessionId] = useAtom(sessionIdAtom);
  const [, setExpiresAt] = useAtom(expiresAtMsAtom);
  const reduceMotion = useReducedMotion();
  const language = useLanguageStore((s) => s.language);
  const setLanguage = useLanguageStore((s) => s.setLanguage);

  const readyzQuery = useReadyz();
  const unlockMutation = useUnlock();
  const initMutation = useInit();

  const [password, setPassword] = useState("");
  const [showInit, setShowInit] = useState(false);

  if (unlocked) {
    return <Navigate to="/dashboard" />;
  }

  const onUnlock = (e: FormEvent): void => {
    e.preventDefault();
    unlockMutation.mutate(
      { admin_password: password },
      {
        onSuccess: (response) => {
          setSessionId(response.session_id);
          setExpiresAt(Date.now() + response.expires_in_seconds * 1000);
          setPassword("");
          void navigate({ to: "/dashboard" });
        },
        onError: (err) => {
          if (err instanceof SidecarHttpError && err.status === 401) {
            toast.error(t("lock.auth_failure_constant"));
          } else {
            toast.error(t("errors.network"));
          }
        },
      },
    );
  };

  const onInit = (e: FormEvent): void => {
    e.preventDefault();
    initMutation.mutate(
      { admin_password: password, kdf: "pbkdf2" },
      {
        onSuccess: () => {
          toast.success(t("lock.init_success"));
          setShowInit(false);
          void readyzQuery.refetch();
        },
        onError: (err) => {
          if (err instanceof SidecarHttpError && err.status === 400) {
            toast.error(t("errors.weak_password"));
          } else {
            toast.error(err.message);
          }
        },
      },
    );
  };

  const isInitialised = readyzQuery.data?.vault_initialized === true;

  return (
    <main className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-background p-8">
      <BackgroundAurora />
      <header className="absolute right-6 top-6 flex items-center gap-2 text-xs text-muted-foreground">
        <button
          type="button"
          onClick={() => setLanguage(language === "fr" ? "en" : "fr")}
          className="rounded-md border border-input px-2 py-1 hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={t("common.language")}
        >
          {language === "fr" ? "EN" : "FR"}
        </button>
      </header>

      <motion.section
        initial={reduceMotion ? false : { opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        className="z-10 flex w-full max-w-md flex-col items-center gap-8"
      >
        <div className="flex flex-col items-center gap-3">
          <div className="rounded-full bg-card/60 p-4 ring-1 ring-border backdrop-blur-sm">
            <LockKeyhole className="h-9 w-9 text-foreground/85" aria-hidden />
          </div>
          <h1 className="font-semibold text-3xl tracking-tight">{t("app.name")}</h1>
          <p className="max-w-md text-balance text-center text-muted-foreground text-sm">
            {showInit ? t("lock.init_subtitle") : t("lock.subtitle")}
          </p>
        </div>

        {showInit || !isInitialised ? (
          <form onSubmit={onInit} className="flex w-full flex-col gap-4">
            <PasswordField
              value={password}
              onChange={setPassword}
              placeholder={t("password.placeholder")}
              autoFocus
              ariaLabel={t("password.placeholder")}
              disabled={initMutation.isPending}
            />
            <button
              type="submit"
              disabled={initMutation.isPending || password.length < 12}
              className={cn(
                "h-10 rounded-md bg-primary px-4 font-medium text-primary-foreground text-sm transition-colors",
                "hover:bg-primary/90",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                "disabled:cursor-not-allowed disabled:opacity-60",
              )}
            >
              {initMutation.isPending ? t("common.loading") : t("lock.init_submit")}
            </button>
            {showInit ? (
              <button
                type="button"
                onClick={() => setShowInit(false)}
                className="text-muted-foreground text-xs hover:text-foreground"
              >
                {t("common.back")}
              </button>
            ) : null}
          </form>
        ) : (
          <form onSubmit={onUnlock} className="flex w-full flex-col gap-4">
            <PasswordField
              value={password}
              onChange={setPassword}
              placeholder={t("password.placeholder")}
              autoFocus
              ariaLabel={t("password.placeholder")}
              showStrength={false}
              disabled={unlockMutation.isPending}
            />
            <button
              type="submit"
              disabled={unlockMutation.isPending || password.length === 0}
              className={cn(
                "h-10 rounded-md bg-primary px-4 font-medium text-primary-foreground text-sm transition-colors",
                "hover:bg-primary/90",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                "disabled:cursor-not-allowed disabled:opacity-60",
              )}
            >
              {unlockMutation.isPending ? t("common.loading") : t("lock.submit")}
            </button>
            <button
              type="button"
              onClick={() => setShowInit(true)}
              className="flex items-center justify-center gap-2 text-muted-foreground text-xs hover:text-foreground"
            >
              <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
              {t("lock.init_button")}
            </button>
          </form>
        )}
      </motion.section>
    </main>
  );
}

function BackgroundAurora(): React.ReactElement {
  return (
    <div aria-hidden className="absolute inset-0 -z-0 overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,_oklch(0.65_0.18_260/0.18),transparent_60%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,_oklch(0.68_0.16_300/0.14),transparent_60%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(180deg,transparent,oklch(0_0_0/0.4))]" />
    </div>
  );
}
