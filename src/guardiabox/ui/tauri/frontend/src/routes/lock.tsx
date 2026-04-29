import { SidecarHttpError } from "@/api/client";
import { useInit, useReadyz, useUnlock } from "@/api/queries";
import { BootSplash } from "@/components/BootSplash";
import { PasswordField } from "@/components/PasswordField";
import { SidecarUnreachable } from "@/components/SidecarUnreachable";
import { WindowControls } from "@/components/WindowControls";
import { toastSidecarError } from "@/lib/sidecarErrors";
import { cn } from "@/lib/utils";
import { useLanguageStore } from "@/stores/language";
import { expiresAtMsAtom, isUnlockedAtom, sessionIdAtom } from "@/stores/lock";
import { Navigate, createFileRoute, useNavigate } from "@tanstack/react-router";
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
  const [confirm, setConfirm] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
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
          // Anti-oracle: 401 collapses to a constant string. Other
          // categories (handshake, fetch, server, rate-limit) get
          // typed toasts so the reviewer can diagnose mid-demo.
          if (err instanceof SidecarHttpError && err.status === 401) {
            toast.error(t("lock.auth_failure_constant"));
            return;
          }
          toastSidecarError(err, t);
        },
      },
    );
  };

  const onInit = (e: FormEvent): void => {
    e.preventDefault();
    if (password !== confirm) {
      toast.error(t("password.confirm_mismatch"));
      return;
    }
    if (!acknowledged) {
      return;
    }
    initMutation.mutate(
      { admin_password: password, kdf: "pbkdf2" },
      {
        onSuccess: () => {
          toast.success(t("lock.init_success"));
          setShowInit(false);
          setPassword("");
          setConfirm("");
          setAcknowledged(false);
          void readyzQuery.refetch();
        },
        onError: (err) => {
          if (err instanceof SidecarHttpError && err.status === 400) {
            toast.error(t("errors.weak_password"));
            return;
          }
          toastSidecarError(err, t);
        },
      },
    );
  };

  // Audit B P0-1: do not flip to "Init vault" while /readyz is in
  // flight or errored. Boot splash + SidecarUnreachable are first-
  // class states so the returning user never sees the wrong CTA.
  const showBootSplash = readyzQuery.isPending;
  const showSidecarError = readyzQuery.isError;
  const isInitialised = readyzQuery.data?.vault_initialized === true;

  return (
    <main className="relative flex min-h-screen flex-col overflow-hidden bg-background">
      {/* Drag-region title strip (audit B P0-3): the only frameless
          surface that can move the window. WindowControls + buttons
          opt out via their own click handlers. */}
      <header
        data-tauri-drag-region
        className="flex h-9 select-none items-center justify-between border-border/40 border-b px-4"
      >
        <span
          data-tauri-drag-region
          className="pointer-events-none flex items-center gap-2 text-muted-foreground/60 text-xs"
        >
          <LockKeyhole className="h-3.5 w-3.5" aria-hidden />
          <span>{t("app.name")}</span>
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setLanguage(language === "fr" ? "en" : "fr")}
            className="rounded-md border border-input px-2 py-0.5 text-muted-foreground text-xs hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={t("common.language")}
          >
            {language === "fr" ? "EN" : "FR"}
          </button>
          <WindowControls />
        </div>
      </header>

      <section className="relative flex flex-1 items-center justify-center p-8">
        <BackgroundAurora />

        <motion.section
          initial={reduceMotion ? false : { opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          className="z-10 flex w-full max-w-md flex-col items-center gap-8"
        >
          {showBootSplash ? (
            <BootSplash />
          ) : showSidecarError ? (
            <SidecarUnreachable
              error={readyzQuery.error}
              onRetry={() => void readyzQuery.refetch()}
            />
          ) : (
            <>
              <div className="flex flex-col items-center gap-3">
                <div className="rounded-full bg-card/60 p-4 ring-1 ring-border backdrop-blur-sm">
                  <LockKeyhole className="h-9 w-9 text-foreground/85" aria-hidden />
                </div>
                <h1 className="font-semibold text-3xl tracking-tight">{t("app.name")}</h1>
                <p className="max-w-md text-balance text-center text-muted-foreground text-sm">
                  {showInit || !isInitialised ? t("lock.init_subtitle") : t("lock.subtitle")}
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
                  <PasswordField
                    value={confirm}
                    onChange={setConfirm}
                    placeholder={t("password.confirm_placeholder")}
                    ariaLabel={t("password.confirm_placeholder")}
                    showStrength={false}
                    disabled={initMutation.isPending}
                  />
                  {confirm.length > 0 && password !== confirm ? (
                    <p role="alert" className="text-destructive text-xs" aria-live="polite">
                      {t("password.confirm_mismatch")}
                    </p>
                  ) : null}
                  <label className="flex items-start gap-2 text-muted-foreground text-xs">
                    <input
                      type="checkbox"
                      checked={acknowledged}
                      onChange={(e) => setAcknowledged(e.target.checked)}
                      disabled={initMutation.isPending}
                      className="mt-0.5 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    />
                    <span>{t("lock.init_acknowledgement")}</span>
                  </label>
                  <button
                    type="submit"
                    disabled={
                      initMutation.isPending ||
                      password.length < 12 ||
                      password !== confirm ||
                      !acknowledged
                    }
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
                      onClick={() => {
                        setShowInit(false);
                        setConfirm("");
                        setAcknowledged(false);
                      }}
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
            </>
          )}
        </motion.section>
      </section>
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
