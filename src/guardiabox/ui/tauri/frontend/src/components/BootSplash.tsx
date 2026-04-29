/**
 * Cold-start splash shown while the sidecar handshake is in flight.
 *
 * Audit B P0-1 finding: the lock screen previously rendered the
 * "Initialise vault" branch as soon as `readyzQuery.data` was
 * undefined (loading), confusing returning users for the ~5s
 * sidecar boot window.
 *
 * The component is intentionally self-contained -- no dependency on
 * router state or atoms -- so a future "watchdog" wrapper can mount
 * it before the rest of the app is ready.
 */

import { motion, useReducedMotion } from "framer-motion";
import { LockKeyhole } from "lucide-react";
import { useTranslation } from "react-i18next";

interface BootSplashProps {
  /** Optional override for the loading message. */
  message?: string;
}

export function BootSplash({ message }: BootSplashProps): React.ReactElement {
  const { t } = useTranslation();
  const reduceMotion = useReducedMotion();
  const text = message ?? t("lock.booting_sidecar");

  return (
    <div className="flex flex-col items-center gap-6" role="status" aria-live="polite">
      <motion.div
        initial={reduceMotion ? false : { opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
        className="rounded-full bg-card/60 p-5 ring-1 ring-border backdrop-blur-sm"
      >
        <LockKeyhole className="h-10 w-10 text-foreground/80" aria-hidden />
      </motion.div>
      <motion.div
        initial={reduceMotion ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2, duration: 0.4 }}
        className="flex flex-col items-center gap-3"
      >
        <p className="text-muted-foreground text-sm">{text}</p>
        {reduceMotion ? null : (
          <span className="inline-block h-1 w-32 overflow-hidden rounded-full bg-muted" aria-hidden>
            <motion.span
              className="block h-full w-full bg-primary"
              initial={{ x: "-100%" }}
              animate={{ x: "100%" }}
              transition={{ duration: 1.4, repeat: Number.POSITIVE_INFINITY, ease: "easeInOut" }}
            />
          </span>
        )}
      </motion.div>
    </div>
  );
}
