import { motion } from "framer-motion";
import { LockKeyhole } from "lucide-react";

/**
 * Top-level shell. Replaced by TanStack Router once routes are scaffolded.
 * Kept as a single placeholder for the bootstrap commit.
 */
export function App(): JSX.Element {
  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground">
      <BackgroundAurora />

      <main className="relative z-10 flex min-h-screen flex-col items-center justify-center gap-8 p-8">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          className="flex flex-col items-center gap-4"
        >
          <LockKeyhole className="h-12 w-12 text-foreground/80" aria-hidden />
          <h1 className="font-semibold text-4xl tracking-tight">GuardiaBox</h1>
          <p className="max-w-md text-balance text-center text-muted-foreground">
            Local secure vault. Encrypt, store, and share files without ever trusting a remote
            server.
          </p>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4, duration: 0.6 }}
          className="text-muted-foreground/60 text-xs"
        >
          v0.1.0 — bootstrap scaffold
        </motion.p>
      </main>
    </div>
  );
}

function BackgroundAurora(): JSX.Element {
  return (
    <div
      aria-hidden
      className="absolute inset-0 -z-10 overflow-hidden bg-background"
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,_oklch(0.65_0.18_260/0.18),transparent_60%)]" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,_oklch(0.68_0.16_300/0.14),transparent_60%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(180deg,transparent,oklch(0_0_0/0.4))]" />
    </div>
  );
}
