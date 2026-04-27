import { isUnlockedAtom } from "@/stores/lock";
import { createFileRoute, Navigate } from "@tanstack/react-router";
import { useAtomValue } from "jotai";

export const Route = createFileRoute("/")({
  component: HomePage,
});

function HomePage(): React.ReactElement {
  const unlocked = useAtomValue(isUnlockedAtom);
  return unlocked ? <Navigate to="/dashboard" /> : <Navigate to="/lock" />;
}
