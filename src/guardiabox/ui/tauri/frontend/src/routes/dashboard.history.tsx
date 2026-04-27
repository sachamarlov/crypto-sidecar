import { useAudit, useAuditVerify } from "@/api/queries";
import { createFileRoute } from "@tanstack/react-router";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

export const Route = createFileRoute("/dashboard/history")({
  component: HistoryModal,
});

function HistoryModal(): React.ReactElement {
  const { t } = useTranslation();
  const [actionFilter, setActionFilter] = useState("");
  const [limit, setLimit] = useState(200);
  const auditQuery = useAudit({
    action: actionFilter.length > 0 ? actionFilter : undefined,
    limit,
  });
  const verifyMutation = useAuditVerify();

  const onVerify = (): void => {
    verifyMutation.mutate(undefined, {
      onSuccess: (resp) => {
        if (resp.ok) {
          toast.success(t("history.verify_ok", { count: resp.entries_checked }));
        } else {
          toast.error(t("history.verify_fail", { sequence: resp.first_bad_sequence }));
        }
      },
      onError: () => toast.error(t("errors.network")),
    });
  };

  return (
    <article className="flex flex-col gap-5">
      <header className="flex items-center justify-between">
        <h2 className="font-semibold text-xl">{t("history.title")}</h2>
        <button
          type="button"
          onClick={onVerify}
          disabled={verifyMutation.isPending}
          className="flex items-center gap-2 rounded-md border border-primary/40 bg-primary/10 px-3 py-1.5 text-primary text-xs font-medium hover:bg-primary/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:opacity-60"
        >
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
          {t("history.verify_chain")}
        </button>
      </header>

      <div className="flex flex-wrap gap-3">
        <label className="flex items-center gap-2 text-sm">
          {t("history.filter_action")}:
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="h-9 rounded-md border border-input bg-background px-2 text-xs"
          >
            <option value="">--</option>
            <option value="user.create">user.create</option>
            <option value="user.delete">user.delete</option>
            <option value="file.encrypt">file.encrypt</option>
            <option value="file.decrypt">file.decrypt</option>
            <option value="file.share">file.share</option>
            <option value="file.share_accept">file.share_accept</option>
            <option value="file.secure_delete">file.secure_delete</option>
            <option value="system.startup">system.startup</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm">
          {t("history.filter_limit")}:
          <input
            type="number"
            min={1}
            max={1000}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="h-9 w-20 rounded-md border border-input bg-background px-2 text-xs"
          />
        </label>
      </div>

      {auditQuery.isLoading ? (
        <p className="text-muted-foreground text-sm">{t("common.loading")}</p>
      ) : (auditQuery.data?.entries.length ?? 0) === 0 ? (
        <p className="flex items-center gap-2 text-muted-foreground text-sm">
          <ShieldAlert className="h-4 w-4" aria-hidden />
          {t("history.empty")}
        </p>
      ) : (
        <div className="overflow-hidden rounded-md border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-card text-muted-foreground text-xs uppercase">
              <tr>
                <th scope="col" className="px-3 py-2">
                  {t("history.columns.sequence")}
                </th>
                <th scope="col" className="px-3 py-2">
                  {t("history.columns.timestamp")}
                </th>
                <th scope="col" className="px-3 py-2">
                  {t("history.columns.actor")}
                </th>
                <th scope="col" className="px-3 py-2">
                  {t("history.columns.action")}
                </th>
                <th scope="col" className="px-3 py-2">
                  {t("history.columns.target")}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {auditQuery.data?.entries.map((e) => (
                <tr key={e.sequence} className="hover:bg-accent/40">
                  <td className="px-3 py-2 font-mono text-xs">{e.sequence}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2">{e.actor_username ?? "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs">{e.action}</td>
                  <td className="px-3 py-2 text-xs">{e.target ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </article>
  );
}
