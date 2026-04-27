import { useDoctor, useVersion } from "@/api/queries";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

export const Route = createFileRoute("/dashboard/settings")({
  component: SettingsModal,
});

function SettingsModal(): React.ReactElement {
  const { t } = useTranslation();
  const doctorQuery = useDoctor(false, true);
  const versionQuery = useVersion();

  return (
    <article className="flex flex-col gap-6">
      <h2 className="font-semibold text-xl">{t("settings.title")}</h2>

      <section className="rounded-xl border border-border bg-card p-5">
        <h3 className="mb-3 font-medium text-sm">{t("settings.diagnostic_section")}</h3>
        {doctorQuery.isLoading ? (
          <p className="text-muted-foreground text-sm">{t("common.loading")}</p>
        ) : doctorQuery.data ? (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="font-medium">{t("settings.data_dir_label")}</dt>
            <dd className="font-mono text-xs">{doctorQuery.data.data_dir}</dd>
            <dt className="font-medium">{t("settings.sqlcipher_label")}</dt>
            <dd>{doctorQuery.data.sqlcipher_available ? t("common.yes") : t("common.no")}</dd>
            {doctorQuery.data.ssd_report ? (
              <>
                <dt className="font-medium">SSD</dt>
                <dd>
                  {doctorQuery.data.ssd_report.is_ssd === null
                    ? "?"
                    : doctorQuery.data.ssd_report.is_ssd
                      ? "SSD"
                      : "HDD"}
                  <p className="mt-1 text-muted-foreground text-xs">
                    {doctorQuery.data.ssd_report.recommendation}
                  </p>
                </dd>
              </>
            ) : null}
          </dl>
        ) : null}
      </section>

      <section className="rounded-xl border border-border bg-card p-5">
        <h3 className="mb-3 font-medium text-sm">{t("settings.version_section")}</h3>
        {versionQuery.data ? (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="font-medium">GuardiaBox</dt>
            <dd className="font-mono text-xs">{versionQuery.data.version}</dd>
            <dt className="font-medium">Python</dt>
            <dd className="font-mono text-xs">{versionQuery.data.python_version}</dd>
            <dt className="font-medium">Platform</dt>
            <dd className="font-mono text-xs">
              {versionQuery.data.platform} ({versionQuery.data.machine})
            </dd>
          </dl>
        ) : null}
      </section>

      <section className="rounded-xl border border-border bg-card p-5">
        <p className="text-muted-foreground text-xs">{t("settings.config_set_hint")}</p>
      </section>
    </article>
  );
}
