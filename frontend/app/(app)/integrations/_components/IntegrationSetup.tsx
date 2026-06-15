"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { listSourceConnections } from "@/lib/client/sources-api";
import type { Integration } from "@/lib/client/connectors-api";
import { GitHubActionSteps } from "../[slug]/_steps/GitHubActionSteps";
import { GitLabComponentSteps } from "../[slug]/_steps/GitLabComponentSteps";
import { BitbucketPipeSteps } from "../[slug]/_steps/BitbucketPipeSteps";
import { AzureDevOpsTaskSteps } from "../[slug]/_steps/AzureDevOpsTaskSteps";
import { JenkinsLibrarySteps } from "../[slug]/_steps/JenkinsLibrarySteps";
import { Select } from "@/components/ui/Select";

const STEPS_BY_SLUG: Record<string, React.ComponentType<{ sourceId: string; aegisUrl: string }>> = {
  "github-action":          GitHubActionSteps,
  "gitlab-component":       GitLabComponentSteps,
  "bitbucket-pipe":         BitbucketPipeSteps,
  "azure-devops-task":      AzureDevOpsTaskSteps,
  "jenkins-shared-library": JenkinsLibrarySteps,
};

export function hasSetupSteps(slug: string): boolean {
  return slug in STEPS_BY_SLUG;
}

export function IntegrationSetup({ integration }: { integration: Integration }) {
  const StepsComponent = STEPS_BY_SLUG[integration.slug];

  const [sources, setSources] = useState<{ id: string; name: string }[]>([]);
  const [selectedSourceId, setSelectedSourceId] = useState<string>("");

  useEffect(() => {
    listSourceConnections().then(result => {
      if (result.ok) {
        const list = result.data.connections.map(c => ({ id: c.id, name: c.name }));
        setSources(list);
        if (list.length > 0) setSelectedSourceId(list[0].id);
      }
    });
  }, []);

  if (!StepsComponent) {
    return <p className="text-sm text-[var(--color-text-secondary)]">Setup is not available for this integration.</p>;
  }

  const aegisUrl = typeof window !== "undefined" ? window.location.origin : "";

  return (
    <div className="space-y-8">
      <section>
        <h3 className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Step 1 · Pick a source
        </h3>
        <Select
          value={selectedSourceId}
          onChange={e => setSelectedSourceId(e.target.value)}
        >
          {sources.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
          {sources.length === 0 && <option value="">No sources yet — add one first</option>}
        </Select>
      </section>

      <section>
        <h3 className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Step 2 · Create an API key
        </h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Go to{" "}
          <Link href="/settings/api-keys" className="text-[var(--color-accent)] underline">
            Settings → API keys
          </Link>
          , create a key with{" "}
          <code className="rounded bg-[var(--color-surface-raised)] px-1 py-0.5 text-2xs">scan:trigger</code>{" "}
          scope, and add it to your CI as a secret named{" "}
          <code className="rounded bg-[var(--color-surface-raised)] px-1 py-0.5 text-2xs">AEGIS_API_KEY</code>.
        </p>
      </section>

      <section>
        <h3 className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Step 3 · Add this to your CI config
        </h3>
        <StepsComponent sourceId={selectedSourceId} aegisUrl={aegisUrl} />
      </section>
    </div>
  );
}
