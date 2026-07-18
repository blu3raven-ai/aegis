"use client";
import Link from "next/link";
import type { Integration } from "@/lib/client/integrations-catalog-api";
import { GitHubActionSteps } from "../[slug]/_steps/GitHubActionSteps";
import { GitLabComponentSteps } from "../[slug]/_steps/GitLabComponentSteps";
import { BitbucketPipeSteps } from "../[slug]/_steps/BitbucketPipeSteps";
import { AzureDevOpsTaskSteps } from "../[slug]/_steps/AzureDevOpsTaskSteps";
import { JenkinsLibrarySteps } from "../[slug]/_steps/JenkinsLibrarySteps";

const STEPS_BY_SLUG: Record<string, React.ComponentType<{ aegisUrl: string }>> = {
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

  if (!StepsComponent) {
    // Integrations that connect elsewhere carry an `href` and never open this
    // drawer, so a stepless integration here is one that isn't available yet.
    const label = integration.status === "preview" ? "Coming soon" : "Not yet available";
    return (
      <div className="rounded-md border border-dashed border-[var(--color-border)] px-4 py-8 text-center">
        <p className="text-sm font-medium text-[var(--color-text-primary)]">{label}</p>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Setup for {integration.name} isn’t available yet. It’s on the roadmap.
        </p>
      </div>
    );
  }

  const aegisUrl = typeof window !== "undefined" ? window.location.origin : "";

  return (
    <div className="space-y-8">
      <section>
        <h3 className="mb-2 text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Step 1 · Create an API key
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
        <h3 className="mb-2 text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Step 2 · Add this to your CI config
        </h3>
        <StepsComponent aegisUrl={aegisUrl} />
        <p className="mt-2 text-2xs text-[var(--color-text-tertiary)]">
          Aegis links results to the right source automatically from the repository. No source id needed.
        </p>
      </section>
    </div>
  );
}
