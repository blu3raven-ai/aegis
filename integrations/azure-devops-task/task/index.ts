import * as tl from "azure-pipelines-task-lib/task";
import axios, { AxiosError, AxiosResponse } from "axios";

type FailOn = "none" | "low" | "medium" | "high";

interface TriggerResponse {
  scan_id: string;
  status: string;
  status_url?: string;
  deduplicated?: boolean;
}

interface ScanStatusResponse {
  status:
    | "queued"
    | "running"
    | "completed"
    | "completed_with_merge_error"
    | "failed"
    | "cancelled";
  finding_counts?: {
    high?: number;
    medium?: number;
    low?: number;
  };
  error?: string;
}

const BACKOFF_SECONDS = [5, 15, 45];
const MAX_TRIGGER_ATTEMPTS = 4;
const POLL_INTERVAL_MS = 5_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetriableHttpStatus(status: number | undefined): boolean {
  if (status === undefined) return true;
  return status === 429 || (status >= 500 && status < 600);
}

function parseFailOn(input: string): FailOn {
  const v = input.toLowerCase();
  if (v === "low" || v === "medium" || v === "high" || v === "none") {
    return v;
  }
  tl.warning(`Unknown fail-on value: ${input} (treated as none)`);
  return "none";
}

async function triggerScan(
  aegisUrl: string,
  apiKey: string,
  sourceId: string,
  body: Record<string, unknown>,
): Promise<TriggerResponse> {
  const url = `${aegisUrl}/api/v1/sources/${sourceId}/scans/trigger`;

  let lastError: string = "";
  let lastStatus: number | undefined;

  for (let attempt = 0; attempt < MAX_TRIGGER_ATTEMPTS; attempt++) {
    try {
      const res: AxiosResponse<TriggerResponse> = await axios.post(url, body, {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        timeout: 30_000,
        validateStatus: () => true,
      });

      lastStatus = res.status;

      if (res.status === 202) {
        return res.data;
      }

      const bodyStr =
        typeof res.data === "string" ? res.data : JSON.stringify(res.data);
      lastError = `${res.status}: ${bodyStr}`;

      if (res.status === 401 || res.status === 403) {
        throw new Error(`Aegis trigger auth failed (${lastError})`);
      }
      if (res.status === 404) {
        throw new Error(`Aegis source not found (${lastError})`);
      }
      if (res.status === 409) {
        throw new Error(`Aegis source disabled (${lastError})`);
      }

      if (!isRetriableHttpStatus(res.status)) {
        throw new Error(`Aegis trigger failed (${lastError})`);
      }
    } catch (err) {
      if (err instanceof AxiosError) {
        lastError = err.message;
      } else if (err instanceof Error) {
        if (!isRetriableHttpStatus(lastStatus)) {
          throw err;
        }
        lastError = err.message;
      }
    }

    if (attempt < MAX_TRIGGER_ATTEMPTS - 1) {
      const delay = BACKOFF_SECONDS[attempt];
      tl.warning(
        `trigger attempt ${attempt + 1} failed (${lastError}); retrying in ${delay}s`,
      );
      await sleep(delay * 1000);
    }
  }

  if (lastStatus === 429) {
    throw new Error(
      "Aegis trigger rate limited; reduce CI scan frequency",
    );
  }
  throw new Error(`Aegis trigger failed after retries (${lastError})`);
}

async function pollScan(
  aegisUrl: string,
  apiKey: string,
  scanId: string,
  timeoutSeconds: number,
): Promise<ScanStatusResponse | null> {
  const start = Date.now();
  const deadline = start + timeoutSeconds * 1000;
  const url = `${aegisUrl}/api/v1/scans/${scanId}`;

  while (Date.now() < deadline) {
    try {
      const res: AxiosResponse<ScanStatusResponse> = await axios.get(url, {
        headers: { Authorization: `Bearer ${apiKey}` },
        timeout: 30_000,
        validateStatus: () => true,
      });

      if (res.status === 200) {
        const { status } = res.data;
        if (
          status === "completed" ||
          status === "completed_with_merge_error" ||
          status === "failed" ||
          status === "cancelled"
        ) {
          return res.data;
        }
      }
    } catch {
      // transient errors during polling are swallowed; loop retries until timeout
    }

    await sleep(POLL_INTERVAL_MS);
  }

  return null;
}

function writeSummary(
  aegisUrl: string,
  scanId: string,
  status: string,
  findings: { high: number; medium: number; low: number },
): void {
  const lines = [
    "# Aegis Security Scan",
    "",
    `Status: **${status}**`,
    "",
    `View in Aegis: ${aegisUrl}/api/v1/scans/${scanId}`,
    "",
    "| Severity | Count |",
    "|---|---|",
    `| High | ${findings.high} |`,
    `| Medium | ${findings.medium} |`,
    `| Low | ${findings.low} |`,
    "",
  ];
  const content = lines.join("\n");

  const summaryDir = tl.getVariable("Agent.TempDirectory") ?? ".";
  const summaryPath = `${summaryDir}/aegis-scan-summary.md`;
  try {
    require("fs").writeFileSync(summaryPath, content, "utf8");
    tl.addAttachment(
      "Distributedtask.Core.Summary",
      "Aegis Security Scan",
      summaryPath,
    );
  } catch (err) {
    tl.warning(
      `Failed to write Aegis summary attachment: ${(err as Error).message}`,
    );
  }
}

function gateExit(failOn: FailOn, findings: {
  high: number;
  medium: number;
  low: number;
}): void {
  const { high, medium, low } = findings;
  switch (failOn) {
    case "high":
      if (high > 0) {
        tl.setResult(
          tl.TaskResult.Failed,
          `Found ${high} high-severity finding(s); failing per fail-on=high`,
        );
        return;
      }
      break;
    case "medium":
      if (high > 0 || medium > 0) {
        tl.setResult(
          tl.TaskResult.Failed,
          "Found findings >= medium severity; failing per fail-on=medium",
        );
        return;
      }
      break;
    case "low":
      if (high > 0 || medium > 0 || low > 0) {
        tl.setResult(
          tl.TaskResult.Failed,
          "Found findings; failing per fail-on=low",
        );
        return;
      }
      break;
    case "none":
      break;
  }
  tl.setResult(tl.TaskResult.Succeeded, "Aegis scan completed");
}

async function run(): Promise<void> {
  try {
    const aegisUrlRaw = tl.getInput("aegis-url", true) ?? "";
    const apiKey = tl.getInput("aegis-api-key", true) ?? "";
    const sourceId = tl.getInput("source-id", true) ?? "";
    const wait = tl.getBoolInput("wait", false);
    const failOn = parseFailOn(tl.getInput("fail-on", false) ?? "none");
    const pollTimeout =
      parseInt(tl.getInput("poll-timeout-seconds", false) ?? "1800", 10) ||
      1800;

    const aegisUrl = aegisUrlRaw.replace(/\/+$/, "");

    const commitSha = process.env.BUILD_SOURCEVERSION;
    const branch = process.env.BUILD_SOURCEBRANCHNAME;
    const prNumberRaw = process.env.SYSTEM_PULLREQUEST_PULLREQUESTNUMBER;
    const runId = process.env.BUILD_BUILDID;

    if (!commitSha) {
      tl.setResult(
        tl.TaskResult.Failed,
        "Could not resolve commit SHA from BUILD_SOURCEVERSION",
      );
      return;
    }

    const prNumber = prNumberRaw ? parseInt(prNumberRaw, 10) : null;

    const body = {
      commit_sha: commitSha,
      branch: branch || null,
      pr_number: Number.isFinite(prNumber as number) ? prNumber : null,
      trigger_metadata: {
        ci_provider: "azure_devops",
        run_id: runId ?? "",
      },
    };

    const trigger = await triggerScan(aegisUrl, apiKey, sourceId, body);
    console.log(
      `Aegis scan_id=${trigger.scan_id} deduplicated=${trigger.deduplicated ?? false}`,
    );

    if (!wait) {
      tl.setResult(tl.TaskResult.Succeeded, "Aegis scan triggered");
      return;
    }

    const summary = await pollScan(aegisUrl, apiKey, trigger.scan_id, pollTimeout);
    if (!summary) {
      tl.warning(
        `Aegis scan still running after ${pollTimeout}s; check ${aegisUrl}/api/v1/scans/${trigger.scan_id}`,
      );
      tl.setResult(tl.TaskResult.SucceededWithIssues, "Polling timed out");
      return;
    }

    const findings = {
      high: summary.finding_counts?.high ?? 0,
      medium: summary.finding_counts?.medium ?? 0,
      low: summary.finding_counts?.low ?? 0,
    };

    writeSummary(aegisUrl, trigger.scan_id, summary.status, findings);

    if (summary.status === "failed") {
      tl.setResult(
        tl.TaskResult.Failed,
        `Aegis scan failed: ${summary.error ?? "unknown"}`,
      );
      return;
    }
    if (summary.status === "cancelled") {
      tl.warning("Aegis scan was cancelled (superseded by newer commit)");
      tl.setResult(tl.TaskResult.SucceededWithIssues, "Scan cancelled");
      return;
    }

    gateExit(failOn, findings);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    tl.setResult(tl.TaskResult.Failed, message);
  }
}

run();
