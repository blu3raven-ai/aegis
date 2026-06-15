"use client";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { CostChart } from "@/components/shared/settings/llm/CostChart";
import { TestConnectionButton } from "@/components/shared/settings/llm/TestConnectionButton";
import { UsageMeter } from "@/components/shared/settings/llm/UsageMeter";

type LlmConfig = {
  api_base_url: string;
  model: string;
  scan_token_budget: number;
  daily_token_budget: number;
  enabled: boolean;
  configured: boolean;
};

type DayUsage = {
  date: string;
  tokens_in: number;
  tokens_out: number;
  scans: number;
};

type UsageResponse = {
  days: DayUsage[];
  today_used: number;
  today_budget: number;
  today_remaining: number;
};

type FormState = {
  api_key: string;
  api_base_url: string;
  model: string;
  scan_token_budget: number;
  daily_token_budget: number;
  enabled: boolean;
};

const INITIAL_FORM: FormState = {
  api_key: "",
  api_base_url: "https://api.anthropic.com/v1",
  model: "claude-sonnet-4-6",
  scan_token_budget: 100_000,
  daily_token_budget: 1_000_000,
  enabled: false,
};

export function LlmContent() {
  const [cfg, setCfg] = useState<LlmConfig | null>(null);
  const [form, setForm] = useState<FormState>(INITIAL_FORM);
  const [status, setStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [usage, setUsage] = useState<UsageResponse | null>(null);

  useEffect(() => {
    fetch("/api/v1/settings/llm")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        setCfg(data);
        setForm((f) => ({
          ...f,
          api_base_url: data.api_base_url ?? f.api_base_url,
          model: data.model ?? f.model,
          scan_token_budget: data.scan_token_budget ?? f.scan_token_budget,
          daily_token_budget: data.daily_token_budget ?? f.daily_token_budget,
          enabled: Boolean(data.enabled),
        }));
      })
      .catch(() => {
        // Treat as unconfigured — leave form on its defaults.
      });
  }, []);

  // Load 30-day usage independently — surfaces even when the config endpoint
  // hasn't returned yet, so the meter doesn't lag behind the form.
  useEffect(() => {
    fetch("/api/v1/settings/llm/usage?days=30")
      .then((r) => (r.ok ? (r.json() as Promise<UsageResponse>) : null))
      .then((data) => {
        if (data) setUsage(data);
      })
      .catch(() => {
        /* leave usage as null — the chart renders its skeleton */
      });
  }, [status]);

  async function save() {
    setStatus("saving");
    try {
      const r = await fetch("/api/v1/settings/llm", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!r.ok) {
        setStatus("error");
        return;
      }
      const next = await r.json();
      setCfg(next);
      setForm((f) => ({ ...f, api_key: "" }));
      setStatus("saved");
    } catch {
      setStatus("error");
    }
  }

  return (
    <>
      <div className="max-w-xl space-y-4">
        <label className="block">
          <span className="text-sm font-medium">API key</span>
          <Input
            type="password"
            className="mt-1"
            value={form.api_key}
            placeholder={cfg?.configured ? "•••••••• (stored)" : "sk-..."}
            onChange={(e) => setForm({ ...form, api_key: e.target.value })}
          />
        </label>

        <label className="block">
          <span className="text-sm font-medium">API base URL</span>
          <Input
            type="url"
            className="mt-1"
            value={form.api_base_url}
            onChange={(e) => setForm({ ...form, api_base_url: e.target.value })}
          />
        </label>

        <label className="block">
          <span className="text-sm font-medium">Model</span>
          <Input
            type="text"
            className="mt-1"
            value={form.model}
            onChange={(e) => setForm({ ...form, model: e.target.value })}
          />
        </label>

        <label className="block">
          <span className="text-sm font-medium">Per-scan token budget</span>
          <Input
            type="number"
            min={1000}
            className="mt-1 tabular-nums"
            value={form.scan_token_budget}
            onChange={(e) =>
              setForm({ ...form, scan_token_budget: Number(e.target.value) || 0 })
            }
          />
        </label>

        <label className="block">
          <span className="text-sm font-medium">Daily token cap</span>
          <Input
            type="number"
            min={10000}
            className="mt-1 tabular-nums"
            value={form.daily_token_budget}
            onChange={(e) =>
              setForm({ ...form, daily_token_budget: Number(e.target.value) || 0 })
            }
          />
        </label>

        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          />
          <span className="text-sm">Enable LLM verification</span>
        </label>

        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant="primary"
            size="md"
            onClick={save}
            disabled={status === "saving" || !form.api_key}
            isLoading={status === "saving"}
          >
            {status === "saving" ? "Saving…" : "Save"}
          </Button>
          {cfg?.configured && <TestConnectionButton />}
          {status === "saved" && (
            <span className="text-xs text-[var(--color-status-ok)]">✓ Saved</span>
          )}
          {status === "error" && (
            <span className="text-xs text-[var(--color-severity-critical)]">
              ✕ Save failed
            </span>
          )}
        </div>
      </div>

      {usage && (
        <div className="mt-8 max-w-3xl space-y-6">
          <UsageMeter used={usage.today_used} budget={usage.today_budget} />
          <CostChart days={usage.days} />
        </div>
      )}
    </>
  );
}
