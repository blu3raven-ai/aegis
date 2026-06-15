import { LlmContent } from "./LlmContent";

export default function LlmSettingsPage() {
  return (
    <div className="px-6 py-4">
      <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">
        LLM verification
      </h1>
      <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
        Bring your own LLM key for the agentic verification layer. Works with any
        OpenAI-compatible gateway (OpenAI, Anthropic adapter, Azure OpenAI, vLLM,
        LiteLLM, OpenRouter).
      </p>

      <div className="mt-6">
        <LlmContent />
      </div>
    </div>
  );
}
