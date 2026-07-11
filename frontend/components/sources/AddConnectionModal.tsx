"use client"

import { useEffect, useRef, useState } from "react"
import Link from "next/link"
import type { SourceCategory, SourceType, SourceConnectionAuth } from "@/lib/shared/sources-types"
import {
  SOURCE_TYPE_FIELDS,
  CATEGORY_SOURCE_TYPES,
  SOURCE_TYPE_LABELS,
  SOURCE_TYPE_SETUP_GUIDES,
  CATEGORY_LABELS,
  SOURCE_TYPE_TO_CATEGORY,
} from "@/lib/shared/sources-types"
import {
  createSourceConnection,
  testNewSourceConnection,
  syncSourceConnection,
} from "@/lib/client/source-connections-api"
import { RepoPicker } from "@/components/sources/RepoPicker"
import {
  createWebhookEndpoint,
  rotateWebhookEndpoint,
  listWebhookEndpoints,
  type WebhookProvider,
} from "@/lib/client/webhook-endpoints-api"
import { createApiKey } from "@/lib/client/api-keys-api"
import { useDialogA11y } from "@/lib/client/use-dialog-a11y"
import { HostReachabilityNote } from "@/components/shared/HostReachabilityNote"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { KeyRound, Webhook, Workflow, Check, Copy } from "lucide-react"
import { GitHubActionSteps } from "@/app/(app)/integrations/[slug]/_steps/GitHubActionSteps"
import { GitLabComponentSteps } from "@/app/(app)/integrations/[slug]/_steps/GitLabComponentSteps"
import { BitbucketPipeSteps } from "@/app/(app)/integrations/[slug]/_steps/BitbucketPipeSteps"
import { AzureDevOpsTaskSteps } from "@/app/(app)/integrations/[slug]/_steps/AzureDevOpsTaskSteps"


function ProviderIcon({ type }: { type: SourceType }) {
  const cls = "h-6 w-6 shrink-0"
  switch (type) {
    case "github":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
        </svg>
      )
    case "gitlab":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z" />
        </svg>
      )
    case "docker-hub":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.186.186 0 00-.185.186v1.887c0 .102.083.185.185.185zm-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.186.186 0 00-.185.185v1.888c0 .102.082.185.185.186zm0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.186.186 0 00-.185.185v1.887c0 .102.082.186.185.186zm-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.186.186 0 00-.185.185v1.887c0 .102.083.186.185.186zm-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.186.186 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.186.186.186zm5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.186.186 0 00-.185.186v1.887c0 .102.082.185.185.185zm-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.186v1.887c0 .102.083.185.185.185zm-2.964 0h2.119a.186.186 0 00.185-.185V9.006a.186.186 0 00-.185-.186H5.136a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185zm-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.185.186v1.887c0 .102.083.185.185.185zM23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288z" />
        </svg>
      )
    case "ghcr":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
        </svg>
      )
    case "bitbucket":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M.778 1.213a.768.768 0 00-.768.892l3.263 19.81c.084.5.515.868 1.022.873H19.95a.772.772 0 00.77-.646l3.27-20.03a.768.768 0 00-.768-.891zM14.52 15.53H9.522L8.17 8.466h7.561z" />
        </svg>
      )
    case "gitea":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M4.209 4.603c-.247 0-.525.02-.84.088-.333.07-1.28.283-2.054 1.027C-.403 7.25.035 9.685.089 10.052c.065.446.263 1.687 1.21 2.768 1.749 2.141 5.513 2.092 5.513 2.092s.462 1.103 1.168 2.119c.955 1.263 1.936 2.248 2.89 2.367 2.406 0 7.212-.004 7.212-.004s.458.004 1.08-.394c.535-.324 1.013-.893 1.013-.893s.492-.527 1.18-1.73c.21-.37.385-.729.538-1.068 0 0 2.107-4.471 2.107-8.823-.042-1.318-.367-1.55-.443-1.627-.156-.156-.366-.153-.366-.153s-4.475.252-6.792.306c-.508.011-1.012.023-1.512.027v4.474l-.634-.301c0-1.39-.004-4.17-.004-4.17-1.107.016-3.405-.084-3.405-.084s-5.399-.27-5.987-.324c-.187-.011-.401-.032-.648-.032zm.354 1.832h.111s.271 2.269.6 3.597C5.549 11.147 6.22 13 6.22 13s-.996-.119-1.641-.348c-.99-.324-1.409-.714-1.409-.714s-.73-.511-1.096-1.52C1.444 8.73 2.021 7.7 2.021 7.7s.32-.859 1.47-1.145c.395-.106.863-.12 1.072-.12zm8.33 2.554c.26.003.509.127.509.127l.868.422-.529 1.075a.686.686 0 00-.614.359.685.685 0 00.072.756l-.939 1.924a.69.69 0 00-.66.527.687.687 0 00.347.763.686.686 0 00.867-.206.688.688 0 00-.069-.882l.916-1.874a.667.667 0 00.237-.02.657.657 0 00.271-.137 8.826 8.826 0 011.016.512.761.761 0 01.286.282c.073.21-.073.569-.073.569-.087.29-.702 1.55-.702 1.55a.692.692 0 00-.676.477.681.681 0 101.157-.252c.073-.141.141-.282.214-.431.19-.397.515-1.16.515-1.16.035-.066.218-.394.103-.814-.095-.435-.48-.638-.48-.638-.467-.301-1.116-.58-1.116-.58s0-.156-.042-.27a.688.688 0 00-.148-.241l.516-1.062 2.89 1.401s.48.218.583.619c.073.282-.019.534-.069.657-.24.587-2.1 4.317-2.1 4.317s-.232.554-.748.588a1.065 1.065 0 01-.393-.045l-.202-.08-4.31-2.1s-.417-.218-.49-.596c-.083-.31.104-.691.104-.691l2.073-4.272s.183-.37.466-.497a.855.855 0 01.35-.077z" />
        </svg>
      )
    case "ecr":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2L2 7v10l10 5 10-5V7zm0 2.18L18.36 7.5 12 10.82 5.64 7.5zM4 8.72l7 3.5V19l-7-3.5zm9 10.28v-6.78l7-3.5V15.5z" />
        </svg>
      )
    case "acr":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2L2 7v10l10 5 10-5V7zm0 2.18L18.36 7.5 12 10.82 5.64 7.5zM4 8.72l7 3.5V19l-7-3.5zm9 10.28v-6.78l7-3.5V15.5z" />
        </svg>
      )
    case "gcr":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M12.19 2.38a9.344 9.344 0 00-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 004.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 00-2.821-4.552l-.043.043.006-.05A9.344 9.344 0 0012.19 2.38zm-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.186 5.186 0 011.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.59 2.59 0 01-1.067-.23h.001a2.597 2.597 0 113.437-3.437l3.013-3.012A6.747 6.747 0 008.11 8.24c.018-.01.04-.026.054-.023a5.186 5.186 0 013.67-1.69z" />
        </svg>
      )
    case "gitlab-registry":
      return (
        <svg className={cls} viewBox="0 0 24 24" fill="currentColor">
          <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z" />
        </svg>
      )
    default:
      return <div className={`${cls} rounded bg-[var(--color-surface-raised)]`} />
  }
}


// ─── Connection methods ─────────────────────────────────────────────────────

type ConnectMethod = "pat" | "webhook" | "cicd"

// Source types that have a webhook receiver + CI/CD integration. Other git
// hosts (e.g. Gitea) are token-only, so they skip the method step entirely.
const MULTI_METHOD_TYPES: Partial<Record<SourceType, WebhookProvider>> = {
  github: "github",
  gitlab: "gitlab",
  bitbucket: "bitbucket",
  azure_devops: "azure_devops",
}

const WEBHOOK_PATHS: Partial<Record<SourceType, string>> = {
  github: "/integrations/github/webhook",
  gitlab: "/integrations/gitlab/webhook",
  bitbucket: "/integrations/bitbucket/webhook",
  azure_devops: "/integrations/azure-devops/webhook",
}

// Inline CI/CD pipeline snippet per provider (reused from the integrations setup).
const CICD_STEPS: Partial<Record<SourceType, React.ComponentType<{ aegisUrl: string }>>> = {
  github: GitHubActionSteps,
  gitlab: GitLabComponentSteps,
  bitbucket: BitbucketPipeSteps,
  azure_devops: AzureDevOpsTaskSteps,
}

// Where the webhook is configured, per provider — keeps the steps accurate.
const WEBHOOK_SETTINGS_PATH: Partial<Record<SourceType, string>> = {
  github: "Settings → Webhooks → Add webhook",
  gitlab: "Settings → Webhooks",
  bitbucket: "Repository settings → Webhooks → Add webhook",
  azure_devops: "Project settings → Service hooks → Create subscription",
}

function methodsFor(type: SourceType): ConnectMethod[] {
  return type in MULTI_METHOD_TYPES ? ["pat", "webhook", "cicd"] : ["pat"]
}

const METHOD_META: Record<
  ConnectMethod,
  { label: string; icon: typeof KeyRound; recommended?: boolean; describe: (p: string) => string; outcome: string }
> = {
  pat: {
    label: "Personal Access Token",
    icon: KeyRound,
    recommended: true,
    describe: () => "Aegis pulls your repositories directly using a token. Best for a full inventory and scheduled scans.",
    outcome: "You'll need a token with read access.",
  },
  webhook: {
    label: "Webhook",
    icon: Webhook,
    describe: (p) => `${p} notifies Aegis on push and pull-request events so it can rescan in near real time.`,
    outcome: "You'll get a webhook URL and signing secret to add in your provider.",
  },
  cicd: {
    label: "CI/CD pipeline",
    icon: Workflow,
    describe: () => "Run the scanner inside your existing pipeline and report results back to Aegis.",
    outcome: "You'll get a config snippet to drop into your pipeline.",
  },
}


interface AddConnectionModalProps {
  lockedCategory?: SourceCategory
  onClose: () => void
  onCreated: () => void
}


export function AddConnectionModal({
  lockedCategory,
  onClose,
  onCreated,
}: AddConnectionModalProps) {
  const visibleCategories: SourceCategory[] = lockedCategory
    ? [lockedCategory]
    : (Object.keys(CATEGORY_LABELS) as SourceCategory[])

  const dialogRef = useRef<HTMLDivElement>(null)
  useDialogA11y(dialogRef, onClose)

  const [screen, setScreen] = useState<"provider" | "method" | "settings">("provider")
  const [selectedType, setSelectedType] = useState<SourceType | null>(null)
  const [method, setMethod] = useState<ConnectMethod>("pat")
  const [auth, setAuth] = useState<SourceConnectionAuth>({})
  const [name, setName] = useState("")
  const [testing, setTesting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState<Record<string, boolean>>({})

  const [discoveredRepos, setDiscoveredRepos] = useState<string[]>([])
  // For git-repo sources, discovery loads the picker inline on the same screen
  // as the token field (so the token stays editable and can reload the list).
  const [hasDiscovered, setHasDiscovered] = useState(false)

  // Webhook-method state
  const [webhookSecret, setWebhookSecret] = useState<string | null>(null)
  const [webhookBusy, setWebhookBusy] = useState(false)
  const [existingWebhookId, setExistingWebhookId] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)

  // CI/CD-method state
  const [apiKeyToken, setApiKeyToken] = useState<string | null>(null)
  const [apiKeyBusy, setApiKeyBusy] = useState(false)
  const [apiKeyError, setApiKeyError] = useState<string | null>(null)

  const category: SourceCategory | null = selectedType
    ? SOURCE_TYPE_TO_CATEGORY[selectedType]
    : null

  const hasMethodStep =
    category === "code-repositories" && selectedType !== null && methodsFor(selectedType).length > 1

  function handleTypeSelect(type: SourceType) {
    setSelectedType(type)
    const fields = SOURCE_TYPE_FIELDS[type]
    const defaults: SourceConnectionAuth = {}
    for (const f of fields) {
      if (f.defaultValue) defaults[f.key] = f.defaultValue
    }
    setAuth(defaults)
    setName("")
    setError(null)
  }

  function handleNext() {
    if (!selectedType) return
    setError(null)
    if (category === "code-repositories" && methodsFor(selectedType).length > 1) {
      setScreen("method")
    } else {
      setMethod("pat")
      setScreen("settings")
    }
  }

  function pickMethod(m: ConnectMethod) {
    setMethod(m)
    setWebhookSecret(null)
    setExistingWebhookId(null)
    setApiKeyToken(null)
    setApiKeyError(null)
    setError(null)
    setScreen("settings")
  }

  function handleBack() {
    setError(null)
    // Leaving the settings screen drops any loaded repo list so a re-entry
    // starts clean.
    setHasDiscovered(false)
    setDiscoveredRepos([])
    if (screen === "settings" && hasMethodStep) setScreen("method")
    else setScreen("provider")
  }

  async function copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(key)
      window.setTimeout(() => setCopied((c) => (c === key ? null : c)), 1500)
    } catch {
      /* clipboard unavailable */
    }
  }

  // When the webhook panel opens, detect whether a secret already exists for
  // this provider so we offer "Rotate" instead of a dead-end "already exists".
  useEffect(() => {
    if (screen !== "settings" || method !== "webhook" || !selectedType) return
    const provider = MULTI_METHOD_TYPES[selectedType]
    if (!provider) return
    let cancelled = false
    listWebhookEndpoints()
      .then((res) => {
        if (cancelled) return
        const ep = res.endpoints.find((e) => e.provider === provider)
        setExistingWebhookId(ep ? ep.id : null)
      })
      .catch(() => { /* listing optional — fall back to create */ })
    return () => { cancelled = true }
  }, [screen, method, selectedType])

  async function handleWebhookSecret() {
    if (!selectedType) return
    const provider = MULTI_METHOD_TYPES[selectedType]
    if (!provider) return
    setWebhookBusy(true)
    setError(null)
    try {
      const ep = existingWebhookId
        ? await rotateWebhookEndpoint(existingWebhookId)
        : await createWebhookEndpoint(provider)
      setWebhookSecret(ep.secret)
      setExistingWebhookId(ep.id)
    } catch {
      setError("Could not generate the webhook secret. Please try again.")
    } finally {
      setWebhookBusy(false)
    }
  }

  async function handleCreateApiKey() {
    if (!selectedType) return
    setApiKeyBusy(true)
    setApiKeyError(null)
    try {
      const key = await createApiKey({
        name: `CI/CD — ${SOURCE_TYPE_LABELS[selectedType]}`,
        scopes: ["scan:trigger"],
      })
      setApiKeyToken(key.token)
    } catch {
      setApiKeyError("Could not create the API key. Please try again.")
    } finally {
      setApiKeyBusy(false)
    }
  }

  function _testPayload() {
    return {
      category: category as SourceCategory,
      sourceType: selectedType as SourceType,
      name: name.trim() || (selectedType ? SOURCE_TYPE_LABELS[selectedType] : ""),
      auth,
      scanScope: "all" as const,
      excludedItems: [],
      includedItems: [],
      connectionMethods: [method],
      syncSchedule: "1h" as const,
      status: "not-synced" as const,
    }
  }

  // Discover repos for a git source and populate the picker on the right. Both
  // callers (the reload button after field validation, and the token blur below)
  // guarantee a token is present, so this just guards against a missing token /
  // in-flight request defensively.
  const lastDiscoveredToken = useRef<string | null>(null)
  async function discover() {
    if (!selectedType || category !== "code-repositories") return
    const token = (auth["token"] ?? "").trim()
    if (!token || testing) return
    lastDiscoveredToken.current = token
    setTesting(true)
    setError(null)
    const testResult = await testNewSourceConnection(_testPayload())
    setTesting(false)
    if (!testResult.ok) {
      setError(testResult.error)
      return
    }
    if (!testResult.data.success) {
      setError(testResult.data.message)
      return
    }
    setDiscoveredRepos(testResult.data.discovered_items ?? [])
    setHasDiscovered(true)
  }

  // Auto-load on token blur — skips a re-fetch when the token is unchanged so
  // clicking from the field into the picker doesn't reload the list.
  function handleTokenBlur() {
    if (category !== "code-repositories") return
    if ((auth["token"] ?? "").trim() !== lastDiscoveredToken.current) void discover()
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!selectedType || !category) return

    const fields = SOURCE_TYPE_FIELDS[selectedType]
    for (const field of fields) {
      if (field.required && !auth[field.key]?.trim()) {
        setError(`${field.label} is required.`)
        return
      }
    }

    // Git sources load the picker (pick-then-add); other categories test and
    // create directly.
    if (category === "code-repositories") {
      await discover()
      return
    }

    setTesting(true)
    setError(null)
    const testResult = await testNewSourceConnection(_testPayload())
    if (!testResult.ok) {
      setTesting(false)
      setError(testResult.error)
      return
    }
    if (!testResult.data.success) {
      setTesting(false)
      setError(testResult.data.message)
      return
    }
    await finishCreate("all", [])
  }

  // Shared create → sync → close, used by both the direct (non-repo) path and
  // the repo cherry-pick picker's confirm.
  async function finishCreate(
    scanScope: "all" | "selected",
    includedItems: string[],
  ) {
    if (!selectedType || !category) return
    setTesting(true)
    const payload = {
      category,
      sourceType: selectedType,
      name: name.trim() || SOURCE_TYPE_LABELS[selectedType],
      auth,
      scanScope,
      excludedItems: [],
      includedItems,
      connectionMethods: [method],
      syncSchedule: "1h" as const,
      status: "not-synced" as const,
    }
    const createResult = await createSourceConnection(payload)
    setTesting(false)
    if (!createResult.ok) {
      setError(createResult.error)
      return
    }
    void syncSourceConnection(createResult.data.connection.id)
    onCreated()
    onClose()
  }

  const providerLabel = selectedType ? SOURCE_TYPE_LABELS[selectedType] : ""
  const totalSteps = hasMethodStep ? 3 : 2
  const stepNumber = screen === "provider" ? 1 : screen === "method" ? 2 : totalSteps

  // Git sources use a two-pane layout for the whole settings step: the token
  // form stays editable on the left while the repo picker fills the right. The
  // list auto-loads as soon as a token is entered, so there is no separate
  // "test, then pick" step — you just pick and add.
  const splitView =
    screen === "settings" &&
    method === "pat" &&
    category === "code-repositories"

  const title =
    screen === "provider"
      ? "Add a Source"
      : screen === "method"
        ? `Connect ${providerLabel}`
        : method === "webhook"
          ? `${providerLabel} Webhook`
          : method === "cicd"
            ? `${providerLabel} CI/CD`
            : `Connect to ${providerLabel}`

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div className="fixed inset-0 bg-[var(--color-overlay-strong)] transition-opacity" aria-hidden="true" />

      <div
        ref={dialogRef}
        tabIndex={-1}
        className={`relative flex max-h-[calc(100dvh-2rem)] w-full flex-col overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[0_28px_80px_rgba(15,23,42,0.06)] focus:outline-none transition-[max-width] duration-200 ${splitView ? "max-w-4xl h-[85dvh]" : "max-w-lg"}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="add-source-title"
      >
        {/* Header */}
        <div className="flex shrink-0 items-center justify-between border-b border-[var(--color-border)] px-6 py-4">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
              Step {stepNumber} of {totalSteps}
            </p>
            <h2 id="add-source-title" className="mt-1 text-lg font-semibold text-[var(--color-text-primary)]">{title}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
            aria-label="Close"
          >
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className={`flex min-h-0 flex-1 ${splitView ? "flex-row" : "flex-col overflow-y-auto px-6 py-5"}`}>
          {/* Screen 1: provider selection */}
          {screen === "provider" && (
            <div>
              <p className="mb-5 text-sm text-[var(--color-text-secondary)]">
                Select the provider you want to connect.
              </p>
              <div className="space-y-6">
                {visibleCategories.map((cat) => {
                  const types = CATEGORY_SOURCE_TYPES[cat]
                  return (
                    <div key={cat}>
                      {!lockedCategory && (
                        <p className="mb-3 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                          {CATEGORY_LABELS[cat]}
                        </p>
                      )}
                      {types.length === 0 ? (
                        <div
                          aria-disabled="true"
                          className="flex cursor-not-allowed items-center gap-3 rounded-2xl border border-dashed border-[var(--color-border)] p-4 opacity-50"
                        >
                          <span className="flex h-6 w-6 shrink-0 items-center justify-center text-[var(--color-text-secondary)]">
                            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <circle cx="12" cy="12" r="9" />
                              <path d="M12 7v5l3 2" />
                            </svg>
                          </span>
                          <span className="text-sm font-medium text-[var(--color-text-secondary)]">Coming soon</span>
                        </div>
                      ) : (
                        <div className="grid grid-cols-2 gap-3">
                          {types.map((type) => {
                            const isSelected = selectedType === type
                            return (
                              <button
                                key={type}
                                type="button"
                                onClick={() => handleTypeSelect(type)}
                                aria-pressed={isSelected}
                                className={`group flex items-center gap-3 rounded-2xl border p-3.5 text-left transition-colors ${
                                  isSelected
                                    ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                                    : "border-[var(--color-border)] hover:border-[var(--color-accent-border)] hover:bg-[var(--color-surface-raised)]"
                                }`}
                              >
                                <span
                                  className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl border transition-colors ${
                                    isSelected
                                      ? "border-[var(--color-accent)]/40 bg-[var(--color-surface)] text-[var(--color-accent)]"
                                      : "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)] group-hover:text-[var(--color-text-primary)]"
                                  }`}
                                >
                                  <ProviderIcon type={type} />
                                </span>
                                <span className={`text-sm font-semibold leading-tight ${isSelected ? "text-[var(--color-accent)]" : "text-[var(--color-text-primary)]"}`}>
                                  {SOURCE_TYPE_LABELS[type]}
                                </span>
                              </button>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Screen 2: connection method */}
          {screen === "method" && selectedType && (
            <div>
              <p className="mb-5 text-sm text-[var(--color-text-secondary)]">
                Choose how Aegis should connect to {providerLabel}.
              </p>
              <div className="space-y-3">
                {methodsFor(selectedType).map((m) => {
                  const meta = METHOD_META[m]
                  const Icon = meta.icon
                  return (
                    <button
                      key={m}
                      type="button"
                      onClick={() => pickMethod(m)}
                      className="group flex w-full items-start gap-3.5 rounded-2xl border border-[var(--color-border)] p-4 text-left transition-colors hover:border-[var(--color-accent-border)] hover:bg-[var(--color-surface-raised)]"
                    >
                      <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--color-accent-subtle)] text-[var(--color-accent)]">
                        <Icon className="h-5 w-5" />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-center gap-2">
                          <span className="text-sm font-semibold text-[var(--color-text-primary)]">{meta.label}</span>
                          {meta.recommended && (
                            <span className="rounded-full bg-[var(--color-accent-subtle)] px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-accent)]">
                              Recommended
                            </span>
                          )}
                        </span>
                        <span className="mt-1 block text-xs leading-relaxed text-[var(--color-text-secondary)]">
                          {meta.describe(providerLabel)}
                        </span>
                        <span className="mt-1.5 block text-xs text-[var(--color-text-tertiary)]">{meta.outcome}</span>
                      </span>
                      <svg className="mt-1 h-4 w-4 shrink-0 text-[var(--color-text-tertiary)] transition-colors group-hover:text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Screen 3a: PAT settings */}
          {screen === "settings" && selectedType && method === "pat" && (
            <>
            <form
              onSubmit={handleSubmit}
              id="add-connection-form"
              className={splitView ? "w-[380px] shrink-0 overflow-y-auto border-r border-[var(--color-border)] px-6 py-5" : undefined}
            >
              {(() => {
                const guide = SOURCE_TYPE_SETUP_GUIDES[selectedType]
                return (
                  <div className="mb-5 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
                    <div className="flex items-start gap-3">
                      <svg className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z" />
                      </svg>
                      <div className="min-w-0">
                        <p className="text-xs font-semibold text-[var(--color-text-primary)]">
                          How to get your {guide.tokenLabel}
                        </p>
                        <ol className="mt-2 space-y-1">
                          {guide.steps.map((s, i) => (
                            <li key={i} className="text-xs leading-relaxed text-[var(--color-text-secondary)]">
                              {i + 1}. {s}
                            </li>
                          ))}
                        </ol>
                        <div className="mt-2.5 flex flex-wrap gap-1.5">
                          {guide.requiredScopes.map((scope) => (
                            <span key={scope} className="inline-block rounded bg-[var(--color-accent-subtle)] px-1.5 py-0.5 font-mono text-[11px] font-medium text-[var(--color-accent)]">
                              {scope}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })()}

              <FormField
                label={<>Display name <span className="font-normal text-[var(--color-text-tertiary)]">(optional)</span></>}
                htmlFor="connection-display-name"
                className="mb-4"
              >
                <Input
                  id="connection-display-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={SOURCE_TYPE_LABELS[selectedType]}
                />
              </FormField>

              {SOURCE_TYPE_FIELDS[selectedType].map((field) => {
                const isPassword = field.type === "password"
                const isVisible = showPassword[field.key]
                const fieldId = `connection-${field.key}`
                return (
                  <FormField
                    key={field.key}
                    label={field.label}
                    htmlFor={fieldId}
                    required={field.required}
                    hint={field.helperText}
                    className="mb-4"
                  >
                    <div className="relative">
                      <Input
                        id={fieldId}
                        type={isPassword && !isVisible ? "password" : "text"}
                        value={auth[field.key] ?? ""}
                        placeholder={field.placeholder}
                        onChange={(e) => setAuth((prev) => ({ ...prev, [field.key]: e.target.value }))}
                        // The PAT field auto-loads the repo list on commit so no
                        // separate "test" click is needed before picking.
                        onBlur={field.key === "token" ? handleTokenBlur : undefined}
                        className={isPassword ? "pr-14" : ""}
                      />
                      {isPassword && (
                        <button
                          type="button"
                          onClick={() => setShowPassword((prev) => ({ ...prev, [field.key]: !prev[field.key] }))}
                          className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded px-1.5 py-0.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
                          tabIndex={-1}
                        >
                          {isVisible ? "Hide" : "Show"}
                        </button>
                      )}
                    </div>
                  </FormField>
                )
              })}

              {error && (
                <div className="mb-4 flex items-start gap-2.5 rounded-2xl border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3.5 py-3">
                  <svg className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-severity-critical-text)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" />
                  </svg>
                  <div>
                    <p className="text-sm font-medium text-[var(--color-severity-critical-text)]">Connection failed</p>
                    <p className="mt-0.5 text-xs text-[var(--color-severity-critical-text)]">{error}</p>
                  </div>
                </div>
              )}

              {/* Two-pane view: the form owns Back and a reload fallback (the
                  list auto-loads on token blur); the right pane's "Add
                  repositories" bar is the single primary action. */}
              {splitView && (
                <div className="mt-6 flex items-center gap-2 border-t border-[var(--color-border)] pt-4">
                  <Button type="button" variant="ghost" size="sm" onClick={handleBack}>
                    Back
                  </Button>
                  <Button
                    type="submit"
                    form="add-connection-form"
                    variant={hasDiscovered ? "secondary" : "primary"}
                    size="sm"
                    isLoading={testing}
                    disabled={testing}
                  >
                    {testing
                      ? hasDiscovered ? "Reloading…" : "Loading…"
                      : hasDiscovered ? "Reload repositories" : "Load repositories"}
                  </Button>
                </div>
              )}
            </form>

            {/* Right pane: repos auto-load here as the token is entered; before
                that, a prompt keeps the two-pane balanced. */}
            {splitView && (
              <div className="min-h-0 flex-1">
                {hasDiscovered ? (
                  <RepoPicker
                    discovered={discoveredRepos}
                    isSubmitting={testing}
                    onConfirm={(included) => finishCreate("selected", included)}
                  />
                ) : (
                  <div className="flex h-full flex-col items-center justify-center gap-3 px-8 text-center">
                    <div className="grid h-11 w-11 place-items-center rounded-full bg-[var(--color-bg-subtle)] text-[var(--color-text-tertiary)]">
                      {testing ? (
                        <svg className="h-5 w-5 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M21 12a9 9 0 1 1-6.219-8.56" /></svg>
                      ) : (
                        <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></svg>
                      )}
                    </div>
                    <p className="text-sm font-medium text-[var(--color-text-primary)]">
                      {testing ? "Loading your repositories…" : "Your repositories will appear here"}
                    </p>
                    <p className="max-w-xs text-xs leading-relaxed text-[var(--color-text-secondary)]">
                      {testing
                        ? "Discovering every repo your token can access."
                        : "Enter your Personal Access Token on the left — every repo it can access loads here to cherry-pick."}
                    </p>
                  </div>
                )}
              </div>
            )}
            </>
          )}

          {/* Screen 3b: Webhook setup */}
          {screen === "settings" && selectedType && method === "webhook" && (
            <div className="space-y-4">
              <p className="text-sm text-[var(--color-text-secondary)]">
                Send {providerLabel} push and pull-request events to Aegis so it rescans automatically. Add the
                webhook below in your {providerLabel} repository (or organisation) settings.
              </p>

              <HostReachabilityNote
                origin={typeof window !== "undefined" ? window.location.origin : ""}
                audience={providerLabel}
              />

              <ol className="space-y-4">
                <Step n={1}>
                  In {providerLabel}, open{" "}
                  <span className="font-medium text-[var(--color-text-primary)]">
                    {WEBHOOK_SETTINGS_PATH[selectedType] ?? "your webhook settings"}
                  </span>.
                </Step>
                <Step n={2}>
                  Set the <span className="font-medium text-[var(--color-text-primary)]">Payload URL</span> to:
                  <CopyRow
                    value={(typeof window !== "undefined" ? window.location.origin : "") + (WEBHOOK_PATHS[selectedType] ?? "")}
                    copied={copied === "url"}
                    onCopy={(v) => copy(v, "url")}
                  />
                </Step>
                <Step n={3}>
                  Set <span className="font-medium text-[var(--color-text-primary)]">Content type</span> to{" "}
                  <code className="rounded bg-[var(--color-surface-raised)] px-1 py-0.5 font-mono text-[11px]">application/json</code>.
                </Step>
                <Step n={4}>
                  Generate a signing secret and paste it into the webhook&apos;s{" "}
                  <span className="font-medium text-[var(--color-text-primary)]">Secret</span> field:
                  {webhookSecret ? (
                    <>
                      <CopyRow value={webhookSecret} mono copied={copied === "secret"} onCopy={(v) => copy(v, "secret")} />
                      <p className="text-[var(--color-text-tertiary)]">
                        Copy it now — it won&apos;t be shown again. You can rotate it later from Webhook Endpoints.
                      </p>
                    </>
                  ) : (
                    <>
                      <span className="block">
                        <Button variant="secondary" size="sm" onClick={handleWebhookSecret} disabled={webhookBusy} isLoading={webhookBusy}>
                          {webhookBusy
                            ? (existingWebhookId ? "Rotating…" : "Generating…")
                            : (existingWebhookId ? "Rotate signing secret" : "Generate signing secret")}
                        </Button>
                      </span>
                      {existingWebhookId && (
                        <p className="text-[var(--color-text-tertiary)]">
                          A secret already exists for {providerLabel}. Rotating generates a new one and invalidates the old.
                        </p>
                      )}
                    </>
                  )}
                </Step>
                <Step n={5}>
                  Under events, select{" "}
                  <span className="font-medium text-[var(--color-text-primary)]">Pushes</span> and{" "}
                  <span className="font-medium text-[var(--color-text-primary)]">Pull requests</span>, then save.
                </Step>
              </ol>

              {error && <p className="text-xs text-[var(--color-severity-critical-text)]">{error}</p>}
            </div>
          )}

          {/* Screen 3c: CI/CD setup */}
          {screen === "settings" && selectedType && method === "cicd" && (() => {
            const StepsComponent = CICD_STEPS[selectedType]
            const aegisUrl = typeof window !== "undefined" ? window.location.origin : ""
            return (
              <div className="space-y-4">
                <p className="text-sm text-[var(--color-text-secondary)]">
                  Run the Aegis scanner inside your {providerLabel} pipeline. It scans each build and reports findings
                  back to Aegis — no webhook required.
                </p>

                <HostReachabilityNote origin={aegisUrl} audience={`your ${providerLabel} pipeline`} />

                <ol className="space-y-4">
                  <Step n={1}>
                    Create an API key with{" "}
                    <code className="rounded bg-[var(--color-surface-raised)] px-1 py-0.5 font-mono text-[11px]">scan:trigger</code>{" "}
                    scope and add it to your CI as a secret named{" "}
                    <code className="rounded bg-[var(--color-surface-raised)] px-1 py-0.5 font-mono text-[11px]">AEGIS_API_KEY</code>.
                    {apiKeyToken ? (
                      <>
                        <CopyRow value={apiKeyToken} mono copied={copied === "apikey"} onCopy={(v) => copy(v, "apikey")} />
                        <p className="text-[var(--color-text-tertiary)]">
                          Copy it now — it won&apos;t be shown again. It&apos;s saved under{" "}
                          <Link href="/settings/api-keys" className="text-[var(--color-accent)] underline" onClick={onClose}>
                            Settings → API keys
                          </Link>.
                        </p>
                      </>
                    ) : (
                      <>
                        <span className="block">
                          <Button variant="secondary" size="sm" onClick={handleCreateApiKey} disabled={apiKeyBusy} isLoading={apiKeyBusy}>
                            {apiKeyBusy ? "Creating…" : "Create API key"}
                          </Button>
                        </span>
                        {apiKeyError && <p className="text-[var(--color-severity-critical-text)]">{apiKeyError}</p>}
                      </>
                    )}
                  </Step>
                  <Step n={2}>
                    Add this to your {providerLabel} pipeline config, then commit and run a build:
                    {StepsComponent && (
                      <div className="mt-1">
                        <StepsComponent aegisUrl={aegisUrl} />
                      </div>
                    )}
                  </Step>
                  <Step n={3}>
                    That&apos;s it — Aegis links each scan to the right source from the repository
                    automatically, so there&apos;s no source id to manage.
                  </Step>
                </ol>
              </div>
            )
          })()}
        </div>

        {/* Global footer — hidden in the two-pane git-repo view, where the left
            form owns Back/Reload and the right pane owns "Add repositories". */}
        {!splitView && (
        <div className="flex shrink-0 items-center justify-between border-t border-[var(--color-border)] px-6 py-4">
          {screen === "provider" ? (
            <>
              <Button variant="ghost" size="md" onClick={onClose}>Cancel</Button>
              <Button variant="primary" size="md" disabled={!selectedType} onClick={handleNext}>Next</Button>
            </>
          ) : screen === "method" ? (
            <Button variant="ghost" size="md" onClick={handleBack}>Back</Button>
          ) : method === "pat" ? (
            <>
              <Button variant="ghost" size="md" onClick={handleBack}>Back</Button>
              <Button type="submit" form="add-connection-form" variant="primary" size="md" disabled={testing} isLoading={testing}>
                {testing ? "Testing…" : "Test & Connect"}
              </Button>
            </>
          ) : (
            <>
              <Button variant="ghost" size="md" onClick={handleBack}>Back</Button>
              <Button variant="primary" size="md" onClick={onClose}>Done</Button>
            </>
          )}
        </div>
        )}
      </div>
    </div>
  )
}


// A numbered step in the webhook / CI-CD setup instructions.
function Step({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-accent-subtle)] text-[11px] font-semibold text-[var(--color-accent)]">
        {n}
      </span>
      <div className="min-w-0 flex-1 space-y-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">
        {children}
      </div>
    </li>
  )
}


function CopyRow({
  label, value, mono, copied, onCopy,
}: {
  label?: string
  value: string
  mono?: boolean
  copied: boolean
  onCopy: (value: string) => void
}) {
  return (
    <div>
      {label && <p className="mb-1.5 text-xs font-medium text-[var(--color-text-secondary)]">{label}</p>}
      <div className="flex items-center gap-2">
        <code className={`min-w-0 flex-1 truncate rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-xs text-[var(--color-text-primary)] ${mono ? "font-mono" : ""}`}>
          {value}
        </code>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => onCopy(value)}
          leadingIcon={copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  )
}
