// ─── Type Aliases ────────────────────────────────────────────────────────────

export type SourceCategory =
  | "code-repositories"
  | "container-registry"
  | "cloud-infrastructure"
  | "ci-systems"

export type SourceType =
  | "github"
  | "gitlab"
  | "bitbucket"
  | "gitea"
  | "azure_devops"
  | "docker-hub"
  | "ghcr"
  | "ecr"
  | "acr"
  | "gcr"
  | "gitlab-registry"
  | "jenkins"

export type ScanScope = "all" | "all-except-excluded"

export type ScannerType =
  | "dependencies_scanning"
  | "secret_scanning"
  | "code_scanning"
  | "container_scanning"

export type ConnectionMethod = "pat" | "webhook" | "cicd"

export type SyncSchedule = "1h" | "3h" | "6h" | "12h" | "24h"

export type ScheduleMode = "preset" | "cron"

export type ConnectionStatus = "connected" | "syncing" | "error" | "disconnected" | "not-synced"

// ─── Interfaces ───────────────────────────────────────────────────────────────

export interface SourceConnectionAuth {
  token?: string
  username?: string
  instanceUrl?: string
  orgOrOwner?: string
  groupOrProject?: string
}

export interface SourceConnection {
  id: string
  category: SourceCategory
  sourceType: SourceType
  name: string
  auth: SourceConnectionAuth
  scanScope: ScanScope
  excludedItems: string[]
  /** Scanners to run on Scan Now. Empty = all applicable to the category. */
  scanners: ScannerType[]
  /** How the source was connected — PAT, webhook, CI/CD, or a combination. */
  connectionMethods: ConnectionMethod[]
  syncSchedule: SyncSchedule
  syncScheduleMode: ScheduleMode
  syncScheduleCron?: string
  scanAutoEnabled: boolean
  scanScheduleMode: ScheduleMode
  scanSchedulePreset: SyncSchedule
  scanScheduleCron?: string
  status: ConnectionStatus
  statusMessage?: string
  lastSyncedAt?: string
  /** Most recent scan for this source's org (from the latest scan_run). */
  lastScanAt?: string
  nextSyncAt?: string
  discoveredItemCount?: number
  discoveredItems?: string[]
  /** Canonical asset refs (display_name format, e.g. "github:owner/repo") for
   *  scoping the per-source findings list. Derived from discoveredItems server-
   *  side via the same repo_ref/image_ref helper that names the assets. */
  scopeRefs?: string[]
  createdAt: string
  updatedAt: string
}

export interface ConnectionTestResult {
  success: boolean
  message: string
  discoveredCount?: number
}

export interface CategoryCounts {
  "code-repositories": number
  "container-registry": number
  "cloud-infrastructure": number
  "ci-systems": number
}

// ─── Constants ────────────────────────────────────────────────────────────────

export const CATEGORY_LABELS: Record<SourceCategory, string> = {
  "code-repositories": "Git Repository",
  "container-registry": "Container Registry",
  "cloud-infrastructure": "Cloud Infrastructure",
  "ci-systems": "CI Systems",
}

export const CATEGORY_ITEM_LABELS: Record<SourceCategory, string> = {
  "code-repositories": "repositories",
  "container-registry": "images",
  "cloud-infrastructure": "accounts",
  "ci-systems": "pipelines",
}

export const CATEGORY_SOURCE_TYPES: Record<SourceCategory, SourceType[]> = {
  "code-repositories": ["github", "gitlab", "bitbucket", "gitea", "azure_devops"],
  "container-registry": ["docker-hub", "ghcr", "ecr", "acr", "gcr", "gitlab-registry"],
  "cloud-infrastructure": [],
  "ci-systems": ["jenkins"],
}

// Scanner job types that run for each source category. Mirrors the backend's
// SCANNERS_BY_CATEGORY — keep the two in sync.
export const CATEGORY_SCANNERS: Record<SourceCategory, ScannerType[]> = {
  "code-repositories": ["dependencies_scanning", "secret_scanning", "code_scanning"],
  "container-registry": ["container_scanning"],
  "cloud-infrastructure": [],
  "ci-systems": [],
}

export const SCANNER_LABELS: Record<ScannerType, string> = {
  dependencies_scanning: "Dependency Scanning",
  secret_scanning: "Secret Scanning",
  code_scanning: "Code Scanning",
  container_scanning: "Container Scanning",
}

export const SCANNER_DESCRIPTIONS: Record<ScannerType, string> = {
  dependencies_scanning: "Checks the open-source libraries your project relies on for known security problems.",
  secret_scanning: "Looks for passwords, API keys, and other secrets accidentally left in your code.",
  code_scanning: "Reviews your own code for security weaknesses and risky mistakes.",
  container_scanning: "Inspects your container images for known vulnerabilities in their software.",
}

export const CONNECTION_METHOD_LABELS: Record<ConnectionMethod, string> = {
  pat: "PAT",
  webhook: "Webhook",
  cicd: "CI/CD",
}

export const SOURCE_TYPE_TO_CATEGORY: Record<SourceType, SourceCategory> = {
  github: "code-repositories",
  gitlab: "code-repositories",
  bitbucket: "code-repositories",
  gitea: "code-repositories",
  azure_devops: "code-repositories",
  "docker-hub": "container-registry",
  ghcr: "container-registry",
  ecr: "container-registry",
  acr: "container-registry",
  gcr: "container-registry",
  "gitlab-registry": "container-registry",
  jenkins: "ci-systems",
}

export const CATEGORY_API_SLUGS: Record<SourceCategory, string> = {
  "code-repositories": "code-repositories",
  "container-registry": "container-images",
  "cloud-infrastructure": "cloud-infrastructure",
  "ci-systems": "ci-systems",
}

export const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  github: "GitHub",
  gitlab: "GitLab",
  bitbucket: "Bitbucket",
  gitea: "Gitea",
  azure_devops: "Azure DevOps",
  "docker-hub": "Docker Hub",
  ghcr: "GitHub Container Registry",
  ecr: "AWS ECR",
  acr: "Azure ACR",
  gcr: "Google GCR",
  "gitlab-registry": "GitLab Registry",
  jenkins: "Jenkins",
}

/**
 * Display label for a source: the user's custom name when set, otherwise the
 * org/owner that identifies it (e.g. "frogasia"). Sources created without a
 * name default to the provider label (e.g. "GitHub"), which is ambiguous when
 * several sources share a provider — so fall back to the org instead.
 */
export function sourceDisplayName(
  connection: Pick<SourceConnection, "name" | "sourceType" | "auth">,
): string {
  const name = connection.name?.trim() ?? ""
  const isProviderDefault = name === SOURCE_TYPE_LABELS[connection.sourceType]
  if (name && !isProviderDefault) return name
  const { orgOrOwner, groupOrProject, username } = connection.auth
  return orgOrOwner || groupOrProject || username || name || SOURCE_TYPE_LABELS[connection.sourceType]
}

export const SYNC_SCHEDULE_LABELS: Record<SyncSchedule, string> = {
  "1h": "Every hour",
  "3h": "Every 3 hours",
  "6h": "Every 6 hours",
  "12h": "Every 12 hours",
  "24h": "Every 24 hours",
}

// ─── Source Type Field Config ─────────────────────────────────────────────────

export interface SourceTypeFieldConfig {
  key: keyof SourceConnectionAuth
  label: string
  type: "text" | "password"
  placeholder?: string
  helperText?: string
  required?: boolean
  defaultValue?: string
}

export const SOURCE_TYPE_FIELDS: Record<SourceType, SourceTypeFieldConfig[]> = {
  github: [
    {
      key: "orgOrOwner",
      label: "Organization or owner",
      type: "text",
      placeholder: "my-org",
      helperText: "Repos under this org or user will be discovered.",
    },
    {
      key: "token",
      label: "Personal Access Token",
      type: "password",
      placeholder: "ghp_••••••••••••",
      helperText: "Use a classic PAT. See the guide above for required scopes.",
      required: true,
    },
  ],
  gitlab: [
    {
      key: "instanceUrl",
      label: "Instance URL",
      type: "text",
      placeholder: "https://gitlab.com",
      defaultValue: "https://gitlab.com",
      helperText: "Leave as default for GitLab.com, or enter your self-hosted URL.",
    },
    {
      key: "groupOrProject",
      label: "Group or Project",
      type: "text",
      placeholder: "my-group",
      helperText: "Top-level group or project path to scan.",
    },
    {
      key: "token",
      label: "Personal Access Token",
      type: "password",
      placeholder: "glpat-••••••••••••",
      helperText: "See the guide above for required scopes.",
      required: true,
    },
  ],
  bitbucket: [
    {
      key: "orgOrOwner",
      label: "Workspace",
      type: "text",
      placeholder: "my-workspace",
      helperText: "Your Bitbucket workspace slug.",
      required: true,
    },
    {
      key: "username",
      label: "Username",
      type: "text",
      placeholder: "my-username",
      helperText: "Your Bitbucket username (for app password auth).",
    },
    {
      key: "token",
      label: "App Password",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "Create an app password with repository read permissions.",
      required: true,
    },
  ],
  gitea: [
    {
      key: "instanceUrl",
      label: "Instance URL",
      type: "text",
      placeholder: "https://gitea.example.com",
      helperText: "Your Gitea or Forgejo instance URL.",
      required: true,
    },
    {
      key: "orgOrOwner",
      label: "Organization or owner",
      type: "text",
      placeholder: "my-org",
      helperText: "Leave blank to discover all repos for the token owner.",
    },
    {
      key: "token",
      label: "Access Token",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "A token with read:organization and read:repository scopes.",
      required: true,
    },
  ],
  "docker-hub": [
    {
      key: "username",
      label: "Username",
      type: "text",
      placeholder: "my-username",
      helperText: "Your Docker Hub username or organization name.",
      required: true,
    },
    {
      key: "token",
      label: "Access Token",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "A read-only access token is sufficient.",
      required: true,
    },
  ],
  ghcr: [
    {
      key: "orgOrOwner",
      label: "Organization or owner",
      type: "text",
      placeholder: "my-org",
      helperText: "Packages under this org or user will be discovered.",
    },
    {
      key: "token",
      label: "Personal Access Token",
      type: "password",
      placeholder: "ghp_••••••••••••",
      helperText: "Use a classic PAT. See the guide above for required scopes.",
      required: true,
    },
  ],
  ecr: [
    {
      key: "instanceUrl",
      label: "Registry URL",
      type: "text",
      placeholder: "123456789.dkr.ecr.us-east-1.amazonaws.com",
      helperText: "Your ECR registry endpoint.",
      required: true,
    },
    {
      key: "token",
      label: "Auth Token",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "From 'aws ecr get-login-password'. Tokens expire after 12 hours.",
      required: true,
    },
  ],
  acr: [
    {
      key: "instanceUrl",
      label: "Registry URL",
      type: "text",
      placeholder: "myregistry.azurecr.io",
      helperText: "Your Azure Container Registry login server.",
      required: true,
    },
    {
      key: "username",
      label: "Username",
      type: "text",
      placeholder: "myregistry",
      helperText: "Admin username or service principal client ID.",
    },
    {
      key: "token",
      label: "Password / Token",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "Admin password or service principal secret.",
      required: true,
    },
  ],
  gcr: [
    {
      key: "instanceUrl",
      label: "Registry Host",
      type: "text",
      placeholder: "gcr.io",
      defaultValue: "gcr.io",
      helperText: "gcr.io, us-docker.pkg.dev, or your regional endpoint.",
    },
    {
      key: "orgOrOwner",
      label: "Project ID",
      type: "text",
      placeholder: "my-gcp-project",
      helperText: "Your Google Cloud project ID.",
      required: true,
    },
    {
      key: "token",
      label: "Service Account Key / Access Token",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "Paste the full JSON service account key or an OAuth2 access token.",
      required: true,
    },
  ],
  "gitlab-registry": [
    {
      key: "instanceUrl",
      label: "GitLab Instance URL",
      type: "text",
      placeholder: "https://gitlab.com",
      defaultValue: "https://gitlab.com",
      helperText: "Leave as default for GitLab.com, or enter your self-hosted URL.",
    },
    {
      key: "groupOrProject",
      label: "Group or Project",
      type: "text",
      placeholder: "my-group",
      helperText: "Top-level group to discover container images from.",
      required: true,
    },
    {
      key: "token",
      label: "Access Token",
      type: "password",
      placeholder: "glpat-••••••••••••",
      helperText: "Personal, project, or group access token with read_api scope.",
      required: true,
    },
  ],
  azure_devops: [
    {
      key: "instanceUrl",
      label: "Organization URL",
      type: "text",
      placeholder: "https://dev.azure.com/my-org",
      helperText: "Your Azure DevOps organization URL.",
      required: true,
    },
    {
      key: "groupOrProject",
      label: "Project",
      type: "text",
      placeholder: "my-project",
      helperText: "Repos under this project will be discovered.",
    },
    {
      key: "token",
      label: "Personal Access Token",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "Use a PAT with Code (read) scope.",
      required: true,
    },
  ],
  jenkins: [
    {
      key: "instanceUrl",
      label: "Jenkins URL",
      type: "text",
      placeholder: "https://jenkins.example.com",
      helperText: "Your Jenkins controller URL.",
      required: true,
    },
    {
      key: "username",
      label: "Username",
      type: "text",
      placeholder: "my-username",
      helperText: "Jenkins user the API token belongs to.",
      required: true,
    },
    {
      key: "token",
      label: "API Token",
      type: "password",
      placeholder: "••••••••••••",
      helperText: "Generate from User → Configure → API Token.",
      required: true,
    },
  ],
}

// ─── Setup Guides ────────────────────────────────────────────────────────────

export interface SourceTypeSetupGuide {
  tokenLabel: string
  steps: string[]
  requiredScopes: string[]
}

export const SOURCE_TYPE_SETUP_GUIDES: Record<SourceType, SourceTypeSetupGuide> = {
  github: {
    tokenLabel: "Personal Access Token (classic)",
    steps: [
      "Go to GitHub → Settings → Developer settings → Personal access tokens",
      "Click \"Generate new token (classic)\"",
      "Set an expiration and select the scopes below",
    ],
    requiredScopes: ["repo", "read:org"],
  },
  gitlab: {
    tokenLabel: "Personal Access Token",
    steps: [
      "Go to GitLab → User Settings → Access Tokens",
      "Click \"Add new token\"",
      "Set an expiration and select the scopes below",
    ],
    requiredScopes: ["read_api", "read_repository"],
  },
  bitbucket: {
    tokenLabel: "App Password",
    steps: [
      "Go to Bitbucket → Personal settings → App passwords",
      "Click \"Create app password\"",
      "Select the permissions below",
    ],
    requiredScopes: ["Repositories: Read", "Account: Read"],
  },
  gitea: {
    tokenLabel: "Access Token",
    steps: [
      "Go to your Gitea instance → User Settings → Applications",
      "Under \"Manage Access Tokens\", create a new token",
      "Select the scopes below",
    ],
    requiredScopes: ["read:organization", "read:repository"],
  },
  "docker-hub": {
    tokenLabel: "Access Token",
    steps: [
      "Go to Docker Hub → Account Settings → Security",
      "Click \"New Access Token\"",
      "Set the permission to \"Read-only\"",
    ],
    requiredScopes: ["Read-only"],
  },
  ghcr: {
    tokenLabel: "Personal Access Token (classic)",
    steps: [
      "Go to GitHub → Settings → Developer settings → Personal access tokens",
      "Click \"Generate new token (classic)\"",
      "Set an expiration and select the scopes below",
    ],
    requiredScopes: ["read:packages"],
  },
  ecr: {
    tokenLabel: "Auth Token",
    steps: [
      "Install and configure the AWS CLI with appropriate IAM credentials",
      "Run: aws ecr get-login-password --region <region>",
      "Paste the output as the auth token (expires after 12 hours)",
    ],
    requiredScopes: ["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:ListImages"],
  },
  acr: {
    tokenLabel: "Admin Password or Service Principal Secret",
    steps: [
      "Go to Azure Portal → Container Registry → Access keys",
      "Enable Admin user, or use a service principal",
      "Copy the username and password",
    ],
    requiredScopes: ["AcrPull"],
  },
  gcr: {
    tokenLabel: "Service Account Key",
    steps: [
      "Go to Google Cloud Console → IAM → Service Accounts",
      "Create or select a service account with the roles below",
      "Create a JSON key and paste the full contents",
    ],
    requiredScopes: ["roles/artifactregistry.reader"],
  },
  "gitlab-registry": {
    tokenLabel: "Access Token",
    steps: [
      "Go to GitLab → User Settings → Access Tokens (or use a project/group token)",
      "Click \"Add new token\"",
      "Set an expiration and select the scopes below",
    ],
    requiredScopes: ["read_api"],
  },
  azure_devops: {
    tokenLabel: "Personal Access Token",
    steps: [
      "Go to Azure DevOps → User Settings → Personal access tokens",
      "Click \"New Token\"",
      "Set an expiration and select the scopes below",
    ],
    requiredScopes: ["Code (read)"],
  },
  jenkins: {
    tokenLabel: "API Token",
    steps: [
      "Go to Jenkins → User → Configure",
      "Under \"API Token\", click \"Add new Token\"",
      "Copy the generated token",
    ],
    requiredScopes: ["Overall: Read", "Job: Read"],
  },
}
