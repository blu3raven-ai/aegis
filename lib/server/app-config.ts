export interface AppConfig {
  dashboard: {
    username?: string
    email?: string
    password?: string
    sessionSecret: string
  }
  authSecurity: {
    requireMfaManualUsers: boolean
    requireMfaAdmins: boolean
    trustedSessionDurationDays: number
    recoveryCodePolicy: "mandatory" | "optional" | "disabled"
  }
  tools: {
    dependencies: {
      enabled: boolean
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
      scanConcurrency: string
      dockerImage: string
      nvdEnabled: boolean
      nvdApiKey: string
      nvdApiKeyHint: string
      ghsaEnabled: boolean
      ghsaApiKey: string
      ghsaApiKeyHint: string
      retentionDays: number
    }
    codeScanning: {
      enabled: boolean
      dockerImage: string
      scanConcurrency: string
      rulesets: string[]
      aiReviewEnabled: boolean
      aiApiKey: string
      aiBaseUrl: string
      aiModelName: string
      aiAutoClassifyOnScan: boolean
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
      retentionDays: number
    }
    secrets: {
      enabled: boolean
      scanConcurrency: string
      dockerImage: string
      scanDepth: string
      scanHistoryWindow: string
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
      retentionDays: number
    }
    containerScanning: {
      enabled: boolean
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
      scanConcurrency: string
      dockerImage: string
      nvdEnabled: boolean
      nvdApiKey: string
      nvdApiKeyHint: string
      ghsaEnabled: boolean
      ghsaApiKey: string
      ghsaApiKeyHint: string
      argusEnabled: boolean
      argusApiKey: string
      argusApiKeyHint: string
      retentionDays: number
    }
    iacSecurity: {
      enabled: boolean
    }
  }
}

export type EnvMap = Record<string, string>

const BACKEND_URL = process.env.FASTAPI_URL ?? "http://localhost:8000"

function toBoolean(value: string | undefined, fallback: boolean) {
  if (value === undefined) return fallback
  return value.toLowerCase() !== "false"
}

function configFromEnv(env: EnvMap): AppConfig {
  return {
    dashboard: {
      username: env.ADMIN_USERNAME ?? "admin",
      email: env.ADMIN_EMAIL ?? "",
      password: env.ADMIN_PASSWORD ?? "",
      sessionSecret: env.SESSION_SECRET ?? "",
    },
    authSecurity: {
      requireMfaManualUsers: toBoolean(env.AUTH_SECURITY_REQUIRE_MFA_MANUAL, false),
      requireMfaAdmins: toBoolean(env.AUTH_SECURITY_REQUIRE_MFA_ADMINS, false),
      trustedSessionDurationDays: parseInt(env.AUTH_SECURITY_TRUSTED_SESSION_DURATION ?? "30", 10),
      recoveryCodePolicy: (env.AUTH_SECURITY_RECOVERY_CODE_POLICY as any) ?? "mandatory",
    },
    tools: {
      dependencies: {
        enabled: toBoolean(env.SCA_ENABLED, false),
        autoRerunEnabled: toBoolean(env.SCA_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: env.SCA_RERUN_SCHEDULE_TYPE === "cron" ? "cron" : "simple",
        rerunScheduleValue: env.SCA_RERUN_SCHEDULE_VALUE ?? "02:00",
        scanConcurrency: env.SCA_SCAN_CONCURRENCY ?? "4",
        dockerImage: env.SCA_SCANNER_IMAGE ?? "aegis/scanner-dependencies:latest",
        nvdEnabled: env.SCA_NVD_ENABLED !== "false",
        nvdApiKey: env.SCA_NVD_API_KEY ?? "",
        nvdApiKeyHint: "",
        ghsaEnabled: env.SCA_GHSA_ENABLED === "true",
        ghsaApiKey: env.SCA_GHSA_API_KEY ?? "",
        ghsaApiKeyHint: "",
        retentionDays: parseInt(env.SCA_RETENTION_DAYS ?? "7", 10) || 7,
      },
      codeScanning: {
        enabled: toBoolean(env.SAST_ENABLED, false),
        dockerImage: env.SAST_DOCKER_IMAGE ?? "aegis/scanner-code-scanning:latest",
        scanConcurrency: env.SAST_SCAN_CONCURRENCY ?? "2",
        rulesets: (env.SAST_RULESETS ?? "p/owasp-top-ten,p/cwe-top-25").split(","),
        aiReviewEnabled: toBoolean(env.SAST_AI_REVIEW_ENABLED, false),
        aiApiKey: env.SAST_AI_API_KEY ?? "",
        aiBaseUrl: env.SAST_AI_BASE_URL ?? "https://api.openai.com/v1",
        aiModelName: env.SAST_AI_MODEL ?? "gpt-4o-mini",
        aiAutoClassifyOnScan: toBoolean(env.SAST_AI_AUTO_CLASSIFY_ON_SCAN, false),
        autoRerunEnabled: toBoolean(env.SAST_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: env.SAST_RERUN_SCHEDULE_TYPE === "cron" ? "cron" : "simple",
        rerunScheduleValue: env.SAST_RERUN_SCHEDULE_VALUE ?? "02:00",
        retentionDays: parseInt(env.SAST_RETENTION_DAYS ?? "7", 10) || 7,
      },
      secrets: {
        enabled: toBoolean(env.SECRETS_ENABLED, false),
        scanConcurrency: env.SECRET_SCANNER_CONCURRENCY ?? env.SECRETS_SCAN_CONCURRENCY ?? "4",
        dockerImage: env.SECRET_SCANNER_IMAGE ?? "aegis/scanner-secrets:latest",
        scanDepth: env.SECRETS_SCAN_DEPTH ?? "light",
        scanHistoryWindow: env.SECRETS_SCAN_HISTORY_WINDOW ?? "all",
        autoRerunEnabled: toBoolean(env.SECRETS_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: env.SECRETS_RERUN_SCHEDULE_TYPE === "cron" ? "cron" : "simple",
        rerunScheduleValue: env.SECRETS_RERUN_SCHEDULE_VALUE ?? "02:00",
        retentionDays: parseInt(env.SECRETS_RETENTION_DAYS ?? "7", 10) || 7,
      },
      containerScanning: {
        enabled: toBoolean(env.CONTAINER_SCANNING_ENABLED, false),
        autoRerunEnabled: toBoolean(env.CONTAINER_SCANNING_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: env.CONTAINER_SCANNING_RERUN_SCHEDULE_TYPE === "cron" ? "cron" : "simple",
        rerunScheduleValue: env.CONTAINER_SCANNING_RERUN_SCHEDULE_VALUE ?? "02:00",
        scanConcurrency: env.CONTAINER_SCANNING_SCAN_CONCURRENCY ?? "4",
        dockerImage: env.CONTAINER_SCANNER_IMAGE ?? "aegis/scanner-container:latest",
        nvdEnabled: toBoolean(env.CONTAINER_SCANNING_NVD_ENABLED, false),
        nvdApiKey: env.CONTAINER_SCANNING_NVD_API_KEY ?? "",
        nvdApiKeyHint: "",
        ghsaEnabled: toBoolean(env.CONTAINER_SCANNING_GHSA_ENABLED, false),
        ghsaApiKey: env.CONTAINER_SCANNING_GHSA_API_KEY ?? "",
        ghsaApiKeyHint: "",
        argusEnabled: toBoolean(env.CONTAINER_SCANNING_ARGUS_ENABLED, false),
        argusApiKey: env.CONTAINER_SCANNING_ARGUS_API_KEY ?? "",
        argusApiKeyHint: "",
        retentionDays: parseInt(env.CONTAINER_SCANNING_RETENTION_DAYS ?? "7", 10) || 7,
      },
      iacSecurity: {
        enabled: toBoolean(env.IAC_SECURITY_ENABLED, false),
      },
    },
  }
}

function normalizeConfig(value: Partial<AppConfig> | null, fallback: AppConfig): AppConfig {
  return {
    dashboard: {
      username: value?.dashboard?.username ?? fallback.dashboard.username,
      email: value?.dashboard?.email ?? fallback.dashboard.email,
      password: value?.dashboard?.password ?? fallback.dashboard.password,
      sessionSecret: value?.dashboard?.sessionSecret ?? fallback.dashboard.sessionSecret,
    },
    authSecurity: {
      requireMfaManualUsers: value?.authSecurity?.requireMfaManualUsers ?? fallback.authSecurity.requireMfaManualUsers,
      requireMfaAdmins: value?.authSecurity?.requireMfaAdmins ?? fallback.authSecurity.requireMfaAdmins,
      trustedSessionDurationDays: value?.authSecurity?.trustedSessionDurationDays ?? fallback.authSecurity.trustedSessionDurationDays,
      recoveryCodePolicy: value?.authSecurity?.recoveryCodePolicy ?? fallback.authSecurity.recoveryCodePolicy,
    },
    tools: {
      dependencies: {
        enabled: value?.tools?.dependencies?.enabled ?? fallback.tools.dependencies.enabled,
        autoRerunEnabled: value?.tools?.dependencies?.autoRerunEnabled ?? fallback.tools.dependencies.autoRerunEnabled,
        rerunScheduleType: value?.tools?.dependencies?.rerunScheduleType ?? fallback.tools.dependencies.rerunScheduleType,
        rerunScheduleValue: value?.tools?.dependencies?.rerunScheduleValue ?? fallback.tools.dependencies.rerunScheduleValue,
        scanConcurrency: value?.tools?.dependencies?.scanConcurrency ?? fallback.tools.dependencies.scanConcurrency,
        dockerImage: value?.tools?.dependencies?.dockerImage ?? fallback.tools.dependencies.dockerImage,
        nvdEnabled: value?.tools?.dependencies?.nvdEnabled ?? fallback.tools.dependencies.nvdEnabled,
        nvdApiKey: value?.tools?.dependencies?.nvdApiKey ?? fallback.tools.dependencies.nvdApiKey,
        nvdApiKeyHint: value?.tools?.dependencies?.nvdApiKeyHint ?? fallback.tools.dependencies.nvdApiKeyHint,
        ghsaEnabled: value?.tools?.dependencies?.ghsaEnabled ?? fallback.tools.dependencies.ghsaEnabled,
        ghsaApiKey: value?.tools?.dependencies?.ghsaApiKey ?? fallback.tools.dependencies.ghsaApiKey,
        ghsaApiKeyHint: value?.tools?.dependencies?.ghsaApiKeyHint ?? fallback.tools.dependencies.ghsaApiKeyHint,
        retentionDays: value?.tools?.dependencies?.retentionDays ?? fallback.tools.dependencies.retentionDays,
      },
      codeScanning: {
        enabled: value?.tools?.codeScanning?.enabled ?? fallback.tools.codeScanning.enabled,
        dockerImage: value?.tools?.codeScanning?.dockerImage ?? fallback.tools.codeScanning.dockerImage,
        scanConcurrency: value?.tools?.codeScanning?.scanConcurrency ?? fallback.tools.codeScanning.scanConcurrency,
        rulesets: value?.tools?.codeScanning?.rulesets ?? fallback.tools.codeScanning.rulesets,
        aiReviewEnabled: value?.tools?.codeScanning?.aiReviewEnabled ?? fallback.tools.codeScanning.aiReviewEnabled,
        aiApiKey: value?.tools?.codeScanning?.aiApiKey ?? fallback.tools.codeScanning.aiApiKey,
        aiBaseUrl: value?.tools?.codeScanning?.aiBaseUrl ?? fallback.tools.codeScanning.aiBaseUrl,
        aiModelName: value?.tools?.codeScanning?.aiModelName ?? fallback.tools.codeScanning.aiModelName,
        aiAutoClassifyOnScan: value?.tools?.codeScanning?.aiAutoClassifyOnScan ?? fallback.tools.codeScanning.aiAutoClassifyOnScan,
        autoRerunEnabled: value?.tools?.codeScanning?.autoRerunEnabled ?? fallback.tools.codeScanning.autoRerunEnabled,
        rerunScheduleType: value?.tools?.codeScanning?.rerunScheduleType ?? fallback.tools.codeScanning.rerunScheduleType,
        rerunScheduleValue: value?.tools?.codeScanning?.rerunScheduleValue ?? fallback.tools.codeScanning.rerunScheduleValue,
        retentionDays: value?.tools?.codeScanning?.retentionDays ?? fallback.tools.codeScanning.retentionDays,
      },
      secrets: {
        enabled: value?.tools?.secrets?.enabled ?? fallback.tools.secrets.enabled,
        scanConcurrency: value?.tools?.secrets?.scanConcurrency ?? fallback.tools.secrets.scanConcurrency,
        dockerImage: value?.tools?.secrets?.dockerImage ?? fallback.tools.secrets.dockerImage,
        scanDepth: value?.tools?.secrets?.scanDepth ?? fallback.tools.secrets.scanDepth,
        scanHistoryWindow: value?.tools?.secrets?.scanHistoryWindow ?? fallback.tools.secrets.scanHistoryWindow,
        autoRerunEnabled: value?.tools?.secrets?.autoRerunEnabled ?? fallback.tools.secrets.autoRerunEnabled,
        rerunScheduleType: value?.tools?.secrets?.rerunScheduleType ?? fallback.tools.secrets.rerunScheduleType,
        rerunScheduleValue: value?.tools?.secrets?.rerunScheduleValue ?? fallback.tools.secrets.rerunScheduleValue,
        retentionDays: value?.tools?.secrets?.retentionDays ?? fallback.tools.secrets.retentionDays,
      },
      containerScanning: {
        enabled: value?.tools?.containerScanning?.enabled ?? fallback.tools.containerScanning.enabled,
        autoRerunEnabled: value?.tools?.containerScanning?.autoRerunEnabled ?? fallback.tools.containerScanning.autoRerunEnabled,
        rerunScheduleType: value?.tools?.containerScanning?.rerunScheduleType ?? fallback.tools.containerScanning.rerunScheduleType,
        rerunScheduleValue: value?.tools?.containerScanning?.rerunScheduleValue ?? fallback.tools.containerScanning.rerunScheduleValue,
        scanConcurrency: value?.tools?.containerScanning?.scanConcurrency ?? fallback.tools.containerScanning.scanConcurrency,
        dockerImage: value?.tools?.containerScanning?.dockerImage ?? fallback.tools.containerScanning.dockerImage,
        nvdEnabled: value?.tools?.containerScanning?.nvdEnabled ?? fallback.tools.containerScanning.nvdEnabled,
        nvdApiKey: value?.tools?.containerScanning?.nvdApiKey ?? fallback.tools.containerScanning.nvdApiKey,
        nvdApiKeyHint: value?.tools?.containerScanning?.nvdApiKeyHint ?? fallback.tools.containerScanning.nvdApiKeyHint,
        ghsaEnabled: value?.tools?.containerScanning?.ghsaEnabled ?? fallback.tools.containerScanning.ghsaEnabled,
        ghsaApiKey: value?.tools?.containerScanning?.ghsaApiKey ?? fallback.tools.containerScanning.ghsaApiKey,
        ghsaApiKeyHint: value?.tools?.containerScanning?.ghsaApiKeyHint ?? fallback.tools.containerScanning.ghsaApiKeyHint,
        argusEnabled: value?.tools?.containerScanning?.argusEnabled ?? fallback.tools.containerScanning.argusEnabled,
        argusApiKey: value?.tools?.containerScanning?.argusApiKey ?? fallback.tools.containerScanning.argusApiKey,
        argusApiKeyHint: value?.tools?.containerScanning?.argusApiKeyHint ?? fallback.tools.containerScanning.argusApiKeyHint,
        retentionDays: value?.tools?.containerScanning?.retentionDays ?? fallback.tools.containerScanning.retentionDays,
      },
      iacSecurity: {
        enabled: value?.tools?.iacSecurity?.enabled ?? fallback.tools.iacSecurity.enabled,
      },
    },
  }
}

// Cache to avoid hitting backend on every call
let _cachedConfig: AppConfig | null = null
let _cacheTime = 0
const CACHE_TTL = 5_000 // 5 seconds

export function readAppConfig(): AppConfig {
  const fallback = configFromEnv(process.env as EnvMap)

  // Return cache if fresh
  const now = Date.now()
  if (_cachedConfig && now - _cacheTime < CACHE_TTL) {
    return _cachedConfig
  }

  // Try fetching from backend synchronously via a cached result
  // On first call or cache miss, return env fallback and trigger async refresh
  if (!_cachedConfig) {
    // First call — kick off async fetch, return env fallback for now
    _refreshConfigAsync(fallback)
    return fallback
  }

  // Cache expired — refresh in background, return stale cache
  _refreshConfigAsync(fallback)
  return _cachedConfig
}

async function _refreshConfigAsync(fallback: AppConfig) {
  try {
    const { signInternalJwt } = await import("./jwt-internal")
    const jwt = signInternalJwt("system", "owner" as any)
    const response = await fetch(`${BACKEND_URL}/settings/api?t=${Date.now()}`, {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${jwt}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    })
    if (response.ok) {
      const data = await response.json()
      _cachedConfig = normalizeConfig(data as Partial<AppConfig>, fallback)
      _cacheTime = Date.now()
    }
  } catch {
    // Backend unavailable — keep using env fallback
    if (!_cachedConfig) {
      _cachedConfig = fallback
      _cacheTime = Date.now()
    }
  }
}

function configToEnv(config: AppConfig): EnvMap {
  const env: EnvMap = {}
  if (config.dashboard.username) env.ADMIN_USERNAME = config.dashboard.username
  if (config.dashboard.email) env.ADMIN_EMAIL = config.dashboard.email
  if (config.dashboard.password) env.ADMIN_PASSWORD = config.dashboard.password
  env.SESSION_SECRET = config.dashboard.sessionSecret

  env.AUTH_SECURITY_REQUIRE_MFA_MANUAL = String(config.authSecurity.requireMfaManualUsers)
  env.AUTH_SECURITY_REQUIRE_MFA_ADMINS = String(config.authSecurity.requireMfaAdmins)
  env.AUTH_SECURITY_TRUSTED_SESSION_DURATION = String(config.authSecurity.trustedSessionDurationDays)
  env.AUTH_SECURITY_RECOVERY_CODE_POLICY = config.authSecurity.recoveryCodePolicy

  env.SCA_ENABLED = config.tools.dependencies.enabled ? "true" : "false"
  env.SCA_AUTO_RERUN_ENABLED = config.tools.dependencies.autoRerunEnabled ? "true" : "false"
  env.SCA_RERUN_SCHEDULE_TYPE = config.tools.dependencies.rerunScheduleType
  env.SCA_RERUN_SCHEDULE_VALUE = config.tools.dependencies.rerunScheduleValue
  env.SCA_SCAN_CONCURRENCY = config.tools.dependencies.scanConcurrency
  env.SCA_SCANNER_IMAGE = config.tools.dependencies.dockerImage
  env.SAST_ENABLED = config.tools.codeScanning.enabled ? "true" : "false"
  env.SAST_DOCKER_IMAGE = config.tools.codeScanning.dockerImage
  env.SAST_SCAN_CONCURRENCY = config.tools.codeScanning.scanConcurrency
  env.SAST_RULESETS = Array.isArray(config.tools.codeScanning.rulesets) ? config.tools.codeScanning.rulesets.join(",") : config.tools.codeScanning.rulesets
  env.SAST_AI_REVIEW_ENABLED = config.tools.codeScanning.aiReviewEnabled ? "true" : "false"
  env.SAST_AI_API_KEY = config.tools.codeScanning.aiApiKey
  env.SAST_AI_BASE_URL = config.tools.codeScanning.aiBaseUrl
  env.SAST_AI_MODEL = config.tools.codeScanning.aiModelName
  env.SAST_AI_AUTO_CLASSIFY_ON_SCAN = config.tools.codeScanning.aiAutoClassifyOnScan ? "true" : "false"
  env.SAST_AUTO_RERUN_ENABLED = config.tools.codeScanning.autoRerunEnabled ? "true" : "false"
  env.SAST_RERUN_SCHEDULE_TYPE = config.tools.codeScanning.rerunScheduleType
  env.SAST_RERUN_SCHEDULE_VALUE = config.tools.codeScanning.rerunScheduleValue
  env.SECRETS_ENABLED = config.tools.secrets.enabled ? "true" : "false"
  env.SECRET_SCANNER_CONCURRENCY = config.tools.secrets.scanConcurrency
  env.SECRETS_SCAN_CONCURRENCY = config.tools.secrets.scanConcurrency
  env.SECRET_SCANNER_IMAGE = config.tools.secrets.dockerImage
  env.SECRETS_SCAN_DEPTH = config.tools.secrets.scanDepth
  env.SECRETS_AUTO_RERUN_ENABLED = config.tools.secrets.autoRerunEnabled ? "true" : "false"
  env.SECRETS_RERUN_SCHEDULE_TYPE = config.tools.secrets.rerunScheduleType
  env.SECRETS_RERUN_SCHEDULE_VALUE = config.tools.secrets.rerunScheduleValue
  env.CONTAINER_SCANNING_ENABLED = config.tools.containerScanning.enabled ? "true" : "false"
  env.CONTAINER_SCANNING_AUTO_RERUN_ENABLED = config.tools.containerScanning.autoRerunEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_RERUN_SCHEDULE_TYPE = config.tools.containerScanning.rerunScheduleType
  env.CONTAINER_SCANNING_RERUN_SCHEDULE_VALUE = config.tools.containerScanning.rerunScheduleValue
  env.CONTAINER_SCANNING_SCAN_CONCURRENCY = config.tools.containerScanning.scanConcurrency
  env.CONTAINER_SCANNER_IMAGE = config.tools.containerScanning.dockerImage
  env.CONTAINER_SCANNING_NVD_ENABLED = config.tools.containerScanning.nvdEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_NVD_API_KEY = config.tools.containerScanning.nvdApiKey
  env.CONTAINER_SCANNING_GHSA_ENABLED = config.tools.containerScanning.ghsaEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_GHSA_API_KEY = config.tools.containerScanning.ghsaApiKey
  env.CONTAINER_SCANNING_ARGUS_ENABLED = config.tools.containerScanning.argusEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_ARGUS_API_KEY = config.tools.containerScanning.argusApiKey
  env.IAC_SECURITY_ENABLED = config.tools.iacSecurity.enabled ? "true" : "false"
  return env
}

export function getAppConfigEnvValue(key: string) {
  return configToEnv(readAppConfig())[key] ?? process.env[key] ?? ""
}
