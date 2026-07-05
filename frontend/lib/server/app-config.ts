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
    dependencies_scanning: {
      enabled: boolean
      scanConcurrency: string
      nvdEnabled: boolean
      nvdApiKey: string
      nvdApiKeyHint: string
      ghsaEnabled: boolean
      ghsaApiKey: string
      ghsaApiKeyHint: string
      releaseAgeEnabled: boolean
      releaseAgeThresholdDays: string
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
    }
    code_scanning: {
      enabled: boolean
      scanConcurrency: string
      rulesets: string
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
    }
    secret_scanning: {
      enabled: boolean
      scanConcurrency: string
      scanDepth: string
      scanHistoryWindow: string
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
    }
    container_scanning: {
      enabled: boolean
      scanConcurrency: string
      nvdEnabled: boolean
      nvdApiKey: string
      nvdApiKeyHint: string
      ghsaEnabled: boolean
      ghsaApiKey: string
      ghsaApiKeyHint: string
      argusEnabled: boolean
      argusApiKey: string
      argusApiKeyHint: string
      releaseAgeEnabled: boolean
      releaseAgeThresholdDays: string
      baseImageTagsEnabled: boolean
      baseImageRecommendEnabled: boolean
      autoRerunEnabled: boolean
      rerunScheduleType: "simple" | "cron"
      rerunScheduleValue: string
    }
    iac_scanning: {
      enabled: boolean
    }
  }
}

export type EnvMap = Record<string, string>


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
      dependencies_scanning: {
        enabled: toBoolean(env.SCA_ENABLED, false),
        scanConcurrency: env.SCA_SCAN_CONCURRENCY ?? "4",
        nvdEnabled: env.SCA_NVD_ENABLED !== "false",
        nvdApiKey: env.SCA_NVD_API_KEY ?? "",
        nvdApiKeyHint: "",
        ghsaEnabled: env.SCA_GHSA_ENABLED === "true",
        ghsaApiKey: env.SCA_GHSA_API_KEY ?? "",
        ghsaApiKeyHint: "",
        releaseAgeEnabled: env.SCA_RELEASE_AGE_ENABLED === "true",
        releaseAgeThresholdDays: env.SCA_RELEASE_AGE_THRESHOLD_DAYS ?? "90",
        autoRerunEnabled: toBoolean(env.SCA_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: (env.SCA_RERUN_SCHEDULE_TYPE as "simple" | "cron") ?? "simple",
        rerunScheduleValue: env.SCA_RERUN_SCHEDULE_VALUE ?? "02:00",
      },
      code_scanning: {
        enabled: toBoolean(env.SAST_ENABLED, false),
        scanConcurrency: env.SAST_SCAN_CONCURRENCY ?? "2",
        rulesets: env.SAST_RULESETS ?? "",
        autoRerunEnabled: toBoolean(env.SAST_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: (env.SAST_RERUN_SCHEDULE_TYPE as "simple" | "cron") ?? "simple",
        rerunScheduleValue: env.SAST_RERUN_SCHEDULE_VALUE ?? "02:00",
      },
      secret_scanning: {
        enabled: toBoolean(env.SECRETS_ENABLED, false),
        scanConcurrency: env.SECRET_SCANNER_CONCURRENCY ?? env.SECRETS_SCAN_CONCURRENCY ?? "4",
        scanDepth: env.SECRETS_SCAN_DEPTH ?? "full",
        scanHistoryWindow: env.SECRETS_SCAN_HISTORY_WINDOW ?? "90",
        autoRerunEnabled: toBoolean(env.SECRETS_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: (env.SECRETS_RERUN_SCHEDULE_TYPE as "simple" | "cron") ?? "simple",
        rerunScheduleValue: env.SECRETS_RERUN_SCHEDULE_VALUE ?? "02:00",
      },
      container_scanning: {
        enabled: toBoolean(env.CONTAINER_SCANNING_ENABLED, false),
        scanConcurrency: env.CONTAINER_SCANNING_SCAN_CONCURRENCY ?? "4",
        nvdEnabled: toBoolean(env.CONTAINER_SCANNING_NVD_ENABLED, false),
        nvdApiKey: env.CONTAINER_SCANNING_NVD_API_KEY ?? "",
        nvdApiKeyHint: "",
        ghsaEnabled: toBoolean(env.CONTAINER_SCANNING_GHSA_ENABLED, false),
        ghsaApiKey: env.CONTAINER_SCANNING_GHSA_API_KEY ?? "",
        ghsaApiKeyHint: "",
        argusEnabled: toBoolean(env.CONTAINER_SCANNING_ARGUS_ENABLED, false),
        argusApiKey: env.CONTAINER_SCANNING_ARGUS_API_KEY ?? "",
        argusApiKeyHint: "",
        releaseAgeEnabled: toBoolean(env.CONTAINER_SCANNING_RELEASE_AGE_ENABLED, false),
        releaseAgeThresholdDays: env.CONTAINER_SCANNING_RELEASE_AGE_THRESHOLD_DAYS ?? "90",
        baseImageTagsEnabled: toBoolean(env.CONTAINER_SCANNING_BASE_IMAGE_TAGS_ENABLED, false),
        baseImageRecommendEnabled: toBoolean(env.CONTAINER_SCANNING_BASE_IMAGE_RECOMMEND_ENABLED, false),
        autoRerunEnabled: toBoolean(env.CONTAINER_SCANNING_AUTO_RERUN_ENABLED, false),
        rerunScheduleType: (env.CONTAINER_SCANNING_RERUN_SCHEDULE_TYPE as "simple" | "cron") ?? "simple",
        rerunScheduleValue: env.CONTAINER_SCANNING_RERUN_SCHEDULE_VALUE ?? "02:00",
      },
      iac_scanning: {
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
      dependencies_scanning: {
        enabled: value?.tools?.dependencies_scanning?.enabled ?? fallback.tools.dependencies_scanning.enabled,
        scanConcurrency: value?.tools?.dependencies_scanning?.scanConcurrency ?? fallback.tools.dependencies_scanning.scanConcurrency,
        nvdEnabled: value?.tools?.dependencies_scanning?.nvdEnabled ?? fallback.tools.dependencies_scanning.nvdEnabled,
        nvdApiKey: value?.tools?.dependencies_scanning?.nvdApiKey ?? fallback.tools.dependencies_scanning.nvdApiKey,
        nvdApiKeyHint: value?.tools?.dependencies_scanning?.nvdApiKeyHint ?? fallback.tools.dependencies_scanning.nvdApiKeyHint,
        ghsaEnabled: value?.tools?.dependencies_scanning?.ghsaEnabled ?? fallback.tools.dependencies_scanning.ghsaEnabled,
        ghsaApiKey: value?.tools?.dependencies_scanning?.ghsaApiKey ?? fallback.tools.dependencies_scanning.ghsaApiKey,
        ghsaApiKeyHint: value?.tools?.dependencies_scanning?.ghsaApiKeyHint ?? fallback.tools.dependencies_scanning.ghsaApiKeyHint,
        releaseAgeEnabled: value?.tools?.dependencies_scanning?.releaseAgeEnabled ?? fallback.tools.dependencies_scanning.releaseAgeEnabled,
        releaseAgeThresholdDays: value?.tools?.dependencies_scanning?.releaseAgeThresholdDays ?? fallback.tools.dependencies_scanning.releaseAgeThresholdDays,
        autoRerunEnabled: value?.tools?.dependencies_scanning?.autoRerunEnabled ?? fallback.tools.dependencies_scanning.autoRerunEnabled,
        rerunScheduleType: value?.tools?.dependencies_scanning?.rerunScheduleType ?? fallback.tools.dependencies_scanning.rerunScheduleType,
        rerunScheduleValue: value?.tools?.dependencies_scanning?.rerunScheduleValue ?? fallback.tools.dependencies_scanning.rerunScheduleValue,
      },
      code_scanning: {
        enabled: value?.tools?.code_scanning?.enabled ?? fallback.tools.code_scanning.enabled,
        scanConcurrency: value?.tools?.code_scanning?.scanConcurrency ?? fallback.tools.code_scanning.scanConcurrency,
        rulesets: value?.tools?.code_scanning?.rulesets ?? fallback.tools.code_scanning.rulesets,
        autoRerunEnabled: value?.tools?.code_scanning?.autoRerunEnabled ?? fallback.tools.code_scanning.autoRerunEnabled,
        rerunScheduleType: value?.tools?.code_scanning?.rerunScheduleType ?? fallback.tools.code_scanning.rerunScheduleType,
        rerunScheduleValue: value?.tools?.code_scanning?.rerunScheduleValue ?? fallback.tools.code_scanning.rerunScheduleValue,
      },
      secret_scanning: {
        enabled: value?.tools?.secret_scanning?.enabled ?? fallback.tools.secret_scanning.enabled,
        scanConcurrency: value?.tools?.secret_scanning?.scanConcurrency ?? fallback.tools.secret_scanning.scanConcurrency,
        scanDepth: value?.tools?.secret_scanning?.scanDepth ?? fallback.tools.secret_scanning.scanDepth,
        scanHistoryWindow: value?.tools?.secret_scanning?.scanHistoryWindow ?? fallback.tools.secret_scanning.scanHistoryWindow,
        autoRerunEnabled: value?.tools?.secret_scanning?.autoRerunEnabled ?? fallback.tools.secret_scanning.autoRerunEnabled,
        rerunScheduleType: value?.tools?.secret_scanning?.rerunScheduleType ?? fallback.tools.secret_scanning.rerunScheduleType,
        rerunScheduleValue: value?.tools?.secret_scanning?.rerunScheduleValue ?? fallback.tools.secret_scanning.rerunScheduleValue,
      },
      container_scanning: {
        enabled: value?.tools?.container_scanning?.enabled ?? fallback.tools.container_scanning.enabled,
        scanConcurrency: value?.tools?.container_scanning?.scanConcurrency ?? fallback.tools.container_scanning.scanConcurrency,
        nvdEnabled: value?.tools?.container_scanning?.nvdEnabled ?? fallback.tools.container_scanning.nvdEnabled,
        nvdApiKey: value?.tools?.container_scanning?.nvdApiKey ?? fallback.tools.container_scanning.nvdApiKey,
        nvdApiKeyHint: value?.tools?.container_scanning?.nvdApiKeyHint ?? fallback.tools.container_scanning.nvdApiKeyHint,
        ghsaEnabled: value?.tools?.container_scanning?.ghsaEnabled ?? fallback.tools.container_scanning.ghsaEnabled,
        ghsaApiKey: value?.tools?.container_scanning?.ghsaApiKey ?? fallback.tools.container_scanning.ghsaApiKey,
        ghsaApiKeyHint: value?.tools?.container_scanning?.ghsaApiKeyHint ?? fallback.tools.container_scanning.ghsaApiKeyHint,
        argusEnabled: value?.tools?.container_scanning?.argusEnabled ?? fallback.tools.container_scanning.argusEnabled,
        argusApiKey: value?.tools?.container_scanning?.argusApiKey ?? fallback.tools.container_scanning.argusApiKey,
        argusApiKeyHint: value?.tools?.container_scanning?.argusApiKeyHint ?? fallback.tools.container_scanning.argusApiKeyHint,
        releaseAgeEnabled: value?.tools?.container_scanning?.releaseAgeEnabled ?? fallback.tools.container_scanning.releaseAgeEnabled,
        releaseAgeThresholdDays: value?.tools?.container_scanning?.releaseAgeThresholdDays ?? fallback.tools.container_scanning.releaseAgeThresholdDays,
        baseImageTagsEnabled: value?.tools?.container_scanning?.baseImageTagsEnabled ?? fallback.tools.container_scanning.baseImageTagsEnabled,
        baseImageRecommendEnabled: value?.tools?.container_scanning?.baseImageRecommendEnabled ?? fallback.tools.container_scanning.baseImageRecommendEnabled,
        autoRerunEnabled: value?.tools?.container_scanning?.autoRerunEnabled ?? fallback.tools.container_scanning.autoRerunEnabled,
        rerunScheduleType: value?.tools?.container_scanning?.rerunScheduleType ?? fallback.tools.container_scanning.rerunScheduleType,
        rerunScheduleValue: value?.tools?.container_scanning?.rerunScheduleValue ?? fallback.tools.container_scanning.rerunScheduleValue,
      },
      iac_scanning: {
        enabled: value?.tools?.iac_scanning?.enabled ?? fallback.tools.iac_scanning.enabled,
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
  // Config is now sourced exclusively from environment variables.
  // The backend /api/v1/settings endpoint requires auth context not available here.
  if (!_cachedConfig) {
    _cachedConfig = fallback
    _cacheTime = Date.now()
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

  env.SCA_ENABLED = config.tools.dependencies_scanning.enabled ? "true" : "false"
  env.SCA_SCAN_CONCURRENCY = config.tools.dependencies_scanning.scanConcurrency
  env.SAST_ENABLED = config.tools.code_scanning.enabled ? "true" : "false"
  env.SAST_SCAN_CONCURRENCY = config.tools.code_scanning.scanConcurrency
  env.SECRETS_ENABLED = config.tools.secret_scanning.enabled ? "true" : "false"
  env.SECRET_SCANNER_CONCURRENCY = config.tools.secret_scanning.scanConcurrency
  env.SECRETS_SCAN_CONCURRENCY = config.tools.secret_scanning.scanConcurrency
  env.CONTAINER_SCANNING_ENABLED = config.tools.container_scanning.enabled ? "true" : "false"
  env.CONTAINER_SCANNING_SCAN_CONCURRENCY = config.tools.container_scanning.scanConcurrency
  env.CONTAINER_SCANNING_NVD_ENABLED = config.tools.container_scanning.nvdEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_NVD_API_KEY = config.tools.container_scanning.nvdApiKey
  env.CONTAINER_SCANNING_GHSA_ENABLED = config.tools.container_scanning.ghsaEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_GHSA_API_KEY = config.tools.container_scanning.ghsaApiKey
  env.CONTAINER_SCANNING_ARGUS_ENABLED = config.tools.container_scanning.argusEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_ARGUS_API_KEY = config.tools.container_scanning.argusApiKey
  env.CONTAINER_SCANNING_RELEASE_AGE_ENABLED = config.tools.container_scanning.releaseAgeEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_RELEASE_AGE_THRESHOLD_DAYS = config.tools.container_scanning.releaseAgeThresholdDays
  env.CONTAINER_SCANNING_BASE_IMAGE_TAGS_ENABLED = config.tools.container_scanning.baseImageTagsEnabled ? "true" : "false"
  env.CONTAINER_SCANNING_BASE_IMAGE_RECOMMEND_ENABLED = config.tools.container_scanning.baseImageRecommendEnabled ? "true" : "false"
  env.SCA_RELEASE_AGE_ENABLED = config.tools.dependencies_scanning.releaseAgeEnabled ? "true" : "false"
  env.SCA_RELEASE_AGE_THRESHOLD_DAYS = config.tools.dependencies_scanning.releaseAgeThresholdDays
  env.IAC_SECURITY_ENABLED = config.tools.iac_scanning.enabled ? "true" : "false"
  return env
}

export function getAppConfigEnvValue(key: string) {
  return configToEnv(readAppConfig())[key] ?? process.env[key] ?? ""
}
