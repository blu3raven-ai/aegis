import com.blu3raven.aegis.AegisClient

def call(Map config = [:]) {
    String aegisUrl = (config.aegisUrl ?: '').toString().replaceAll('/+$', '')
    String apiKey = (config.apiKey ?: '').toString()
    String sourceId = (config.sourceId ?: '').toString()
    boolean wait = config.containsKey('wait') ? (config.wait as boolean) : true
    String failOn = (config.failOn ?: 'none').toString().toLowerCase()
    int pollTimeoutSeconds = (config.pollTimeoutSeconds ?: 1800) as int

    if (!aegisUrl || !apiKey || !sourceId) {
        error 'aegisScan: aegisUrl, apiKey, and sourceId are required'
    }
    if (!(failOn in ['none', 'low', 'medium', 'high'])) {
        echo "WARN: aegisScan: unknown failOn=${failOn} (treated as none)"
        failOn = 'none'
    }

    String commitSha = env.GIT_COMMIT
    if (!commitSha) {
        error 'aegisScan: env.GIT_COMMIT is empty; ensure the SCM checkout step ran before this stage'
    }

    String branch = (env.GIT_BRANCH ?: '').replaceFirst(/^origin\//, '')
    String prNumber = env.CHANGE_ID ?: ''
    String runId = env.BUILD_NUMBER ?: ''

    def client = new AegisClient(aegisUrl, apiKey)

    echo "Aegis: triggering scan for ${commitSha.take(8)} on ${branch ?: 'unknown branch'}"

    def trigger = client.triggerScan(sourceId, commitSha, branch, prNumber, runId)

    String scanId = trigger.scan_id
    boolean deduplicated = (trigger.deduplicated ?: false) as boolean
    echo "Aegis scan_id=${scanId} deduplicated=${deduplicated}"

    if (!wait) {
        return
    }

    def summary = client.pollScan(scanId, pollTimeoutSeconds)
    if (summary == null) {
        echo "WARN: Aegis scan still running after ${pollTimeoutSeconds}s; check ${aegisUrl}/api/v1/scans/${scanId}"
        return
    }

    String status = summary.status
    Map counts = (summary.finding_counts ?: [:]) as Map
    int high = (counts.high ?: 0) as int
    int medium = (counts.medium ?: 0) as int
    int low = (counts.low ?: 0) as int

    echo ''
    echo '======== Aegis Security Scan ========'
    echo "Status: ${status}"
    echo "View in Aegis: ${aegisUrl}/api/v1/scans/${scanId}"
    echo "Findings: high=${high} medium=${medium} low=${low}"
    echo '====================================='

    if (status == 'failed') {
        error "Aegis scan failed: ${summary.error ?: 'unknown'}"
    }
    if (status == 'cancelled') {
        echo 'WARN: Aegis scan was cancelled (superseded by newer commit)'
        return
    }

    switch (failOn) {
        case 'high':
            if (high > 0) {
                error "Aegis: found ${high} high-severity finding(s); failing per failOn=high"
            }
            break
        case 'medium':
            if (high > 0 || medium > 0) {
                error 'Aegis: found findings >= medium severity; failing per failOn=medium'
            }
            break
        case 'low':
            if (high > 0 || medium > 0 || low > 0) {
                error 'Aegis: found findings; failing per failOn=low'
            }
            break
        case 'none':
        default:
            break
    }
}
