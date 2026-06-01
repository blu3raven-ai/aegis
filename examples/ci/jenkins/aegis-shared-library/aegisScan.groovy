// Jenkins Shared Library step — aegisScan
//
// Usage in a Jenkinsfile (after loading the shared library):
//
//   @Library('your-shared-library') _
//   aegisScan scannerType: 'dependencies', blockOn: 'critical'
//
// Parameters:
//   scannerType  (String)  — scanner to run, default: 'dependencies'
//   blockOn      (String)  — minimum severity that blocks the build, default: 'critical'
//   warnOn       (String)  — minimum severity that emits a warning, default: 'high'
//   postComment  (Boolean) — post a report comment to the PR (requires gh/glab CLI), default: false

def call(Map config = [:]) {
  String scannerType = config.get('scannerType', 'dependencies')
  String blockOn     = config.get('blockOn',     'critical')
  String warnOn      = config.get('warnOn',      'high')
  boolean postComment = config.get('postComment', false)

  withCredentials([
    string(credentialsId: 'aegis-api-token', variable: 'AEGIS_API_TOKEN'),
    string(credentialsId: 'aegis-base-url',  variable: 'AEGIS_BASE_URL'),
  ]) {
    sh "pip install --quiet aegis-cli"
    sh "aegis --version"
    sh "aegis scan --scanner ${scannerType} --wait --json > aegis-findings.json"
    archiveArtifacts artifacts: 'aegis-findings.json', allowEmptyArchive: false

    sh "aegis decide --block-on ${blockOn} --warn-on ${warnOn} --exit-code"

    if (postComment && env.CHANGE_ID) {
      sh "aegis report --format markdown > aegis-report.md"
      // Use the gh CLI if available; adjust for glab or other tools as needed.
      sh "gh pr comment ${env.CHANGE_ID} --body-file aegis-report.md || true"
    }
  }
}
