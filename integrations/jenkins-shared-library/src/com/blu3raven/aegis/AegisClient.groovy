package com.blu3raven.aegis

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.net.HttpURLConnection
import java.net.URL

class AegisClient implements Serializable {
    private static final long serialVersionUID = 1L

    private static final List<Integer> BACKOFF_SECONDS = [5, 15, 45]
    private static final int MAX_TRIGGER_ATTEMPTS = 4
    private static final int POLL_INTERVAL_MS = 5_000
    private static final int CONNECT_TIMEOUT_MS = 30_000
    private static final int READ_TIMEOUT_MS = 30_000

    private final String aegisUrl
    private final String apiKey

    AegisClient(String aegisUrl, String apiKey) {
        this.aegisUrl = aegisUrl
        this.apiKey = apiKey
    }

    Map triggerScan(String sourceId, String commitSha, String branch, String prNumber, String runId) {
        Map body = [
            commit_sha: commitSha,
            branch: branch ?: null,
            pr_number: prNumber ? prNumber.toInteger() : null,
            trigger_metadata: [
                ci_provider: 'jenkins',
                run_id: runId ?: ''
            ]
        ]
        String url = "${aegisUrl}/api/v1/sources/${sourceId}/scans/trigger"
        String payload = JsonOutput.toJson(body)

        Map lastResult = [status: 0, body: '']
        for (int attempt = 0; attempt < MAX_TRIGGER_ATTEMPTS; attempt++) {
            lastResult = postJson(url, payload)
            int status = lastResult.status as int

            if (status == 202) {
                return parseJson(lastResult.body as String) as Map
            }

            if (status in [401, 403]) {
                throw new RuntimeException("Aegis trigger auth failed (${status}): ${lastResult.body}")
            }
            if (status == 404) {
                throw new RuntimeException("Aegis source not found (${status}): ${lastResult.body}")
            }
            if (status == 409) {
                throw new RuntimeException("Aegis source disabled (${status}): ${lastResult.body}")
            }

            boolean retriable = status == 0 || status == 429 || (status >= 500 && status < 600)
            if (!retriable) {
                throw new RuntimeException("Aegis trigger failed (${status}): ${lastResult.body}")
            }

            if (attempt < MAX_TRIGGER_ATTEMPTS - 1) {
                int delay = BACKOFF_SECONDS[attempt]
                println "WARN: Aegis trigger attempt ${attempt + 1} failed (status=${status}); retrying in ${delay}s"
                Thread.sleep(delay * 1000L)
            }
        }

        int finalStatus = lastResult.status as int
        if (finalStatus == 429) {
            throw new RuntimeException('Aegis trigger rate limited; reduce CI scan frequency')
        }
        throw new RuntimeException("Aegis trigger failed after retries (${finalStatus}): ${lastResult.body}")
    }

    Map pollScan(String scanId, int timeoutSeconds) {
        long deadline = System.currentTimeMillis() + (timeoutSeconds * 1000L)
        String url = "${aegisUrl}/api/v1/scans/${scanId}"

        while (System.currentTimeMillis() < deadline) {
            Map result = getJson(url)
            if ((result.status as int) == 200) {
                Map parsed = parseJson(result.body as String) as Map
                String status = parsed.status
                if (status in ['completed', 'completed_with_merge_error', 'failed', 'cancelled']) {
                    return parsed
                }
            }
            Thread.sleep(POLL_INTERVAL_MS)
        }
        return null
    }

    @NonCPS
    private Map postJson(String urlStr, String payload) {
        HttpURLConnection conn = null
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection()
            conn.setRequestMethod('POST')
            conn.setDoOutput(true)
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS)
            conn.setReadTimeout(READ_TIMEOUT_MS)
            conn.setRequestProperty('Authorization', "Bearer ${apiKey}")
            conn.setRequestProperty('Content-Type', 'application/json')
            conn.outputStream.withWriter('UTF-8') { it.write(payload) }
            int status = conn.responseCode
            String body = readBody(conn, status)
            return [status: status, body: body]
        } catch (Exception e) {
            return [status: 0, body: e.message ?: 'network error']
        } finally {
            if (conn != null) {
                conn.disconnect()
            }
        }
    }

    @NonCPS
    private Map getJson(String urlStr) {
        HttpURLConnection conn = null
        try {
            conn = (HttpURLConnection) new URL(urlStr).openConnection()
            conn.setRequestMethod('GET')
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS)
            conn.setReadTimeout(READ_TIMEOUT_MS)
            conn.setRequestProperty('Authorization', "Bearer ${apiKey}")
            int status = conn.responseCode
            String body = readBody(conn, status)
            return [status: status, body: body]
        } catch (Exception e) {
            return [status: 0, body: e.message ?: 'network error']
        } finally {
            if (conn != null) {
                conn.disconnect()
            }
        }
    }

    @NonCPS
    private static String readBody(HttpURLConnection conn, int status) {
        try {
            def stream = (status >= 200 && status < 400) ? conn.inputStream : conn.errorStream
            return stream ? stream.getText('UTF-8') : ''
        } catch (Exception e) {
            return ''
        }
    }

    @NonCPS
    private static Object parseJson(String raw) {
        if (!raw) {
            return [:]
        }
        return new JsonSlurper().parseText(raw)
    }
}
