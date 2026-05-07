#!/bin/bash
set -euo pipefail

ORG="$1"
TARGET_DIR="$2"
RUN_ID="$3"

RAW_DIR="$TARGET_DIR"
FINDINGS_FILE="$TARGET_DIR/findings.jsonl"
> "$FINDINGS_FILE"

find "$RAW_DIR" -name opengrep.json 2>/dev/null | while read -r file; do
    repo_dir=$(dirname "$file")

    repo_full_name="${repo_dir#"$RAW_DIR"/}"
    commit="HEAD"
    if [[ -f "$repo_dir/head-sha.txt" ]]; then
        commit=$(cat "$repo_dir/head-sha.txt" | tr -d '[:space:]')
    fi

    # Ensure files exist so --slurpfile never fails
    context_file="$repo_dir/context.json"
    [[ ! -f "$context_file" ]] && echo '{}' > "$context_file"

    reach_file="$repo_dir/reachability.json"
    [[ ! -f "$reach_file" ]] && echo '{}' > "$reach_file"

    jq -c \
        --arg org "$ORG" \
        --arg repo_full_name "$repo_full_name" \
        --arg commit "$commit" \
        --slurpfile ctx "$context_file" \
        --slurpfile reach "$reach_file" \
        '
        .runs[]? |
        . as $run |

        (($run.tool.driver.rules // []) | map({key: .id, value: .}) | from_entries) as $rules |

        $run.results[]? |
        . as $result |

        ($rules[$result.ruleId] // {}) as $rule |

        ($rule.defaultConfiguration.level // $result.level // "warning") as $level |
        ($rule.properties.precision // "medium") as $precision |
        (if $precision == "very-high" or $precision == "high" then "high" else $precision end) as $confidence |
        (
          if $level == "error" then
            if $confidence == "high" then "critical" else "high" end
          elif $level == "warning" then
            if $confidence == "high" then "high"
            elif $confidence == "low" then "low"
            else "medium"
            end
          else "low"
          end
        ) as $severity |

        ($result.locations // [] | .[0]? // {}) as $loc |
        ($loc.physicalLocation // {}) as $phys |
        ($phys.artifactLocation // {}) as $artifact |
        ($phys.region // {}) as $region |

        [($rule.properties.tags // []) | .[]? | select(type == "string") | select(startswith("CWE-"))] as $cwe |

        ($ctx[0] // {}) as $context |
        (($artifact.uri // "") + ":" + (($region.startLine // 0) | tostring)) as $ctx_key |
        ($context[$ctx_key] // {}) as $ctx_entry |
        ($ctx_entry.file_class // "source") as $file_class |

        ($reach[0] // {}) as $reach_data |
        ($reach_data[$ctx_key] // null) as $reach_entry |

        # Drop vendor/generated files and secret-detection rules (handled by secrets scanner)
        select($file_class != "vendor" and $file_class != "generated") |
        select($result.ruleId | test("\\.secrets\\."; "i") | not) |

        [($result.codeFlows[0]?.threadFlows[0]?.locations[]? | {
          file: .location.physicalLocation.artifactLocation.uri,
          line: (.location.physicalLocation.region.startLine // 0),
          snippet: (.location.physicalLocation.region.snippet.text // "")
        })] as $code_flows |

        {
          repo_full_name: $repo_full_name,
          file_path:      ($artifact.uri // ""),
          start_line:     ($region.startLine // 0),
          end_line:       ($region.endLine // $region.startLine // 0),
          rule_id:        ($result.ruleId // ""),
          rule_name:      ($rule.shortDescription.text // $rule.name // $result.ruleId // ""),
          severity:       $severity,
          confidence:     $confidence,
          category:       ($rule.properties.category // "security"),
          cwe:            $cwe,
          message:        ($result.message.text // ""),
          snippet:        ($region.snippet.text // ""),
          fix_suggestion: ($result.fixes[0].description.text // null),
          commit_sha:     $commit,
          stateCandidate: "open",
          code_flows:     (if ($code_flows | length) > 0 then $code_flows else null end),
          code_window:    ($ctx_entry.code_window // null),
          imports:        ($ctx_entry.imports // null),
          file_class:     $file_class,
          reachability:   $reach_entry
        }
        ' "$file" >> "$FINDINGS_FILE" 2>/dev/null || true
done

# Active rule IDs let the backend distinguish "rule removed" from "code fixed"
ACTIVE_RULES_FILE="$TARGET_DIR/active_rules.json"
# Process one at a time to avoid OOM on large SARIF files
find "$RAW_DIR" -name opengrep.json 2>/dev/null \
    | while read -r f; do jq -r '[.runs[]?.tool.driver.rules[]?.id // empty] | .[]' "$f" 2>/dev/null; done \
    | sort -u | jq -R -s 'split("\n") | map(select(. != ""))' \
    > "$ACTIVE_RULES_FILE" 2>/dev/null || echo '[]' > "$ACTIVE_RULES_FILE"

finding_count=$(wc -l < "$FINDINGS_FILE" | tr -d ' ')
echo "[✓] Normalized $finding_count code scanning findings → $FINDINGS_FILE"
