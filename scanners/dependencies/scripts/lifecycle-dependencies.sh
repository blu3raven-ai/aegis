#!/bin/bash
set -euo pipefail

INPUT_FILE="$1"
OUTPUT_FILE="$2"

jq -s '
  sort_by(.repository, .packageName, .advisoryId, .commitSha) |
  reduce .[] as $item (
    {};
    .[
      ($item.repository + "::" + ($item.manifestPath // "") + "::" + $item.packageName + "::" + $item.ecosystem + "::" + $item.advisoryId)
    ] += [$item]
  ) |
  to_entries |
  map(
    .value as $items |
    if ($items | length) == 0 then empty else
      ($items[-1] + {
        identityKey: (.key),
        firstSeenCommit: $items[0].commitSha,
        lastSeenCommit: $items[-1].commitSha,
        stateCandidate: "open"
      })
    end
  )[]' "$INPUT_FILE" > "$OUTPUT_FILE"
