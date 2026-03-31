#!/bin/sh
set -e

ARGS="scan $INPUT_PATH --format $INPUT_FORMAT --severity $INPUT_SEVERITY"

if [ -n "$INPUT_CONFIG" ]; then
  ARGS="$ARGS --config $INPUT_CONFIG"
fi

if [ "$INPUT_GITHUB_COMMENT" = "true" ]; then
  ARGS="$ARGS --github-comment"
fi

exec bf $ARGS
