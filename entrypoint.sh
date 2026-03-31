#!/bin/sh
set -e

# Build argument list using positional parameters (safe word splitting).
set -- scan "${INPUT_PATH:-.}" --format "${INPUT_FORMAT:-table}" --severity "${INPUT_SEVERITY:-info}"

if [ -n "$INPUT_CONFIG" ]; then
  set -- "$@" --config "$INPUT_CONFIG"
fi

if [ "$INPUT_GITHUB_COMMENT" = "true" ]; then
  set -- "$@" --github-comment
fi

exec bf "$@"
