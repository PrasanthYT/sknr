#!/usr/bin/env sh
set -eu

args="scan ${INPUT_PATH:-.} --format ${INPUT_FORMAT:-sarif}"

if [ -n "${INPUT_FAIL_ON:-}" ]; then
  args="$args --fail-on ${INPUT_FAIL_ON}"
fi

if [ "${INPUT_AI_PRIORITIZE:-false}" = "true" ]; then
  args="$args --ai-prioritize"
fi

if [ -n "${INPUT_OPENAI_MODEL:-}" ]; then
  args="$args --openai-model ${INPUT_OPENAI_MODEL}"
fi

exec sknr $args
