#!/usr/bin/env bash
set -eu

SCRIPT_INVOKED_AS="${0}"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

temp_dir=$(mktemp -d)

function capture() {
    subset="${1:-}"

    raw_data="${temp_dir}/raw-data.streaming-json"

    echo "Benchmarking with $(rustc --version)"

    cargo criterion -p comparison --message-format=json -- "${subset}" > "${raw_data}"

    echo "Raw benchmark data captured to ${raw_data}"
    echo "Next, run \`${SCRIPT_INVOKED_AS} analyze ${raw_data}\`"
}

function analyze() {
    cleaned_data="${temp_dir}/cleaned-data.streaming-json"

    # Capture our input to keep things consistent
    cp "${@}" "${temp_dir}"

    "${SCRIPT_DIR}/prepare-data.jq" "${@}" > "${cleaned_data}"
    "${SCRIPT_DIR}/generate-graph.R" "${cleaned_data}" "${temp_dir}"

    svgo \
        --quiet \
        --config "${SCRIPT_DIR}/svgo.config.js" \
        --multipass \
        --pretty \
        --indent 2 \
        --final-newline \
        --recursive \
        "${temp_dir}"

    echo "Graphs saved in ${temp_dir}"
}

mode="${1:-}"
case "${mode}" in
    capture)
        capture "${@:2}"
        ;;

    analyze)
        analyze "${@:2}"
        ;;

    *)
        echo "Unknown command '${mode}'" >&2
        echo "Known commands: capture, analyze" >&2
        exit 1
        ;;
esac
