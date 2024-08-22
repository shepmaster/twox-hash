#!/usr/bin/env jq --from-file --compact-output

select(.reason == "benchmark-complete") |
  # Split the ID string into separate fields
  (
    .id
    | split("/")
    | map(split("-") | { key: .[0], value: .[1:] | join("-")})
    | from_entries
    # Clean up the separate fields
    | .size |= tonumber
    | if .chunk_size then .chunk_size |= tonumber end
  )

  +

  # Add the benchmark numbers
  {
    throughput: .throughput[0].per_iteration,
    mean_estimate: .mean.estimate,
  }
