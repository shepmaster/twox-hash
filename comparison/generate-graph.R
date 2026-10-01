#!/usr/bin/env Rscript

source("shared.R")

args = commandArgs(trailingOnly = TRUE)

output_dir = args[1]
filenames = args[2:length(args)]

data = load_benchmark_trials(filenames)

data |> group_by(algo) |> group_walk(function(data, key) {
    algo = key$algo
    message(str_glue("# {algo}"))

    min_max = data |>
        group_by(bench) |>
        summarize(
            min_time = min(time),
            max_time = max(time),
            min_throughput = min(throughput),
            max_throughput = max(throughput)
        )

    data |> group_by(arch) |> group_walk(function(data, key) {
        arch = key$arch
        message(str_glue("## {arch}"))

        data |> group_by(bench) |> group_walk(function(data, key) {
            bench = key$bench
            message(str_glue("### {bench}"))

            min_max = min_max |> filter(bench == .env$bench)
            time_y_limits = c(0, min_max |> pull(max_time))
            bytes_y_limits = c(min_max |> pull(min_throughput), min_max |> pull(max_throughput))

            if (bench == "tiny_data") {
                data |> group_by(fn_name) |> group_walk(function(data, key) {
                    fn_name = key$fn_name
                    if (!is.na(fn_name)) {
                        message(str_glue("#### {fn_name}"))
                    }

                    plot = data |> tiny_data_plot(algo = algo, arch = arch, fn_name = fn_name, y_limits = time_y_limits)

                    save_svg(plot, directory = output_dir, algo = algo, bench = bench, fn_name = fn_name, arch = arch)
                })
            } else if (bench == "oneshot") {
                plot = data |> oneshot_plot(algo = algo, arch = arch, y_limits = bytes_y_limits)
                table = data |> oneshot_table()

                save_svg(plot, directory = output_dir, algo = algo, bench = bench, arch = arch)
                print(table)
            } else if (bench == "streaming") {
                plot = data |> streaming_plot(algo = algo, arch = arch, y_limits = bytes_y_limits)

                save_svg(plot, directory = output_dir, algo = algo, bench = bench, arch = arch)
            } else {
                stop(str_glue("Unknown benchmark `{bench}`"))
            }
        })
    })
})

warnings()
