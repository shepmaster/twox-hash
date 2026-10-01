#!/usr/bin/env Rscript

source("shared.R")

args = commandArgs(trailingOnly = TRUE)

output_dir = args[1]
before_arg_idx = which(args == "--before")
after_arg_idx = which(args == "--after")

before_filenames = args[(before_arg_idx + 1) : (after_arg_idx - 1)]
after_filenames = args[(after_arg_idx + 1) : length(args)]

deltas = load_delta_benchmark_data(before_filenames, after_filenames)

deltas |> group_by(algo) |> group_walk(function(data, key) {
    algo = key$algo
    message(str_glue("# {algo}"))

    data |> group_by(arch) |> group_walk(function(data, key) {
        arch = key$arch
        message(str_glue("## {arch}"))

        data |> group_by(bench) |> group_walk(function(data, key) {
            bench = key$bench
            message(str_glue("### {bench}"))

            if (bench == "tiny_data") {
                data |> group_by(fn_name) |> group_walk(function(data, key) {
                    fn_name = key$fn_name
                    if (!is.na(fn_name)) {
                        message(str_glue("#### {fn_name}"))
                    }

                    data = data |> rename(factor = factor.time)

                    plot = data |> tiny_data_delta_plot(algo = algo, fn_name = fn_name, arch = arch)
                    table = tiny_data_delta_table(data)

                    save_svg(plot, directory = output_dir, prefix = "delta", algo = algo, bench = bench, fn_name = fn_name, arch = arch)
                    print(table)
                })
            } else if (bench == "oneshot") {
                data = data |> rename(factor = factor.throughput)

                plot = data |> oneshot_delta_plot(algo = algo, arch = arch)

                save_svg(plot, directory = output_dir, prefix = "delta", algo = algo, bench = bench, arch = arch)
            } else if (bench == "streaming") {
                data = data |> rename(factor = factor.throughput)

                plot = data |> streaming_delta_plot(algo = algo, arch = arch)

                save_svg(plot, directory = output_dir, prefix = "delta", algo = algo, bench = bench, arch = arch)
            } else {
                stop(str_glue("Unknown benchmark `{bench}`"))
            }
        })
    })
})

warnings()
