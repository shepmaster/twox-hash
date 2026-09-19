#!/usr/bin/env Rscript

source("shared.R")

args = commandArgs(trailingOnly = TRUE)

output_dir = args[1]
before_filename = args[2]
after_filename = args[3]

load_rust_benchmark_data = function(filename) {
    load_benchmark_data(filename) |>
        filter(impl == "rust") |>
        select(-impl)
}

before = load_rust_benchmark_data(before_filename)
after = load_rust_benchmark_data(after_filename)

deltas =
    inner_join(
        before,
        after,
        by = join_by(algo, arch, bench, fn_name, size)
    ) |>
    rename(before = mean_estimate.x, after = mean_estimate.y) |>
    mutate(factor = after / before)

deltas |> group_by(algo) |> group_walk(function(data, key) {
    algo = key$algo
    message(str_glue("# {algo}"))

    data |> group_by(arch) |> group_walk(function(data, key) {
        arch = key$arch
        message(str_glue("## {arch}"))

        data |> group_by(bench) |> group_walk(function(data, key) {
            bench = key$bench
            message(str_glue("### {bench}"))

            data |> group_by(fn_name) |> group_walk(function(data, key) {
                fn_name = key$fn_name
                if (!is.na(fn_name)) {
                    message(str_glue("#### {fn_name}"))
                }

                plot = tiny_data_delta_plot(data, algo = algo, fn_name = fn_name, arch = arch)
                table = tiny_data_delta_table(data)

                save_svg(plot, directory = output_dir, prefix = "delta", algo = algo, bench = bench, fn_name = fn_name, arch = arch)
                print(table)
            })
        })
    })
})

warnings()
