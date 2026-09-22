## install.packages("tidyverse")
## install.packages("knitr")

library(tidyverse)
library(knitr)
library(scales)

impl_names = c(
    "rust" = "Rust",
    "c" = "C",
    "c-scalar" = "C (scalar)",
    "c-neon" = "C (NEON)",
    "c-sse2" = "C (SSE2)",
    "c-avx2" = "C (AVX2)"
)
impl_name = \(x) impl_names[x]

cpus = c(
    aarch64 = "Apple M1 Max",
    x86_64 = "AMD Ryzen 9 3950X"
)

pretty_arch = function(arch) {
    str_glue("{arch} ({cpus[arch]})")
}

MiB = 2^20
GiB = 2^30
TiB = 2^40
powers_of_two = 2^(0:40)

byte_labels_raw = label_bytes(units = "auto_binary")
byte_labels = function(x) {
    l = byte_labels_raw(x)
    l = gsub(" iB", " B", l) # Why would you call them "iB"
    gsub(" kiB", " KiB", l) # That K should be capitalized
}
bytes_per_second_labels = function(x) {
    paste0(byte_labels(x), "/sec")
}

load_benchmark_data = function(filename) {
    filename |>
        file() |>
        jsonlite::stream_in(verbose = FALSE) |>
        tibble() |>
        rename(fn_name = `function`) |>
        mutate(
            arch = as_factor(arch),
            algo = as_factor(algo),
            bench = as_factor(bench),
            impl = factor(impl, levels = names(impl_names)),
            fn_name = as_factor(fn_name),
            throughput = size / (mean_estimate / 1e9),
            mean_estimate = lubridate::dnanoseconds(mean_estimate)
        )
}

scale_x_continuous_log2 = scale_x_continuous(
    transform = transform_log2(),
    labels = byte_labels,
    breaks = powers_of_two,
    minor_breaks = NULL
)

## Round down / up to the nearest power of 2
log2_limits = function(limits) {
    if (is.null(limits)) {
        NULL
    } else {
        c(
            2^floor(log2(limits[1])),
            2^ceiling(log2(limits[2]))
        )
    }
}

scale_y_continuous_log2_bytes_per_second = scale_y_continuous(
    transform = transform_log2(),
    labels = bytes_per_second_labels,
    breaks = powers_of_two,
    minor_breaks = NULL,
    limits = log2_limits
)

common_theme = theme(
    legend.position = "inside",
    legend.position.inside = c(0.8, 0.2),
    plot.margin = unit(c(0.1, 1, 0.1, 0.1), 'cm')
)

save_svg = function(plot, directory, prefix = NA, algo, bench, fn_name = NA, arch) {
    base =
        list(prefix, algo, bench, fn_name, arch) |>
        lapply(as.character) |>
        str_flatten(collapse = "-", na.rm = TRUE)
    filename = str_glue("{base}.svg")

    ggsave(
        filename = filename,
        path = directory,
        plot = plot,
        width = 3000,
        height = 2000,
        units = "px",
        scale = 1.5
    )
}

## ====================
## Rust vs C specific code

point_and_line = function() {
    list(
        geom_point(alpha = 0.7),
        geom_line(alpha = 0.3)
    )
}

colour_by_impl = function(labels = impl_name) {
    list(
        aes(colour = impl),
        scale_colour_brewer(labels = labels, palette = "Set1"),
        labs(colour = "Implementation")
    )
}

tiny_data_plot = function(data, algo, arch, fn_name, y_limits = NULL) {
    using = if (is.na(fn_name)) "" else str_glue(" using `{fn_name}`")

    data |>
        ggplot(aes(x = size, y = mean_estimate)) +
        point_and_line() +
        colour_by_impl() +
        scale_x_continuous(labels = byte_labels) +
        scale_y_time(
            labels = label_timespan(),
            limits = y_limits,
            breaks = seq(0, 100) * 1e-9
        ) +
        labs(
            title = str_glue("[{algo}] Hashing small amounts of bytes{using} (lower is better)"),
            subtitle = pretty_arch(arch),
            x = "Size",
            y = "Time"
        ) +
        common_theme
}

## Assumes that each implementation is a flat line and returns the
## estimated speed.
oneshot_speeds = function(data) {
    data |>
        group_by(impl) |>
        group_modify(~ broom::tidy(lm(throughput ~ size, data = .x))) |>
        filter(term == '(Intercept)') |>
        select(impl, estimate) |>
        mutate(estimate = round(estimate / GiB, digits = 1))
}

oneshot_plot = function(data, algo, arch, y_limits = NULL) {
    keyed_speeds = data |> oneshot_speeds() |> pull(estimate, name = impl)

    impl_name_and_speed = function(n) {
        str_glue("{impl_names[n]} — {keyed_speeds[n]} GiB/sec")
    }

    data |>
        ggplot(aes(x = size, y = throughput)) +
        point_and_line() +
        colour_by_impl(labels = impl_name_and_speed) +
        scale_x_continuous_log2 +
        scale_y_continuous_log2_bytes_per_second +
        labs(
            title = str_glue("[{algo}] Throughput to hash a buffer (higher is better)"),
            subtitle = pretty_arch(arch),
            x = "Buffer Size",
            y = "Throughput"
        ) +
        common_theme
}

oneshot_table = function(data) {
    data |>
        oneshot_speeds() |>
        rename(
            `Implementation` = impl,
            `Throughput (GiB/s)` = estimate
        ) |>
        kable()
}

streaming_plot = function(data, algo, arch, y_limits = NULL) {
    data |>
        ggplot(aes(x = chunk_size, y = throughput)) +
        point_and_line() +
        colour_by_impl() +
        scale_x_continuous_log2 +
        scale_y_continuous_log2_bytes_per_second +
        labs(
            title = str_glue("[{algo}] Throughput of a 1 MiB buffer by chunk size (higher is better)"),
            subtitle = pretty_arch(arch),
            x = "Chunk Size",
            y = "Throughput"
        ) +
        common_theme
}

## ====================
## Delta-specific code

lollipop_factor = function() {
    list(
        geom_hline(yintercept = 1, linetype = "dashed", colour = "darkgrey"),
        geom_point(),
        geom_linerange(aes(ymin = 1, ymax = factor)),
        labs(y = "Factor"),
        scale_y_continuous(
            minor_breaks = seq(0, 10, by = 0.1),
            limits = ~ range(0, .x, 2)
        )
    )
}

tiny_data_delta_plot = function(data, algo, arch, fn_name) {
    using = if (is.na(fn_name)) "" else str_glue(" using `{fn_name}`")

    data |>
        ggplot(aes(x = size, y = factor)) +
        lollipop_factor() +
        scale_x_continuous(labels = byte_labels) +
        labs(
            title = str_glue("[{algo}] Time factor vs previous code; Hashing small amounts of bytes{using} (lower is better)"),
            subtitle = pretty_arch(arch),
            x = "Size"
        ) +
        common_theme
}

tiny_data_delta_table = function(data) {
    data |>
        select(size, factor) |>
        mutate(factor = round(factor, digits = 3)) |>
        kable()
}

oneshot_delta_plot = function(data, algo, arch) {
    data |>
        ggplot(aes(x = size, y = factor)) +
        lollipop_factor() +
        scale_x_continuous_log2 +
        labs(
            title = str_glue("[{algo}] Time factor vs previous code; Throughput to hash a buffer (higher is better)"),
            subtitle = pretty_arch(arch),
            x = "Size"
        ) +
        common_theme
}

streaming_delta_plot = function(data, algo, arch) {
    data |>
        ggplot(aes(x = chunk_size, y = factor)) +
        lollipop_factor() +
        scale_x_continuous_log2 +
        labs(
            title = str_glue("[{algo}] Time factor vs previous code; Throughput of a 1 MiB buffer by chunk size (higher is better)"),
            subtitle = pretty_arch(arch),
            x = "Chunk Size"
        ) +
        common_theme
}
