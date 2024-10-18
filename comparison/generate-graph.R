#!/usr/bin/env Rscript

library(forcats)
library(ggplot2)
library(nlme)
library(rlang)
library(scales)

args = commandArgs(trailingOnly = TRUE)

filename = args[1]
output_dir = args[2]

make_filename = function(algo, bench, arch) {
    paste0(output_dir, "/", algo, "-", bench, "-", arch, ".svg")
}

log2min = function(x) { 2 ^ floor(log2(min(x))) }
log2max = function(x) { 2 ^ ceiling(log2(max(x))) }

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

## Load the data
data = jsonlite::stream_in(file(filename), verbose = FALSE)

## Reorder and rename the implementation factor
data$impl = fct_relevel(data$impl, "rust", "c", "c-scalar", "c-neon", "c-sse2", "c-avx2")
impl_names = c("rust" = "Rust", "c" = "C", "c-scalar" = "C (scalar)", "c-neon" = "C (NEON)", "c-sse2" = "C (SSE2)" , "c-avx2" = "C (AVX2)")
impl_name = function(n) { impl_names[n] }

cpus = c(aarch64 = "Apple M1 Max", x86_64 = "AMD Ryzen 9 3950X")

common_theme = theme(legend.position = "inside", legend.position.inside = c(0.8, 0.2), plot.margin = unit(c(0.1, 1, 0.1, 0.1), 'cm'))

for (algo in c("xxhash64", "xxhash3_64")) {
    message("# ", algo)

    algo_data = data[data$algo == algo,]

    all_tiny_data = algo_data[algo_data$bench == "tiny_data",]
    all_oneshot = algo_data[algo_data$bench == "oneshot",]
    all_streaming = algo_data[algo_data$bench == "streaming",]

    ## Convert to a duration type
    all_tiny_data$mean_estimate = lubridate::dnanoseconds(all_tiny_data$mean_estimate)

    ## Get bytes per second; the time estimate is in nanoseconds
    all_oneshot$throughput = all_oneshot$size/(all_oneshot$mean_estimate / 1e9)

    ## Get bytes per second; the time estimate is in nanoseconds
    all_streaming$throughput = all_streaming$size / (all_streaming$mean_estimate / 1e9)

    tiny_data_y_limits = c(min(all_tiny_data$mean_estimate), max(all_tiny_data$mean_estimate))
    oneshot_y_limits = c(log2min(all_oneshot$throughput), log2max(all_oneshot$throughput))
    streaming_y_limits = c(log2min(all_streaming$throughput), log2max(all_streaming$throughput))

    for (arch in c("aarch64", "x86_64")) {
        message("## ", arch)

        oneshot = all_oneshot[all_oneshot$arch == arch,]
        tiny_data = all_tiny_data[all_tiny_data$arch == arch,]
        streaming = all_streaming[all_streaming$arch == arch,]

        cpu = cpus[arch]
        subtitle = paste0(arch, " (", cpu, ")")

        if (nrow(tiny_data) != 0) {
            message("### Tiny data")

            title = paste0("[", algo, "] Hashing small amounts of bytes (lower is better)")

            p = ggplot(tiny_data, aes(x = size, y = mean_estimate, colour = impl)) +
                geom_point(alpha = 0.7) +
                geom_line(alpha = 0.3) +
                scale_x_continuous(labels = byte_labels) +
                scale_y_time(labels = label_timespan(), limits = tiny_data_y_limits) +
                scale_colour_brewer(labels = impl_name, palette = "Set1") +
                labs(title = title, subtitle = subtitle, x = "Size", y = "Time", colour = "Implementation") +
                common_theme

            output_filename = make_filename(algo = algo, bench = "tiny_data", arch = arch)
            ggsave(output_filename, width = 3000, height = 2000, units = "px", scale = 1.5)
        }

        if (nrow(oneshot) != 0) {
            message("### Oneshot")

            fit = lmList(throughput ~ size | impl, data = oneshot, pool = FALSE, na.action = na.pass)
            coef = as.data.frame(t(sapply(fit, coefficients)))
            speeds = round(coef$"(Intercept)" / GiB, digits = 1)
            names(speeds) = rownames(coef)

            impl_name_and_speed = function(n) {
                name = impl_name(n)
                paste(name, "—", speeds[n], "GiB/sec")
            }

            title = paste0("[", algo, "] Throughput to hash a buffer (higher is better)")

            p = ggplot(oneshot, aes(x = size, y = throughput, colour = impl)) +
                geom_point(alpha = 0.7) +
                geom_line(alpha = 0.3) +
                scale_x_continuous(transform = transform_log2(), labels = byte_labels, minor_breaks = NULL) +
                scale_y_continuous(transform = transform_log2(), labels = bytes_per_second_labels, breaks = powers_of_two, minor_breaks = NULL, limits = oneshot_y_limits) +
                scale_colour_brewer(labels = impl_name_and_speed, palette = "Set1") +
                labs(title = title, subtitle = subtitle, x = "Buffer Size", y = "Throughput", colour = "Implementation") +
                common_theme

            output_filename = make_filename(algo = algo, bench = "oneshot", arch = arch)
            ggsave(output_filename, width = 3000, height = 2000, units = "px", scale = 1.5)

            speeds_table = data.frame(speeds)
            rownames(speeds_table) = impl_names[rownames(speeds_table)]
            print(speeds_table)
        }

        if (nrow(streaming) != 0) {
            message("### Streaming")

            title = paste0("[", algo, "] Throughput of a 1 MiB buffer by chunk size (higher is better)")

            p = ggplot(streaming, aes(x = chunk_size, y = throughput, colour = impl)) +
                geom_point(alpha = 0.7) +
                geom_line(alpha = 0.3) +
                scale_x_continuous(transform = transform_log2(), labels = byte_labels, breaks = powers_of_two, minor_breaks = NULL) +
                scale_y_continuous(transform = transform_log2(), labels = bytes_per_second_labels, breaks = powers_of_two, minor_breaks = NULL, limits = streaming_y_limits) +
                scale_colour_brewer(palette = "Set1", labels = impl_name) +
                labs(title = title , subtitle = subtitle, x = "Chunk Size", y = "Throughput", colour = "Implementation") +
                common_theme

            output_filename = make_filename(algo = algo, bench = "streaming", arch = arch)
            ggsave(output_filename, width = 3000, height = 2000, units = "px", scale = 1.5)
        }
    }
}

warnings()
