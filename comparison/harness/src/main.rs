#![feature(exit_status_error)]

use argh::FromArgs;
use std::path::PathBuf;

#[derive(Debug, FromArgs)]
/// Benchmarking harness
struct Args {
    #[argh(subcommand)]
    mode: Mode,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand)]
enum Mode {
    FullstackDelta(FullstackDeltaArgs),
    FullstackDeltaOf(FullstackDeltaOfArgs),
    FullstackComparison(FullstackComparisonArgs),
    Capture(CaptureArgs),
    CleanAgain(CleanAgainArgs),
    CleanRawJson(CleanRawJsonArgs),
    ReportDelta(ReportDeltaArgs),
    ReportDeltaOf(ReportDeltaOfArgs),
    ReportComparison(ReportComparisonArgs),
    Absorb(AbsorbArgs),
    DirectoryList(DirectoryListArgs),
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "fullstack-delta")]
/// Capture and report benchmarking data showing the Rust change of each commit
struct FullstackDeltaArgs {
    #[argh(switch)]
    /// ignore existing captured data and capture more
    new_trial: bool,
    #[argh(option)]
    /// passed to `cargo criterion` to select which benchmarks to run
    subset: Option<String>,
    #[argh(positional)]
    hashes: Vec<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "fullstack-delta-of")]
/// Capture and report benchmarking data showing the Rust change between commits
struct FullstackDeltaOfArgs {
    #[argh(switch)]
    /// ignore existing captured data and capture more
    new_trial: bool,
    #[argh(option)]
    /// passed to `cargo criterion` to select which benchmarks to run
    subset: Option<String>,
    #[argh(positional)]
    from: String,
    #[argh(positional)]
    to: String,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "fullstack-comparison")]
/// Capture and report benchmarking data comparing C vs Rust for each commit
struct FullstackComparisonArgs {
    #[argh(switch)]
    /// ignore existing captured data and capture more
    new_trial: bool,
    #[argh(option)]
    /// passed to `cargo criterion` to select which benchmarks to run
    subset: Option<String>,
    #[argh(positional)]
    hashes: Vec<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "capture")]
/// Capture benchmarking data
struct CaptureArgs {
    #[argh(switch)]
    /// ignore existing captured data and capture more
    new_trial: bool,
    #[argh(option)]
    /// passed to `cargo criterion` to select which benchmarks to run
    subset: Option<String>,
    #[argh(switch)]
    /// include the parent commit to provide comparisons against
    include_parents: bool,
    #[argh(positional)]
    hashes: Vec<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "clean-again")]
/// Clean all the raw benchmarking JSON again
struct CleanAgainArgs {}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "clean-raw-json")]
/// Clean the given raw benchmarking JSON
struct CleanRawJsonArgs {
    #[argh(positional)]
    path: PathBuf,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "report-delta")]
/// Generate a report for between commits and thier parents
struct ReportDeltaArgs {
    #[argh(positional)]
    hashes: Vec<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "report-delta-of")]
/// Generate a report between two commits
struct ReportDeltaOfArgs {
    #[argh(positional)]
    from: String,
    #[argh(positional)]
    to: String,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "report-comparison")]
/// Generate a report comparing C and Rust for the commits
struct ReportComparisonArgs {
    #[argh(positional)]
    hashes: Vec<String>,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "absorb")]
/// Absorb data from another system
struct AbsorbArgs {
    #[argh(positional)]
    dir: PathBuf,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "directory-list")]
/// Show local dirs for hashes
struct DirectoryListArgs {
    #[argh(positional)]
    hashes: Vec<String>,
}

type Error = snafu::Whatever;

#[snafu::report]
fn main() -> Result<(), Error> {
    let args: Args = argh::from_env();

    match args.mode {
        Mode::FullstackDelta(args) => fullstack::delta(args),
        Mode::FullstackDeltaOf(args) => fullstack::delta_of(args),
        Mode::FullstackComparison(args) => fullstack::comparison(args),
        Mode::Capture(args) => capture::main(args),
        Mode::CleanAgain(_) => clean::again(),
        Mode::CleanRawJson(args) => clean::raw_json(args),
        Mode::ReportDelta(args) => report::delta(args),
        Mode::ReportDeltaOf(args) => report::delta_of(args),
        Mode::ReportComparison(args) => report::comparison(args),
        Mode::Absorb(args) => absorb::from(args),
        Mode::DirectoryList(args) => directory::list(args),
    }
}

mod fullstack {
    use crate::{
        Error, FullstackComparisonArgs, FullstackDeltaArgs, FullstackDeltaOfArgs, capture,
        git::{self, Cache},
        report,
    };

    pub fn delta(args: FullstackDeltaArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in git::rev_list(&args.hashes)? {
            capture::capture_one(
                &mut cache,
                &hash,
                true,
                args.subset.as_deref(),
                args.new_trial,
            )?;
            report::delta_one(&mut cache, &hash)?;
        }

        Ok(())
    }

    pub fn delta_of(args: FullstackDeltaOfArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in [&args.from, &args.to] {
            capture::capture_one(
                &mut cache,
                hash,
                false,
                args.subset.as_deref(),
                args.new_trial,
            )?;
        }
        report::delta_core(&mut cache, &args.from, &args.to)?;

        Ok(())
    }

    pub fn comparison(args: FullstackComparisonArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in git::rev_list(&args.hashes)? {
            capture::capture_one(
                &mut cache,
                &hash,
                false,
                args.subset.as_deref(),
                args.new_trial,
            )?;
            report::comparison_one(&mut cache, &hash)?;
        }

        Ok(())
    }
}

mod capture {
    use snafu::prelude::*;
    use std::{
        fs::{self, File},
        mem::DropGuard,
        process::Command,
    };

    use crate::{
        CaptureArgs, Error, clean,
        git::{self, Cache},
        paths::Paths,
    };

    pub fn main(args: CaptureArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in git::rev_list(&args.hashes)? {
            capture_one(
                &mut cache,
                &hash,
                args.include_parents,
                args.subset.as_deref(),
                args.new_trial,
            )?;
        }

        Ok(())
    }

    pub fn capture_one(
        cache: &mut Cache,
        hash: &str,
        include_parents: bool,
        subset: Option<&str>,
        new_trial: bool,
    ) -> Result<(), Error> {
        capture_hash(cache, hash, subset, new_trial)?;
        if include_parents {
            let parent = format!("{hash}~");
            capture_hash(cache, &parent, subset, new_trial)?;
        }
        Ok(())
    }

    fn capture_hash(
        cache: &mut Cache,
        hash: &str,
        subset: Option<&str>,
        new_trial: bool,
    ) -> Result<(), Error> {
        let paths = Paths::new();
        let hash_path = paths.for_hash(cache, hash)?;

        let data_dir = hash_path.data_dir();
        let latest_trial = data_dir.latest_trial()?;
        let trial_path = match (latest_trial, new_trial) {
            (None, _) => data_dir.trial_for(0),
            (Some(t), true) => data_dir.trial_for(t.next_id()),
            (Some(_), false) => return Ok(()),
        };

        let clean_path = trial_path.clean_path();
        let raw_path = trial_path.raw_path();

        fs::create_dir_all(&trial_path).whatever_context("create trial path")?;
        let dir_guard = DropGuard::new(trial_path, |trial_path| {
            fs::remove_dir_all(trial_path).unwrap();
        });

        let raw_file = File::create(&raw_path).whatever_context("create raw file")?;
        let clean_file = File::create(&clean_path).whatever_context("create clean file")?;

        let _branch_guard = DropGuard::new((), |_| git::checkout("-").unwrap());
        git::checkout(hash)?;

        let mut c = Command::new("cargo");

        c.env("RUSTUP_TOOLCHAIN", "stable")
            .arg("criterion")
            .args(["-p", "comparison"])
            .arg("--message-format=json");

        if let Some(subset) = subset {
            c.arg("--").arg(subset);
        }

        c.stdout(raw_file)
            .status()
            .whatever_context("criterion status")?;
        // We don't check the exit status because it's always a failure on Windows.

        let raw_json = fs::read_to_string(&raw_path).whatever_context("criterion output")?;

        let clean_data = clean::clean_data(&raw_json)?;

        clean::write_data(clean_file, &clean_data)?;
        DropGuard::dismiss(dir_guard);

        Ok(())
    }
}

mod clean {
    use serde_json::Value;
    use snafu::prelude::*;
    use std::{
        fs::{self, File},
        io::{self, ErrorKind},
        str::FromStr as _,
    };

    use crate::{CleanRawJsonArgs, Error, paths};

    pub fn again() -> Result<(), Error> {
        let paths = paths::Paths::new();

        for hash_path in paths.all_hash_paths()? {
            for trial_path in hash_path.data_dir().all_trials()? {
                let raw = trial_path.raw_path();
                let raw_file = match fs::read_to_string(&raw) {
                    Ok(f) => f,
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    e => e.whatever_context("read file")?,
                };

                let clean_data = clean_data(&raw_file)?;

                let clean = trial_path.clean_path();
                let clean_file = File::create(&clean).whatever_context("create clean file")?;

                write_data(clean_file, &clean_data)?;
            }
        }
        Ok(())
    }

    pub fn raw_json(args: CleanRawJsonArgs) -> Result<(), Error> {
        let raw = fs::read_to_string(args.path).whatever_context("read file")?;
        let clean = clean_data(&raw)?;
        let stdout = std::io::stdout().lock();
        write_data(stdout, &clean)?;
        Ok(())
    }

    #[derive(Debug, serde::Serialize)]
    pub struct Data {
        #[serde(flatten)]
        keys: serde_json::Map<String, Value>,
        mean_estimate: f64,
    }

    pub fn write_data(mut w: impl io::Write, data: &[Data]) -> Result<(), Error> {
        for d in data {
            serde_json::to_writer(&mut w, d).whatever_context("write json")?;
            writeln!(&mut w).whatever_context("adding newline")?;
        }

        Ok(())
    }

    pub fn clean_data(raw_json: &str) -> Result<Vec<Data>, Error> {
        let raw_json = raw_json
            .lines()
            .map(Value::from_str)
            .collect::<Result<Vec<_>, _>>()
            .whatever_context("invalid json")?;

        raw_json
            .into_iter()
            .flat_map(serde_json::from_value)
            .map(|bc: BenchmarkComplete| {
                let mut keys = serde_json::Map::new();

                for part in bc.id.split("/") {
                    let (key, value) = part
                        .split_once("-")
                        .whatever_context("Id not formatted correctly")?;
                    let key = key.to_owned();

                    match key.as_str() {
                        "size" | "chunk_size" => {
                            let value = value
                                .parse::<usize>()
                                .with_whatever_context(|_| format!("`{key}` is `{value}`"))?;
                            keys.insert(key, Value::Number(value.into()));
                        }
                        _ => {
                            let value = value.to_owned();
                            keys.insert(key, Value::String(value));
                        }
                    }
                }

                Ok(Data {
                    keys,
                    mean_estimate: bc.mean.estimate,
                })
            })
            .collect()
    }

    #[derive(Debug, serde::Deserialize)]
    struct BenchmarkComplete {
        id: String,
        mean: Mean,
    }

    #[derive(Debug, serde::Deserialize)]
    struct Mean {
        estimate: f64,
    }
}

mod report {
    use snafu::prelude::*;
    use std::{ffi::OsStr, path::Path, process::Command};

    use crate::{
        Error, ReportComparisonArgs, ReportDeltaArgs, ReportDeltaOfArgs,
        git::{self, Cache},
        paths::{self, Paths},
    };

    pub fn delta(args: ReportDeltaArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in git::rev_list(&args.hashes)? {
            delta_one(&mut cache, &hash)?;
        }

        Ok(())
    }

    pub fn delta_one(cache: &mut Cache, hash: &str) -> Result<(), Error> {
        let parent_hash = format!("{hash}~");

        delta_core(cache, &parent_hash, hash)
    }

    pub fn delta_of(args: ReportDeltaOfArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        delta_core(&mut cache, &args.from, &args.to)
    }

    pub fn delta_core(
        cache: &mut Cache,
        baseline_hash: &str,
        target_hash: &str,
    ) -> Result<(), Error> {
        let paths = Paths::new();

        let output_dir_path = paths.for_hash(cache, target_hash)?;

        let baseline_paths = paths.all_clean_paths(cache, baseline_hash)?;
        let target_paths = paths.all_clean_paths(cache, target_hash)?;

        assert!(
            !baseline_paths.is_empty(),
            "No benchmarks found for {baseline_hash}",
        );
        assert!(
            !target_paths.is_empty(),
            "No benchmarks found for {target_hash}",
        );

        r_script_command("generate-delta.R")
            .arg(&output_dir_path)
            .arg("--before")
            .args(&baseline_paths)
            .arg("--after")
            .args(&target_paths)
            .status()
            .whatever_context("spawn R")?
            .exit_ok()
            .whatever_context("R retval")?;

        optimize_svgs_in_dir(&output_dir_path)?;

        eprintln!("Report for {target_hash} in {output_dir_path}");

        Ok(())
    }

    pub fn comparison(args: ReportComparisonArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in git::rev_list(&args.hashes)? {
            comparison_one(&mut cache, &hash)?;
        }

        Ok(())
    }

    pub fn comparison_one(cache: &mut Cache, hash: &str) -> Result<(), Error> {
        let paths = Paths::new();

        let output_dir = paths.for_hash(cache, hash)?;
        let clean_paths = paths.all_clean_paths(cache, hash)?;

        r_script_command("generate-graph.R")
            .arg(&output_dir)
            .args(&clean_paths)
            .status()
            .whatever_context("spawn R")?
            .exit_ok()
            .whatever_context("R retval")?;

        optimize_svgs_in_dir(&output_dir)?;

        eprintln!("Report for {hash} in {output_dir}");

        Ok(())
    }

    fn r_script_command(name: impl AsRef<Path>) -> Command {
        let comparison_dir = paths::comparison_dir();
        let script_path = comparison_dir.join(name);

        let mut c = Command::new(script_path);
        c.current_dir(comparison_dir);
        c
    }

    fn optimize_svgs_in_dir(dir: impl AsRef<OsStr>) -> Result<(), Error> {
        let mut config_path = paths::comparison_dir();
        config_path.push("svgo.config.js");

        Command::new("svgo")
            .arg("--quiet")
            .arg("--config")
            .arg(config_path)
            .arg("--multipass")
            .arg("--pretty")
            .args(["--indent", "2"])
            .arg("--final-newline")
            .arg("--recursive")
            .arg(dir)
            .status()
            .whatever_context("spawn svgo")?
            .exit_ok()
            .whatever_context("svgo retval")?;

        Ok(())
    }
}

mod absorb {
    use crate::{AbsorbArgs, Error, paths::Paths};

    pub fn from(args: AbsorbArgs) -> Result<(), Error> {
        let our_paths = Paths::new();
        let other_paths = Paths::in_path(args.dir);

        our_paths.absorb(other_paths)
    }
}

mod git {
    use snafu::prelude::*;
    use std::{
        collections::{HashMap, hash_map},
        process::Command,
        sync::Arc,
    };

    use crate::Error;

    pub fn checkout(branch: &str) -> Result<(), Error> {
        Command::new("git")
            .arg("checkout")
            .arg(branch)
            .status()
            .whatever_context("checkout status")?
            .exit_ok()
            .whatever_context("checkout retval")
    }

    pub fn rev_list(hashes: &[String]) -> Result<Vec<String>, Error> {
        let mut results = Vec::new();

        for hash_arg in hashes {
            if hash_arg.contains("..") {
                let output = Command::new("git")
                    .arg("rev-list")
                    .arg(hash_arg)
                    .output()
                    .whatever_context("rev-list output")?
                    .exit_ok()
                    .whatever_context("rev-list retval")?;
                let stdout = str::from_utf8(&output.stdout).whatever_context("rev-list utf8")?;
                results.extend(stdout.split_ascii_whitespace().map(str::to_owned));
            } else {
                results.push(hash_arg.to_owned())
            }
        }

        Ok(results)
    }

    #[derive(Default)]
    pub struct Cache {
        tree_hashes: HashMap<String, Arc<str>>,
    }

    impl Cache {
        pub fn tree_hash(&mut self, hash: impl Into<String>) -> Result<&Arc<str>, Error> {
            let v = match self.tree_hashes.entry(hash.into()) {
                hash_map::Entry::Occupied(entry) => entry.into_mut(),
                hash_map::Entry::Vacant(entry) => {
                    let tree_hash = tree_hash(entry.key())?;
                    entry.insert(tree_hash.into())
                }
            };
            Ok(v)
        }
    }

    fn tree_hash(hash: &str) -> Result<String, Error> {
        let output = Command::new("git")
            .arg("rev-parse")
            .arg(format!("{hash}^{{tree}}"))
            .output()
            .whatever_context("rev-parse output")?
            .exit_ok()
            .whatever_context("rev-parse retval")?;

        let stdout = str::from_utf8(&output.stdout).whatever_context("rev-parse utf8")?;

        Ok(stdout.trim().to_owned())
    }
}

mod directory {
    use crate::{
        DirectoryListArgs, Error,
        git::{self, Cache},
    };

    pub fn list(args: DirectoryListArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in git::rev_list(&args.hashes)? {
            let tree_hash = cache.tree_hash(&hash)?;
            println!("`{}` maps to `{}`", hash, tree_hash);
        }

        Ok(())
    }
}

mod paths {
    use snafu::prelude::*;
    use std::{
        ffi::OsStr,
        fmt, fs,
        io::ErrorKind,
        path::{Path, PathBuf},
    };

    use crate::{Error, git::Cache};

    const CAPTURE_DIRNAME: &str = "captures";
    const DATA_DIRNAME: &str = "data";
    const RAW_FNAME: &str = "raw.json";
    const CLEAN_FNAME: &str = "clean.json";

    fn project_root() -> PathBuf {
        let mut root = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        root.pop();
        root.pop();
        root
    }

    pub fn comparison_dir() -> PathBuf {
        let mut base = project_root();
        base.push("comparison");
        base
    }

    pub struct Paths(PathBuf);

    impl Paths {
        pub fn new() -> Self {
            let mut base = comparison_dir();
            base.push(CAPTURE_DIRNAME);
            Self(base)
        }

        pub fn in_path(path: impl Into<PathBuf>) -> Self {
            Self(path.into())
        }

        pub fn for_hash(
            &self,
            cache: &mut Cache,
            hash: impl Into<String>,
        ) -> Result<HashPath, Error> {
            let tree_hash = cache.tree_hash(hash)?;
            let p = self.0.join(&**tree_hash);
            Ok(HashPath(p))
        }

        pub fn all_hash_paths(&self) -> Result<Vec<HashPath>, Error> {
            fs::read_dir(&self.0)
                .whatever_context("listing dir")?
                .map(|dir| {
                    let dir = dir.whatever_context("dir entry")?;
                    Ok(HashPath(dir.path()))
                })
                .collect()
        }

        pub fn all_clean_paths(
            &self,
            cache: &mut Cache,
            hash: &str,
        ) -> Result<Vec<PathBuf>, Error> {
            let hash_path = self.for_hash(cache, hash)?;
            let data_path = hash_path.data_dir();
            let trials = data_path.all_trials()?;
            let clean_paths = trials.into_iter().map(|t| t.clean_path()).collect();
            Ok(clean_paths)
        }

        pub fn absorb(&self, other_paths: Paths) -> Result<(), Error> {
            for other_hash_path in other_paths.all_hash_paths()? {
                let other_file_name = other_hash_path
                    .0
                    .file_name()
                    .whatever_context("no file name")?;
                let my_hash_path = HashPath(self.0.join(other_file_name));

                let my_data_dir = my_hash_path.data_dir();
                let other_data_dir = other_hash_path.data_dir();

                let my_latest_trial = my_hash_path.data_dir().latest_trial()?;
                let new_trial_id_start = my_latest_trial.map_or(0, |t| t.next_id());
                let new_trial_ids = new_trial_id_start..;
                let other_trials = other_data_dir.all_trials()?;

                for (new_id, other_trial) in new_trial_ids.zip(other_trials) {
                    let my_trial = my_data_dir.trial_for(new_id);
                    fs::create_dir_all(&my_trial).whatever_context("create absorb target dir")?;

                    let other_raw = other_trial.raw_path();
                    let my_raw = my_trial.raw_path();
                    fs::copy(other_raw, my_raw).whatever_context("copy raw")?;

                    let other_clean = other_trial.clean_path();
                    let my_clean = my_trial.clean_path();
                    fs::copy(other_clean, my_clean).whatever_context("copy clean")?;
                }
            }

            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct HashPath(PathBuf);

    impl HashPath {
        pub fn data_dir(&self) -> DataPath {
            DataPath(self.0.join(DATA_DIRNAME))
        }
    }

    impl AsRef<Path> for HashPath {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<OsStr> for HashPath {
        fn as_ref(&self) -> &OsStr {
            self.0.as_ref()
        }
    }

    impl fmt::Display for HashPath {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.display().fmt(f)
        }
    }

    #[derive(Debug)]
    pub struct DataPath(PathBuf);

    impl DataPath {
        pub fn trial_for(&self, id: TrialId) -> TrialPath {
            let mut buf = std::fmt::NumBuffer::new();
            let s = id.format_into(&mut buf);
            let path = self.0.join(s);
            TrialPath(id, path)
        }

        pub fn all_trials(&self) -> Result<Vec<TrialPath>, Error> {
            let dir = match fs::read_dir(&self.0) {
                Ok(d) => d,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
                e => e.with_whatever_context(|_| format!("open dir {}", self.0.display()))?,
            };

            let mut trials = dir
                .map(|e| {
                    let path = e.whatever_context("no path")?.path();

                    let id = path
                        .file_name()
                        .whatever_context("no name")?
                        .to_str()
                        .whatever_context("not a str")?
                        .parse()
                        .whatever_context("not a number")?;

                    Ok(TrialPath(id, path))
                })
                .collect::<Result<Vec<_>, _>>()?;

            trials.sort_by_key(|t| t.id());

            Ok(trials)
        }

        pub fn latest_trial(&self) -> Result<Option<TrialPath>, Error> {
            self.all_trials().map(|mut t| t.pop())
        }
    }

    type TrialId = u16;

    #[derive(Debug)]
    pub struct TrialPath(TrialId, PathBuf);

    impl TrialPath {
        pub fn id(&self) -> TrialId {
            self.0
        }

        pub fn next_id(&self) -> TrialId {
            self.0 + 1
        }

        pub fn raw_path(&self) -> PathBuf {
            self.1.join(RAW_FNAME)
        }

        pub fn clean_path(&self) -> PathBuf {
            self.1.join(CLEAN_FNAME)
        }
    }

    impl AsRef<Path> for TrialPath {
        fn as_ref(&self) -> &Path {
            &self.1
        }
    }
}
