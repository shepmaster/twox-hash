#![feature(drop_guard)]
#![feature(exit_status_error)]
#![feature(file_buffered)]

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
/// Capture and report benchmarking data showing the change of each commit
struct FullstackDeltaArgs {
    #[argh(switch)]
    /// ignore any existing captured data
    force: bool,
    #[argh(option)]
    /// passed to `cargo criterion` to select which benchmarks to run
    subset: Option<String>,
    #[argh(positional)]
    hashes: String,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "capture")]
/// Capture benchmarking data
struct CaptureArgs {
    #[argh(switch)]
    /// ignore any existing captured data
    force: bool,
    #[argh(option)]
    /// passed to `cargo criterion` to select which benchmarks to run
    subset: Option<String>,
    #[argh(switch)]
    /// include the parent commit to provide comparisons against
    include_parents: bool,
    #[argh(positional)]
    hashes: String,
}

#[derive(Debug, FromArgs)]
#[argh(subcommand, name = "clean-again")]
/// Capture benchmarking data
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
/// Generate a report for captured commits
struct ReportDeltaArgs {
    #[argh(positional)]
    hashes: String,
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
    hashes: String,
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
    hashes: String,
}

type Error = snafu::Whatever;

#[snafu::report]
fn main() -> Result<(), Error> {
    let args: Args = argh::from_env();

    match args.mode {
        Mode::FullstackDelta(args) => fullstack::delta(args),
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
        Error, FullstackDeltaArgs, capture,
        git::{self, Cache},
        report,
    };

    pub fn delta(args: FullstackDeltaArgs) -> Result<(), Error> {
        let mut cache = Cache::default();

        for hash in git::rev_list(&args.hashes)? {
            capture::capture_one(&mut cache, &hash, true, args.subset.as_deref(), args.force)?;
            report::delta_one(&mut cache, &hash)?;
        }

        Ok(())
    }
}

mod capture {
    use snafu::prelude::*;
    use std::{
        fs::{self, File},
        io::ErrorKind,
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
                args.force,
            )?;
        }

        Ok(())
    }

    pub fn capture_one(
        cache: &mut Cache,
        hash: &str,
        include_parents: bool,
        subset: Option<&str>,
        force: bool,
    ) -> Result<(), Error> {
        capture_hash(cache, hash, subset, force)?;
        if include_parents {
            let parent = format!("{hash}~");
            capture_hash(cache, &parent, subset, force)?;
        }
        Ok(())
    }

    fn capture_hash(cache: &mut Cache, hash: &str, subset: Option<&str>, force: bool) -> Result<(), Error> {
        let paths = Paths::new();
        let hash_path = paths.for_hash(cache, hash)?;

        fs::create_dir_all(&hash_path).whatever_context("create hash path")?;

        let clean_path = hash_path.clean_path();
        let clean_file = if force {
            File::create(&clean_path).whatever_context("create clean file")?
        } else {

            match File::create_new(&clean_path) {
            Ok(f) => f,

            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                // Already created, use cached version
                return Ok(());
            }

            Err(e) => {
                return Err(e).with_whatever_context(|_| {
                    format!("create clean file {}", clean_path.display())
                });
            }
            }
        };

        let mut file_guard = DropGuard::new(clean_file, |f| {
            drop(f);
            fs::remove_file(clean_path).unwrap();
        });

        let raw_path = hash_path.raw_path();
        let raw_file = File::create(&raw_path).whatever_context("create raw file")?;

        Command::new("git")
            .arg("checkout")
            .arg(hash)
            .status()
            .whatever_context("checkout status")?
            .exit_ok()
            .whatever_context("checkout retval")?;

        let mut c = Command::new("cargo");

        c.arg("criterion")
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

        clean::write_data(&mut *file_guard, &clean_data)?;
        DropGuard::dismiss(file_guard);

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

        for hash_path in paths.all()? {
            let raw = hash_path.raw_path();
            let raw_file = match fs::read_to_string(&raw) {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                e => e.whatever_context("read file")?,
            };

            let clean_data = clean_data(&raw_file)?;

            let clean = hash_path.clean_path();
            let clean_file = File::create(&clean).whatever_context("create clean file")?;

            write_data(clean_file, &clean_data)?;
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
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
        process::Command,
    };

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

        let baseline_hash_path = paths.for_hash(cache, baseline_hash)?;
        let target_hash_path = paths.for_hash(cache, target_hash)?;

        let baseline_path = baseline_hash_path.clean_path();
        let target_path = target_hash_path.clean_path();

        let script = r_script("generate-delta.R");

        Command::new(script)
            .arg(&target_hash_path)
            .arg(&baseline_path)
            .arg(&target_path)
            .status()
            .whatever_context("spawn R")?
            .exit_ok()
            .whatever_context("R retval")?;

        optimize_svgs_in_dir(&target_hash_path)?;

        eprintln!("Report for {target_hash} in {target_hash_path}");

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
        let cleaned_data = output_dir.clean_path();

        let script = r_script("generate-graph.R");

        Command::new(script)
            .arg(&cleaned_data)
            .arg(&output_dir)
            .status()
            .whatever_context("spawn R")?
            .exit_ok()
            .whatever_context("R retval")?;

        optimize_svgs_in_dir(&output_dir)?;

        Ok(())
    }

    fn r_script(name: impl AsRef<Path>) -> PathBuf {
        let mut script = paths::comparison_dir();
        script.push(name);
        script
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

    pub fn rev_list(hashes: &str) -> Result<Vec<String>, Error> {
        let hashes = hashes.trim();

        if hashes.contains("..") {
            let output = Command::new("git")
                .arg("rev-list")
                .arg(hashes)
                .output()
                .whatever_context("rev-list output")?
                .exit_ok()
                .whatever_context("rev-list retval")?;
            let stdout = str::from_utf8(&output.stdout).whatever_context("rev-list utf8")?;
            Ok(stdout
                .split_ascii_whitespace()
                .map(|h| h.to_owned())
                .collect())
        } else {
            Ok(vec![hashes.to_owned()])
        }
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
        collections::BTreeSet,
        ffi::OsStr,
        fmt,
        fs::{self, File},
        io::ErrorKind,
        path::{Path, PathBuf},
    };

    use crate::{Error, git::Cache};

    const RAW_FNAME: &str = "raw.json";
    const CLEAN_FNAME: &str = "clean.json";
    const CAPTURE_DIRNAME: &str = "captures";

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

        pub fn all(&self) -> Result<Vec<HashPath>, Error> {
            fs::read_dir(&self.0)
                .whatever_context("listing dir")?
                .map(|dir| {
                    let dir = dir.whatever_context("dir entry")?;
                    Ok(HashPath(dir.path()))
                })
                .collect()
        }

        pub fn absorb(&self, other_paths: Paths) -> Result<(), Error> {
            for other_hash_path in other_paths.all()? {
                let other_file_name = other_hash_path
                    .0
                    .file_name()
                    .whatever_context("no file name")?;
                let my_equivalent = self.0.join(other_file_name);
                let my_hash_path = HashPath(my_equivalent);

                fs::create_dir_all(&my_hash_path).whatever_context("create absorb target dir")?;

                fn absorb_file(dest: PathBuf, src: PathBuf) -> Result<(), Error> {
                    let d = fs::read_to_string(&dest);
                    let s = fs::read_to_string(&src);

                    let (d, s) = match (d, s) {
                        (Ok(d), Ok(s)) => (d, s),

                        (Err(d), Ok(_)) if d.kind() == ErrorKind::NotFound => {
                            return fs::copy(&src, &dest).map(drop).with_whatever_context(|_| {
                                format!(
                                    "copy `{}` to `{}` while absorb",
                                    src.display(),
                                    dest.display(),
                                )
                            });
                        }

                        (Ok(_), Err(e)) if e.kind() == ErrorKind::NotFound => {
                            return Ok(());
                        }

                        (Err(e), _) | (_, Err(e)) => {
                            return Err(e).whatever_context("could not open file during absorb");
                        }
                    };

                    let combined = d.lines().chain(s.lines()).collect::<BTreeSet<_>>();

                    let mut f = File::create_buffered(&dest)
                        .whatever_context("Could not create dest file")?;
                    for l in combined {
                        use std::io::Write;
                        writeln!(f, "{l}").whatever_context("absorb newline")?;
                    }

                    Ok(())
                }

                absorb_file(my_hash_path.raw_path(), other_hash_path.raw_path())?;
                absorb_file(my_hash_path.clean_path(), other_hash_path.clean_path())?;
            }

            Ok(())
        }
    }

    impl AsRef<Path> for Paths {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl AsRef<OsStr> for Paths {
        fn as_ref(&self) -> &OsStr {
            self.0.as_ref()
        }
    }

    pub struct HashPath(PathBuf);

    impl HashPath {
        pub fn raw_path(&self) -> PathBuf {
            self.0.join(RAW_FNAME)
        }

        pub fn clean_path(&self) -> PathBuf {
            self.0.join(CLEAN_FNAME)
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
}
