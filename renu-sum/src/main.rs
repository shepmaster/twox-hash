use std::{
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use xx_renu::XxHash64;

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

fn main() -> Result<()> {
    let mut buffer = vec![0; 32 * 1024 * 1024];

    for path in env::args_os().skip(1) {
        let path = PathBuf::from(path);
        let hash = hash_one_file(&path, &mut buffer)?;
        eprintln!("{hash:x}  {}", path.display());
    }

    Ok(())
}

fn hash_one_file(path: &Path, buffer: &mut [u8]) -> Result<u64> {
    let mut file = File::open(path)?;
    let mut hasher = XxHash64::with_seed(0);

    loop {
        let n_bytes = file.read(buffer)?;
        if n_bytes == 0 {
            break;
        }

        let valid = &buffer[..n_bytes];

        hasher.write(valid);
    }

    let hash = hasher.finish();
    Ok(hash)
}
