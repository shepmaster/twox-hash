use std::{
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::mpsc::{self, SendError},
    thread,
};
use xx_renu::XxHash64;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T, E = Error> = std::result::Result<T, E>;

const BUFFER_SIZE: usize = 128 * 1024;
const BUFFER_COUNT: usize = 8;

struct Config {
    buffer_size: usize,
    buffer_count: usize,
}

impl Config {
    fn from_env() -> Self {
        let buffer_size = env::var("BUFFER_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(BUFFER_SIZE);

        let buffer_count = env::var("BUFFER_COUNT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(BUFFER_COUNT);

        Self {
            buffer_size,
            buffer_count,
        }
    }
}

fn main() -> Result<()> {
    let config = Config::from_env();

    let mut buffer = vec![0; config.buffer_count * config.buffer_size];

    for path in env::args_os().skip(1) {
        let path = PathBuf::from(path);
        let hash = hash_one_file(&config, &path, &mut buffer)?;
        eprintln!("{hash:x}  {}", path.display());
    }

    Ok(())
}

fn hash_one_file(config: &Config, path: &Path, buffer: &mut [u8]) -> Result<u64> {
    let mut file = File::open(path)?;
    let mut hasher = XxHash64::with_seed(0);

    let (tx_empty, rx_empty) = mpsc::channel();
    let (tx_filled, rx_filled) = mpsc::channel();

    for buffer in buffer.chunks_mut(config.buffer_size) {
        tx_empty
            .send(buffer)
            .expect("Must be able to populate initial buffers");
    }

    thread::scope(|scope| {
        let thread_reader = scope.spawn(move || {
            while let Ok(buffer) = rx_empty.recv() {
                let n_bytes = file.read(buffer)?;

                if n_bytes == 0 {
                    break;
                }

                tx_filled
                    .send((buffer, n_bytes))
                    .map_err(|_| SendError(()))?;
            }

            Ok::<_, Error>(())
        });

        let hasher = &mut hasher;
        let thread_hasher = scope.spawn(move || {
            while let Ok((buffer, n_bytes)) = rx_filled.recv() {
                let valid = &buffer[..n_bytes];

                hasher.write(valid);

                if tx_empty.send(buffer).is_err() {
                    // The reading thread has exited and there's
                    // nowhere to return this buffer to.
                    continue;
                }
            }

            Ok::<_, Error>(())
        });

        thread_reader.join().unwrap()?;
        thread_hasher.join().unwrap()?;

        Ok::<_, Error>(())
    })?;

    let hash = hasher.finish();
    Ok(hash)
}
