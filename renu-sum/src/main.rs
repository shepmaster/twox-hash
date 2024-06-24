use std::{
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};
use xx_renu::XxHash64;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T, E = Error> = std::result::Result<T, E>;

const BUFFER_SIZE: usize = 16 * 1024;
const BUFFER_COUNT: usize = 8;

fn main() -> Result<()> {
    for path in env::args_os().skip(1) {
        let path = PathBuf::from(path);
        let hash = hash_one_file(&path)?;
        eprintln!("{hash:x}  {}", path.display());
    }

    Ok(())
}

fn hash_one_file(path: &Path) -> Result<u64> {
    let mut file = File::open(path)?;
    let mut hasher = XxHash64::with_seed(0);

    let (tx, rx) = mpsc::sync_channel(BUFFER_COUNT);
    let (tx2, rx2) = mpsc::sync_channel(BUFFER_COUNT);

    for _ in 0..BUFFER_COUNT {
        tx.send(vec![0; BUFFER_SIZE])
            .expect("Must be able to populate initial buffers");
    }

    thread::scope(|scope| {
        let t1 = scope.spawn(move || {
            while let Ok(mut buffer) = rx.recv() {
                let n_bytes = file.read(&mut buffer)?;

                if n_bytes == 0 {
                    break;
                }

                tx2.send((buffer, n_bytes))?;
            }

            Ok::<_, Error>(())
        });

        let t2 = scope.spawn({
            let hasher = &mut hasher;
            move || {
                while let Ok((buffer, n_bytes)) = rx2.recv() {
                    let valid = &buffer[..n_bytes];

                    hasher.write(valid);

                    if tx.send(buffer).is_err() {
                        // The reading thread has exited and there's
                        // nowhere to return this buffer to.
                        continue;
                    }
                }

                Ok::<_, Error>(())
            }
        });

        t1.join().unwrap()?;
        t2.join().unwrap()?;

        Ok::<_, Error>(())
    })?;

    let hash = hasher.finish();
    Ok(hash)
}
