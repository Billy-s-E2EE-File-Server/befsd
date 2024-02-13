mod file_server;
mod ipc;
mod watcher;

use anyhow::Context;
use bfsp::ipc::{directory_listing, DirectoryListing};
use bfsp::{cli::FileHeader, hash_file, ChunkHash, EncryptionKey, FileHash};
use bfsp::{config::*, ChunkID, ChunkMetadata};
use dashmap::DashMap;
use file_server::*;
use log::trace;
use path_absolutize::Absolutize;
use tokio::io;
use watcher::*;

use notify::{event::CreateKind, INotifyWatcher, Watcher};
use thiserror::Error;

use macaroon::Macaroon;
use tokio::{
    fs::{self, File},
    io::AsyncSeekExt,
    net::TcpStream,
    sync::{Mutex, RwLock},
};

use std::collections::HashMap;
use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, Result};
use sqlx::{Row, SqlitePool};

#[tokio::main]
async fn main() -> Result<()> {
    fern::Dispatch::new()
        .format(|out, msg, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339(std::time::SystemTime::now()),
                record.level(),
                record.target(),
                msg
            ))
        }) // Add blanket level filter -
        .level(log::LevelFilter::Trace)
        .level_for("sqlx", log::LevelFilter::Debug)
        .level_for("hyper", log::LevelFilter::Warn)
        // - and per-module overrides
        // Output to stdout, files, and other Dispatch configurations
        .chain(std::io::stdout())
        .chain(fern::log_file("output.log").unwrap())
        // Apply globally
        .apply()
        .unwrap();

    trace!("Getting config directory");
    let config_path = get_config_dir()
        .await
        .with_context(|| "failed getting config directory")?
        .join("config.toml");

    trace!("Config path: {}", config_path.display());

    trace!("Getting config file");
    let config = config_from_file(&config_path)
        .await
        .with_context(|| "failed getting config file")?;

    trace!("Getting macaroon");
    let macaroon = match config.macaroon {
        Some(macaroon) => Macaroon::deserialize(macaroon)?,
        None => {
            return Err(anyhow!("No macaroon found in config file"));
        }
    };

    trace!("Getting encryption key");
    let enc_key = match config.enc_key {
        Some(enc_key) => {
            let bytes = hex::decode(enc_key)?;
            EncryptionKey::try_from(bytes)?
        }
        None => {
            return Err(anyhow!("No encryption key found in config file"));
        }
    };

    let pool_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        format!(
            "sqlite:{}/data.db",
            env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string())
        )
    });

    let path = pool_url.strip_prefix("sqlite:").unwrap();
    if !fs::try_exists(&path).await.unwrap() {
        trace!("Creating database file at {path}");
        File::create(&path)
            .await
            .with_context(|| "Error creating database file")?;
    }

    let pool = sqlx::SqlitePool::connect(&pool_url).await.unwrap();
    sqlx::migrate!().run(&pool).await?;

    let (watcher, mut file_event_receiver) = async_watcher().unwrap();
    let watcher = Arc::new(RwLock::new(watcher));

    let sock = Arc::new(Mutex::new(
        TcpStream::connect("::1:9999")
            .await
            .with_context(|| "error connecting to file server")?,
    ));

    log::info!("Initializing watcher");
    for path in sqlx::query!("select path from directories_to_watch")
        .fetch_all(&pool)
        .await?
        .into_iter()
        .map(|row| row.path)
    {
        let path = PathBuf::from(path);

        log::debug!("Adding directory to watch: {}", path.display());

        let watcher = &mut watcher.write().await;

        if let Err(err) = watcher.watch(&path, notify::RecursiveMode::Recursive) {
            match err.kind {
                notify::ErrorKind::Io(err) => match err.kind() {
                    io::ErrorKind::NotFound => {
                        let sock = &mut sock.lock().await;
                        let macaroon = macaroon.serialize(macaroon::Format::V2).unwrap();
                        remove_directory(&path, &pool, sock, &macaroon, watcher)
                            .await
                            .unwrap()
                    }
                    _ => panic!("{err}"),
                },
                _ => panic!("{err}"),
            };
        }
    }
    log::info!("Intialized watcher");

    let file_locks: Arc<DashMap<PathBuf, Mutex<()>>> = Arc::new(DashMap::new());

    tokio::task::spawn(ipc::server_loop(
        watcher.clone(),
        sock.clone(),
        macaroon.serialize(macaroon::Format::V2).unwrap(),
        pool.clone(),
    ));

    while let Some(event_result) = file_event_receiver.recv().await {
        let event = match event_result {
            Ok(event) => event,
            Err(e) => {
                log::error!("watch error: {:?}", e);
                continue;
            }
        };

        let add_files = || {
            event.paths.iter().cloned().for_each(|path| {
                let pool = pool.clone();
                let sock = sock.clone();
                let enc_key = enc_key.clone();
                let macaroon = macaroon.clone();
                let file_locks = file_locks.clone();

                tokio::spawn(async move {
                    let path = fs::canonicalize(path).await.unwrap();

                    trace!("Locking file {}", path.display());

                    // The file lock prevents us from modifying the same file at the same time on the daemon
                    let lock = file_locks.get(&path).unwrap_or_else(|| {
                        file_locks.insert(path.clone(), Mutex::new(()));
                        file_locks.get(&path).unwrap()
                    });
                    let _ = lock.lock().await;

                    if let Err(err) = add_file(
                        &path,
                        pool,
                        sock,
                        &enc_key,
                        &macaroon.serialize(macaroon::Format::V2).unwrap(),
                    )
                    .await
                    {
                        log::error!("Error while adding file: {err}");
                    };
                });
            })
        };

        let update_files = || {
            event.paths.iter().cloned().for_each(|path| {
                let pool = pool.clone();
                let sock = sock.clone();
                let enc_key = enc_key.clone();
                let macaroon = macaroon.clone();
                let file_locks = file_locks.clone();

                tokio::spawn(async move {
                    let path = fs::canonicalize(path).await.unwrap();

                    trace!("Locking file {}", path.display());

                    // The file lock prevents us from modifying the same file at the same time on the server
                    let lock = file_locks.get(&path).unwrap_or_else(|| {
                        file_locks.insert(path.clone(), Mutex::new(()));
                        file_locks.get(&path).unwrap()
                    });

                    let _ = lock.lock().await;

                    trace!("Locked file {}", path.display());

                    if let Err(err) = update_file(
                        &path,
                        pool,
                        sock,
                        &enc_key,
                        &macaroon.serialize(macaroon::Format::V2).unwrap(),
                    )
                    .await
                    {
                        log::error!("Error while updating file: {err}");
                    };
                });
            })
        };

        match event.kind {
            notify::EventKind::Access(_) => (),
            notify::EventKind::Create(CreateKind::File) => add_files(),
            notify::EventKind::Create(_) => (),
            notify::EventKind::Modify(_) => update_files(),
            notify::EventKind::Remove(_) => todo!(),
            notify::EventKind::Other => todo!(),
            notify::EventKind::Any => todo!(),
        }
    }

    Ok(())
}

#[derive(Error, Debug)]
pub enum AddFileErr {
    #[error("Already added file {0}")]
    AlreadyAddedFile(PathBuf),
    #[error("Unknown database error: {0}")]
    UnknownDBError(#[from] sqlx::Error),
    #[error("Already added this chunk: {0}")]
    AlreadyAddedChunk(ChunkID),
    #[error("IO error {0}")]
    IOError(#[from] std::io::Error),
    #[error("Error uploading file: {0}")]
    UploadFileErr(anyhow::Error),
}

async fn add_file(
    file_path: &Path,
    pool: SqlitePool,
    sock: Arc<Mutex<TcpStream>>,
    key: &EncryptionKey,
    macaroon: &str,
) -> Result<(), AddFileErr> {
    trace!("Adding file {}", file_path.display());
    let file_path = fs::canonicalize(file_path).await?;
    let file_path = file_path.to_str().unwrap();

    let mut file = fs::File::open(file_path).await?;
    trace!("Getting file header");
    let file_header = FileHeader::from_file(&mut file).await.unwrap();
    file.rewind().await?;

    trace!("Hashing file");
    let file_hash = hash_file(&mut file).await.unwrap();
    file.rewind().await?;

    sqlx::query!(
        r#"insert into files
            (file_path, hash, chunk_size)
            values ( ?, ?, ? )
        "#,
        file_path,
        file_hash,
        file_header.chunk_size,
    )
    .execute(&pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(ref err_box) => match err_box.kind() {
            sqlx::error::ErrorKind::UniqueViolation => {
                AddFileErr::AlreadyAddedFile(file_path.into())
            }
            _ => AddFileErr::UnknownDBError(err),
        },
        err => AddFileErr::UnknownDBError(err),
    })?;

    trace!("Inserting chunks");

    //TODO: batch job this
    for (chunk_id, chunk) in file_header.chunks.iter() {
        let indice: i64 = (*file_header.chunk_indices.get(chunk_id).unwrap())
            .try_into()
            .unwrap();

        let chunk_hash = ChunkHash::from_bytes(chunk.clone().hash.try_into().unwrap()).to_string();
        sqlx::query!(
            r#"insert into chunks
                (hash, id, chunk_size, indice, file_hash, nonce )
                values ( ?, ?, ?, ?, ?, ? )
            "#,
            chunk_hash,
            chunk_id,
            chunk.size,
            indice,
            file_hash,
            chunk.nonce,
        )
        .execute(&pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::Database(ref err_box) => match err_box.kind() {
                sqlx::error::ErrorKind::UniqueViolation => {
                    AddFileErr::AlreadyAddedFile(file_path.into())
                }
                _ => AddFileErr::UnknownDBError(err),
            },
            _ => AddFileErr::UnknownDBError(err),
        })?;
    }

    let sock = &mut sock.lock().await;
    upload_file(file_path, &file_header, sock, key, macaroon)
        .await
        .map_err(AddFileErr::UploadFileErr)?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum UpdateFileErr {
    #[error("IO error: {0}")]
    IOErr(#[from] std::io::Error),
    #[error("Unknown database error: {0}")]
    UnknownDBError(#[from] sqlx::Error),
}

async fn update_file(
    file_path: &Path,
    pool: SqlitePool,
    sock: Arc<Mutex<TcpStream>>,
    key: &EncryptionKey,
    macaroon: &str,
) -> Result<(), UpdateFileErr> {
    trace!("Updating file {}", file_path.display());
    let file_path = file_path.absolutize().unwrap();
    let file_path_str = file_path.to_str().unwrap();

    let original_file_hash: FileHash =
        match sqlx::query!("select hash from files where file_path = ?", file_path_str)
            .fetch_one(&pool)
            .await
        {
            Ok(res) => res.hash.try_into().unwrap(),
            Err(err) => return Err(UpdateFileErr::UnknownDBError(err)),
        };

    let (file_header, file_hash) = {
        let mut file = File::open(file_path_str).await?;

        let file_header = FileHeader::from_file(&mut file).await.unwrap();
        file.rewind().await?;
        let file_hash = hash_file(&mut file).await.unwrap();

        (file_header, file_hash)
    };

    sqlx::query!(
        "update files set hash = ?, chunk_size = ? where file_path = ?",
        file_hash,
        file_header.chunk_size,
        file_path_str
    )
    .execute(&pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(err) => match err.kind() {
            sqlx::error::ErrorKind::UniqueViolation => {
                anyhow!("File already added")
            }
            _ => anyhow!("Unknown database error: {err:#}"),
        },
        _ => anyhow!("Unknown database error: {err:#}"),
    })
    .unwrap();

    {
        let sock = &mut sock.lock().await;
        delete_chunks(&original_file_hash, sock, macaroon, &pool)
            .await
            .unwrap();
    }

    trace!("Inserting chunks for file {file_path_str}");

    for (indice, (chunk_id, chunk)) in file_header.chunks.iter().enumerate() {
        let indice: i64 = indice.try_into().unwrap();
        sqlx::query!(
            r#"insert into chunks
                (hash, id, file_hash, chunk_size, indice, nonce)
                values ( ?, ?, ?, ?, ?, ? )
            "#,
            chunk.hash,
            chunk_id,
            file_header.hash,
            chunk.size,
            indice,
            chunk.nonce,
        )
        .execute(&pool)
        .await
        .unwrap();
    }

    let sock = &mut sock.lock().await;
    upload_file(file_path_str, &file_header, sock, key, macaroon)
        .await
        .unwrap();

    Ok(())
}

async fn remove_file(path: &Path, pool: SqlitePool) {
    todo!()
}

#[derive(Error, Debug)]
enum AddDirectoryErr {
    #[error("Not a directory")]
    NotADirectory,
    #[error("Error executing SQL while adding directory {0}")]
    SqlError(#[from] sqlx::Error),
}

async fn add_directory(
    dir: &Path,
    pool: &SqlitePool,
    watcher: &mut INotifyWatcher,
) -> Result<(), AddDirectoryErr> {
    trace!("Adding directory {}", dir.display());
    if !dir.is_dir() {
        return Err(AddDirectoryErr::NotADirectory);
    }

    let dir_str = dir.to_str().unwrap();
    sqlx::query!(
        "insert into directories_to_watch (path) values (?)",
        dir_str
    )
    .execute(pool)
    .await?;

    watcher
        .watch(dir, notify::RecursiveMode::Recursive)
        .unwrap();

    Ok(())
}

async fn remove_directory(
    dir: &Path,
    pool: &SqlitePool,
    sock: &mut TcpStream,
    macaroon: &str,
    watcher: &mut INotifyWatcher,
) -> Result<(), AddDirectoryErr> {
    trace!("Removing directory {}", dir.display());
    if let Ok(meta) = fs::metadata(dir).await {
        if !meta.is_dir() {
            return Err(AddDirectoryErr::NotADirectory);
        }
    }

    let dir_str = dir.to_str().unwrap();
    sqlx::query!("delete from directories_to_watch where path = ?", dir_str)
        .execute(pool)
        .await?;

    delete_chunks_from_file_path(dir.to_str().unwrap(), sock, macaroon, pool)
        .await
        .unwrap();

    if let Err(err) = watcher.unwatch(dir) {
        match err.kind {
            notify::ErrorKind::PathNotFound | notify::ErrorKind::WatchNotFound => (),
            _ => panic!("{err}"),
        }
    }

    Ok(())
}

#[derive(Error, Debug)]
pub enum FileHeaderFromPathErr {
    #[error("Database error: {0}")]
    SqlxError(#[from] sqlx::Error),
}

// Constructs the file header from the path, using the database
async fn file_header_from_db(
    path: &Path,
    pool: &SqlitePool,
) -> Result<FileHeader, FileHeaderFromPathErr> {
    let file_info = sqlx::query("select hash, file_path from files where file_path = ?")
        .bind(path.to_str().unwrap())
        .fetch_one(pool)
        .await?;

    let file_hash: FileHash = file_info.get::<String, _>("hash").try_into().unwrap();
    let file_path = file_info.get::<&str, _>("file_path");

    let chunks =
        sqlx::query("select hash, id, chunk_size, indice, nonce from chunks where file_hash = ?")
            .bind(&file_hash)
            .fetch_all(pool)
            .await?;

    let chunks = chunks.into_iter().map(|chunk| {
        let chunk_id: ChunkID = chunk.get::<String, _>("id").try_into().unwrap();
        let chunk_hash: ChunkHash = chunk.get::<String, _>("hash").try_into().unwrap();
        ChunkMetadata {
            id: chunk_id.to_bytes().to_vec(),
            hash: chunk_hash.to_bytes().to_vec(),
            size: chunk.get::<u32, _>("chunk_size"),
            indice: chunk.get::<i64, _>("indice").try_into().unwrap(),
            nonce: chunk.get::<Vec<u8>, _>("nonce"),
        }
    });

    let chunk_indices: HashMap<ChunkID, u64> =
        sqlx::query("select indice, id from chunks where file_hash = ?")
            .bind(&file_hash)
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|chunk_info| {
                let chunk_id: ChunkID = chunk_info.get::<String, _>("id").try_into().unwrap();
                let chunk_indice: u64 = chunk_info.get::<i64, _>("indice").try_into().unwrap();

                (chunk_id, chunk_indice)
            })
            .collect();

    let chunks = chunks
        .into_iter()
        .map(|chunk| {
            (
                ChunkID::from_bytes(chunk.id.clone().try_into().unwrap()),
                chunk,
            )
        })
        .collect();

    let file_info = sqlx::query("select hash, chunk_size from files where file_path = ?")
        .bind(file_path)
        .fetch_one(pool)
        .await?;

    Ok(FileHeader {
        hash: file_info.get::<String, _>("hash").try_into().unwrap(),
        chunk_size: file_info.get::<u32, _>("chunk_size"),
        chunks,
        chunk_indices,
    })
}

#[derive(Error, Debug)]
enum ListDirectoryError {
    #[error("Unknown database error: {0}")]
    UnknownDBError(#[from] sqlx::Error),
}

async fn list_directory(
    dir: &Path,
    pool: &SqlitePool,
) -> Result<DirectoryListing, ListDirectoryError> {
    let path_query = dir.to_str().unwrap().to_owned() + "%";

    let listings = sqlx::query!(
        "select hash, file_path from files where file_path like ?",
        path_query,
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|file_info| async move {
        let file_path = PathBuf::try_from(file_info.file_path).unwrap();

        let total_chunks = sqlx::query!(
            "select count(*) as count from chunks where file_hash = ?",
            file_info.hash
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .count;

        let chunks_uploaded = sqlx::query!(
            "select count(*) as count from chunks where file_hash = ? and uploaded = true",
            file_info.hash
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .count;

        let path_in_dir_somewhere: bool = {
            let mut path_in_dir_somewhere = false;
            let mut file_path = file_path.as_path();

            while let Some(parent) = file_path.parent() {
                if parent == dir {
                    path_in_dir_somewhere = true;
                }

                file_path = parent;
            }

            path_in_dir_somewhere
        };

        match path_in_dir_somewhere {
            true => Some(directory_listing::File {
                path: file_path.to_str().unwrap().to_string(),
                chunks_uploaded,
                total_chunks,
            }),
            false => None,
        }
    });

    let files = futures::future::join_all(listings)
        .await
        .into_iter()
        .flatten()
        .collect();

    Ok(DirectoryListing { file: files })
}
