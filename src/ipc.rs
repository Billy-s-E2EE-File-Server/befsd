use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};

use futures::AsyncReadExt;
use interprocess::local_socket::{
    tokio::{LocalSocketListener, LocalSocketStream},
    NameTypeSupport,
};
use notify::INotifyWatcher;
use sqlx::SqlitePool;
use thiserror::Error;

use bfsp::{
    ipc::{self},
    Message,
};
use tokio::{
    fs,
    sync::{Mutex, RwLock},
};

use crate::{add_directory, remove_directory, AddDirectoryErr};

#[derive(Error, Debug)]
pub enum IPCServerError {
    #[error("Couldn't bind to socket")]
    BindErr(#[from] std::io::Error),
    #[error("The server is already running")]
    ServerAlreadyRunning,
}

pub async fn server_loop(
    watcher: Arc<RwLock<INotifyWatcher>>,
    pool: SqlitePool,
) -> Result<(), IPCServerError> {
    let name = {
        match NameTypeSupport::query() {
            NameTypeSupport::OnlyPaths => "/tmp/befsd.sock",
            NameTypeSupport::OnlyNamespaced | NameTypeSupport::Both => "@befsd.sock",
        }
    };

    // TODO: check if server is already running
    let listener = LocalSocketListener::bind(name)?;

    loop {
        let conn = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("Error accepting connection: {}", e);
                continue;
            }
        };

        let watcher = watcher.clone();
        let pool = pool.clone();

        tokio::task::spawn(async move {
            if let Err(e) = handle_conn(conn, watcher, pool).await {
                eprintln!("Error while handling connection: {}", e);
            }
        });
    }
}

#[derive(Error, Debug)]
enum HandleIPCConnErr {
    #[error("Error reading from socket")]
    ReadErr(#[from] std::io::Error),
    #[error("Failed to decode IpcMessage")]
    DecodeError,
    #[error("No message in IpcMessage")]
    NoIPCMessage,
    #[error(transparent)]
    AddDirectoryError(#[from] AddDirectoryErr),
}

async fn handle_conn(
    sock: LocalSocketStream,
    watcher: Arc<RwLock<INotifyWatcher>>,
    pool: SqlitePool,
) -> Result<(), HandleIPCConnErr> {
    let (mut reader, _writer) = sock.into_split();

    let mut msg = Vec::new();
    reader.read_to_end(&mut msg).await?;

    let msg = ipc::IpcMessage::decode(msg.as_slice()).map_err(|_| HandleIPCConnErr::DecodeError)?;

    match msg.message.ok_or(HandleIPCConnErr::NoIPCMessage)? {
        ipc::ipc_message::Message::AddDirectory(info) => {
            let path = fs::canonicalize(&PathBuf::from_str(&info.directory).unwrap()).await?;
            add_directory(&path, &pool, &mut *watcher.write().await).await?;
        }
        ipc::ipc_message::Message::RemoveDirectory(info) => {
            let path = fs::canonicalize(&PathBuf::from_str(&info.directory).unwrap()).await?;
            remove_directory(&path, &pool, &mut *watcher.write().await).await?;
        }
    }

    Ok(())
}
