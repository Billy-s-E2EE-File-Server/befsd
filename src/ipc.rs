use std::{path::PathBuf, str::FromStr, sync::Arc};

use futures::{AsyncReadExt, AsyncWriteExt};
use interprocess::local_socket::{
    tokio::{LocalSocketListener, LocalSocketStream},
    NameTypeSupport,
};
use notify::INotifyWatcher;
use path_absolutize::Absolutize;
use sqlx::SqlitePool;
use thiserror::Error;

use bfsp::{
    ipc::{self},
    Message, PrependLen,
};
use tokio::{
    net::TcpStream,
    sync::{Mutex, RwLock},
};

use crate::{add_directory, list_directory, remove_directory, AddDirectoryErr, ListDirectoryError};

#[derive(Error, Debug)]
pub enum IPCServerError {
    #[error("Couldn't bind to socket")]
    BindErr(#[from] std::io::Error),
    #[error("The server is already running")]
    ServerAlreadyRunning,
}

pub async fn server_loop(
    watcher: Arc<RwLock<INotifyWatcher>>,
    sock: Arc<Mutex<TcpStream>>,
    macaroon: String,
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

        let sock = sock.clone();
        let macaroon = macaroon.clone();
        tokio::task::spawn(async move {
            if let Err(e) = handle_conn(conn, sock, macaroon, watcher, pool).await {
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
    #[error(transparent)]
    ListDirectoryError(#[from] ListDirectoryError),
}

async fn handle_conn(
    sock: LocalSocketStream,
    server_sock: Arc<Mutex<TcpStream>>,
    macaroon: String,
    watcher: Arc<RwLock<INotifyWatcher>>,
    pool: SqlitePool,
) -> Result<(), HandleIPCConnErr> {
    let (mut reader, mut writer) = sock.into_split();

    let mut len = [0u8; 4];
    println!("Reading len");
    reader.read_exact(&mut len).await?;
    let len: u32 = u32::from_le_bytes(len[..].try_into().unwrap());

    println!("Reading msg of len {len}");
    let mut msg = vec![0; len as usize];
    reader.read_exact(&mut msg).await?;

    let msg = ipc::IpcMessage::decode(msg.as_slice()).map_err(|_| HandleIPCConnErr::DecodeError)?;

    match msg.message.ok_or(HandleIPCConnErr::NoIPCMessage)? {
        ipc::ipc_message::Message::AddDirectory(info) => {
            let path = PathBuf::from_str(&info.directory).unwrap();
            let path = path.absolutize().unwrap();
            add_directory(&path, &pool, &mut *watcher.write().await).await?;
        }
        ipc::ipc_message::Message::RemoveDirectory(info) => {
            let path = PathBuf::from_str(&info.directory).unwrap();
            let path = path.absolutize().unwrap();

            let server_sock = &mut server_sock.lock().await;

            remove_directory(
                &path,
                &pool,
                server_sock,
                &macaroon,
                &mut *watcher.write().await,
            )
            .await?;
        }
        ipc::ipc_message::Message::ListDirectory(info) => {
            let path = PathBuf::from_str(&info.directory).unwrap();
            let path = path.absolutize().unwrap();
            let dir_listing = list_directory(&path, &pool).await?;

            writer
                .write_all(dir_listing.encode_to_vec().prepend_len().as_slice())
                .await?;
        }
    }

    Ok(())
}
