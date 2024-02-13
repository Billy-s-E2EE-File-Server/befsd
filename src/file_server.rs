use std::collections::HashSet;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use bfsp::file_server_message::DeleteChunksQuery;
use bfsp::{
    cli::{compressed_encrypted_chunk_from_file, FileHeader},
    file_server_message::{Authentication, Message, UploadChunkQuery},
    ChunkID, EncryptionKey, FileServerMessage, UploadChunkResp,
};
use bfsp::{DeleteChunksResp, FileHash, Message as FileMessage, PrependLen};
use log::{debug, trace};
use macaroon::Macaroon;
use sqlx::{pool, QueryBuilder, SqlitePool};
use thiserror::Error;
use tokio::{
    fs::OpenOptions,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

// TODO: Use thiserror
pub async fn upload_file(
    file_path: &str,
    file_header: &FileHeader,
    sock: &mut TcpStream,
    key: &EncryptionKey,
    macaroon: &str,
) -> Result<()> {
    trace!("Uploading file");
    let chunks_to_upload = file_header.chunks.values();

    trace!("Uploading {} chunks", chunks_to_upload.len());
    let mut file = OpenOptions::new()
        .read(true)
        .open(file_path)
        .await
        .with_context(|| "Reading file for upload")?;

    file_header
        .chunks
        .keys()
        .for_each(|chunk_meta| log::debug!("{:?}", chunk_meta));
    // TODO: optimize with query_chunks_uploade
    for chunk_meta in chunks_to_upload {
        let chunk_id = ChunkID::from_bytes(chunk_meta.clone().id.try_into().unwrap());
        trace!("Uploading chunk {chunk_id}");

        let chunk =
            compressed_encrypted_chunk_from_file(file_header, &mut file, chunk_id, key).await?;

        let msg = FileServerMessage {
            auth: Some(Authentication {
                macaroon: macaroon.to_string(),
            }),
            message: Some(Message::UploadChunkQuery(UploadChunkQuery {
                chunk_metadata: Some(chunk_meta.clone()),
                chunk,
            })),
        };

        trace!("Writing to socket");
        sock.write_all(msg.to_bytes().as_slice()).await?;

        trace!("Reading response");
        let resp_len = sock.read_u32_le().await?;

        let mut resp_bytes = vec![0; resp_len.try_into().unwrap()];
        sock.read_exact(&mut resp_bytes).await?;

        let resp = UploadChunkResp::decode(resp_bytes.as_slice())
            .map_err(|_| anyhow!("Error deserializing UploadChunkResp"))?;
    }

    trace!("Uploaded file");

    Ok(())
}

#[derive(Debug, Error)]
pub enum DeleteChunksErr {}

pub async fn delete_chunks_from_file_path(
    file_path: &str,
    sock: &mut TcpStream,
    macaroon: &str,
    pool: &SqlitePool,
) -> Result<()> {
    debug!("Deleting chunks from file_path {file_path}");
    let path_query = file_path.to_owned() + "%";

    let file_hash: FileHash =
        sqlx::query!("select hash from files where file_path like ?", path_query,)
            .fetch_one(pool)
            .await?
            .hash
            .try_into()
            .with_context(|| anyhow!("Error getting has from file_path: {file_path}"))?;

    delete_chunks(&file_hash, sock, macaroon, pool).await
}

/// Delete the chunks locally and on the server, but don't delete the file_header
pub async fn delete_chunks(
    file_hash: &FileHash,
    sock: &mut TcpStream,
    macaroon: &str,
    pool: &SqlitePool,
) -> Result<()> {
    trace!("Deleting chunks");
    trace!("Deleting chunks locally");

    let chunks_to_delete = sqlx::query!(
        "delete from chunks where file_hash = ? returning id",
        file_hash
    )
    .fetch_all(pool)
    .await
    .with_context(|| anyhow!("Failed deleting chunks with file_hash {file_hash}"))?
    .into_iter()
    .map(|row| ChunkID::try_from(row.id).unwrap().to_bytes().to_vec())
    .collect::<Vec<_>>();

    trace!("Deleting chunks on server");
    let msg = FileServerMessage {
        auth: Some(Authentication {
            macaroon: macaroon.to_string(),
        }),
        message: Some(Message::DeleteChunksQuery(DeleteChunksQuery {
            chunk_ids: chunks_to_delete,
        })),
    }
    .encode_to_vec()
    .prepend_len();

    sock.write_all(&msg).await?;

    let resp_len = sock.read_u32_le().await?;
    let mut msg = vec![0; resp_len as usize];
    sock.read_exact(&mut msg).await?;

    let resp = DeleteChunksResp::decode(msg.as_slice())
        .map_err(|_| anyhow!("Error deserializing DeleteChunksResp"))?;

    trace!("Deleted chunks");

    Ok(())
}
