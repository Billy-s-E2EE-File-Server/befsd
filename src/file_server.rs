use anyhow::{anyhow, Context, Result};
use bfsp::Message as FileMessage;
use bfsp::{
    cli::{compressed_encrypted_chunk_from_file, FileHeader},
    file_server_message::{Authentication, Message, UploadChunkQuery},
    ChunkID, EncryptionKey, FileServerMessage, UploadChunkResp,
};
use log::trace;
use macaroon::Macaroon;
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
    {
        let macaroon = Macaroon::deserialize(macaroon).unwrap();
        macaroon.caveats().into_iter().for_each(|caveat| {
            let bstring = match caveat {
                macaroon::Caveat::FirstParty(b) => b.predicate(),
                macaroon::Caveat::ThirdParty(b) => todo!(),
            };

            println!("Caveat: {:?}", bstring.to_string());
        });
    }

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
