create table chunks (
    hash text primary key unique not null,
    id text unique not null,
    indice int not null,
    chunk_size int not null,
    file_hash text not null,
    nonce blob not null
)

