create table files (
    file_path text primary key not null,
    hash text not null,
    chunk_size int not null,
    num_chunks int not null
);