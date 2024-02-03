create table files (
    file_path text primary key not null,
    hash text not null unique,
    chunk_size int not null
);
