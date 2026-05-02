//! File write tests against an in-memory filesystem.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb::{ReadAt, WriteAt};
use smb_fscc::FileAccessMask;

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_write_overwrites_existing_bytes() {
    let mut fs = InMemoryFs::new();
    fs.add_file("notes.txt", b"Hello, world!".to_vec());
    let fs_for_assert = fs.clone();

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().share("public", fs).build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let (conn, session, tree) =
        connect_and_tree_connect(client_io, r"\\test-server\public").await;

    let resource = tree
        .open_existing(
            "notes.txt",
            FileAccessMask::new()
                .with_file_read_data(true)
                .with_file_write_data(true),
        )
        .await
        .expect("open notes.txt failed");
    let file = resource.unwrap_file();

    // "Hello, world!" → "Hello, SMB!!!" (overwrite "world" → "SMB!!")
    let n = file
        .write_at(b"SMB!!", 7)
        .await
        .expect("WRITE failed");
    assert_eq!(n, 5);

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();

    assert_eq!(
        fs_for_assert.snapshot("notes.txt").as_deref(),
        Some(b"Hello, SMB!!!".as_ref()),
    );
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_reads_back_what_it_just_wrote() {
    let mut fs = InMemoryFs::new();
    fs.add_file("rw.txt", b"AAAAAAAA".to_vec());

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().share("public", fs).build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let (conn, session, tree) =
        connect_and_tree_connect(client_io, r"\\test-server\public").await;

    let resource = tree
        .open_existing(
            "rw.txt",
            FileAccessMask::new()
                .with_file_read_data(true)
                .with_file_write_data(true),
        )
        .await
        .expect("open rw.txt failed");
    let file = resource.unwrap_file();

    file.write_at(b"BBBB", 2).await.expect("WRITE failed");

    let mut buf = vec![0u8; 8];
    let n = file.read_at(&mut buf, 0).await.expect("READ failed");
    buf.truncate(n);
    assert_eq!(&buf, b"AABBBBAA");

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_write_extends_file_past_eof() {
    let mut fs = InMemoryFs::new();
    fs.add_file("growing.bin", b"abc".to_vec());
    let fs_for_assert = fs.clone();

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().share("public", fs).build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let (conn, session, tree) =
        connect_and_tree_connect(client_io, r"\\test-server\public").await;

    let resource = tree
        .open_existing(
            "growing.bin",
            FileAccessMask::new()
                .with_file_read_data(true)
                .with_file_write_data(true),
        )
        .await
        .expect("open growing.bin failed");
    let file = resource.unwrap_file();

    // Write past EOF; bytes between original end and offset are zero-filled.
    let n = file.write_at(b"XYZ", 8).await.expect("WRITE failed");
    assert_eq!(n, 3);

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();

    let snap = fs_for_assert.snapshot("growing.bin").expect("file exists");
    assert_eq!(snap.len(), 11);
    assert_eq!(&snap[..3], b"abc");
    assert_eq!(&snap[3..8], &[0; 5]);
    assert_eq!(&snap[8..], b"XYZ");
}
