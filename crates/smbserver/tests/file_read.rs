//! File read tests against an in-memory filesystem.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb::ReadAt;
use smb_fscc::FileAccessMask;

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_can_read_file_contents() {
    let mut fs = InMemoryFs::new();
    fs.add_file("hello.txt", b"Hello, SMB!".to_vec());

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
            "hello.txt",
            FileAccessMask::new().with_file_read_data(true),
        )
        .await
        .expect("open hello.txt failed");

    let file = resource.unwrap_file();

    let mut buf = vec![0u8; 64];
    let n = file
        .read_at(&mut buf, 0)
        .await
        .expect("READ failed");
    buf.truncate(n);
    assert_eq!(&buf, b"Hello, SMB!");

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_can_read_file_at_offset() {
    let mut fs = InMemoryFs::new();
    fs.add_file("greeting.txt", b"Hello, world!".to_vec());

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
            "greeting.txt",
            FileAccessMask::new().with_file_read_data(true),
        )
        .await
        .expect("open greeting.txt failed");

    let file = resource.unwrap_file();

    let mut buf = vec![0u8; 5];
    let n = file
        .read_at(&mut buf, 7) // skip "Hello, "
        .await
        .expect("READ at offset failed");
    buf.truncate(n);
    assert_eq!(&buf, b"world");

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
