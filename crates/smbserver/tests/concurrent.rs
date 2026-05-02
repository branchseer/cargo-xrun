//! Concurrent-connection tests: one Server handling multiple
//! simultaneous client connections, each with isolated per-connection
//! state but a shared backing filesystem.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb::ReadAt;
use smb_fscc::FileAccessMask;

#[tokio::test]
#[ntest::timeout(5000)]
async fn two_concurrent_clients_read_same_file() {
    let mut fs = InMemoryFs::new();
    fs.add_file("shared.txt", b"shared content".to_vec());

    let server = smbserver::Server::builder().share("public", fs).build();

    // Spawn the same server twice on two independent duplex pipes.
    let (client_a, server_a) = tokio::io::duplex(64 * 1024);
    let (client_b, server_b) = tokio::io::duplex(64 * 1024);
    let task_a = {
        let s = server.clone();
        tokio::spawn(async move { let _ = s.serve_connection(server_a).await; })
    };
    let task_b = {
        let s = server.clone();
        tokio::spawn(async move { let _ = s.serve_connection(server_b).await; })
    };

    // Drive both clients concurrently. We pin the futures and await with
    // join so smb-rs round-trips can interleave.
    let client_a_work = async move {
        let (conn, session, tree) =
            connect_and_tree_connect(client_a, r"\\test-server\public").await;
        let resource = tree
            .open_existing("shared.txt", FileAccessMask::new().with_file_read_data(true))
            .await
            .expect("client A: open failed");
        let file = resource.unwrap_file();
        let mut buf = vec![0u8; 64];
        let n = file.read_at(&mut buf, 0).await.expect("client A: read failed");
        buf.truncate(n);
        drop(file);
        drop(tree);
        drop(session);
        drop(conn);
        buf
    };
    let client_b_work = async move {
        let (conn, session, tree) =
            connect_and_tree_connect(client_b, r"\\test-server\public").await;
        let resource = tree
            .open_existing("shared.txt", FileAccessMask::new().with_file_read_data(true))
            .await
            .expect("client B: open failed");
        let file = resource.unwrap_file();
        let mut buf = vec![0u8; 64];
        let n = file.read_at(&mut buf, 0).await.expect("client B: read failed");
        buf.truncate(n);
        drop(file);
        drop(tree);
        drop(session);
        drop(conn);
        buf
    };

    let (a_buf, b_buf) = tokio::join!(client_a_work, client_b_work);

    assert_eq!(&a_buf, b"shared content");
    assert_eq!(&b_buf, b"shared content");

    task_a.abort();
    task_b.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn writer_and_reader_on_separate_connections_see_consistent_data() {
    let mut fs = InMemoryFs::new();
    fs.add_file("buf.bin", b"AAAAAAAA".to_vec());
    let fs_for_assert = fs.clone();

    let server = smbserver::Server::builder().share("public", fs).build();
    let (client_w, server_w) = tokio::io::duplex(64 * 1024);
    let (client_r, server_r) = tokio::io::duplex(64 * 1024);
    let task_w = {
        let s = server.clone();
        tokio::spawn(async move { let _ = s.serve_connection(server_w).await; })
    };
    let task_r = {
        let s = server.clone();
        tokio::spawn(async move { let _ = s.serve_connection(server_r).await; })
    };

    // Writer connection: replace bytes 2-5 with "BBBB".
    {
        let (conn, session, tree) =
            connect_and_tree_connect(client_w, r"\\test-server\public").await;
        let resource = tree
            .open_existing(
                "buf.bin",
                FileAccessMask::new().with_file_write_data(true),
            )
            .await
            .expect("writer: open failed");
        let file = resource.unwrap_file();
        use smb::WriteAt;
        file.write_at(b"BBBB", 2).await.expect("writer: write failed");
        file.handle().close().await.expect("writer: close failed");
        drop(file);
        drop(tree);
        drop(session);
        drop(conn);
    }

    // Reader connection (separate ConnectionState in the server): observe
    // the writer's mutation through the shared InMemoryFs.
    let buf = {
        let (conn, session, tree) =
            connect_and_tree_connect(client_r, r"\\test-server\public").await;
        let resource = tree
            .open_existing(
                "buf.bin",
                FileAccessMask::new().with_file_read_data(true),
            )
            .await
            .expect("reader: open failed");
        let file = resource.unwrap_file();
        let mut buf = vec![0u8; 8];
        let n = file.read_at(&mut buf, 0).await.expect("reader: read failed");
        buf.truncate(n);
        drop(file);
        drop(tree);
        drop(session);
        drop(conn);
        buf
    };

    assert_eq!(&buf, b"AABBBBAA");
    assert_eq!(fs_for_assert.snapshot("buf.bin").as_deref(), Some(b"AABBBBAA".as_ref()));

    task_w.abort();
    task_r.abort();
}
