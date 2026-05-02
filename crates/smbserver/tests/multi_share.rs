//! Multi-share routing tests.
//!
//! Verifies the server's share registry: a single Server can host
//! multiple distinct filesystems addressed by share name, and
//! unknown shares are rejected at TREE_CONNECT time.

mod common;

use std::str::FromStr;

use common::{guest_identity, DuplexTransport, InMemoryFs};
use smb::{Connection, ConnectionConfig, Guid, ReadAt, UncPath};
use smb_fscc::FileAccessMask;

#[tokio::test]
#[ntest::timeout(5000)]
async fn distinct_shares_serve_distinct_filesystems() {
    let mut public_fs = InMemoryFs::new();
    public_fs.add_file("greeting.txt", b"hello from public".to_vec());

    let mut private_fs = InMemoryFs::new();
    private_fs.add_file("greeting.txt", b"hello from private".to_vec());

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder()
        .share("public", public_fs)
        .share("private", private_fs)
        .build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let transport = Box::new(DuplexTransport::new(client_io));
    let conn = Connection::from_transport(
        transport,
        "test-server",
        Guid::generate(),
        ConnectionConfig {
            smb2_only_negotiate: true,
            allow_unsigned_guest_access: true,
            ..ConnectionConfig::default()
        },
    )
    .await
    .expect("NEGOTIATE failed");
    let session = conn.authenticate(guest_identity()).await.expect("SESSION_SETUP failed");

    // Connect to both shares concurrently on the same session.
    let public_tree = session
        .tree_connect(&UncPath::from_str(r"\\test-server\public").unwrap())
        .await
        .expect("TREE_CONNECT public failed");
    let private_tree = session
        .tree_connect(&UncPath::from_str(r"\\test-server\private").unwrap())
        .await
        .expect("TREE_CONNECT private failed");

    let read_share = |tree: smb::Tree, expected: &'static [u8]| async move {
        let resource = tree
            .open_existing(
                "greeting.txt",
                FileAccessMask::new().with_file_read_data(true),
            )
            .await
            .expect("open greeting.txt failed");
        let file = resource.unwrap_file();
        let mut buf = vec![0u8; 64];
        let n = file.read_at(&mut buf, 0).await.expect("READ failed");
        buf.truncate(n);
        assert_eq!(&buf, expected);
        drop(file);
        tree
    };

    let public_tree = read_share(public_tree, b"hello from public").await;
    let private_tree = read_share(private_tree, b"hello from private").await;

    drop(public_tree);
    drop(private_tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn unknown_share_returns_bad_network_name() {
    let fs = InMemoryFs::new();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().share("public", fs).build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let transport = Box::new(DuplexTransport::new(client_io));
    let conn = Connection::from_transport(
        transport,
        "test-server",
        Guid::generate(),
        ConnectionConfig {
            smb2_only_negotiate: true,
            allow_unsigned_guest_access: true,
            ..ConnectionConfig::default()
        },
    )
    .await
    .expect("NEGOTIATE failed");
    let session = conn.authenticate(guest_identity()).await.expect("SESSION_SETUP failed");

    let result = session
        .tree_connect(&UncPath::from_str(r"\\test-server\nope").unwrap())
        .await;
    let err = match result {
        Ok(_) => panic!("expected TREE_CONNECT to fail for unknown share"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("network")
            || msg.to_lowercase().contains("bad")
            || msg.contains("c00000cc"),
        "unexpected error message: {msg}"
    );

    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn share_lookup_is_case_insensitive() {
    let mut fs = InMemoryFs::new();
    fs.add_file("hi.txt", b"hi".to_vec());

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().share("Public", fs).build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let transport = Box::new(DuplexTransport::new(client_io));
    let conn = Connection::from_transport(
        transport,
        "test-server",
        Guid::generate(),
        ConnectionConfig {
            smb2_only_negotiate: true,
            allow_unsigned_guest_access: true,
            ..ConnectionConfig::default()
        },
    )
    .await
    .expect("NEGOTIATE failed");
    let session = conn.authenticate(guest_identity()).await.expect("SESSION_SETUP failed");

    // Registered as "Public", connect via lowercase "public".
    let tree = session
        .tree_connect(&UncPath::from_str(r"\\test-server\PUBLIC").unwrap())
        .await
        .expect("TREE_CONNECT case-insensitive failed");

    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
