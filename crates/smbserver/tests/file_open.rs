//! File open tests against an in-memory filesystem.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb_fscc::FileAccessMask;

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_can_open_existing_file() {
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
        .expect("CREATE for hello.txt failed");

    drop(resource);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn opening_directory_as_file_returns_file_is_a_directory() {
    let mut fs = InMemoryFs::new();
    // Create an inferred directory by putting a file inside.
    fs.add_file("docs/readme.md", b"hi".to_vec());

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

    use smb::{CreateDisposition, CreateOptions, FileAttributes, FileCreateArgs};
    let result = tree
        .create(
            "docs",
            &FileCreateArgs {
                disposition: CreateDisposition::Open,
                options: CreateOptions::new().with_non_directory_file(true),
                attributes: FileAttributes::new(),
                desired_access: FileAccessMask::new().with_file_read_data(true),
            },
        )
        .await;
    let err = match result {
        Ok(_) => panic!("expected CREATE to fail with FILE_IS_A_DIRECTORY"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("directory") || msg.contains("c00000ba"),
        "unexpected error message: {msg}"
    );

    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn opening_file_as_directory_returns_not_a_directory() {
    let mut fs = InMemoryFs::new();
    fs.add_file("plain.txt", b"hi".to_vec());

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

    use smb::{CreateDisposition, CreateOptions, FileAttributes, FileCreateArgs};
    let result = tree
        .create(
            "plain.txt",
            &FileCreateArgs {
                disposition: CreateDisposition::Open,
                options: CreateOptions::new().with_directory_file(true),
                attributes: FileAttributes::new(),
                desired_access: FileAccessMask::new().with_file_read_data(true),
            },
        )
        .await;
    let err = match result {
        Ok(_) => panic!("expected CREATE to fail with NOT_A_DIRECTORY"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("directory") || msg.contains("c0000103"),
        "unexpected error message: {msg}"
    );

    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn missing_file_returns_object_name_not_found() {
    let fs = InMemoryFs::new(); // empty

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

    let result = tree
        .open_existing(
            "nope.txt",
            FileAccessMask::new().with_file_read_data(true),
        )
        .await;
    let err = match result {
        Ok(_) => panic!("expected CREATE to fail for missing file"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("not found")
            || msg.to_lowercase().contains("no such file")
            || msg.contains("c0000034"),
        "unexpected error message: {msg}"
    );

    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
