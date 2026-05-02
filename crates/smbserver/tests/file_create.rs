//! File create-disposition tests.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb::{CreateDisposition, CreateOptions, FileAttributes, FileCreateArgs, WriteAt};
use smb_fscc::FileAccessMask;

fn create_new_file_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Create,
        options: CreateOptions::new(),
        attributes: FileAttributes::new(),
        desired_access: FileAccessMask::new()
            .with_file_read_data(true)
            .with_file_write_data(true),
    }
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_creates_new_file_then_writes_to_it() {
    let fs = InMemoryFs::new();
    let fs_for_assert = fs.clone();

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().build(fs);
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let (conn, session, tree) =
        connect_and_tree_connect(client_io, r"\\test-server\public").await;

    let resource = tree
        .create("brand_new.txt", &create_new_file_args())
        .await
        .expect("CREATE for new file failed");
    let file = resource.unwrap_file();
    file.write_at(b"Just made this!", 0)
        .await
        .expect("WRITE failed");

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();

    assert_eq!(
        fs_for_assert.snapshot("brand_new.txt").as_deref(),
        Some(b"Just made this!".as_ref()),
    );
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn create_disposition_create_fails_when_file_exists() {
    let mut fs = InMemoryFs::new();
    fs.add_file("preexisting.txt", b"don't clobber me".to_vec());

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().build(fs);
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let (conn, session, tree) =
        connect_and_tree_connect(client_io, r"\\test-server\public").await;

    let result = tree
        .create("preexisting.txt", &create_new_file_args())
        .await;
    let err = match result {
        Ok(_) => panic!("expected CREATE to fail on existing file"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("collision")
            || msg.to_lowercase().contains("exist")
            || msg.contains("c0000035"),
        "unexpected error message: {msg}"
    );

    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
