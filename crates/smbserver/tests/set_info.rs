//! SET_INFO tests — truncate, delete-on-close, rename.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb_fscc::{
    FileAccessMask, FileDispositionInformation, FileEndOfFileInformation, FileRenameInformation,
};

#[tokio::test]
#[ntest::timeout(5000)]
async fn set_end_of_file_truncates_existing_file() {
    let mut fs = InMemoryFs::new();
    fs.add_file("big.bin", vec![0xAB; 1000]);
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
            "big.bin",
            FileAccessMask::new()
                .with_file_read_data(true)
                .with_file_write_data(true)
                .with_file_write_attributes(true),
        )
        .await
        .expect("open big.bin failed");
    let file = resource.unwrap_file();

    file.handle()
        .set_info(FileEndOfFileInformation { end_of_file: 100 })
        .await
        .expect("SET_INFO end_of_file failed");

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();

    let snap = fs_for_assert.snapshot("big.bin").expect("file exists");
    assert_eq!(snap.len(), 100);
    assert!(snap.iter().all(|&b| b == 0xAB));
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn set_disposition_deletes_file_on_close() {
    let mut fs = InMemoryFs::new();
    fs.add_file("ephemeral.txt", b"goodbye".to_vec());
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
            "ephemeral.txt",
            FileAccessMask::new()
                .with_file_read_data(true)
                .with_delete(true),
        )
        .await
        .expect("open ephemeral.txt failed");
    let file = resource.unwrap_file();

    file.handle()
        .set_info(FileDispositionInformation { delete_pending: true.into() })
        .await
        .expect("SET_INFO disposition failed");

    file.handle()
        .close()
        .await
        .expect("CLOSE failed");
    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();

    assert!(
        fs_for_assert.snapshot("ephemeral.txt").is_none(),
        "file should have been deleted on close"
    );
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn set_rename_moves_file_to_new_path() {
    let mut fs = InMemoryFs::new();
    fs.add_file("old_name.txt", b"contents stay".to_vec());
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
            "old_name.txt",
            FileAccessMask::new()
                .with_file_read_data(true)
                .with_delete(true),
        )
        .await
        .expect("open old_name.txt failed");
    let file = resource.unwrap_file();

    let rename = FileRenameInformation {
        replace_if_exists: false.into(),
        root_directory: 0,
        file_name: "new_name.txt".into(),
    };
    file.handle()
        .set_info(rename)
        .await
        .expect("SET_INFO rename failed");

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();

    assert!(fs_for_assert.snapshot("old_name.txt").is_none());
    assert_eq!(
        fs_for_assert.snapshot("new_name.txt").as_deref(),
        Some(b"contents stay".as_ref()),
    );
}
