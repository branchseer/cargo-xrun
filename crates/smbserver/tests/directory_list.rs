//! Directory listing tests.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use futures_util::StreamExt;
use smb::{CreateDisposition, CreateOptions, FileAttributes, FileCreateArgs};
use smb_fscc::{FileAccessMask, FileBothDirectoryInformation};

fn open_existing_directory_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Open,
        options: CreateOptions::new().with_directory_file(true),
        attributes: FileAttributes::new(),
        desired_access: FileAccessMask::new().with_file_read_data(true),
    }
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_lists_root_directory() {
    let mut fs = InMemoryFs::new();
    fs.add_file("alpha.txt", b"a".to_vec());
    fs.add_file("beta.bin", b"bb".to_vec());
    fs.add_file("gamma/inner.dat", b"ccc".to_vec());

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
        .create("", &open_existing_directory_args())
        .await
        .expect("open root directory failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    let entries: Vec<(String, bool)> = {
        let stream = smb::Directory::query::<FileBothDirectoryInformation>(&dir, "*")
            .await
            .expect("QUERY_DIRECTORY failed");
        futures_util::pin_mut!(stream);
        let mut acc = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.expect("entry decode failed");
            acc.push((entry.file_name.to_string(), entry.file_attributes.directory()));
        }
        acc
    };

    assert_eq!(
        entries,
        vec![
            ("alpha.txt".to_string(), false),
            ("beta.bin".to_string(), false),
            ("gamma".to_string(), true),
        ]
    );

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_lists_subdirectory() {
    let mut fs = InMemoryFs::new();
    fs.add_file("docs/readme.md", b"hi".to_vec());
    fs.add_file("docs/changelog.md", b"hi".to_vec());
    fs.add_file("other.bin", b"x".to_vec());

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
        .create("docs", &open_existing_directory_args())
        .await
        .expect("open docs directory failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    let names: Vec<String> = {
        let stream = smb::Directory::query::<FileBothDirectoryInformation>(&dir, "*")
            .await
            .expect("QUERY_DIRECTORY failed");
        futures_util::pin_mut!(stream);
        let mut acc = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.expect("entry decode failed");
            acc.push(entry.file_name.to_string());
        }
        acc
    };

    assert_eq!(names, vec!["changelog.md".to_string(), "readme.md".to_string()]);

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
