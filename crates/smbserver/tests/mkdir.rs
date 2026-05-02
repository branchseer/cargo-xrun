//! mkdir tests — CREATE with FILE_DIRECTORY_FILE option.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb::{CreateDisposition, CreateOptions, FileAttributes};
use smb_fscc::FileAccessMask;

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_creates_new_directory() {
    let fs = InMemoryFs::new();
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
        .create_directory(
            "newdir",
            CreateDisposition::Create,
            FileAccessMask::new().with_file_read_data(true),
        )
        .await
        .expect("CREATE_DIR failed");
    let dir = resource.unwrap_dir();

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();

    assert!(fs_for_assert.has_directory("newdir"));
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn opening_then_listing_a_freshly_created_dir_returns_empty() {
    let fs = InMemoryFs::new();

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

    // Create then re-open with disposition=Open + DirectoryFile.
    let resource = tree
        .create_directory(
            "empty_dir",
            CreateDisposition::Create,
            FileAccessMask::new().with_file_read_data(true),
        )
        .await
        .expect("CREATE_DIR failed");
    drop(resource);

    let resource = tree
        .create(
            "empty_dir",
            &smb::FileCreateArgs {
                disposition: CreateDisposition::Open,
                options: CreateOptions::new().with_directory_file(true),
                attributes: FileAttributes::new(),
                desired_access: FileAccessMask::new().with_file_read_data(true),
            },
        )
        .await
        .expect("re-open empty_dir failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    let entries: Vec<String> = {
        use futures_util::StreamExt;
        let stream =
            smb::Directory::query::<smb_fscc::FileBothDirectoryInformation>(&dir, "*")
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

    assert!(entries.is_empty(), "fresh directory should be empty, got {entries:?}");

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
