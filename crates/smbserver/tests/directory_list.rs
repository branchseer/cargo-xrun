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
async fn client_lists_with_glob_pattern_matches_extension() {
    let mut fs = InMemoryFs::new();
    fs.add_file("notes.txt", b"a".to_vec());
    fs.add_file("readme.txt", b"b".to_vec());
    fs.add_file("data.bin", b"c".to_vec());
    fs.add_file("image.png", b"d".to_vec());

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
        .expect("open root failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    let names: Vec<String> = {
        use futures_util::StreamExt;
        let stream = smb::Directory::query::<FileBothDirectoryInformation>(&dir, "*.txt")
            .await
            .expect("QUERY_DIRECTORY *.txt failed");
        futures_util::pin_mut!(stream);
        let mut acc = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.expect("entry decode failed");
            acc.push(entry.file_name.to_string());
        }
        acc
    };

    assert_eq!(names, vec!["notes.txt".to_string(), "readme.txt".to_string()]);

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn large_directory_paginates_across_multiple_round_trips() {
    let mut fs = InMemoryFs::new();
    // 200 entries with reasonably long names — far more than fits in
    // a small client-supplied buffer in one round-trip.
    for i in 0..200 {
        fs.add_file(format!("file_{i:04}.bin"), vec![0u8; 1]);
    }

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
        .expect("open root failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    // Use the Directory::query_with_options API so we can pass a small
    // buffer and force the server to paginate.
    let names: Vec<String> = {
        use futures_util::StreamExt;
        let stream = smb::Directory::query_with_options::<FileBothDirectoryInformation>(
            &dir, "*", 4096,
        )
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

    assert_eq!(names.len(), 200);
    // Names come back sorted (InMemoryFs::list_internal sorts).
    assert_eq!(names[0], "file_0000.bin");
    assert_eq!(names[199], "file_0199.bin");

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
