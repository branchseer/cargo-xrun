//! QUERY_INFO tests — file metadata classes.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb_fscc::{
    FileAccessMask, FileAllInformation, FileBasicInformation, FileNetworkOpenInformation,
    FileStandardInformation,
};

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_standard_info_reports_correct_size() {
    let mut fs = InMemoryFs::new();
    fs.add_file("ten.bin", b"0123456789".to_vec());

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
        .open_existing("ten.bin", FileAccessMask::new().with_file_read_attributes(true))
        .await
        .expect("open ten.bin failed");
    let file = resource.unwrap_file();

    let info: FileStandardInformation = file
        .handle()
        .query_info()
        .await
        .expect("QUERY_INFO Standard failed");
    assert_eq!(info.end_of_file, 10);
    assert_eq!(info.allocation_size, 10);
    assert_eq!(info.directory, false.into());

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_basic_info_returns_timestamps_set_by_filesystem() {
    let mut fs = InMemoryFs::new();
    // 2024-06-15 12:34:56 UTC in FILETIME (100ns ticks since 1601-01-01).
    let created = 0x01DAB_F8B6_2BAC_E000_u64;
    let modified = created + 60 * 10_000_000; // +6 seconds × 10^7 ticks
    fs.add_file_with_timestamps("dated.txt", b"hi".to_vec(), created, modified);

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
            "dated.txt",
            FileAccessMask::new().with_file_read_attributes(true),
        )
        .await
        .expect("open dated.txt failed");
    let file = resource.unwrap_file();

    let info: FileBasicInformation = file
        .handle()
        .query_info()
        .await
        .expect("QUERY_INFO Basic failed");
    assert_eq!(info.creation_time.since_epoch().as_nanos(), created as u128 * 100);
    assert_eq!(info.last_write_time.since_epoch().as_nanos(), modified as u128 * 100);

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_basic_info_reports_normal_attributes_for_file() {
    let mut fs = InMemoryFs::new();
    fs.add_file("file.txt", b"hi".to_vec());

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
        .open_existing("file.txt", FileAccessMask::new().with_file_read_attributes(true))
        .await
        .expect("open file.txt failed");
    let file = resource.unwrap_file();

    let info: FileBasicInformation = file
        .handle()
        .query_info()
        .await
        .expect("QUERY_INFO Basic failed");
    assert!(!info.file_attributes.directory());
    // Our default metadata reports zero timestamps; verify they're carried through.
    assert!(info.creation_time.is_zero());

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_all_information_returns_size_and_path() {
    let mut fs = InMemoryFs::new();
    fs.add_file("subdir/all.dat", vec![0u8; 42]);

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
            "subdir/all.dat",
            FileAccessMask::new().with_file_read_attributes(true),
        )
        .await
        .expect("open subdir/all.dat failed");
    let file = resource.unwrap_file();

    let info: FileAllInformation = file
        .handle()
        .query_info()
        .await
        .expect("QUERY_INFO All failed");
    assert_eq!(info.standard.end_of_file, 42);
    assert_eq!(info.standard.number_of_links, 1);
    assert!(!Into::<bool>::into(info.standard.directory));
    assert_eq!(info.name.file_name.to_string(), "subdir/all.dat");

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_network_open_info_carries_size_and_attributes() {
    let mut fs = InMemoryFs::new();
    fs.add_file("doc.bin", vec![0u8; 1234]);

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
        .open_existing("doc.bin", FileAccessMask::new().with_file_read_attributes(true))
        .await
        .expect("open doc.bin failed");
    let file = resource.unwrap_file();

    let info: FileNetworkOpenInformation = file
        .handle()
        .query_info()
        .await
        .expect("QUERY_INFO NetworkOpen failed");
    assert_eq!(info.end_of_file, 1234);
    assert_eq!(info.allocation_size, 1234);
    assert!(!info.file_attributes.directory());

    drop(file);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
