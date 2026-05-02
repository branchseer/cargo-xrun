//! QUERY_INFO type=FILESYSTEM tests — volume metadata.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb_fscc::{
    FileAccessMask, FileFsAttributeInformation, FileFsFullSizeInformation,
    FileFsSizeInformation, FileFsVolumeInformation,
};

async fn open_root(
    fs: InMemoryFs,
) -> (
    smb::Connection,
    smb::Session,
    smb::Tree,
    tokio::task::JoinHandle<()>,
    std::sync::Arc<smb::Directory>,
) {
    use smb::{CreateDisposition, CreateOptions, FileAttributes, FileCreateArgs};

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
        .create(
            "",
            &FileCreateArgs {
                disposition: CreateDisposition::Open,
                options: CreateOptions::new().with_directory_file(true),
                attributes: FileAttributes::new(),
                desired_access: FileAccessMask::new().with_file_read_attributes(true),
            },
        )
        .await
        .expect("open root failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    (conn, session, tree, server_task, dir)
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_fs_size_reports_total_and_free() {
    let fs = InMemoryFs::new();
    let (conn, session, tree, server_task, dir) = open_root(fs).await;

    let info: FileFsSizeInformation = dir
        .handle()
        .query_fs_info()
        .await
        .expect("QUERY_INFO Fs Size failed");
    assert_eq!(info.bytes_per_sector, 512);
    assert_eq!(info.sectors_per_allocation_unit, 8);
    // 1 GiB / (512 * 8) = 262144
    assert_eq!(info.total_allocation_units, 262_144);
    // 512 MiB / (512 * 8) = 131072
    assert_eq!(info.available_allocation_units, 131_072);

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_fs_volume_reports_label_and_serial() {
    let fs = InMemoryFs::new();
    let (conn, session, tree, server_task, dir) = open_root(fs).await;

    let info: FileFsVolumeInformation = dir
        .handle()
        .query_fs_info()
        .await
        .expect("QUERY_INFO Fs Volume failed");
    assert_eq!(info.volume_serial_number, 0xDEAD_BEEF);
    assert_eq!(info.volume_label.to_string(), "InMemoryFs");

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_fs_attribute_reports_fs_name_and_case_sensitivity() {
    let fs = InMemoryFs::new();
    let (conn, session, tree, server_task, dir) = open_root(fs).await;

    let info: FileFsAttributeInformation = dir
        .handle()
        .query_fs_info()
        .await
        .expect("QUERY_INFO Fs Attribute failed");
    assert_eq!(info.file_system_name.to_string(), "InMemoryFs");
    assert_eq!(info.maximum_component_name_length, 255);
    // Case-sensitive flag is bit 0 (0x0000_0001).
    assert!(info.attributes.case_sensitive_search());

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn query_fs_full_size_reports_caller_and_actual_available() {
    let fs = InMemoryFs::new();
    let (conn, session, tree, server_task, dir) = open_root(fs).await;

    let info: FileFsFullSizeInformation = dir
        .handle()
        .query_fs_info()
        .await
        .expect("QUERY_INFO Fs FullSize failed");
    assert_eq!(info.total_allocation_units, 262_144);
    assert_eq!(info.caller_available_allocation_units, 131_072);
    assert_eq!(info.actual_available_allocation_units, 131_072);

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
