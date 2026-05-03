//! CHANGE_NOTIFY tests — deferred response architecture.

mod common;

use common::{connect_and_tree_connect, InMemoryFs};
use smb::{CreateDisposition, CreateOptions, FileAttributes, FileCreateArgs};
use smb_fscc::FileAccessMask;

fn open_dir_args() -> FileCreateArgs {
    FileCreateArgs {
        disposition: CreateDisposition::Open,
        options: CreateOptions::new().with_directory_file(true),
        attributes: FileAttributes::new(),
        desired_access: FileAccessMask::new()
            .with_file_read_data(true)
            .with_file_read_attributes(true),
    }
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn change_notify_delivers_filesystem_event_to_client() {
    let fs = InMemoryFs::new();
    // Add a directory so it's openable.
    fs.has_directory(""); // root always exists
    let fs_for_notify = fs.clone();

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
        .create("", &open_dir_args())
        .await
        .expect("open root failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    // One-shot watch: server holds the request until the FS fires.
    let dir_for_watch = dir.clone();
    let watch_handle = tokio::spawn(async move {
        smb::Directory::watch(
            &dir_for_watch,
            smb_msg::NotifyFilter::new().with_file_name(true),
            false,
        )
        .await
    });

    // Brief yield + sleep so the server registers the watcher before we fire.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    fs_for_notify.notify("", "newfile.txt", smbserver::ChangeKind::Added);

    let infos = tokio::time::timeout(std::time::Duration::from_secs(2), watch_handle)
        .await
        .expect("CHANGE_NOTIFY did not arrive within 2s")
        .expect("task join failed")
        .expect("CHANGE_NOTIFY returned an error");

    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].file_name.to_string(), "newfile.txt");

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn cancelling_change_notify_returns_status_cancelled() {
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

    let resource = tree
        .create("", &open_dir_args())
        .await
        .expect("open root failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    let cancel = tokio_util::sync::CancellationToken::new();
    let dir_for_watch = dir.clone();
    let cancel_for_watch = cancel.clone();
    let watch_handle = tokio::spawn(async move {
        let stream = smb::Directory::watch_stream_cancellable(
            &dir_for_watch,
            smb_msg::NotifyFilter::new().with_file_name(true),
            false,
            cancel_for_watch,
        )
        .expect("set up watch_stream");
        use futures_util::StreamExt;
        futures_util::pin_mut!(stream);
        // Pull until the stream ends — should end after cancel.
        let mut items = Vec::new();
        while let Some(item) = stream.next().await {
            items.push(item);
        }
        items
    });

    // Give the server a beat to register the parked CHANGE_NOTIFY.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancel.cancel();

    let items = tokio::time::timeout(std::time::Duration::from_secs(2), watch_handle)
        .await
        .expect("CANCEL did not complete the watch within 2s")
        .expect("task join failed");

    // smb-rs's stream may close cleanly (Vec empty) or emit the cancellation
    // error — both are valid signals that CANCEL took effect.
    assert!(
        items.is_empty()
            || items.iter().any(|r| {
                if let Err(e) = r {
                    let m = format!("{e}");
                    m.to_lowercase().contains("cancel") || m.contains("c0000120")
                } else {
                    false
                }
            }),
        "expected cancellation signal, got {items:?}"
    );

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}

/// Filesystem stub that opens an empty directory but doesn't implement
/// `watch` — the server should map that to STATUS_NOT_SUPPORTED.
struct NoWatchFs;
impl smbserver::Filesystem for NoWatchFs {
    fn open(&self, _path: &str) -> std::io::Result<std::sync::Arc<dyn smbserver::FileHandle>> {
        Ok(std::sync::Arc::new(EmptyDir))
    }
}
struct EmptyDir;
impl smbserver::FileHandle for EmptyDir {
    fn size(&self) -> u64 { 0 }
    fn is_directory(&self) -> bool { true }
    fn list_children(&self) -> std::io::Result<Vec<smbserver::DirEntry>> { Ok(Vec::new()) }
}

#[tokio::test]
#[ntest::timeout(5000)]
async fn change_notify_returns_not_supported_when_fs_lacks_watch() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = smbserver::Server::builder().share("public", NoWatchFs).build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let (conn, session, tree) =
        connect_and_tree_connect(client_io, r"\\test-server\public").await;

    let resource = tree
        .create("", &open_dir_args())
        .await
        .expect("open root failed");
    let dir = std::sync::Arc::new(resource.unwrap_dir());

    // smb-rs Directory::watch should yield an Err with STATUS_NOT_SUPPORTED.
    let result = smb::Directory::watch(
        &dir,
        smb_msg::NotifyFilter::new().with_file_name(true),
        false,
    )
    .await;
    let err = match result {
        Ok(_) => panic!("expected watch to fail"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("not supported")
            || msg.to_lowercase().contains("not_supported")
            || msg.contains("c00000bb"),
        "unexpected error message: {msg}"
    );

    drop(dir);
    drop(tree);
    drop(session);
    drop(conn);
    server_task.abort();
}
