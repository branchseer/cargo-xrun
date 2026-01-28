use std::convert::Infallible;

use bytes::Bytes;
use dav_server::body::Body;
use dav_server::davpath::DavPath;
use dav_server::fs::{DavFileSystem, OpenOptions};
use dav_server::localfs::LocalFs;
use dav_server::memfs::MemFs;
use dav_server::{DavMethodSet, memls::MemLs};
use hyper::{Request, Response, StatusCode};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::embedded_binaries;

async fn create_remote_bin_fs() -> Box<MemFs> {
    let fs = MemFs::new();

    let files: &[(&str, &[u8])] = &[
        (
            "/cargo-xrun-remote-i686-pc-windows-gnullvm.exe",
            embedded_binaries::WINDOWS_I686,
        ),
        (
            "/cargo-xrun-remote-x86_64-unknown-linux-musl",
            embedded_binaries::LINUX_X86_64,
        ),
        (
            "/cargo-xrun-remote-aarch64-unknown-linux-musl",
            embedded_binaries::LINUX_AARCH64,
        ),
    ];

    for (path, data) in files {
        let dav_path = DavPath::new(path).unwrap();
        let options = OpenOptions {
            read: false,
            write: true,
            append: false,
            truncate: false,
            create: true,
            create_new: true,
            size: Some(data.len() as u64),
            checksum: None,
        };
        let mut file = fs.open(&dav_path, options).await.unwrap();
        file.write_bytes(Bytes::from_static(data)).await.unwrap();
    }

    fs
}

pub async fn serve_webdav() -> anyhow::Result<(u16, impl Future<Output = anyhow::Error>)> {
    let listener = TcpListener::bind("localhost:0").await?;
    let port = listener.local_addr()?.port();

    let fs_handler = dav_server::DavHandler::builder()
        .filesystem(LocalFs::new("/", false, false, false))
        .locksystem(MemLs::new())
        .methods(DavMethodSet::WEBDAV_RO)
        .strip_prefix("/fs")
        .build_handler();

    let remote_bin_fs = create_remote_bin_fs().await;
    let remote_bin_handler = dav_server::DavHandler::builder()
        .filesystem(remote_bin_fs)
        .methods(DavMethodSet::WEBDAV_RO)
        .strip_prefix("/remote-bin")
        .build_handler();

    let server_fut = async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => return err.into(),
            };

            let io = TokioIo::new(stream);
            let fs_handler = fs_handler.clone();
            let remote_bin_handler = remote_bin_handler.clone();

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn({
                            move |req: Request<hyper::body::Incoming>| {
                                let fs_handler = fs_handler.clone();
                                let remote_bin_handler = remote_bin_handler.clone();
                                async move {
                                    let path = req.uri().path();

                                    if path.starts_with("/remote-bin") {
                                        return Ok::<_, Infallible>(
                                            remote_bin_handler.handle(req).await,
                                        );
                                    }

                                    if path.starts_with("/fs") {
                                        return Ok(fs_handler.handle(req).await);
                                    }

                                    Ok(Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Body::from("Not Found"))
                                        .unwrap())
                                }
                            }
                        }),
                    )
                    .await
                {
                    tracing::warn!("Error serving WebDav connection: {err:?}");
                }
            });
        }
    };
    Ok((port, server_fut))
}
