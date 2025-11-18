use std::{
    any,
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

use dav_server::localfs::LocalFs;
use dav_server::{DavMethodSet, memls::MemLs};
use headers::{
    Header,
    authorization::{Authorization, Basic},
};
use hyper::header::AUTHORIZATION;

use std::{convert::Infallible, net::SocketAddr};

use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

pub async fn serve_webdav() -> anyhow::Result<(u16, impl Future<Output = anyhow::Error>)> {
    // bind using std TcpListener to avoid async
    let listener = TcpListener::bind("localhost:0").await?;
    let port = listener.local_addr()?.port();

    let dav_handler = dav_server::DavHandler::builder()
        .filesystem(LocalFs::new("/", false, false, false))
        .locksystem(MemLs::new())
        .methods(DavMethodSet::WEBDAV_RO)
        .build_handler();

    let server_fut = async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => return err.into(),
            };

            let io = TokioIo::new(stream);

            let dav_handler = dav_handler.clone();

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `hello` service
                if let Err(err) = http1::Builder::new()
                    // `service_fn` converts our function in a `Service`
                    .serve_connection(
                        io,
                        service_fn({
                            move |req| {
                                let dav_handler = dav_handler.clone();
                                async move { Ok::<_, Infallible>(dav_handler.handle(req).await) }
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
