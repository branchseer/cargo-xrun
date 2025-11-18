use std::{
    any,
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

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

pub fn serve_webdav(
    prefixes_and_basedirs: impl Iterator<Item = (String, PathBuf)>,
) -> anyhow::Result<(u16, impl Future<Output = anyhow::Error>)> {
    use dav_server::{fakels::FakeLs, localfs::LocalFs};

    let prefixes_and_handlers: Arc<[(String, dav_server::DavHandler)]> = prefixes_and_basedirs
        .map(|(prefix, dir)| {
            let dav_handler = dav_server::DavHandler::builder()
                .filesystem(LocalFs::new(dir, false, false, false))
                .locksystem(MemLs::new())
                .methods(DavMethodSet::WEBDAV_RO)
                .strip_prefix(prefix.clone())
                .build_handler();
            (prefix, dav_handler)
        })
        .collect();

    // bind using std TcpListener to avoid async
    let listener = {
        let std_listener = std::net::TcpListener::bind("localhost:0")?;
        std_listener.set_nonblocking(true)?;
        TcpListener::from_std(std_listener)?
    };
    let port = listener.local_addr()?.port();

    let server_fut = async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => return err.into(),
            };
            let prefixes_and_handlers = Arc::clone(&prefixes_and_handlers);

            let io = TokioIo::new(stream);

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `hello` service
                if let Err(err) = http1::Builder::new()
                    // `service_fn` converts our function in a `Service`
                    .serve_connection(
                        io,
                        service_fn({
                            move |req| {
                                let prefixes_and_handlers = Arc::clone(&prefixes_and_handlers);
                                async move {
                                    for (prefix, dav_server) in prefixes_and_handlers.iter() {
                                        if !req.uri().path().starts_with(prefix) {
                                            continue;
                                        }
                                        return Ok::<_, Infallible>(dav_server.handle(req).await);
                                    }

                                    // No matching prefix found
                                    let response = hyper::Response::builder()
                                        .status(hyper::StatusCode::NOT_FOUND)
                                        .body(dav_server::body::Body::from("Not Found"))
                                        .unwrap();
                                    Ok(response)
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

#[cfg(test)]
#[test_log::test(tokio::test)]
async fn t() -> anyhow::Result<()> {
    let (port, fut) = serve_webdav([
        ("/root".to_string(), PathBuf::from("/")),
        ("/home".to_string(), PathBuf::from("/Users")),
    ].into_iter())?;
    println!("Listening on port {}", port);
    return Err(fut.await);

    Ok(())
}
