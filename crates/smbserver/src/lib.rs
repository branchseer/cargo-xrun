use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

pub mod wire;

pub trait Filesystem: Send + Sync + 'static {}

#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

struct Inner {
    #[allow(dead_code)]
    fs: Box<dyn Filesystem>,
}

#[derive(Default)]
pub struct ServerBuilder {
    _private: (),
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder::default()
    }

    pub async fn serve_connection<S>(&self, _io: S) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        std::future::pending().await
    }
}

impl ServerBuilder {
    pub fn build(self, fs: impl Filesystem) -> Server {
        Server {
            inner: Arc::new(Inner { fs: Box::new(fs) }),
        }
    }
}
