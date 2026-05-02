//! End-to-end negotiate test using smb-rs as the in-process client.

mod common;

use common::{DuplexTransport, NoFs};
use smb::{Connection, ConnectionConfig, Guid};

#[tokio::test]
#[ntest::timeout(3000)]
async fn client_negotiates_smb2() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = smbserver::Server::builder().build(NoFs);
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let transport = Box::new(DuplexTransport::new(client_io));
    let config = ConnectionConfig {
        smb2_only_negotiate: true,
        ..Default::default()
    };

    let conn = Connection::from_transport(transport, "test-server", Guid::generate(), config)
        .await
        .expect("NEGOTIATE returned an error");

    server_task.abort();
    drop(conn);
}
