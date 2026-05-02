//! Target test: smb-rs completes NEGOTIATE → SESSION_SETUP → TREE_CONNECT
//! → disconnect against our server through an in-process duplex pipe.
//!
//! Currently fails at SESSION_SETUP — server only handles NEGOTIATE.

mod common;

use std::str::FromStr;

use common::{DuplexTransport, NoFs};
use smb::{Connection, ConnectionConfig, Guid, UncPath};
use sspi::{AuthIdentity, Secret, Username};

#[tokio::test]
#[ntest::timeout(5000)]
async fn client_can_connect_share_and_disconnect() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = smbserver::Server::builder().share("public", NoFs).build();
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_connection(server_io).await;
        })
    };

    let transport = Box::new(DuplexTransport::new(client_io));
    let config = ConnectionConfig {
        smb2_only_negotiate: true,
        allow_unsigned_guest_access: true,
        ..Default::default()
    };

    let conn = Connection::from_transport(transport, "test-server", Guid::generate(), config)
        .await
        .expect("NEGOTIATE failed");

    let identity = AuthIdentity {
        username: Username::parse("guest").expect("valid username"),
        password: Secret::from(String::new()),
    };
    let session = conn.authenticate(identity).await.expect("SESSION_SETUP failed");

    let target = UncPath::from_str(r"\\test-server\public").expect("valid UNC path");
    let tree = session.tree_connect(&target).await.expect("TREE_CONNECT failed");

    // Explicit, awaitable shutdown — exercises TREE_DISCONNECT and LOGOFF
    // handlers in a way the Drop fire-and-forget path cannot verify.
    tree.disconnect().await.expect("TREE_DISCONNECT failed");
    session.logoff().await.expect("LOGOFF failed");

    drop(conn);
    server_task.abort();
}
