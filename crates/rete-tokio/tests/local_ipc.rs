//! Integration test: Local IPC shared instance.
//!
//! Validates that a LocalServer correctly relays packets between
//! LocalClient instances and the TokioNode transport layer.

use rete_core::{Identity, Packet, PacketType, MTU};
use rete_stack::ReteInterface;
use rete_tokio::local::{LocalClient, LocalServer};
use rete_tokio::{InboundMsg, TokioNode};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

/// Run an async test on a thread with 16MB stack.
///
/// In debug builds `Box::new(T::new())` may materialise the struct on the
/// stack before moving it to the heap, so we need a generous stack.
fn big_stack_test(f: fn()) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// Box-allocate a TokioNode to avoid stack overflow.
fn make_node(seed: &[u8]) -> Box<TokioNode> {
    let identity = Identity::from_seed(seed).unwrap();
    Box::new(TokioNode::new(identity, "rete", &["example", "v1"]).unwrap())
}

// ---------------------------------------------------------------------------
// Test: two clients connected to a server with a running node. Client1 sends
// an announce, the node processes it canonically, and client2 receives it via
// the node's AllExceptSource dispatch through the Hub.
// ---------------------------------------------------------------------------

#[test]
fn two_clients_announce_relay() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("ipc_announce_{}", std::process::id());
                let (inbound_tx, inbound_rx) = mpsc::channel::<InboundMsg>(256);

                let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();
                let broadcaster = server.broadcaster();
                let slot = rete_tokio::InterfaceSlot::Hub(broadcaster.clone());

                tokio::spawn(server.run());

                // Start a node to process packets canonically.
                let mut node = make_node(b"ipc-node-seed");
                node.core.enable_transport();
                let (_cmd_tx, cmd_rx) = mpsc::channel(16);

                let node_fut = node.run_multi_with_commands(
                    vec![slot],
                    inbound_rx,
                    cmd_rx,
                    |_event, _core, _rng| Vec::new(),
                );
                tokio::pin!(node_fut);

                tokio::select! {
                    _ = &mut node_fut => panic!("node exited unexpectedly"),
                    _ = async {
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // Connect two clients
                        let mut client1 = LocalClient::connect(&name).await.unwrap();
                        let mut client2 = LocalClient::connect(&name).await.unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;

                        assert_eq!(broadcaster.client_count().await, 2);

                        // Client1 builds and sends an announce packet
                        let node1 = make_node(b"ipc-client-1");
                        let announce = node1.build_announce(None).unwrap();

                        client1.send(&announce).await.unwrap();

                        // Client2 should receive the announce via canonical dispatch
                        let mut buf = [0u8; MTU];
                        let frame = timeout(Duration::from_secs(3), client2.recv(&mut buf))
                            .await
                            .expect("timeout waiting for announce")
                            .unwrap();

                        let pkt = Packet::parse(frame).expect("invalid packet");
                        assert_eq!(pkt.packet_type, PacketType::Announce);
                    } => {},
                }
            });
    });
}

// ---------------------------------------------------------------------------
// Test: client disconnect does not affect remaining clients
// ---------------------------------------------------------------------------

#[test]
fn client_disconnect_does_not_break_others() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("ipc_disconnect_{}", std::process::id());
                let (inbound_tx, _inbound_rx) = mpsc::channel::<InboundMsg>(256);

                let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();
                let broadcaster = server.broadcaster();
                tokio::spawn(server.run());
                tokio::time::sleep(Duration::from_millis(50)).await;

                let client1 = LocalClient::connect(&name).await.unwrap();
                let mut client2 = LocalClient::connect(&name).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                assert_eq!(broadcaster.client_count().await, 2);

                // Disconnect client1
                drop(client1);
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(broadcaster.client_count().await, 1);

                // Broadcast to remaining client2
                let node2 = make_node(b"ipc-client-2");
                let announce = node2.build_announce(None).unwrap();

                broadcaster.broadcast(&announce, None).await;

                let mut buf = [0u8; MTU];
                let frame = timeout(Duration::from_secs(2), client2.recv(&mut buf))
                    .await
                    .expect("timeout waiting for broadcast")
                    .unwrap();

                let pkt = Packet::parse(frame).expect("invalid packet");
                assert_eq!(pkt.packet_type, PacketType::Announce);
            });
    });
}

// ---------------------------------------------------------------------------
// Test: server forwards client packets to inbound channel (for node ingestion)
// ---------------------------------------------------------------------------

#[test]
fn server_forwards_to_inbound() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("ipc_inbound_{}", std::process::id());
                let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundMsg>(256);
                let iface_idx = 7u8;

                let server = LocalServer::bind(&name, inbound_tx, iface_idx).unwrap();
                tokio::spawn(server.run());
                tokio::time::sleep(Duration::from_millis(50)).await;

                let mut client = LocalClient::connect(&name).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Build an announce and send it
                let node = make_node(b"ipc-inbound-test");
                let announce = node.build_announce(Some(b"test-data")).unwrap();

                client.send(&announce).await.unwrap();

                // The server should forward it to the inbound channel
                let msg = timeout(Duration::from_secs(2), inbound_rx.recv())
                    .await
                    .expect("timeout")
                    .expect("channel closed");

                assert_eq!(msg.iface_idx, iface_idx);
                assert_eq!(msg.data, announce);
            });
    });
}

// ---------------------------------------------------------------------------
// Test: bidirectional communication — node broadcasts to clients via
// broadcaster, clients can send to node via inbound channel
// ---------------------------------------------------------------------------

#[test]
fn bidirectional_node_client_communication() {
    big_stack_test(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let name = format!("ipc_bidir_{}", std::process::id());
                let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundMsg>(256);

                let server = LocalServer::bind(&name, inbound_tx, 0).unwrap();
                let broadcaster = server.broadcaster();
                tokio::spawn(server.run());
                tokio::time::sleep(Duration::from_millis(50)).await;

                let mut client = LocalClient::connect(&name).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Client -> Node direction
                let client_data = b"client to node";
                client.send(client_data).await.unwrap();

                let msg = timeout(Duration::from_secs(2), inbound_rx.recv())
                    .await
                    .expect("timeout")
                    .expect("channel closed");
                assert_eq!(msg.data, client_data);

                // Node -> Client direction
                let node_data = b"node to client";
                broadcaster.broadcast(node_data, None).await;

                let mut buf = [0u8; MTU];
                let frame = timeout(Duration::from_secs(2), client.recv(&mut buf))
                    .await
                    .expect("timeout")
                    .unwrap();
                assert_eq!(frame, node_data);
            });
    });
}
// size check
