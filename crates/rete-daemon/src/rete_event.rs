//! Structured application events.
//!
//! [`ReteEvent`] is the single enum of all observable events in the rete
//! daemon.  Application code constructs a variant and calls [`ReteEvent::emit`]
//! which:
//!
//! 1. Writes a human-readable log line through `tracing::info!` → subscriber → stderr.
//! 2. (When `test-output` is enabled) Writes a machine-parseable `EVENT:field:field`
//!    line directly to stdout for the Python E2E test harness.

/// All structured events emitted by rete binaries.
///
/// Field values are pre-formatted strings (hex-encoded hashes, UTF-8 payloads).
/// Formatting happens at the call site so the subscriber does no allocation.
#[derive(Debug)]
pub enum ReteEvent {
    // ── Lifecycle ────────────────────────────────────────────────────────
    Identity { hash: String },
    DaemonReady,
    DaemonShutdown,
    ShutdownComplete,

    // ── Network ─────────────────────────────────────────────────────────
    Announce { dest: String, identity: String, hops: u8, app_data: Option<String> },
    Data { dest: String, payload: String },
    DataSent { dest: String, payload: String },
    ProofReceived { packet_hash: String },

    // ── Link ────────────────────────────────────────────────────────────
    LinkEstablished { link: String },
    LinkClosed { link: String },
    LinkData { link: String, payload: String },
    ChannelMsg { link: String, msg_type: String, payload: String },

    // ── Request / Response ──────────────────────────────────────────────
    RequestReceived { link: String, request_id: String, path_hash: String, data_len: usize },
    ResponseReceived { link: String, request_id: String, data_len: usize },

    // ── Resource ────────────────────────────────────────────────────────
    ResourceOffered { link: String, resource_hash: String, total_size: usize },
    ResourceComplete { link: String, resource_hash: String, payload: String },
    ResourceFailed { link: String, resource_hash: String },
    ResourceRejected { link: String, resource_hash: String },

    // ── LXMF ────────────────────────────────────────────────────────────
    LxmfReceived { source: String, title: String, content: String },
    LxmfPeer { dest: String, name: String },
    LxmfSent { dest: String },
    LxmfDelivered { msg_hash: String, dest: String },
    LxmfFailed { msg_hash: String, dest: String },
    LxmfRejectedStamp { source: String, msg_hash: String },

    // ── Propagation ─────────────────────────────────────────────────────
    PropDeposit { dest: String, msg_hash: String },
    PropRetrievalRequest { link: String, dest: String, count: usize },
    PropRetrievalSending { link: String },
    PropForward { dest: String, count: usize },
    PropForwardLink { dest: String, link: String },
    PropForwardSending { link: String },

    // ── Peer sync ───────────────────────────────────────────────────────
    PeerDiscovered { dest: String, identity: String },
    PeerSyncComplete { dest: String, messages_sent: usize },
    PeerSyncDeposit { dest: String, msg_hash: String },
    PeerOfferReceived { link: String },

    // ── Stats ───────────────────────────────────────────────────────────
    Stats { payload: String },
}

impl ReteEvent {
    /// Event name used in the test protocol line (e.g. `"ANNOUNCE"`).
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::Identity { .. } => "IDENTITY",
            Self::DaemonReady => "DAEMON_READY",
            Self::DaemonShutdown => "DAEMON_SHUTDOWN",
            Self::ShutdownComplete => "SHUTDOWN_COMPLETE",
            Self::Announce { .. } => "ANNOUNCE",
            Self::Data { .. } => "DATA",
            Self::DataSent { .. } => "DATA_SENT",
            Self::ProofReceived { .. } => "PROOF_RECEIVED",
            Self::LinkEstablished { .. } => "LINK_ESTABLISHED",
            Self::LinkClosed { .. } => "LINK_CLOSED",
            Self::LinkData { .. } => "LINK_DATA",
            Self::ChannelMsg { .. } => "CHANNEL_MSG",
            Self::RequestReceived { .. } => "REQUEST_RECEIVED",
            Self::ResponseReceived { .. } => "RESPONSE_RECEIVED",
            Self::ResourceOffered { .. } => "RESOURCE_OFFERED",
            Self::ResourceComplete { .. } => "RESOURCE_COMPLETE",
            Self::ResourceFailed { .. } => "RESOURCE_FAILED",
            Self::ResourceRejected { .. } => "RESOURCE_REJECTED",
            Self::LxmfReceived { .. } => "LXMF_RECEIVED",
            Self::LxmfPeer { .. } => "LXMF_PEER",
            Self::LxmfSent { .. } => "LXMF_SENT",
            Self::LxmfDelivered { .. } => "LXMF_DELIVERED",
            Self::LxmfFailed { .. } => "LXMF_FAILED",
            Self::LxmfRejectedStamp { .. } => "LXMF_REJECTED_STAMP",
            Self::PropDeposit { .. } => "PROP_DEPOSIT",
            Self::PropRetrievalRequest { .. } => "PROP_RETRIEVAL_REQUEST",
            Self::PropRetrievalSending { .. } => "PROP_RETRIEVAL_SENDING",
            Self::PropForward { .. } => "PROP_FORWARD",
            Self::PropForwardLink { .. } => "PROP_FORWARD_LINK",
            Self::PropForwardSending { .. } => "PROP_FORWARD_SENDING",
            Self::PeerDiscovered { .. } => "PEER_DISCOVERED",
            Self::PeerSyncComplete { .. } => "PEER_SYNC_COMPLETE",
            Self::PeerSyncDeposit { .. } => "PEER_SYNC_DEPOSIT",
            Self::PeerOfferReceived { .. } => "PEER_OFFER_RECEIVED",
            Self::Stats { .. } => "STATS",
        }
    }

    /// Machine-parseable test protocol line: `EVENT:field1:field2:...`
    pub fn test_line(&self) -> String {
        match self {
            Self::Identity { hash } => format!("IDENTITY:{hash}"),
            Self::DaemonReady => "DAEMON_READY".into(),
            Self::DaemonShutdown => "DAEMON_SHUTDOWN".into(),
            Self::ShutdownComplete => "SHUTDOWN_COMPLETE".into(),
            Self::Announce { dest, identity, hops, app_data } => {
                match app_data {
                    Some(ad) => format!("ANNOUNCE:{dest}:{identity}:{hops}:{ad}"),
                    None => format!("ANNOUNCE:{dest}:{identity}:{hops}"),
                }
            }
            Self::Data { dest, payload } => format!("DATA:{dest}:{payload}"),
            Self::DataSent { dest, payload } => format!("DATA_SENT:{dest}:{payload}"),
            Self::ProofReceived { packet_hash } => format!("PROOF_RECEIVED:{packet_hash}"),
            Self::LinkEstablished { link } => format!("LINK_ESTABLISHED:{link}"),
            Self::LinkClosed { link } => format!("LINK_CLOSED:{link}"),
            Self::LinkData { link, payload } => format!("LINK_DATA:{link}:{payload}"),
            Self::ChannelMsg { link, msg_type, payload } => format!("CHANNEL_MSG:{link}:{msg_type}:{payload}"),
            Self::RequestReceived { link, request_id, path_hash, data_len } =>
                format!("REQUEST_RECEIVED:{link}:{request_id}:{path_hash}:{data_len}"),
            Self::ResponseReceived { link, request_id, data_len } =>
                format!("RESPONSE_RECEIVED:{link}:{request_id}:{data_len}"),
            Self::ResourceOffered { link, resource_hash, total_size } =>
                format!("RESOURCE_OFFERED:{link}:{resource_hash}:{total_size}"),
            Self::ResourceComplete { link, resource_hash, payload } =>
                format!("RESOURCE_COMPLETE:{link}:{resource_hash}:{payload}"),
            Self::ResourceFailed { link, resource_hash } =>
                format!("RESOURCE_FAILED:{link}:{resource_hash}"),
            Self::ResourceRejected { link, resource_hash } =>
                format!("RESOURCE_REJECTED:{link}:{resource_hash}"),
            Self::LxmfReceived { source, title, content } =>
                format!("LXMF_RECEIVED:{source}:{title}:{content}"),
            Self::LxmfPeer { dest, name } => format!("LXMF_PEER:{dest}:{name}"),
            Self::LxmfSent { dest } => format!("LXMF_SENT:{dest}"),
            Self::LxmfDelivered { msg_hash, dest } => format!("LXMF_DELIVERED:{msg_hash}:{dest}"),
            Self::LxmfFailed { msg_hash, dest } => format!("LXMF_FAILED:{msg_hash}:{dest}"),
            Self::LxmfRejectedStamp { source, msg_hash } =>
                format!("LXMF_REJECTED_STAMP:{source}:{msg_hash}"),
            Self::PropDeposit { dest, msg_hash } => format!("PROP_DEPOSIT:{dest}:{msg_hash}"),
            Self::PropRetrievalRequest { link, dest, count } =>
                format!("PROP_RETRIEVAL_REQUEST:{link}:{dest}:{count}"),
            Self::PropRetrievalSending { link } => format!("PROP_RETRIEVAL_SENDING:{link}"),
            Self::PropForward { dest, count } => format!("PROP_FORWARD:{dest}:{count}"),
            Self::PropForwardLink { dest, link } => format!("PROP_FORWARD_LINK:{dest}:{link}"),
            Self::PropForwardSending { link } => format!("PROP_FORWARD_SENDING:{link}"),
            Self::PeerDiscovered { dest, identity } => format!("PEER_DISCOVERED:{dest}:{identity}"),
            Self::PeerSyncComplete { dest, messages_sent } =>
                format!("PEER_SYNC_COMPLETE:{dest}:{messages_sent}"),
            Self::PeerSyncDeposit { dest, msg_hash } =>
                format!("PEER_SYNC_DEPOSIT:{dest}:{msg_hash}"),
            Self::PeerOfferReceived { link } => format!("PEER_OFFER_RECEIVED:{link}"),
            Self::Stats { payload } => format!("STATS:{payload}"),
        }
    }

    /// Human-readable log message for stderr.
    pub fn log_message(&self) -> String {
        match self {
            Self::Identity { hash } => format!("identity hash: {hash}"),
            Self::DaemonReady => "daemon ready".into(),
            Self::DaemonShutdown => "daemon shutdown".into(),
            Self::ShutdownComplete => "shutdown complete".into(),
            Self::Announce { dest, identity, hops, .. } =>
                format!("announce received dest={dest} identity={identity} hops={hops}"),
            Self::Data { dest, .. } => format!("data received dest={dest}"),
            Self::DataSent { dest, .. } => format!("data sent dest={dest}"),
            Self::ProofReceived { packet_hash } => format!("proof received hash={packet_hash}"),
            Self::LinkEstablished { link } => format!("link established link={link}"),
            Self::LinkClosed { link } => format!("link closed link={link}"),
            Self::LinkData { link, .. } => format!("link data link={link}"),
            Self::ChannelMsg { link, msg_type, .. } =>
                format!("channel message link={link} type={msg_type}"),
            Self::RequestReceived { link, request_id, path_hash, data_len } =>
                format!("request received link={link} req={request_id} path={path_hash} len={data_len}"),
            Self::ResponseReceived { link, request_id, data_len } =>
                format!("response received link={link} req={request_id} len={data_len}"),
            Self::ResourceOffered { link, resource_hash, total_size } =>
                format!("resource offered link={link} hash={resource_hash} size={total_size}"),
            Self::ResourceComplete { link, resource_hash, payload } =>
                format!("resource complete link={link} hash={resource_hash} len={}", payload.len() / 2),
            Self::ResourceFailed { link, resource_hash } =>
                format!("resource failed link={link} hash={resource_hash}"),
            Self::ResourceRejected { link, resource_hash } =>
                format!("resource rejected link={link} hash={resource_hash}"),
            Self::LxmfReceived { source, title, content } =>
                format!("LXMF received source={source} title={title} content={content}"),
            Self::LxmfPeer { dest, name } => format!("LXMF peer dest={dest} name={name}"),
            Self::LxmfSent { dest } => format!("LXMF sent dest={dest}"),
            Self::LxmfDelivered { msg_hash, dest } =>
                format!("LXMF delivered msg={msg_hash} dest={dest}"),
            Self::LxmfFailed { msg_hash, dest } =>
                format!("LXMF failed msg={msg_hash} dest={dest}"),
            Self::LxmfRejectedStamp { source, msg_hash } =>
                format!("LXMF rejected stamp source={source} msg={msg_hash}"),
            Self::PropDeposit { dest, msg_hash } =>
                format!("propagation deposit dest={dest} msg={msg_hash}"),
            Self::PropRetrievalRequest { link, dest, count } =>
                format!("propagation retrieval request link={link} dest={dest} count={count}"),
            Self::PropRetrievalSending { link } =>
                format!("propagation retrieval sending link={link}"),
            Self::PropForward { dest, count } =>
                format!("propagation forward dest={dest} count={count}"),
            Self::PropForwardLink { dest, link } =>
                format!("propagation forward link dest={dest} link={link}"),
            Self::PropForwardSending { link } =>
                format!("propagation forward sending link={link}"),
            Self::PeerDiscovered { dest, identity } =>
                format!("peer discovered dest={dest} identity={identity}"),
            Self::PeerSyncComplete { dest, messages_sent } =>
                format!("peer sync complete dest={dest} messages={messages_sent}"),
            Self::PeerSyncDeposit { dest, msg_hash } =>
                format!("peer sync deposit dest={dest} msg={msg_hash}"),
            Self::PeerOfferReceived { link } =>
                format!("peer offer received link={link}"),
            Self::Stats { .. } => "stats published".into(),
        }
    }

    /// Emit this event: log to stderr via tracing, write test protocol to stdout.
    pub fn emit(self) {
        tracing::info!("{}", self.log_message());

        #[cfg(feature = "test-output")]
        {
            let line = self.test_line();
            println!("{line}");
            use std::io::Write;
            std::io::stdout().flush().ok();
        }
    }
}
