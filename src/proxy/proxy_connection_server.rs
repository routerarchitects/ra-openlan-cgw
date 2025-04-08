use cgw_common::{
    cgw_app_args::AppArgs,
    cgw_device::CGWDevice,
    cgw_errors::{Error, Result},
    cgw_tls::cgw_tls_get_cn_from_stream,
};

use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{
    net::TcpStream,
    runtime::Runtime,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        RwLock,
    },
    time::{sleep, Duration},
};

use eui48::MacAddress;

use serde::{Deserialize, Serialize};

use crate::{
    proxy_connection_processor::{ProxyConnectionProcessor, ProxyConnectionProcessorReqMsg},
    proxy_remote_discovery::ProxyRemoteDiscovery,
    proxy_runtime::{proxy_get_runtime, ProxyRuntimeType},
};

use lazy_static::lazy_static;
use std::sync::atomic::{AtomicUsize, Ordering};

lazy_static! {
    static ref LAST_CGW_INDEX: AtomicUsize = AtomicUsize::new(0);
}

#[derive(Debug, Clone)]
struct ConnectionInfo {
    mbox_tx: UnboundedSender<ProxyConnectionProcessorReqMsg>,
    connected_to_cgw_id: Option<i32>,
    connected_to_group_id: i32,
}

type ProxyConnmapType = Arc<RwLock<HashMap<MacAddress, ConnectionInfo>>>;

#[derive(Debug)]
struct ProxyConnMap {
    map: ProxyConnmapType,
}

impl ProxyConnMap {
    pub fn new() -> Self {
        let hash_map: HashMap<MacAddress, ConnectionInfo> = HashMap::new();
        let map: Arc<RwLock<HashMap<MacAddress, ConnectionInfo>>> = Arc::new(RwLock::new(hash_map));

        ProxyConnMap { map }
    }
}

type ProxyConnectionServerMboxRx = UnboundedReceiver<ProxyConnectionServerReqMsg>;
type ProxyConnectionServerMboxTx = UnboundedSender<ProxyConnectionServerReqMsg>;

// The following pair used internally by server itself to bind
// Processor's Req/Res
#[derive(Debug)]
pub enum ProxyConnectionServerReqMsg {
    // Connection-related messages
    AddNewConnection(MacAddress, UnboundedSender<ProxyConnectionProcessorReqMsg>),
    ConnectionClosed(MacAddress),
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub enum CGWBroadcastMessageType {
    GidAdded(i32),
    GidRemoved(i32, Option<Vec<MacAddress>>),
    InfraListAssigned(i32, Vec<MacAddress>),
    InfraListDeassigned(i32, Vec<MacAddress>),
    // TODO:
    // RebalanceDone/RebalanceInProgress ???
    // ShardUp / ShardDown - definetely has to be implemented to ease-down
    //   on the sync remote cgw map etc.
    // Potentially:
    // Arbitrary command to address specific shard? cli like interface?:
    //   - restart shard
    //   - issue rebalance without kafka knowledge
    //   - manually create / delete groups / infras etc
    //   - dump debug info?
    //   - close connection with infra XYZ
}

// Broadcasting is needed to speedup some cache operations:
//
#[derive(Debug, Deserialize, Serialize)]
struct CGWBroadcastMessage {
    reporter_shard_id: i32,
    gid: i32,
    msg_type: CGWBroadcastMessageType,
}

impl CGWBroadcastMessage {
    async fn handle(self, server: Arc<ProxyConnectionServer>) {
        debug!("Received BCAST msg {:?}", self);

        // TODO: Wasting mem? Optimize?
        match self.msg_type.clone() {
            CGWBroadcastMessageType::GidAdded(_owner_shard_id) => {
                self.handle_infrastructure_group_added(server, _owner_shard_id)
                    .await;
            }
            CGWBroadcastMessageType::GidRemoved(_owner_shard_id, affected_ifnras_list) => {
                self.handle_infrastructure_group_removed(affected_ifnras_list, server)
                    .await;
            }
            CGWBroadcastMessageType::InfraListAssigned(owner_shard_id, affected_ifnras_list) => {
                self.handle_infras_list_assigned(owner_shard_id, affected_ifnras_list, server)
                    .await;
            }
            CGWBroadcastMessageType::InfraListDeassigned(_owner_shard_id, affected_ifnras_list) => {
                self.handle_infras_list_deassigned(affected_ifnras_list, server)
                    .await;
            }
        }
    }

    async fn handle_infrastructure_group_added(
        &self,
        server: Arc<ProxyConnectionServer>,
        _owner_shard_id: i32,
    ) {
        debug!("handle_infrastructure_group_added entry {:?}", self);
        // New group added, all we can do is make sure
        // we've synced GID to CGW map;
        let _ = server.proxy_remote_discovery.sync_gid_to_cgw_map().await;
    }

    async fn handle_infrastructure_group_removed(
        &self,
        affected_infras_list: Option<Vec<MacAddress>>,
        server: Arc<ProxyConnectionServer>,
    ) {
        debug!("handle_infrastructure_group_removed entry {:?}", self);

        if let Some(infras) = affected_infras_list {
            self.handle_infras_list_deassigned(infras, server).await;
        } else {
            debug!("No specific devices affected by group removal");
        }
    }

    async fn handle_infras_list_assigned(
        &self,
        owner_shard_id: i32,
        affected_infras_list: Vec<MacAddress>,
        server: Arc<ProxyConnectionServer>,
    ) {
        debug!("handle_infras_list_assigned entry {:?}", self);

        if affected_infras_list.is_empty() {
            debug!("No infrastructure devices to assign");
            return;
        }

        let mut devices_to_update = Vec::new();
        {
            let connmap_r_lock = server.connmap.map.read().await;
            for mac in &affected_infras_list {
                if connmap_r_lock.contains_key(mac) {
                    devices_to_update.push(mac.clone());
                } else {
                    debug!(
                        "Received assignment for device {} not in connection map",
                        mac
                    );
                }
            }
        }

        for mac in devices_to_update {
            if let Err(e) = server
                .set_peer_connection(&mac, owner_shard_id, self.gid)
                .await
            {
                error!("Failed to set peer for device {}: {}", mac, e);
            } else {
                debug!(
                    "Assigned device {} to group {} on CGW {}",
                    mac, self.gid, owner_shard_id
                );
            }
        }
    }

    async fn handle_infras_list_deassigned(
        &self,
        affected_infras_list: Vec<MacAddress>,
        server: Arc<ProxyConnectionServer>,
    ) {
        debug!("handle_infras_list_deassigned entry {:?}", self);

        if affected_infras_list.is_empty() {
            debug!("No infrastructure devices to deassign");
            return;
        }

        let mut devices_to_deassign = Vec::new();
        {
            let connmap_r_lock = server.connmap.map.read().await;
            for mac in &affected_infras_list {
                if let Some(conn_info) = connmap_r_lock.get(mac) {
                    // Device exists in connection map
                    // Check if it was previously assigned to a group
                    if conn_info.connected_to_group_id != 0 {
                        // Only deassign if we have a CGW ID
                        if let Some(cgw_id) = conn_info.connected_to_cgw_id {
                            debug!(
                                "Deassigning device {} from group {}",
                                mac, conn_info.connected_to_group_id
                            );
                            devices_to_deassign.push((mac.clone(), cgw_id));
                        }
                    } else {
                        warn!(
                            "Unexpected: received infra deassign for unassigned group {}",
                            mac
                        );
                    }
                } else {
                    debug!(
                        "Received deassignment for device {} not in connection map",
                        mac
                    );
                }
            }
        }

        for (mac, cgw_id) in devices_to_deassign {
            if let Err(e) = server.set_peer_connection(&mac, cgw_id, 0).await {
                error!("Failed to deassign peer for device {}: {}", mac, e);
            }
        }
    }
}

pub struct ProxyConnectionServer {
    // ProxyConnectionServer write into this mailbox,
    // and other corresponding Server task Reads RX counterpart
    mbox_internal_tx: ProxyConnectionServerMboxTx,

    // Object that owns underlying mac:connection map
    connmap: ProxyConnMap,

    // Runtime that schedules all the WSS-messages related tasks
    wss_rx_tx_runtime: Arc<Runtime>,

    // Dedicated runtime (threadpool) for handling internal mbox:
    // ACK/nACK connection, handle duplicates (clone/open) etc.
    mbox_internal_runtime_handle: Arc<Runtime>,

    // Interface used to access all discovered CGW instances
    proxy_remote_discovery: Arc<ProxyRemoteDiscovery>,
}

impl ProxyConnectionServer {
    pub async fn new(app_args: &AppArgs) -> Result<Arc<Self>> {
        let wss_runtime_handle = match proxy_get_runtime(ProxyRuntimeType::WssRxTx) {
            Ok(ret_runtime) => match ret_runtime {
                Some(runtime) => runtime,
                None => {
                    return Err(Error::ConnectionServer(format!(
                        "Failed to find runtime type {:?}",
                        ProxyRuntimeType::WssRxTx
                    )));
                }
            },
            Err(e) => {
                return Err(Error::ConnectionServer(format!(
                    "Failed to get runtime type {:?}! Error: {e}",
                    ProxyRuntimeType::WssRxTx
                )));
            }
        };

        let internal_mbox_runtime_handle = match proxy_get_runtime(ProxyRuntimeType::MboxInternal) {
            Ok(ret_runtime) => match ret_runtime {
                Some(runtime) => runtime,
                None => {
                    return Err(Error::ConnectionServer(format!(
                        "Failed to find runtime type {:?}",
                        ProxyRuntimeType::WssRxTx
                    )));
                }
            },
            Err(e) => {
                return Err(Error::ConnectionServer(format!(
                    "Failed to get runtime type {:?}! Error: {e}",
                    ProxyRuntimeType::WssRxTx
                )));
            }
        };

        let (internal_tx, internal_rx) = unbounded_channel::<ProxyConnectionServerReqMsg>();

        let proxy_remote_discovery = match ProxyRemoteDiscovery::new(app_args).await {
            Ok(d) => d,
            Err(e) => {
                error!(
                    "Can't create Proxy Connection server! Remote Discovery create failed! Error: {e}"
                );
                return Err(Error::ConnectionServer(format!(
                            "Can't create Proxy Connection server! Remote Discovery create failed! Error: {e}"
                )));
            }
        };

        let server = Arc::new(ProxyConnectionServer {
            connmap: ProxyConnMap::new(),
            wss_rx_tx_runtime: wss_runtime_handle,
            mbox_internal_runtime_handle: internal_mbox_runtime_handle,
            mbox_internal_tx: internal_tx,
            proxy_remote_discovery: Arc::new(proxy_remote_discovery),
        });

        let server_clone = server.clone();
        // Task for processing mbox_internal_rx, task owns the RX part
        server.mbox_internal_runtime_handle.spawn(async move {
            server_clone.process(internal_rx).await;
        });

        Ok(server)
    }

    pub async fn ack_connection(
        self: Arc<Self>,
        socket: TcpStream,
        tls_acceptor: tokio_rustls::TlsAcceptor,
        addr: SocketAddr,
    ) {
        // Only ACK connection. We will either drop it or accept it once processor starts
        // (we'll handle it via "mailbox" notify handle in process)
        let server_clone = self.clone();

        self.wss_rx_tx_runtime.spawn(async move {
            // Accept the TLS connection.
            let (client_cn, tls_stream) = match tls_acceptor.accept(socket).await {
                Ok(stream) => match cgw_tls_get_cn_from_stream(&stream).await {
                    Ok(cn) => (cn, stream),
                    Err(e) => {
                        error!("Failed to read client CN! Error: {e}");
                        return;
                    }
                },
                Err(e) => {
                    error!("Failed to accept connection: Error {e}");
                    return;
                }
            };

            let conn_processor = ProxyConnectionProcessor::new(server_clone, addr);
            if let Err(e) = conn_processor.start(tls_stream, client_cn).await {
                error!("Failed to start connection processor! Error: {e}");
            }
        });
    }

    async fn process(self: Arc<Self>, mut rx_mbox: ProxyConnectionServerMboxRx) {
        debug!("process entry");

        let buf_capacity = 200;
        let mut buf: Vec<ProxyConnectionServerReqMsg> = Vec::with_capacity(buf_capacity);
        let mut num_of_msg_read = 0;
        let last_sync_timestamp = Arc::new(RwLock::new(std::time::Instant::now()));
        let devices_to_sync = Arc::new(RwLock::new(Vec::new()));

        loop {
            'mbox_msg_handle_loop: loop {
                // The 'broadcast' messages from remote CGWs have the highest priority
                // of evaluation and handling, because:
                //   * handling of underlying infras while is disconnected from NB API
                //     or processing of remote messages, it is still internally
                //     dependant over data that might change in runtime such as
                //     cloud header, GID association etc;
                //   * the decision this shard in particular makes while processing
                //     NB messages has to be made based on the most actual data
                //     available - redis cache synced, dev cache is up to date,
                //     remote mapping is the latest.
                if let Some(bcast_msg) = self
                    .proxy_remote_discovery
                    .receive_broadcast_message()
                    .await
                {
                    let msg: CGWBroadcastMessage = match serde_json::from_str(&bcast_msg) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("Received msg {:?} but failed to parse it to concrete message type: {e}", bcast_msg);
                            continue;
                        }
                    };

                    // Received message which notifies us about (potential) redis changes.
                    // Based on the underlying message, the following can happen:
                    //   * resync (specific) device cache (if needed);
                    //   * resync remote CGW list (if needed);
                    //   * resync GID to CGW map (if needed);
                    //
                    // This enables 'atomic' handling of events - in case if a single group
                    // gets removed, only those caches of the members of the group would be
                    // altered (GID -> 0, unassigned / GID -> X, assigned).
                    //
                    // The handlers shouldn't filter out the reporter shard id,
                    // hence it gives the following flexibility:
                    //   * Underlying offloaded data (redis, SQL etc) is being
                    //     manipulated (if needed) upon processing Kafka messages
                    //     received from NB services;
                    //   * TODO: RETHINK!!! : We can actually process locally-generated events,
                    //     e.g. generated by local shard, addressed to local shard for
                    //     'later-on' processing
                    //
                    //
                    // TODO: update 'last_update_timestamp' in the underlying func?
                    //       update here - just in place?
                    msg.handle(self.clone()).await;
                } else {
                    // Just to be explicit:
                    // no bcast message received ->
                    // proceed as usual - try to see if we have
                    // and NB api messages etc.
                    break 'mbox_msg_handle_loop;
                }
            }

            let now = std::time::Instant::now();
            let last_sync = *last_sync_timestamp.read().await;
            let elapsed_since_sync = now.duration_since(last_sync);

            if elapsed_since_sync > Duration::from_secs(1) {
                let should_sync = !devices_to_sync.read().await.is_empty();
                if should_sync {
                    let devices_count = devices_to_sync.read().await.len();
                    debug!("Starting to manage {} device connections", devices_count);

                    let start_time = std::time::Instant::now();
                    let _ = self.manage_device_connections(&devices_to_sync).await;
                    let elapsed = start_time.elapsed();

                    debug!(
                        "Exited manage_device_connections, took {:?}, managed {} devices",
                        elapsed, devices_count
                    );
                }

                *last_sync_timestamp.write().await = now;
            }

            // Handle incoming messages
            if num_of_msg_read < buf_capacity {
                // Try to recv_many, but don't sleep too much
                // in case if no messaged pending
                let rd_num = tokio::select! {
                    v = rx_mbox.recv_many(&mut buf, buf_capacity - num_of_msg_read) => {
                        v
                    }
                    _v = sleep(Duration::from_millis(10)) => {
                        0
                    }
                };
                num_of_msg_read += rd_num;

                // We read some messages, try to continue and read more
                // If none read - break from recv, process all buffers that've
                // been filled-up so far (both local and remote).
                // Upon done - repeat.
                if rd_num >= 1 || num_of_msg_read == 0 {
                    continue;
                }
            }

            let mut connmap_w_lock = self.connmap.map.write().await;

            while !buf.is_empty() {
                let msg = buf.remove(0);

                if let ProxyConnectionServerReqMsg::AddNewConnection(
                    device_mac,
                    conn_processor_mbox_tx,
                ) = msg
                {
                    // if connection is unique: simply insert new conn
                    //
                    // if duplicate exists: notify server about such incident.
                    // it's up to server to notify underlying task that it should
                    // drop the connection.
                    // from now on simply insert new connection into hashmap and proceed on
                    // processing it.
                    if let Some(conn_info) = connmap_w_lock.remove(&device_mac) {
                        warn!("Duplicate connection (mac: {}) detected! Closing OLD connection in favor of NEW!", device_mac);
                        let msg: ProxyConnectionProcessorReqMsg =
                            ProxyConnectionProcessorReqMsg::AddNewConnectionShouldClose;
                        if let Err(e) = conn_info.mbox_tx.send(msg) {
                            warn!("Failed to send notification about duplicate connection! Error: {e}")
                        }
                    }

                    // clone a sender handle, as we still have to send ACK back using underlying
                    // tx mbox handle
                    let conn_processor_mbox_tx_clone = conn_processor_mbox_tx.clone();
                    let device_mac_clone = device_mac.clone();

                    info!(
                        "Connection map: connection with {} established, new num_of_connections: {}",
                        device_mac,
                        connmap_w_lock.len() + 1
                    );

                    // Add device to the vec for next sync cycle
                    devices_to_sync.write().await.push(device_mac.clone());

                    let msg: ProxyConnectionProcessorReqMsg =
                        ProxyConnectionProcessorReqMsg::AddNewConnectionAck;

                    if let Err(e) = conn_processor_mbox_tx_clone.send(msg) {
                        error!("Failed to send NewConnection message! Error: {e}");
                    } else {
                        let updated_con_info = ConnectionInfo {
                            mbox_tx: conn_processor_mbox_tx_clone,
                            connected_to_cgw_id: None,
                            connected_to_group_id: 0,
                        };

                        debug!(
                            "Device {} connected, pending group assignment",
                            device_mac_clone
                        );
                        connmap_w_lock.insert(device_mac_clone, updated_con_info);
                    }
                } else if let ProxyConnectionServerReqMsg::ConnectionClosed(device_mac) = msg {
                    // Check if this connection exists
                    if let Some(conn_info) = connmap_w_lock.get_mut(&device_mac) {
                        // If the connection has an assigned CGW, just reset that assignment
                        if conn_info.connected_to_cgw_id.is_some() {
                            info!(
                                "Connection map: CGW connection broken for {}, resetting CGW assignment",
                                device_mac
                            );
                            conn_info.connected_to_cgw_id = None;
                        } else {
                            info!(
                                "Connection map: removed {} serial from connmap, new num_of_connections: {}",
                                device_mac,
                                connmap_w_lock.len() - 1
                            );

                            connmap_w_lock.remove(&device_mac);

                            // Also remove the device from devices_to_sync
                            let mut sync_devices = devices_to_sync.write().await;
                            sync_devices.retain(|mac| *mac != device_mac);
                        }
                    } else {
                        debug!(
                            "Received ConnectionClosed for unknown device: {}",
                            device_mac
                        );
                    }
                }
            }

            buf.clear();
            num_of_msg_read = 0;
        }
    }

    async fn manage_device_connections(
        self: &Arc<Self>,
        devices_to_sync: &Arc<RwLock<Vec<MacAddress>>>,
    ) -> Result<()> {
        // Get the list of devices to process
        let devices_to_process = {
            let devices_read = devices_to_sync.read().await;
            if devices_read.is_empty() {
                return Ok(());
            }
            devices_read.clone()
        };

        debug!("Managing {} device connections", devices_to_process.len());

        // Track which devices to remove
        let mut devices_to_remove = Vec::new();

        let mut tasks = Vec::new();
        let connmap_r_lock = self.connmap.map.read().await;

        for mac in &devices_to_process {
            debug!("processing {mac}");

            if let Some(conn_info) = connmap_r_lock.get(mac) {
                let mac_clone = mac.clone();
                let conn_info_clone = conn_info.clone();
                let self_clone = self.clone();

                let task = self.wss_rx_tx_runtime.spawn(async move {
                    debug!("<internal task> processing {mac_clone}");
                    let device_result = self_clone
                        .proxy_remote_discovery
                        .get_single_device_cache_with_redis(mac_clone)
                        .await;
                    let cgw_group_owner_id: Option<i32>;

                    let device = match device_result {
                        Ok((device, _)) => {
                            let device_group_id = device.get_device_group_id();
                            cgw_group_owner_id = self_clone
                                .proxy_remote_discovery
                                .get_infra_group_owner_id(device_group_id)
                                .await;
                            Some(device)
                        }
                        Err(e) => {
                            error!("Failed to sync device {} with Redis: {}", mac_clone, e);
                            cgw_group_owner_id = None;
                            None
                        }
                    };

                    let result = if conn_info_clone.connected_to_group_id == 0 {
                        self_clone
                            .manage_unassigned_connection(&mac_clone, device, cgw_group_owner_id)
                            .await
                    } else {
                        self_clone
                            .manage_assigned_connection(&mac_clone, device, cgw_group_owner_id)
                            .await
                    };

                    (mac_clone, result)
                });

                tasks.push(task);
            } else {
                debug!("Device {} not found in connection map during sync", mac);
                devices_to_remove.push(*mac);
            }
        }

        drop(connmap_r_lock);

        for task in tasks {
            match task.await {
                Ok((mac, result)) => {
                    if result.is_ok() {
                        devices_to_remove.push(mac);
                        debug!("{} processed", mac);
                    } else {
                        debug!("{} was not processed", mac);
                    }
                }
                Err(e) => {
                    error!("Task joined with error: {}", e);
                }
            }
        }

        // Remove the processed devices from the list
        if !devices_to_remove.is_empty() {
            let mut devices_write = devices_to_sync.write().await;
            devices_write.retain(|m| !devices_to_remove.contains(m));
        }

        Ok(())
    }

    async fn manage_unassigned_connection(
        self: &Arc<Self>,
        mac: &MacAddress,
        device: Option<CGWDevice>,
        cgw_group_owner_id: Option<i32>,
    ) -> Result<()> {
        if let Some(cached_device) = device {
            // Device in cache
            let device_group_id = cached_device.get_device_group_id();
            if let Some(owner_id) = cgw_group_owner_id {
                if let Err(e) = self
                    .set_peer_connection(mac, owner_id, device_group_id)
                    .await
                {
                    error!("Failed to set peer for device {}: {}", mac, e);
                    return Err(Error::ConnectionServer(format!(
                        "Failed to set peer for device {}: {}",
                        mac, e
                    )));
                }
                debug!(
                    "Assigned device {} to group {} on CGW {}",
                    mac, device_group_id, owner_id
                );
            } else {
                // Unexpected: cgw_group_owner_id is not assigned
                warn!("Unexpected: unassigned connection: cgw_group_owner_id is not assigned for mac {} and group id: {}",
                        mac, device_group_id);
            }
        } else {
            // Device is not in cache
            match self.get_round_robin_cgw_id().await {
                Ok(round_robin_cgw_id) => {
                    if let Err(e) = self.set_peer_connection(mac, round_robin_cgw_id, 0).await {
                        error!("Failed to set round-robin peer for device {}: {}", mac, e);
                        return Err(Error::ConnectionServer(format!(
                            "Failed to set round-robin peer for device {}: {}",
                            mac, e
                        )));
                    }
                    debug!(
                        "Assigned unregistered device {} to round-robin CGW {}",
                        mac, round_robin_cgw_id
                    );
                }
                Err(e) => {
                    return Err(Error::ConnectionServer(format!(
                        "Failed to get round-robin CGW ID: {} Error: {}",
                        mac, e
                    )));
                }
            }
            debug!("Unassigned connection done! {} was not in cache", mac);
        }

        Ok(())
    }

    async fn manage_assigned_connection(
        self: &Arc<Self>,
        mac: &MacAddress,
        device: Option<CGWDevice>,
        cgw_group_owner_id: Option<i32>,
    ) -> Result<()> {
        if let Some(cached_device) = device {
            let device_group_id = cached_device.get_device_group_id();
            // Device exists in cache
            if let Some(owner_id) = cgw_group_owner_id {
                if let Err(e) = self
                    .set_peer_connection(mac, owner_id, device_group_id)
                    .await
                {
                    error!(
                        "Failed to update peer for device {} with new group {}: {}",
                        mac, device_group_id, e
                    );
                    return Err(Error::ConnectionServer(format!(
                        "Failed to update peer for device {} with new group {}: {}",
                        mac, device_group_id, e
                    )));
                }
            } else {
                // Unexpected: cgw_group_owner_id is not assigned
                warn!("Unexpected: assigned connection: cgw_group_owner_id is not assigned for mac {} and group id: {}",
                        mac, device_group_id);
            }
        } else {
            // Unexpected: Device not in cache
            // Get round-robin CGW ID
            match self.get_round_robin_cgw_id().await {
                Ok(round_robin_cgw_id) => {
                    // Set peer connection
                    if let Err(e) = self.set_peer_connection(mac, round_robin_cgw_id, 0).await {
                        error!("Failed to reset peer for removed device {}: {}", mac, e);
                        return Err(Error::ConnectionServer(format!(
                            "Failed to reset peer for removed device {}: {}",
                            mac, e
                        )));
                    }
                    debug!(
                        "Device {} not in cache, assigned to round-robin CGW {}",
                        mac, round_robin_cgw_id
                    );
                }
                Err(e) => {
                    error!("Failed to get round-robin CGW ID: {} Error: {}", mac, e);
                    return Err(Error::ConnectionServer(format!(
                        "Failed to get round-robin CGW ID: {} Error: {}",
                        mac, e
                    )));
                }
            }
            warn!("Unexpected: assigned connection: {} is not in cache", mac);
        }

        Ok(())
    }

    pub async fn enqueue_mbox_message_to_proxy_server(&self, req: ProxyConnectionServerReqMsg) {
        if let Err(e) = self.mbox_internal_tx.send(req) {
            error!("Failed to send message to Proxy server (internal)! Error: {e}");
        }
    }

    async fn set_peer_connection(
        self: &Arc<Self>,
        mac: &MacAddress,
        cgw_id: i32,
        group_id: i32,
    ) -> Result<()> {
        let mut connmap_w_lock = self.connmap.map.write().await;
        let conn_info = if let Some(conn_info) = connmap_w_lock.get_mut(mac) {
            conn_info
        } else {
            debug!("Device {} not found in connection map", mac);
            return Err(Error::ConnectionServer(format!(
                "Device {} not found in connection map",
                mac
            )));
        };

        if conn_info.connected_to_cgw_id == Some(cgw_id)
            && conn_info.connected_to_group_id == group_id
        {
            debug!(
                "Noting to do: set_peer_connection, cgw_id: {}, group_id: {}",
                cgw_id, group_id
            );
            return Ok(());
        }

        debug!(
            "set_peer_connection, cgw_id: {}, group_id: {}",
            cgw_id, group_id
        );

        conn_info.connected_to_cgw_id = Some(cgw_id);
        conn_info.connected_to_group_id = group_id;

        let mbox_tx = conn_info.mbox_tx.clone();
        let mac_clone = mac.clone();

        drop(connmap_w_lock);

        // Get the socket address for the CGW instance
        let (host, port) = match self
            .proxy_remote_discovery
            .get_shard_host_and_wss_port(cgw_id)
            .await
        {
            Ok((host, port)) => (host, port),
            Err(e) => {
                error!("Failed to get peer address for device {}: {}", mac_clone, e);
                return Err(Error::ConnectionServer(format!(
                    "Failed to get peer address for device {}: {}",
                    mac_clone, e
                )));
            }
        };

        let peer_msg = ProxyConnectionProcessorReqMsg::SetPeer(format!("{}:{}", host, port));
        if let Err(e) = mbox_tx.send(peer_msg) {
            error!(
                "Failed to send ConnectToPeer message for device {}: {}",
                mac_clone, e
            );
            return Err(Error::ConnectionServer(format!(
                "Failed to send ConnectToPeer message for device {}: {}",
                mac_clone, e
            )));
        }

        Ok(())
    }

    async fn get_round_robin_cgw_id(&self) -> Result<i32> {
        let available_cgw_ids = match self.proxy_remote_discovery.get_available_cgw_ids().await {
            Ok(ids) => ids,
            Err(e) => {
                return Err(Error::ConnectionServer(format!(
                    "Failed to get available CGW IDs: {}",
                    e
                )));
            }
        };

        if available_cgw_ids.is_empty() {
            return Err(Error::ConnectionServer(
                "No available CGW IDs for round-robin assignment".to_string(),
            ));
        }

        let current = LAST_CGW_INDEX.load(Ordering::SeqCst);
        let next_index = (current + 1) % available_cgw_ids.len();

        LAST_CGW_INDEX.store(next_index, Ordering::SeqCst);

        let index = current % available_cgw_ids.len();

        debug!(
            "Selected CGW ID {} for round-robin (index {})",
            available_cgw_ids[index], index
        );

        Ok(available_cgw_ids[index])
    }
}
