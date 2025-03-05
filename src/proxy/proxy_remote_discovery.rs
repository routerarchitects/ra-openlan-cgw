use cgw_common::{
    cgw_errors::{Error, Result},
    cgw_app_args::{AppArgs, CGWRedisArgs},
    cgw_tls::cgw_read_root_certs_dir,
    cgw_device::CGWDevice,
};

use std::{
    collections::HashMap,
    str::FromStr,
    sync::Arc,
};

use redis::{
    aio::{
        MultiplexedConnection, ConnectionManager, ConnectionManagerConfig
    },
    Client, ConnectionInfo, RedisConnectionInfo, RedisResult,
    TlsCertificates, PushInfo, ProtocolVersion, PushKind, Value,
};

use tokio::{
    sync::{
        Mutex,
        RwLock,
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    },
    time::{sleep, Duration},
};

use std::time::Instant;
use eui48::MacAddress;

// Used in remote lookup
static REDIS_KEY_SHARD_ID_PREFIX: &str = "shard_id_";
static REDIS_KEY_SHARD_ID_FIELDS_NUM: usize = 12;

// Used in group assign / reassign
static REDIS_KEY_GID: &str = "group_id_";
static REDIS_KEY_GID_VALUE_GID: &str = "gid";
static REDIS_KEY_GID_VALUE_SHARD_ID: &str = "shard_id";

const CGW_REDIS_DEVICES_CACHE_DB: u32 = 1;

const CGW_REDIS_PUBSUB_TOPIC: &str = "cgw_notification_channel";

pub fn cgw_redis_default_proto() -> ProtocolVersion {
    ProtocolVersion::default()
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CGWREDISDBShard {
    id: i32,
    server_host: String,
    server_port: u16,
    wss_port: u16,
    assigned_groups_num: i32,
    capacity: i32,
    threshold: i32,
}

impl From<Vec<String>> for CGWREDISDBShard {
    fn from(values: Vec<String>) -> Self {
        if values.len() < REDIS_KEY_SHARD_ID_FIELDS_NUM {
            error!("Unexpected size of parsed vector! At least {REDIS_KEY_SHARD_ID_FIELDS_NUM} expected!");
            return CGWREDISDBShard::default();
        }

        if values[0] != "id" {
            error!("redis.res[0] != id, unexpected.");
            return CGWREDISDBShard::default();
        } else if values[2] != "server_host" {
            error!("redis.res[2] != server_host, unexpected.");
            return CGWREDISDBShard::default();
        } else if values[4] != "server_port" {
            error!("redis.res[4] != server_port, unexpected.");
            return CGWREDISDBShard::default();
        } else if values[6] != "wss_port" {
            error!("redis.res[6] != wss_port, unexpected.");
            return CGWREDISDBShard::default();
        } else if values[8] != "assigned_groups_num" {
            error!("redis.res[8] != assigned_groups_num, unexpected.");
            return CGWREDISDBShard::default();
        } else if values[10] != "capacity" {
            error!("redis.res[10] != capacity, unexpected.");
            return CGWREDISDBShard::default();
        } else if values[12] != "threshold" {
            error!("redis.res[12] != threshold, unexpected.");
            return CGWREDISDBShard::default();
        }

        let id = values[1].parse::<i32>().unwrap_or_default();
        let server_host = values[3].clone();
        let server_port = values[5].parse::<u16>().unwrap_or_default();
        let wss_port = values[7].parse::<u16>().unwrap_or_default();
        let assigned_groups_num = values[9].parse::<i32>().unwrap_or_default();
        let capacity = values[11].parse::<i32>().unwrap_or_default();
        let threshold = values[13].parse::<i32>().unwrap_or_default();

        CGWREDISDBShard {
            id,
            server_host,
            server_port,
            wss_port,
            assigned_groups_num,
            capacity,
            threshold,
        }
    }
}

impl From<CGWREDISDBShard> for Vec<String> {
    fn from(val: CGWREDISDBShard) -> Self {
        vec![
            "id".to_string(),
            val.id.to_string(),
            "server_host".to_string(),
            val.server_host,
            "server_port".to_string(),
            val.server_port.to_string(),
            "wss_port".to_string(),
            val.wss_port.to_string(),
            "assigned_groups_num".to_string(),
            val.assigned_groups_num.to_string(),
            "capacity".to_string(),
            val.capacity.to_string(),
            "threshold".to_string(),
            val.threshold.to_string(),
        ]
    }
}

#[derive(Clone)]
pub struct ProxyRemoteDiscovery {
    redis_pubsub_client: ConnectionManager,
    redis_pubsub_rx_mbox: Arc<Mutex<UnboundedReceiver<PushInfo>>>,
    redis_client: ConnectionManager,
    redis_infra_cache_client: ConnectionManager,
    gid_to_cgw_cache: Arc<RwLock<HashMap<i32, i32>>>,
    remote_cgws_map: Arc<RwLock<HashMap<i32, CGWREDISDBShard>>>,
}

pub async fn cgw_create_redis_client(redis_args: &CGWRedisArgs, protocol: ProtocolVersion) -> Result<Client> {
    let redis_client_info = ConnectionInfo {
        addr: match redis_args.redis_tls {
            true => redis::ConnectionAddr::TcpTls {
                host: redis_args.redis_host.clone(),
                port: redis_args.redis_port,
                insecure: true,
                tls_params: None,
            },
            false => {
                redis::ConnectionAddr::Tcp(redis_args.redis_host.clone(), redis_args.redis_port)
            }
        },

        redis: RedisConnectionInfo {
            username: redis_args.redis_username.clone(),
            password: redis_args.redis_password.clone(),
            protocol,
            ..Default::default()
        },
    };

    match redis_args.redis_tls {
        true => {
            let root_cert = cgw_read_root_certs_dir().await.ok();

            let tls_certs: TlsCertificates = TlsCertificates {
                client_tls: None,
                root_cert,
            };

            match redis::Client::build_with_tls(redis_client_info, tls_certs) {
                Ok(client) => Ok(client),
                Err(e) => Err(Error::Redis(format!(
                    "Failed to start Redis client! Error: {e}"
                ))),
            }
        }
        false => match redis::Client::open(redis_client_info) {
            Ok(client) => Ok(client),
            Err(e) => Err(Error::Redis(format!(
                "Failed to start Redis client! Error: {e}"
            ))),
        },
    }
}

impl ProxyRemoteDiscovery {
    pub async fn new(app_args: &AppArgs) -> Result<Self> {
        debug!(
            "Trying to create redis db connection ({}:{})",
            app_args.redis_args.redis_host, app_args.redis_args.redis_port
        );

        // Don't really need RESP3 here, RESP3 only needed for pub/sub client.
        let redis_client = match cgw_create_redis_client(&app_args.redis_args, cgw_redis_default_proto()).await {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Can't create CGW Remote Discovery client! Redis client create failed! Error: {e}"
                );
                return Err(Error::RemoteDiscovery("Redis client create failed"));
            }
        };

        let redis_conn = {
            let max_retries = 3;
            let mut attempt = 0;

            loop {
                attempt += 1;

                let cfg = ConnectionManagerConfig::new()
                    .set_connection_timeout(Duration::from_secs(10))
                    .set_response_timeout(Duration::from_secs(10))
                    .set_number_of_retries(5);

                match ConnectionManager::new_with_config(redis_client.clone(), cfg).await {
                    Ok(conn) => break conn,
                    Err(e) => {
                        if attempt >= max_retries {
                            error!(
                                "Can't create CGW Remote Discovery client after {attempt} attempts! Get Redis async connection failed! Error: {e}"
                            );
                            return Err(Error::RemoteDiscovery("Redis client create failed after max retries"));
                        }
                        warn!("Redis connection attempt {attempt}/{max_retries} failed. Retrying in 1 second... Error: {e}");

                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        };

        /* Start Redis Infra Cache Client */
        let redis_infra_cache_client = match cgw_create_redis_client(&app_args.redis_args, cgw_redis_default_proto()).await {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Can't create CGW Remote Discovery client! Redis infra cache client create failed! Error: {e}"
                );
                return Err(Error::RemoteDiscovery(
                    "Redis infra cache client create failed",
                ));
            }
        };

        let cfg = ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_secs(10))
            .set_response_timeout(Duration::from_secs(10))
            .set_number_of_retries(5);

        let mut redis_infra_cache_client = match ConnectionManager::new_with_config(redis_infra_cache_client, cfg).await {
            Ok(conn) => conn,
            Err(e) => {
                error!(
                    "Can't create CGW Remote Discovery client! Get Redis infra cache async connection failed! Error: {e}"
                );
                return Err(Error::RemoteDiscovery(
                    "Redis infra cache client create failed",
                ));
            }
        };

        let res: RedisResult<()> = redis::cmd("SELECT")
            .arg(CGW_REDIS_DEVICES_CACHE_DB.to_string())
            .query_async(&mut redis_infra_cache_client)
            .await;
        match res {
            Ok(_) => debug!(
                "Switched Redis infra cache client to Redis Database {CGW_REDIS_DEVICES_CACHE_DB}"
            ),
            Err(e) => {
                warn!(
                    "Failed to switch to Redis Database {CGW_REDIS_DEVICES_CACHE_DB}! Error: {e}"
                );
                return Err(Error::RemoteDiscovery("Failed to switch Redis Database"));
            }
        };

        /* End Redis Infra Cache Client */

        /* Start of init pubsub client*/

        // Explicitly request RESP3 here. Needed for underlying push_sender impl.
        let redis_pubsub_client = match cgw_create_redis_client(&app_args.redis_args, ProtocolVersion::RESP3).await {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Can't create CGW Remote Discovery client! PUB/SUB Redis client create failed! Error: {e}"
                );
                return Err(Error::RemoteDiscovery("Redis client create failed"));
            }
        };

        // Needed for push_sender / receiving messages from subscribed topics.
        let (channel_tx, mut channel_rx) = tokio::sync::mpsc::unbounded_channel();

        let cfg = ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_secs(10))
            .set_response_timeout(Duration::from_secs(10))
            .set_number_of_retries(5)
            .set_push_sender(channel_tx)
            .set_automatic_resubscription();

        let mut redis_pubsub_client = match ConnectionManager::new_with_config(redis_pubsub_client, cfg)
            .await
        {
            Ok(conn) => conn,
            Err(e) => {
                error!(
                    "Can't create CGW Remote Discovery client! Get PUB/SUB Redis async connection failed! Error: {e}"
                );
                return Err(Error::RemoteDiscovery("Redis client create failed"));
            }
        };

        redis_pubsub_client.subscribe(CGW_REDIS_PUBSUB_TOPIC).await;

        /* EO of init pubsub client*/

        let rc = ProxyRemoteDiscovery {
            redis_pubsub_client,
            redis_pubsub_rx_mbox: Arc::new(Mutex::new(channel_rx)),
            redis_client: redis_conn,
            redis_infra_cache_client,
            gid_to_cgw_cache: Arc::new(RwLock::new(HashMap::new())),
            remote_cgws_map: Arc::new(RwLock::new(HashMap::new())),
        };

        info!("Connection to REDIS DB has been established!");

        Ok(rc)
    }

    pub async fn sync_gid_to_cgw_map(&self) -> Result<i32> {
        let mut lock = self.gid_to_cgw_cache.write().await;

        // Clear hashmap
        lock.clear();
        let mut con = self.redis_client.clone();

        let redis_keys: Vec<String> = match redis::cmd("KEYS")
            .arg(format!("{REDIS_KEY_GID}*"))
            .query_async(&mut con)
            .await
        {
            Err(e) => {
                error!("Failed to sync gid to cgw map! Error: {e}");
                return Err(Error::RemoteDiscovery("Failed to get KEYS list from REDIS"));
            }
            Ok(keys) => keys,
        };

        let mut total_groups = 0;

        for key in redis_keys {
            let gid: i32 = match redis::cmd("HGET")
                .arg(&key)
                .arg(REDIS_KEY_GID_VALUE_GID)
                .query_async(&mut con)
                .await
            {
                Ok(gid) => gid,
                Err(e) => {
                    warn!("Found proper key '{key}' entry, but failed to fetch GID from it! Error: {e}");
                    continue;
                }
            };

            let shard_id: i32 = match redis::cmd("HGET")
                .arg(&key)
                .arg(REDIS_KEY_GID_VALUE_SHARD_ID)
                .query_async(&mut con)
                .await
            {
                Ok(shard_id) => shard_id,
                Err(e) => {
                    warn!("Found proper key '{key}' entry, but failed to fetch SHARD_ID from it! Error: {e}");
                    continue;
                }
            };

            match lock.insert(gid, shard_id) {
                None => total_groups += 1,
                Some(_v) => warn!(
                    "Populated gid_to_cgw_map with previous value being already set, unexpected!"
                ),
            }
        }

        Ok(total_groups)
    }

    pub async fn sync_remote_cgw_map(&self) -> Result<()> {
        let mut lock = self.remote_cgws_map.write().await;

        // Clear hashmap
        lock.clear();

        let mut con = self.redis_client.clone();
        let redis_keys: Vec<String> = match redis::cmd("KEYS")
            .arg(format!("{REDIS_KEY_SHARD_ID_PREFIX}*"))
            .query_async(&mut con)
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                error!(
                    "Can't sync remote CGW map! Failed to get shard record in REDIS! Error: {e}"
                );
                return Err(Error::RemoteDiscovery("Failed to get KEYS list from REDIS"));
            }
        };

        for key in redis_keys {
            let res: RedisResult<Vec<String>> =
                redis::cmd("HGETALL").arg(&key).query_async(&mut con).await;

            match res {
                Ok(res) => {
                    let shard: CGWREDISDBShard = CGWREDISDBShard::from(res);

                    if shard == CGWREDISDBShard::default() {
                        warn!("Failed to parse CGWREDISDBShard, key: {key}!");
                        continue;
                    }

                    lock.insert(shard.id, shard);
                }
                Err(e) => {
                    warn!("Found proper key '{key}' entry, but failed to fetch Shard info from it! Error: {e}");
                    continue;
                }
            }
        }

        debug!("Final remote_cgws_map size: {}", lock.len());
        return Ok(());
    }

    pub async fn get_infra_group_owner_id(&self, gid: i32) -> Option<i32> {
        if gid == 0 {
            return None; // In case gid wasn't changed
        }
        // Try to use internal cache first
        if let Some(id) = self.gid_to_cgw_cache.read().await.get(&gid) {
            return Some(*id);
        }

        // Then try to sync and check again
        if let Err(e) = self.sync_gid_to_cgw_map().await {
            error!("Failed to sync GID to CGW map! Error: {e}");
        }

        // Check again after sync
        if let Some(id) = self.gid_to_cgw_cache.read().await.get(&gid) {
            return Some(*id);
        }

        None
    }

    pub async fn get_shard_host_and_wss_port(&self, shard_id: i32) -> Result<(String, u16)> {
        debug!("Getting shard host and server port for shard ID: {}", shard_id);

        // if let Err(e) = self.sync_remote_cgw_map().await {
        //     error!("Failed to sync remote CGW map: {e}");
        //     return Err(Error::RemoteDiscovery(
        //         "Failed to sync (sync_remote_cgw_map) remote CGW info from REDIS",
        //     ));
        // }

        let lock = self.remote_cgws_map.read().await;

        match lock.get(&shard_id) {
            Some(instance) => {
                debug!("Found shard {}: host={}, wss_port={}",
                       shard_id, instance.server_host, instance.wss_port);
                Ok((instance.server_host.clone(), instance.wss_port))
            },
            None => {
                error!("Shard ID {} not found in map", shard_id);
                Err(Error::RemoteDiscovery(
                    "Unexpected: Failed to find CGW shard",
                ))
            }
        }
    }

    pub async fn get_single_device_cache_with_redis(
        &self,
        infra: MacAddress,
    ) -> Result<(CGWDevice, MacAddress)> {
        let mut con = self.redis_infra_cache_client.clone();
        // TODO: use specific shard
        let key = format!("{}*|{}", REDIS_KEY_SHARD_ID_PREFIX, infra.to_canonical());
        let redis_keys: Vec<String> = match redis::cmd("KEYS").arg(&key).query_async(&mut con).await
        {
            Err(e) => {
                error!("Failed to get device cache from Redis, Error: {e}");
                return Err(Error::RemoteDiscovery(
                    "Failed to get device cache from Redis",
                ));
            }
            Ok(key) => key,
        };

        if redis_keys.is_empty() {
            debug!("No device entry found in Redis for MAC: {}", infra);
            return Err(Error::RemoteDiscovery(
                "No device entry found",
            ));
        }

        let device_str: String = match redis::cmd("GET").arg(&redis_keys[0]).query_async(&mut con).await {
            Ok(dev) => dev,
            Err(e) => {
                error!(
                    "Failed to get devices cache from Redis, Error: {}", e
                    // "Failed to get devices cache from Redis for shard id {}, Error: {}",
                    // shard_id, e
                );
                return Err(Error::RemoteDiscovery(
                    "Failed to get devices cache from Redis",
                ));
            }
        };

        match self.deserialize_single_device_cache_redis_entry(&device_str, &redis_keys[0]) {
            Ok((dev, mac)) => {
                return Ok((dev, mac));
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    fn deserialize_single_device_cache_redis_entry(
        &self,
        device_str: &String,
        key: &String,
    ) -> Result<(CGWDevice, MacAddress)> {
        let mut splitted_key = key.split_terminator('|');
        let _shard_id = splitted_key.next();
        let infra = match splitted_key.next() {
            Some(mac) => match MacAddress::from_str(mac) {
                Ok(mac_address) => mac_address,
                Err(e) => {
                    error!(
                        "Failed to parse device mac address from key! Error: {}", e
                    );
                    return Err(Error::RemoteDiscovery(
                        "Failed to parse device mac address from key",
                    ));
                }
            },
            None => {
                error!(
                    "Failed to get device mac address from key !"
                );
                return Err(Error::RemoteDiscovery(
                    "Failed to get device mac address from key",
                ));
            }
        };

        match serde_json::from_str(&device_str) {
            Ok(dev) => {
                Ok((dev, infra))
            }
            Err(e) => {
                error!("Failed to deserialize device from Redis cache! Error: {e}");
                Err(Error::RemoteDiscovery(
                    "Failed to deserialize device from Redis cache",
                ))
            }
        }
    }

    pub async fn get_available_cgw_ids(&self) -> Result<Vec<i32>> {
        debug!("Getting available CGW IDs");
        let remote_cgws = self.remote_cgws_map.read().await;

        if remote_cgws.is_empty() {
            warn!("No CGW instances found in remote_cgws_map");
            return Err(Error::RemoteDiscovery("No CGW instances available"));
        }

        // Filter available CGWs based on capacity and threshold
        let mut available_cgws: Vec<i32> = remote_cgws
            .iter()
            .filter(|(_, shard)| {
                // Only include CGWs that have capacity to handle more groups
                shard.assigned_groups_num < shard.capacity &&
                // Allow some buffer using threshold
                (shard.capacity - shard.assigned_groups_num) > shard.threshold
            })
            .map(|(id, _)| *id)
            .collect();

        if available_cgws.is_empty() {
            // If no CGWs meet the capacity/threshold criteria, include all CGW IDs
            // as a fallback, so devices can still connect somewhere
            warn!("No CGWs with available capacity found, returning all CGW IDs");
            available_cgws = remote_cgws.keys().cloned().collect();
        }

        // Sort the CGW IDs for consistent round-robin selection
        available_cgws.sort();
        debug!("Found {} available CGW IDs: {:?}", available_cgws.len(), available_cgws);

        Ok(available_cgws)
    }

    pub async fn receive_broadcast_message(&self) -> Option<String> {
        let mut mbox_lock = self.redis_pubsub_rx_mbox.lock().await;

        // TODO: no sleep?
        let _ = tokio::select! {
            v = mbox_lock.recv() => {
                if let Some(mut v) = v {
                    debug!("Got msg {:?}", v);

                    if let PushKind::Message = v.kind {
                        if v.data.len() != 2 {
                            warn!("Received Broadcast msg {:?}, but the num of args is invalid:{}, ignoring", v.data, v.data.len());
                            return None;
                        }

                        match v.data.swap_remove(0) {
                            Value::BulkString(val) => {
                                let val = match String::from_utf8(val) {
                                    Ok(val_str) => val_str,
                                    Err(e) => {
                                        warn!("Received Broadcast msg {:?}, but couldn't parse topic value, ignoring", v.data);
                                        return None;
                                    }
                                };
                                if val != CGW_REDIS_PUBSUB_TOPIC {
                                    warn!("Received unexpected topic Broadcast msg {:?}, {} expected, ignoring", v.data, CGW_REDIS_PUBSUB_TOPIC);
                                    return None;
                                }
                            }
                            _ => {
                                warn!("Received unexpected Broadcast msg type {:?}, 'bulk_string' expected, ignoring", v.data);
                                return None;
                            }
                        }

                        match v.data.swap_remove(0) {
                            Value::BulkString(val) => {
                                let val = match String::from_utf8(val) {
                                    Ok(val_str) => val_str,
                                    Err(e) => {
                                        warn!("Received Broadcast msg {:?}, but couldn't parse underlying value, ignoring", v.data);
                                        return None;
                                    }
                                };

                                return Some(val);
                            }
                            _ => {
                                warn!("Received unexpected Broadcast msg type {:?}, 'bulk_string' expected, ignoring", v.data);
                                return None;
                            }
                        }
                    } else {
                        return None;
                    }

                } else {
                    // Dead RX part, unexpected, potentially should restart CGW
                    return None;
                }
            }

            _ = sleep(Duration::from_millis(10)) => {
                return None;
            }
        };

        /*
           match v {
           Some(msg) => {
           match msg.get_payload::<String>() {
           Ok(pload) => return Some(pload),
           Err(e) => {
           error!("Received message from Redis pub/sub, but failed to parse it: {:?}", msg);
           return None;
           }
           }
           }
           None => {
           warn!();
           return None;
           }
           }
           }
           */

        None
}

    pub async fn send_broadcast_message(&self, msg: String) -> Result<()> {
        let mut con = self.redis_pubsub_client.clone();
        let res: RedisResult<()> = redis::cmd("PUBLISH")
            .arg(CGW_REDIS_PUBSUB_TOPIC)
            .arg(msg)
            .query_async(&mut con)
            .await;

        if let Err(e) = res {
            warn!(
                "Failed to switch to Redis Database {CGW_REDIS_DEVICES_CACHE_DB}! Error: {e}"
            );
            return Err(Error::RemoteDiscovery("Failed to switch Redis Database"));
        }

        Ok(())
    }
}
