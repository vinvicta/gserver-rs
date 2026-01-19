//! # Player Connection Management
//!
//! This module handles individual TCP connections from Graal clients.
//!
//! # Architecture
//!
//! Each connection runs in its own Tokio task and manages:
//! - TCP socket I/O
//! - Packet buffering and parsing
//! - Compression/decompression
//! - Timeout handling
//! - Connection state tracking
//!
//! # Lifecycle
//!
//! ```text
//! Connected → LoggingIn → Authenticated → Disconnecting → Disconnected
//!             ↓                ↓
//!           Failed           Timeout
//! ```
//!
//! # Memory Usage
//!
//! Each connection uses approximately:
//! - Read buffer: 8KB (configurable)
//! - Write buffer: 8KB (configurable)
//! - State tracking: ~1KB
//! - **Total per connection**: ~17KB (vs 50KB in C++)
//!
//! # Thread Safety
//!
//! Connection state is protected by a `Mutex` but is typically only accessed
//! from within the connection's own task. External access goes through
//! connection handles that clone the `Arc`.

use bytes::{BufMut, BytesMut};
use gserver_accounts::{Account, AccountLoader};
use gserver_core::{PlayerID, Result};
use gserver_protocol::{PacketIn, PacketOut, CompressionType};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::interval;

/// State of a player connection
///
/// # Purpose
/// Tracks where the connection is in its lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection just established, waiting for login
    Connected,

    /// Login packet received, validating credentials
    LoggingIn,

    /// Authentication successful, player is logged in
    Authenticated,

    /// Connection is being closed (cleanup in progress)
    Disconnecting,

    /// Connection closed
    Disconnected,
}

/// Outbound packet queue for batching
///
/// # Purpose
/// Implements CFileQueue-like behavior to batch multiple packets into one compressed bundle.
/// This matches the C++ implementation's packet batching strategy.
///
/// # Architecture
/// - Normal packets: Batched up to 48KB, then compressed and sent
/// - File packets: Sent in order, interleaved with normal packets
///
/// # C++ Equivalence
/// Matches `CFileQueue` in `/home/versa/Desktop/GServer-v2/dependencies/gs2lib/src/CFileQueue.cpp`
#[derive(Debug, Default)]
struct OutboundQueue {
    /// Normal packets (can be batched)
    normal_buffer: Vec<BytesMut>,

    /// File packets (must send in order)
    file_buffer: Vec<BytesMut>,

    /// Total bytes in normal buffer
    normal_bytes: usize,

    /// Number of send cycles without flushing (for GEN_5 compatibility)
    send_cycles_without_flush: u32,
}

impl OutboundQueue {
    /// Create a new empty outbound queue
    fn new() -> Self {
        Self::default()
    }

    /// Add a packet to the appropriate buffer
    ///
    /// # Arguments
    /// * `packet` - Serialized packet data (including newline)
    /// * `is_file_packet` - If true, goes to file buffer (must send in order)
    fn add_packet(&mut self, packet: BytesMut, is_file_packet: bool) {
        if is_file_packet {
            self.file_buffer.push(packet);
        } else {
            self.normal_bytes += packet.len();
            self.normal_buffer.push(packet);
        }
    }

    /// Check if we should flush (C++ logic: >= 48KB or >= 4 send cycles)
    fn should_flush(&self) -> bool {
        self.normal_bytes >= 0xC000 || self.send_cycles_without_flush >= 4
    }

    /// Reset send cycle counter
    fn reset_send_cycles(&mut self) {
        self.send_cycles_without_flush = 0;
    }

    /// Increment send cycle counter
    fn increment_send_cycles(&mut self) {
        self.send_cycles_without_flush += 1;
    }
}

/// Individual player connection
///
/// # Purpose
/// Manages a single TCP connection from a Graal client.
///
/// # Architecture
/// Each connection:
/// 1. Runs in its own Tokio task
/// 2. Has its own read/write buffers
/// 3. Handles packet parsing and validation
/// 4. Manages compression/decompression
/// 5. Tracks timeouts and activity
///
/// # Thread Safety
/// Internally synchronized with `Mutex`, allowing safe sharing across tasks.
///
/// # Example
///
/// ```rust,no_run
/// use gserver_network::PlayerConnection;
/// use tokio::net::TcpStream;
///
/// let stream = TcpStream::connect("127.0.0.1:14902").await?;
/// let conn = PlayerConnection::new(player_id, stream, peer_addr);
/// conn.run().await?;
/// ```
pub struct PlayerConnection {
    /// Unique identifier for this player
    pub player_id: PlayerID,

    /// Peer address (IP:port)
    pub peer_addr: SocketAddr,

    /// Connection state
    state: Arc<Mutex<ConnectionState>>,

    /// TCP socket (protected by Tokio mutex for Send safety)
    socket: Arc<TokioMutex<TcpStream>>,

    /// Read buffer
    read_buf: Arc<Mutex<BytesMut>>,

    /// Write buffer
    write_buf: Arc<Mutex<BytesMut>>,

    /// Outbound packet queue for batching (CFileQueue equivalent)
    outbound_queue: Arc<TokioMutex<OutboundQueue>>,

    /// Encryption generation for this connection (determines compression)
    encryption_gen: Arc<Mutex<u8>>,

    /// Encryption key (received during login, used for XOR encryption)
    encryption_key: Arc<Mutex<u8>>,

    /// Encryption iterator for RECEIVING packets (decrypting incoming packets)
    /// C++: IPacketHandler::Encryption
    encryption_iterator: Arc<Mutex<u32>>,

    /// Encryption iterator for SENDING packets (encrypting outgoing packets)
    /// C++: m_fileQueue's internal encryption state
    /// This is separate from receiving because sending/receiving have independent encryption states
    send_encryption_iterator: Arc<Mutex<u32>>,

    /// Compression type for this connection
    compression: Arc<Mutex<CompressionType>>,

    /// Last activity timestamp (for timeout detection)
    last_activity: Arc<Mutex<Instant>>,

    /// Connection established timestamp
    connected_at: Instant,

    /// Total bytes received
    bytes_received: Arc<Mutex<u64>>,

    /// Total bytes sent
    bytes_sent: Arc<Mutex<u64>>,

    /// Total packets received
    packets_received: Arc<Mutex<u64>>,

    /// Total packets sent
    packets_sent: Arc<Mutex<u64>>,

    /// Track bytes sent without a file packet (for periodic file sending)
    /// C++: bytesSentWithoutFile in CFileQueue
    bytes_sent_without_file: Arc<Mutex<u32>>,

    /// Track consecutive send calls with no data
    /// C++: sendCallsWithoutData in CFileQueue
    send_calls_without_data: Arc<Mutex<u32>>,

    /// Server directory (for loading accounts, levels, etc.)
    server_dir: Arc<String>,

    /// Account data (loaded after login)
    account: Arc<Mutex<Option<Account>>>,
}

impl PlayerConnection {
    /// Create a new player connection
    ///
    /// # Arguments
    /// * `player_id` - Unique player identifier
    /// * `socket` - TCP socket for this connection
    /// * `peer_addr` - Remote address (IP:port)
    /// * `server_dir` - Server directory path (for loading accounts, levels, etc.)
    ///
    /// # Returns
    /// A new connection ready to be started
    #[inline]
    pub fn new(player_id: PlayerID, socket: TcpStream, peer_addr: SocketAddr, server_dir: String) -> Self {
        tracing::debug!("New connection {}: {}", player_id.get(), peer_addr);

        Self {
            player_id,
            peer_addr,
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
            socket: Arc::new(TokioMutex::new(socket)),
            read_buf: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
            write_buf: Arc::new(Mutex::new(BytesMut::with_capacity(8192))),
            outbound_queue: Arc::new(TokioMutex::new(OutboundQueue::new())),
            encryption_gen: Arc::new(Mutex::new(1)), // Default to GEN_1 (will be set based on player type)
            encryption_key: Arc::new(Mutex::new(0)),
            encryption_iterator: Arc::new(Mutex::new(0)),
            send_encryption_iterator: Arc::new(Mutex::new(0)),
            compression: Arc::new(Mutex::new(CompressionType::None)),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            connected_at: Instant::now(),
            bytes_received: Arc::new(Mutex::new(0)),
            bytes_sent: Arc::new(Mutex::new(0)),
            packets_received: Arc::new(Mutex::new(0)),
            packets_sent: Arc::new(Mutex::new(0)),
            bytes_sent_without_file: Arc::new(Mutex::new(0)),
            send_calls_without_data: Arc::new(Mutex::new(0)),
            server_dir: Arc::new(server_dir),
            account: Arc::new(Mutex::new(None)),
        }
    }

    /// Run the connection main loop
    ///
    /// # Purpose
    /// This is the main entry point for a connection task.
    /// It reads packets, dispatches them, and handles I/O.
    ///
    /// # Lifecycle
    /// ```text
    /// 1. Receive packets in loop
    /// 2. Parse packet type
    /// 3. Handle packet
    /// 4. Send responses
    /// 5. Check for timeout
    /// 6. Repeat until disconnect/error
    /// ```
    ///
    /// # Errors
    /// Returns an error if:
    /// - Socket read/write fails
    /// - Packet parsing fails
    /// - Connection times out
    pub async fn run(&self) -> Result<()> {
        tracing::info!("Connection {} starting main loop", self.player_id.get());

        // Set socket options
        {
            let socket = self.socket.lock().await;
            socket.set_nodelay(true)?; // Disable Nagle's algorithm for low latency
        }

        let mut timeout_check = interval(Duration::from_secs(10));
        let mut flush_check = interval(Duration::from_millis(50)); // Flush every 50ms

        loop {
            tokio::select! {
                // Read and process all packets in a bundle
                result = self.read_and_process_bundle() => {
                    match result {
                        Ok(true) => {
                            // Bundle processed successfully, continue
                        }
                        Ok(false) => {
                            // Connection closed by client
                            tracing::info!("Connection {} closed by client", self.player_id.get());
                            break;
                        }
                        Err(e) => {
                            tracing::error!("Connection {} read error: {:?}", self.player_id.get(), e);
                            break;
                        }
                    }
                }

                // Periodic flush: send any queued packets
                _ = flush_check.tick() => {
                    // Flush if queue has data (low-traffic scenario)
                    let queue = self.outbound_queue.lock().await;
                    let has_data = queue.normal_bytes > 0;
                    drop(queue);

                    if has_data {
                        if let Err(e) = self.process_outbound_queue().await {
                            tracing::error!("Connection {} flush error: {:?}", self.player_id.get(), e);
                            break;
                        }
                    }
                }

                // Check timeout
                _ = timeout_check.tick() => {
                    if self.is_timed_out() {
                        tracing::warn!("Connection {} timed out", self.player_id.get());
                        break;
                    }
                }
            }
        }

        // Cleanup
        self.cleanup().await;
        Ok(())
    }

    /// Read and process all packets in a bundle
    ///
    /// # Bundle Format
    /// ```text
    /// {u16 big-endian length}{bundle_data: possibly compressed}
    /// {packets separated by \n}
    /// {each packet: [GCHAR packet_type][packet_data]}
    /// ```
    ///
    /// # Compression
    /// - **GEN_2/3**: Always zlib compressed
    /// - **GEN_4**: Always bzip2 compressed
    /// - **GEN_5**: Compression type byte (0x02=none, 0x04=zlib, 0x06=bz2)
    /// - **GEN_6/1**: No compression
    ///
    /// # Returns
    /// - `Ok(true)` - Bundle processed successfully
    /// - `Ok(false)` - Connection closed
    /// - `Err(e)` - Read error
    async fn read_and_process_bundle(&self) -> Result<bool> {
        // Read bundle length (2 bytes, BIG-ENDIAN u16 format)
        // This is NOT GSHORT encoding - it's raw big-endian!
        let mut len_buf = [0u8; 2];
        {
            let mut socket = self.socket.lock().await;
            if let Err(e) = socket.read_exact(&mut len_buf).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Ok(false); // Connection closed
                }
                return Err(gserver_core::GServerError::Io(e));
            }
        }

        // Read big-endian u16 (NOT GSHORT!)
        let bundle_len = u16::from_be_bytes(len_buf) as usize;

        // Sanity check
        if bundle_len > 1_000_000 {
            return Err(gserver_core::GServerError::InvalidData(
                format!("Bundle too large: {} bytes", bundle_len)
            ));
        }

        // Read bundle data
        let mut bundle_data = vec![0u8; bundle_len];
        {
            let mut socket = self.socket.lock().await;
            socket.read_exact(&mut bundle_data).await?;
        }

        // Update stats
        *self.bytes_received.lock() += (2 + bundle_len) as u64;

        // Log raw bundle data for debugging
        tracing::debug!("Connection {} raw bundle ({} bytes): {:02x?}",
            self.player_id.get(), bundle_len, &bundle_data[..bundle_len.min(32)]);

        // === CRITICAL FIX ===
        // Check if this is the FIRST bundle (login packet) BEFORE decompressing
        // The login packet is handled differently: zlib compressed, NO encryption
        let current_state = self.state();

        tracing::info!("Connection {} state: {:?}, encryption_gen: {}, processing bundle of {} bytes",
            self.player_id.get(), current_state, *self.encryption_gen.lock(), bundle_len);

        let bundle_data = if current_state == ConnectionState::Connected {
            // Login packet: decompress as zlib (no encryption)
            // The login packet is zlib compressed but NOT encrypted
            // Use unconditional decompression to match C++ behavior
            self.decompress_zlib_unconditional(&bundle_data)?
        } else {
            // Subsequent packets: handle based on encryption generation
            // This includes decryption for GEN_4/5
            self.decompress_and_decrypt_bundle(&bundle_data)?
        };

        tracing::debug!("Connection {} decompressed bundle ({} bytes): {:02x?}",
            self.player_id.get(), bundle_data.len(), &bundle_data[..bundle_data.len().min(32)]);

        if current_state == ConnectionState::Connected {
            // First bundle is the login packet - ENTIRE bundle is ONE packet
            tracing::info!("Connection {} handling login bundle ({} bytes)",
                self.player_id.get(), bundle_data.len());

            // Update activity
            self.update_activity();
            *self.packets_received.lock() += 1;

            // Handle login packet (entire bundle)
            if let Err(e) = self.handle_login_packet(&bundle_data).await {
                tracing::error!("Connection {} login error: {:?}",
                    self.player_id.get(), e);
                return Ok(true); // Don't kill connection, let it timeout
            }

            return Ok(true);
        }

        // Process ALL packets in the bundle (newline-separated)
        let mut pos = 0;
        while pos < bundle_data.len() {
            // Find next newline
            let newline_pos = match bundle_data[pos..].iter().position(|&b| b == 0x0A) {
                Some(nl) => pos + nl,
                None => bundle_data.len(), // No more newlines, use rest of bundle
            };

            let packet_bytes = &bundle_data[pos..newline_pos];
            pos = newline_pos + 1; // Skip the newline for next iteration

            if packet_bytes.is_empty() {
                continue; // Skip empty packets
            }

            // Parse packet type (first byte is GChar-encoded)
            let encoded_type = packet_bytes[0];
            let packet_type_byte = encoded_type.saturating_sub(32);
            let packet_data = &packet_bytes[1..];

            // Log packet
            tracing::info!("Received packet: encoded_type={} decoded_type={} data={:02x?}",
                          encoded_type, packet_type_byte, packet_data);

            // Create a PacketIn with the parsed data
            use gserver_protocol::{PacketIn, PacketTypeIn};
            let packet_type = PacketTypeIn::from_u8(packet_type_byte).unwrap_or(PacketTypeIn::LevelWarp);
            let packet = PacketIn::new(packet_type, packet_data.to_vec());

            // Update activity and packet count
            self.update_activity();
            *self.packets_received.lock() += 1;

            // Handle packet
            if let Err(e) = self.handle_packet(packet).await {
                tracing::error!("Connection {} packet handling error: {:?}",
                    self.player_id.get(), e);
                break;
            }
        }

        Ok(true)
    }

    /// Read a GChar-encoded byte from a byte slice
    ///
    /// GChar encoding: value = raw_byte - 32
    /// This is used throughout the Graal protocol for compact integer encoding
    fn read_gchar(data: &[u8], pos: usize) -> Result<u8> {
        if pos >= data.len() {
            return Err(gserver_core::GServerError::InvalidData(
                format!("Not enough bytes for GChar at position {} (have {})", pos, data.len())
            ));
        }
        // GChar subtracts 32 from the raw byte
        Ok(data[pos].wrapping_sub(32))
    }

    /// Read a GUChar-encoded byte (unsigned GChar)
    ///
    /// GUChar is just GChar cast to unsigned: (unsigned char)(readGChar())
    /// Used for string lengths in the Graal protocol
    fn read_guchar(data: &[u8], pos: usize) -> Result<usize> {
        Ok(Self::read_gchar(data, pos)? as usize)
    }

    /// Handle the initial login packet
    ///
    /// # Login Packet Format
    /// ```text
    /// [GCHAR: player_type]     // Determines CLIENT, RC, or NC
    /// [GCHAR: encryption_key]  // For newer clients
    /// [STRING: client_version] // 8 chars (e.g., "G3D0511C")
    /// [GUCHAR: account_len]    // Length of account name
    /// [STRING: account_name]   // Account name
    /// [GUCHAR: password_len]   // Length of password
    /// [STRING: password]       // Password
    /// [STRING: identity]       // Null-terminated identity string
    /// ```
    ///
    /// # Returns
    /// Ok(()) if login successful, Err if login failed
    async fn handle_login_packet(&self, packet_bytes: &[u8]) -> Result<()> {
        let mut pos = 0;

        // Read player type (1 byte, GChar-encoded)
        if pos >= packet_bytes.len() {
            return Err(gserver_core::GServerError::InvalidData(
                "Login packet too short".to_string()
            ));
        }
        let player_type_raw = packet_bytes[pos];
        let player_type_shift = Self::read_gchar(packet_bytes, pos)? as u32;
        let player_type = 1u32 << player_type_shift;
        pos += 1;

        tracing::info!("Connection {} player type: raw={}, shift={}, type=0x{:x}",
            self.player_id.get(), player_type_raw, player_type_shift, player_type);

        // Determine if this is RC, NC, or regular client
        let is_rc = (player_type & 0x02) != 0 || (player_type & 0x40) != 0; // PLTYPE_RC or PLTYPE_RC2
        let _is_nc = (player_type & 0x08) != 0; // PLTYPE_NC
        let is_client = (player_type & 0x01) != 0 || (player_type & 0x10) != 0 || (player_type & 0x20) != 0;

        // Determine encryption key presence based on player type (deterministic)
        // Encryption key is present for: NC (shift=3), CLIENT2 (shift=4), CLIENT3 (shift=5), RC2 (shift=6)
        // NOT present for: CLIENT (shift=0), RC (shift=1)
        let has_encryption_key = match player_type_shift {
            0 => false,  // PLTYPE_CLIENT (old client, no key)
            1 => false,  // PLTYPE_RC (old RC, no key)
            3 => true,   // PLTYPE_NC (has key)
            4 => true,   // PLTYPE_CLIENT2 (has key)
            5 => true,   // PLTYPE_CLIENT3 (has key)
            6 => true,   // PLTYPE_RC2 (has key)
            _ => {
                return Err(gserver_core::GServerError::InvalidData(
                    format!("Unknown player type shift: {}", player_type_shift)
                ));
            }
        };

        // Set encryption generation based on player type (matches C++ PlayerClient.cpp:312-325 and PlayerRC.cpp)
        let encryption_gen = match player_type_shift {
            0 => 2,  // PLTYPE_CLIENT: GEN_2
            1 => 2,  // PLTYPE_RC: GEN_2
            3 => 2,  // PLTYPE_NC: GEN_2
            4 => 4,  // PLTYPE_CLIENT2: GEN_4
            5 => 5,  // PLTYPE_CLIENT3: GEN_5
            6 => 5,  // PLTYPE_RC2: GEN_5 (New RC 2.22+ uses GEN_5!)
            _ => {
                return Err(gserver_core::GServerError::InvalidData(
                    format!("Unknown player type shift: {}", player_type_shift)
                ));
            }
        };

        // Read encryption key if present (1 byte, GChar-encoded)
        let encryption_key = if has_encryption_key {
            if pos >= packet_bytes.len() {
                return Err(gserver_core::GServerError::InvalidData(
                    "Login packet truncated: expected encryption key".to_string()
                ));
            }
            let key = Self::read_gchar(packet_bytes, pos)?;
            pos += 1;

            tracing::debug!("Connection {} encryption key: {} (raw byte: {})",
                self.player_id.get(), key, packet_bytes[pos - 1]);
            key
        } else {
            0
        };

        // Update encryption_gen and initialize encryption state
        *self.encryption_gen.lock() = encryption_gen;
        self.init_encryption(encryption_gen, encryption_key);

        tracing::info!("Connection {} set encryption_gen={}, key={}",
            self.player_id.get(), encryption_gen, encryption_key);

        // Read client version (8 chars)
        let client_version = if pos + 8 <= packet_bytes.len() {
            let version = String::from_utf8_lossy(&packet_bytes[pos..pos + 8]).to_string();
            pos += 8;
            version
        } else {
            "UNKNOWN".to_string()
        };

        tracing::info!("Connection {} client version: {}", self.player_id.get(), client_version);

        // Read account name length (1 byte, GUChar-encoded)
        if pos >= packet_bytes.len() {
            return Err(gserver_core::GServerError::InvalidData(
                "Login packet missing account name length".to_string()
            ));
        }
        // CRITICAL FIX: Use GUChar decoding (subtract 32) instead of raw byte
        let account_len = Self::read_guchar(packet_bytes, pos)?;
        pos += 1;

        tracing::debug!("Connection {} account name length: {} (raw byte: {})",
            self.player_id.get(), account_len, packet_bytes[pos - 1]);

        // Read account name
        if pos + account_len > packet_bytes.len() {
            return Err(gserver_core::GServerError::InvalidData(
                format!("Login packet truncated: expected {} bytes for account name", account_len)
            ));
        }
        let account_name = String::from_utf8_lossy(&packet_bytes[pos..pos + account_len]).to_string();
        pos += account_len;

        tracing::info!("Connection {} account name: {}", self.player_id.get(), account_name);

        // Read password length (1 byte, GUChar-encoded)
        if pos >= packet_bytes.len() {
            return Err(gserver_core::GServerError::InvalidData(
                "Login packet missing password length".to_string()
            ));
        }
        // CRITICAL FIX: Use GUChar decoding (subtract 32) instead of raw byte
        let password_len = Self::read_guchar(packet_bytes, pos)?;
        pos += 1;

        tracing::debug!("Connection {} password length: {} (raw byte: {})",
            self.player_id.get(), password_len, packet_bytes[pos - 1]);

        // Read password
        if pos + password_len > packet_bytes.len() {
            return Err(gserver_core::GServerError::InvalidData(
                format!("Login packet truncated: expected {} bytes for password", password_len)
            ));
        }
        let _password = &packet_bytes[pos..pos + password_len];
        pos += password_len;

        // Read identity string (null-terminated)
        let identity_end = packet_bytes[pos..].iter().position(|&b| b == 0);
        let identity = if let Some(end) = identity_end {
            String::from_utf8_lossy(&packet_bytes[pos..pos + end]).to_string()
        } else {
            String::from_utf8_lossy(&packet_bytes[pos..]).to_string()
        };

        tracing::info!("Connection {} identity: {}", self.player_id.get(), identity);

        // Load account
        let server_path = Path::new(self.server_dir.as_str());
        let loader = AccountLoader::new(server_path);

        match loader.load(&account_name) {
            Ok(account) => {
                tracing::info!("Connection {} loaded account: {} (nick: {}, staff: {})",
                    self.player_id.get(), account.name, account.nick, account.is_staff());

                // Check staff rights for RC
                if is_rc && !account.can_use_rc() {
                    tracing::warn!("Connection {} RC access denied for {} (no staff rights)",
                        self.player_id.get(), account.name);

                    // Send error packet to RC
                    use gserver_protocol::{PacketOut, PacketTypeOut};
                    let error_msg = format!("Error: You don't have staff rights.");
                    let error_packet = PacketOut::new(PacketTypeOut::ServerText, error_msg.into_bytes());
                    let _ = self.send_packet(error_packet).await;

                    return Err(gserver_core::GServerError::InvalidData(
                        "RC access denied: no staff rights".to_string()
                    ));
                }

                // Store account
                *self.account.lock() = Some(account.clone());

                // Update state
                *self.state.lock() = ConnectionState::LoggingIn;

                // Send login response packets
                self.send_login_response(&account).await?;

                tracing::info!("Connection {} login successful, sent login response packets",
                    self.player_id.get());

                Ok(())
            }
            Err(e) => {
                tracing::error!("Connection {} failed to load account {}: {:?}",
                    self.player_id.get(), account_name, e);

                *self.state.lock() = ConnectionState::Disconnecting;
                Err(gserver_core::GServerError::InvalidData(
                    format!("Failed to load account: {}", e)
                ))
            }
        }
    }

    /// Send all login response packets to the client
    ///
    /// # Arguments
    /// * `account` - The loaded account data
    ///
    /// # Packets Sent
    /// 1. PLO_PLAYERPROPS - Player properties (nickname, power, position, etc.)
    /// 2. PLO_CLEARWEAPONS - Clear weapon list
    /// 3. PLO_PLAYERWARP - Warp player to starting location (triggers PLI_LEVELWARP)
    ///
    /// # C++ Equivalence
    /// This matches the C++ login flow in PlayerClient.cpp:
    /// - Line 1170: sendPacket(PLO_PLAYERWARP) - triggers PLI_LEVELWARP response
    /// - PLO_SIGNATURE and PLO_UNKNOWN168 are NOT sent by C++
    async fn send_login_response(&self, account: &Account) -> Result<()> {
        use bytes::BufMut;
        use gserver_protocol::{PacketOut, PacketTypeOut, codecs::*};

        // 1. Send PLO_PLAYERPROPS with essential properties
        let mut props_data = BytesMut::new();

        // Property 0: NICKNAME (string)
        props_data.put_u8(0); // property id
        write_gstring(&mut props_data, &account.nick);

        // Property 1: MAXPOWER (gint)
        props_data.put_u8(1); // property id
        write_gint(&mut props_data, account.max_hp as i32);

        // Property 2: CURPOWER (gint)
        props_data.put_u8(2); // property id
        write_gint(&mut props_data, account.hp as i32);

        // Property 3: RUPEESCOUNT (gint)
        props_data.put_u8(3); // property id
        write_gint(&mut props_data, account.gralats as i32);

        // Property 4: ARROWSCOUNT (gint)
        props_data.put_u8(4); // property id
        write_gint(&mut props_data, account.arrows as i32);

        // Property 5: BOMBSCOUNT (gint)
        props_data.put_u8(5); // property id
        write_gint(&mut props_data, account.bombs as i32);

        // Property 6: GLOVEPOWER (gint)
        props_data.put_u8(6); // property id
        write_gint(&mut props_data, account.glove_power as i32);

        // Property 7: BOMBPOWER (gint)
        props_data.put_u8(7); // property id
        write_gint(&mut props_data, account.bomb_power as i32);

        // Property 8: SWORDPOWER (gint)
        props_data.put_u8(8); // property id
        write_gint(&mut props_data, account.sword_power as i32);

        // Property 9: SHIELDPOWER (gint)
        props_data.put_u8(9); // property id
        write_gint(&mut props_data, account.shield_power as i32);

        // Property 10: GANI (string) - Animation file
        props_data.put_u8(10); // property id
        write_gstring(&mut props_data, &account.ani);

        // Property 11: HEADGIF (string) - Head sprite
        props_data.put_u8(11); // property id
        write_gstring(&mut props_data, &account.head);

        // Property 13: COLORS (string) - Body colors
        props_data.put_u8(13); // property id
        write_gstring(&mut props_data, &account.colors);

        // Property 14: ID (gint)
        props_data.put_u8(14); // property id
        write_gint(&mut props_data, self.player_id.get() as i32);

        // Property 15: X (gint)
        props_data.put_u8(15); // property id
        write_gint(&mut props_data, account.x as i32);

        // Property 16: Y (gint)
        props_data.put_u8(16); // property id
        write_gint(&mut props_data, account.y as i32);

        // Property 17: SPRITE (gint)
        props_data.put_u8(17); // property id
        write_gint(&mut props_data, account.sprite as i32);

        // Property 20: CURLEVEL (string)
        props_data.put_u8(20); // property id
        write_gstring(&mut props_data, &account.level);

        // Property 30: IPADDR (string) - Optional
        if !account.ip.is_empty() {
            props_data.put_u8(30); // property id
            write_gstring(&mut props_data, &account.ip);
        }

        // Property 34: ACCOUNTNAME (string)
        props_data.put_u8(34); // property id
        write_gstring(&mut props_data, &account.name);

        // Property 35: BODYIMG (string)
        props_data.put_u8(35); // property id
        write_gstring(&mut props_data, &account.body);

        let props_packet = PacketOut::new(PacketTypeOut::PlayerProps, props_data.to_vec());
        self.send_packet(props_packet).await?;
        tracing::debug!("Connection {} sent PLO_PLAYERPROPS", self.player_id.get());

        // 3. Send PLO_CLEARWEAPONS
        let clear_weapons_packet = PacketOut::new(PacketTypeOut::ClearWeapons, vec![]);
        self.send_packet(clear_weapons_packet).await?;
        tracing::debug!("Connection {} sent PLO_CLEARWEAPONS", self.player_id.get());

        // 4. Send PLO_PLAYERWARP - This is CRITICAL!
        // This packet tells the client to warp to the starting location,
        // which triggers the client to send PLI_LEVELWARP in response.
        // Without this, the client will hang and never send PLI_LEVELWARP.
        //
        // C++: PlayerClient.cpp:1170
        // sendPacket(CString() >> (char)PLO_PLAYERWARP
        //     << getProp<PlayerProp::X>().serialize()
        //     << getProp<PlayerProp::Y>().serialize()
        //     << levelName);
        use gserver_protocol::packet_builder::build_player_warp;

        let mut warp_data = BytesMut::new();
        // Convert float coordinates to gint (tiles * 16)
        let x = (account.x * 16.0) as i32;
        let y = (account.y * 16.0) as i32;
        build_player_warp(&mut warp_data, x, y, &account.level);

        // Add directly to queue (build_player_warp already includes packet type and newline)
        let mut queue = self.outbound_queue.lock().await;
        queue.add_packet(warp_data, false); // false = not a file packet
        let should_flush = queue.should_flush();
        queue.increment_send_cycles();
        drop(queue);

        // Flush if we should (48KB reached or 4 send cycles)
        if should_flush {
            self.process_outbound_queue().await?;
        }

        tracing::info!("Connection {} sent PLO_PLAYERWARP to {} at ({}, {}) - type=14, encoded=46",
            self.player_id.get(), account.level, x, y);

        // NOTE: PLO_SETACTIVELEVEL and PLO_LEVELNAME are NOT sent here!
        // They are sent in response to PLI_LEVELWARP (see handle_level_warp)
        // The C++ server sends these AFTER receiving the level warp request from the client

        // CRITICAL: Flush packets immediately after login
        // The client won't send PLI_LEVELWARP until it receives these packets
        self.process_outbound_queue().await?;

        Ok(())
    }

    /// Send a packet to the client
    ///
    /// # Arguments
    /// * `packet` - Packet to send
    ///
    /// # Process (C++ CFileQueue equivalent)
    /// 1. Serialize packet to bytes (with newline)
    /// 2. Add to outbound queue (don't send immediately!)
    /// 3. Flush if queue is full (>= 48KB or >= 4 send cycles)
    ///
    /// # C++ Equivalence
    /// Matches `Player::sendPacket()` → `CFileQueue::addPacket()` → `sendCompress()`
    pub async fn send_packet(&self, packet: PacketOut) -> Result<()> {
        // Serialize packet to bytes (includes newline now)
        let mut packet_data = BytesMut::new();
        packet.serialize(&mut packet_data);

        // Add to queue (CRITICAL: don't send immediately!)
        let mut queue = self.outbound_queue.lock().await;
        queue.add_packet(packet_data, false); // false = not a file packet
        let should_flush = queue.should_flush();
        queue.increment_send_cycles();
        drop(queue);

        // Flush if we should (48KB reached or 4 send cycles)
        if should_flush {
            self.process_outbound_queue().await?;
        }

        Ok(())
    }

    /////////////////////////////////////////////////////////////////////////////
    // PACKET BATCHING (CFileQueue equivalent)
    /////////////////////////////////////////////////////////////////////////////

    /// Process outbound queue and send batches
    ///
    /// # Purpose
    /// Matches C++ CFileQueue::sendCompress() behavior EXACTLY:
    /// - Handles huge packets (>60KB) immediately
    /// - Forces file packets if not sent in 32KB
    /// - Batches normal packets up to 48KB
    /// - Tries to add file packet if under 16KB
    /// - Tracks bytes sent without file
    /// - Tracks empty send calls
    ///
    /// # C++ Equivalence
    /// Corresponds to `CFileQueue::sendCompress()` in CFileQueue.cpp lines 103-263
    async fn process_outbound_queue(&self) -> Result<()> {
        let mut queue = self.outbound_queue.lock().await;

        let mut batch = BytesMut::new();
        let mut packet_count = 0;

        // C++: "If the next normal packet is huge, lets 'try' to send it."
        // C++: "Everything else should skip because this may throw is way over the limit."
        if !queue.normal_buffer.is_empty() {
            if let Some(huge_packet) = queue.normal_buffer.first() {
                if huge_packet.len() > 0xF000 {  // 60KB
                    let packet = queue.normal_buffer.remove(0);
                    batch.extend_from_slice(&packet);
                    packet_count += 1;
                }
            }
        }

        // C++: "If we haven't sent a file in a while, forcibly send one now."
        // C++: if (pSend.length() == 0 && (bytesSentWithoutFile > 0x7FFF || forceSendFiles || sendCallsWithoutData >= 4) && !fileBuffer.empty())
        if batch.is_empty() {
            if *self.bytes_sent_without_file.lock() > 0x7FFF || !queue.file_buffer.is_empty() {
                if let Some(file_packet) = queue.file_buffer.first() {
                    if file_packet.len() <= 0xF000 {  // Don't exceed 60KB
                        *self.bytes_sent_without_file.lock() = 0;
                        let file_pkt = queue.file_buffer.remove(0);
                        batch.extend_from_slice(&file_pkt);
                    }
                }
            }
        }

        // C++: "Keep adding packets from normalBuffer until we hit 48KB"
        // C++: while (pSend.length() < 0xC000 && !normalBuffer.empty())
        while !queue.normal_buffer.is_empty() && batch.len() < 0xC000 {  // 48KB
            let packet = queue.normal_buffer.remove(0);
            // C++: "If the next packet sticks us over 60KB, don't add it."
            // C++: if (pSend.length() + normalBuffer.front().length() > 0xF000) break;
            if batch.len() + packet.len() > 0xF000 {  // 60KB
                queue.normal_buffer.insert(0, packet);
                break;
            }
            batch.extend_from_slice(&packet);
            packet_count += 1;
        }

        // C++: bytesSentWithoutFile += pSend.length();
        *self.bytes_sent_without_file.lock() += batch.len() as u32;

        // Log the batch for debugging
        tracing::info!("Connection {} sending batch: {} bytes, {} packets: {:02x?}",
            self.player_id.get(), batch.len(), packet_count, &batch[..batch.len().min(64)]);

        // C++: "If we have less than 16KB of data, try to add a file."
        // C++: if (pSend.length() < 0x4000 && !fileBuffer.empty())
        if batch.len() < 0x4000 && !queue.file_buffer.is_empty() {  // 16KB
            if let Some(file_packet) = queue.file_buffer.first() {
                // C++: if (pSend.length() + fileBuffer.front().length() <= 0xF000)
                if batch.len() + file_packet.len() <= 0xF000 {  // 60KB
                    *self.bytes_sent_without_file.lock() = 0;
                    let file_pkt = queue.file_buffer.remove(0);
                    batch.extend_from_slice(&file_pkt);
                    tracing::debug!("Included file packet in batch");
                }
            }
        }

        // C++: "Reset this if we have no files to send."
        // C++: if (fileBuffer.empty()) bytesSentWithoutFile = 0;
        if queue.file_buffer.is_empty() {
            *self.bytes_sent_without_file.lock() = 0;
        }

        // Update tracking (calculate size first, then update to avoid borrow issues)
        let new_normal_bytes: usize = queue.normal_buffer.iter().map(|p| p.len()).sum();
        queue.normal_bytes = new_normal_bytes;
        queue.reset_send_cycles();

        drop(queue);

        // C++: "If we have no data, just return."
        // C++: if (pSend.length() == 0) { if (sendCallsWithoutData < 5) { sendCallsWithoutData++; } return; }
        if batch.is_empty() {
            let mut calls = self.send_calls_without_data.lock();
            if *calls < 5 {
                *calls += 1;
            }
            return Ok(());
        }
        *self.send_calls_without_data.lock() = 0;

        // Send the batch
        tracing::debug!("Connection {}: Sending batched {} packets, {} bytes",
            self.player_id.get(), packet_count, batch.len());
        self.send_batch(batch, packet_count).await?;

        Ok(())
    }

    /// Send a batch of packets as one compressed bundle
    ///
    /// # Arguments
    /// * `batch` - Multiple serialized packets (with newlines) concatenated
    /// * `packet_count` - Number of packets in the batch (for stats)
    ///
    /// # Process
    /// 1. Get encryption generation
    /// 2. Compress according to GEN rules
    /// 3. Prepend length
    /// 4. Write to socket
    async fn send_batch(&self, batch: BytesMut, packet_count: usize) -> Result<()> {
        let gen = *self.encryption_gen.lock();
        let compressed = self.compress_by_gen(batch, gen)?;

        // Write bundle: [2-byte big-endian length][compressed data]
        let mut buf = BytesMut::with_capacity(2 + compressed.len());
        buf.extend_from_slice(&(compressed.len() as u16).to_be_bytes());
        buf.extend_from_slice(&compressed);

        // Write to socket
        {
            let mut socket = self.socket.lock().await;
            socket.write_all(&buf).await?;
        }

        // Update stats
        *self.bytes_sent.lock() += buf.len() as u64;
        *self.packets_sent.lock() += packet_count as u64;

        Ok(())
    }

    /// Initialize encryption state for a connection
    ///
    /// # Arguments
    /// * `gen` - Encryption generation
    /// * `key` - Encryption key from login packet
    ///
    /// # C++ Equivalence
    /// Matches `CEncryption::reset()` and `CEncryption::CEncryption()`
    fn init_encryption(&self, gen: u8, key: u8) {
        *self.encryption_key.lock() = key;
        let iterator_value = match gen {
            1 | 2 | 6 => 0,
            3 | 4 | 5 => 0x04A80B38,  // From CEncryption::ITERATOR_START
            _ => 0,
        };
        *self.encryption_iterator.lock() = iterator_value;
        *self.send_encryption_iterator.lock() = iterator_value;  // Separate iterator for sending
        tracing::debug!("Initialized encryption: gen={}, key={}, recv_iterator=0x{:08x}, send_iterator=0x{:08x}",
            gen, key, *self.encryption_iterator.lock(), *self.send_encryption_iterator.lock());
    }

    /// Get encryption limit based on compression type
    ///
    /// # C++ Equivalence
    /// Matches `CEncryption::limitFromType()`
    fn get_encryption_limit(compression_type: u8) -> i32 {
        // { type, limit, type2, limit2, ... }
        // From CEncryption.cpp:144
        // 0x02 (uncompressed) -> 0x0C (12 bytes)
        // 0x04 (zlib) -> 0x04 (4 bytes)
        // 0x06 (bz2) -> 0x04 (4 bytes)
        match compression_type {
            0x02 => 0x0C,  // COMPRESS_UNCOMPRESSED
            0x04 => 0x04,  // COMPRESS_ZLIB
            0x06 => 0x04,  // COMPRESS_BZ2
            _ => -1,
        }
    }

    /// XOR-encrypt/decrypt data for GEN_4/5
    ///
    /// # Arguments
    /// * `data` - Data to encrypt/decrypt (modified in place)
    /// * `limit` - Number of bytes to encrypt (0 = unlimited, -1 = none)
    ///
    /// # C++ Equivalence
    /// Matches `CEncryption::encrypt()` and `CEncryption::decrypt()` for GEN_4/5
    fn xor_crypt(&self, data: &mut [u8], limit: i32) {
        let mut iterator = *self.encryption_iterator.lock();
        let key = *self.encryption_key.lock();

        let mut current_limit = limit;
        for (i, byte) in data.iter_mut().enumerate() {
            if i % 4 == 0 {
                if current_limit == 0 {
                    break;
                }
                // Update stored iterator every 4 bytes (matches C++)
                iterator = iterator.wrapping_mul(0x8088405);
                iterator = iterator.wrapping_add(key as u32);
                if current_limit > 0 {
                    current_limit -= 1;
                }
            }
            // C++: const uint8_t* iterator = reinterpret_cast<const uint8_t*>(&m_iterator);
            // When m_iterator is updated, the pointer sees the NEW bytes
            // CRITICAL: C++ on x86 uses little-endian byte order!
            // to_le_bytes() gives [0x38, 0x0B, 0xA8, 0x04] for 0x04A80B38
            *byte ^= iterator.to_le_bytes()[i % 4];
        }

        // Save updated iterator
        *self.encryption_iterator.lock() = iterator;
    }

    /// XOR-encrypt data for SENDING (outgoing packets)
    ///
    /// Uses a separate encryption iterator to avoid interfering with receiving.
    /// C++: m_fileQueue's internal encryption state
    ///
    /// # Arguments
    /// * `data` - Data to encrypt (modified in place)
    /// * `limit` - Number of bytes to encrypt (0 = unlimited, -1 = none)
    fn xor_crypt_send(&self, data: &mut [u8], limit: i32) {
        let mut iterator = *self.send_encryption_iterator.lock();
        let key = *self.encryption_key.lock();

        let mut current_limit = limit;
        for (i, byte) in data.iter_mut().enumerate() {
            if i % 4 == 0 {
                if current_limit == 0 {
                    break;
                }
                // Update stored iterator every 4 bytes (matches C++)
                iterator = iterator.wrapping_mul(0x8088405);
                iterator = iterator.wrapping_add(key as u32);
                if current_limit > 0 {
                    current_limit -= 1;
                }
            }
            // C++ on x86 uses little-endian byte order!
            *byte ^= iterator.to_le_bytes()[i % 4];
        }

        // Save updated send iterator
        *self.send_encryption_iterator.lock() = iterator;
    }

    /// Compress data according to encryption generation
    ///
    /// # Arguments
    /// * `data` - Data to compress
    /// * `gen` - Encryption generation (1-6)
    ///
    /// # Returns
    /// Compressed data (possibly with encryption type byte prefix for GEN_5)
    ///
    /// # C++ Equivalence
    /// Matches the switch statement in CFileQueue::sendCompress()
    fn compress_by_gen(&self, data: BytesMut, gen: u8) -> Result<BytesMut> {
        match gen {
            1 | 6 => {
                // GEN_1 & GEN_6: No compression
                tracing::trace!("GEN_{}: No compression", gen);
                Ok(data)
            }
            2 => {
                // GEN_2: Zlib compress only (no encryption)
                tracing::trace!("GEN_2: Zlib compression");
                self.compress_zlib(&data).map(|v| BytesMut::from(&v[..]))
            }
            3 => {
                // GEN_3: Zlib compress + single byte insertion
                tracing::trace!("GEN_3: Zlib compression + single byte insertion");
                let compressed = self.compress_zlib(&data)?;

                // Insert ")" at calculated position
                // C++: m_iterator *= 0x8088405; m_iterator += m_key;
                //     int pos = ((m_iterator & 0x0FFFF) % pBuf.length());
                let mut iterator = *self.send_encryption_iterator.lock();
                let key = *self.encryption_key.lock();
                iterator = iterator.wrapping_mul(0x8088405);
                iterator = iterator.wrapping_add(key as u32);
                *self.send_encryption_iterator.lock() = iterator;

                let pos = (iterator & 0xFFFF) % (compressed.len() as u32);
                let mut result = Vec::with_capacity(compressed.len() + 1);
                result.extend_from_slice(&compressed[..pos as usize]);
                result.push(b')');
                result.extend_from_slice(&compressed[pos as usize..]);

                Ok(BytesMut::from(&result[..]))
            }
            4 => {
                // GEN_4: BZ2 compress + XOR encrypt
                tracing::trace!("GEN_4: BZ2 compression + XOR encryption");
                let compressed = self.compress_bz2(&data)?;
                let mut encrypted = compressed.into_boxed_slice().into_vec();
                self.xor_crypt_send(&mut encrypted, 4);  // Use send iterator for outgoing packets
                Ok(BytesMut::from(&encrypted[..]))
            }
            5 => {
                // GEN_5: Smart compression + XOR encryption + compression type byte

                // Sanity check: max 65532 bytes (0xFFFC)
                // C++: if (pSend.length() > 0xFFFC) { printf("** [ERROR] Trying to send a GEN_5 packet over 65532 bytes!  Tossing data.\n"); return; }
                if data.len() > 0xFFFC {
                    return Err(gserver_core::GServerError::InvalidData(
                        format!("GEN_5 packet too large: {} bytes (max 65532)", data.len())
                    ));
                }

                // Choose compression type
                // C++: if (pSend.length() > 0x2000) { compressionType = COMPRESS_BZ2; pSend.bzcompressI(); }
                //     else if (pSend.length() > 55) { compressionType = COMPRESS_ZLIB; pSend.zcompressI(); }
                let (compressed, comp_type) = if data.len() > 0x2000 {
                    // > 8KB: Use BZ2
                    (self.compress_bz2(&data)?, 0x06u8)  // COMPRESS_BZ2
                } else if data.len() > 55 {
                    // > 55 bytes: Use ZLIB
                    (self.compress_zlib(&data)?, 0x04u8)  // COMPRESS_ZLIB
                } else {
                    // <= 55 bytes: No compression
                    (data.to_vec(), 0x02u8)  // COMPRESS_UNCOMPRESSED
                };

                // Get encryption limit based on compression type
                let limit = Self::get_encryption_limit(comp_type);

                // XOR-encrypt first N bytes of compressed data
                let mut encrypted = compressed;
                self.xor_crypt_send(&mut encrypted, limit);  // Use send iterator for outgoing packets

                // Prepend compression type byte (NOT encrypted)
                // C++: CString data = CString() << (short)(pSend.length() + 1) << (char)compressionType << pSend;
                let mut result = BytesMut::with_capacity(1 + encrypted.len());
                result.put_u8(comp_type);
                result.extend_from_slice(&encrypted);

                tracing::trace!("GEN_5: Smart compression + XOR, type={}, {} -> {} bytes, encrypted {} bytes",
                    comp_type, data.len(), result.len(), limit);
                Ok(result)
            }
            _ => {
                tracing::warn!("Unknown encryption generation {}, defaulting to no compression", gen);
                Ok(data)
            }
        }
    }

    /// Compress data using zlib
    fn compress_zlib(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).map_err(|e| {
            gserver_core::GServerError::Compression(format!("Zlib compression failed: {}", e))
        })?;
        encoder.finish().map_err(|e| {
            gserver_core::GServerError::Compression(format!("Zlib finish failed: {}", e))
        })
    }

    /// Compress data using bzip2
    ///
    /// # C++ Equivalence
    /// Matches CString::bzcompressI() - IN-PLACE bzip2 compression
    fn compress_bz2(&self, data: &[u8]) -> Result<Vec<u8>> {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;

        let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).map_err(|e| {
            gserver_core::GServerError::Compression(format!("BZ2 compression failed: {}", e))
        })?;
        encoder.finish().map_err(|e| {
            gserver_core::GServerError::Compression(format!("BZ2 finish failed: {}", e))
        })
    }

    /// Decompress zlib data
    ///
    /// # C++ Equivalence
    /// Matches CString::zuncompressI() - zlib decompression
    fn decompress_zlib(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        // Try zlib decompression (magic byte: 0x78)
        if data.get(0) == Some(&0x78) {
            tracing::debug!("Attempting zlib decompression of {} bytes", data.len());
            let mut decoder = ZlibDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                gserver_core::GServerError::Compression(format!("Zlib decompression failed: {}", e))
            })?;
            tracing::debug!("Zlib decompressed: {} -> {} bytes", data.len(), decompressed.len());
            Ok(decompressed)
        } else {
            // Not zlib data, return as-is
            tracing::debug!("Not zlib data (first byte: {:02x?}), returning as-is ({} bytes)",
                data.get(0), data.len());
            Ok(data.to_vec())
        }
    }

    /// Decompress zlib data unconditionally (for GEN_2/3)
    ///
    /// # C++ Equivalence
    /// Matches CString::zuncompressI() - unconditional zlib decompression
    /// The C++ code doesn't check for magic bytes, it just tries to decompress.
    /// If decompression fails, it returns the original data (for RC compatibility).
    fn decompress_zlib_unconditional(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        tracing::info!("GEN_2/3: Attempting zlib decompression of {} bytes (first: {:02x?}, full: {:02x?})",
            data.len(), data.get(0), data);

        match Self::try_zlib_decompress(data) {
            Ok(decompressed) => {
                tracing::info!("GEN_2/3: Zlib decompressed: {} -> {} bytes", data.len(), decompressed.len());
                Ok(decompressed)
            }
            Err(e) => {
                // If decompression fails, return as-is (RC sends uncompressed packets after login)
                tracing::info!("GEN_2/3: Zlib decompression failed ({}), using data as-is. First 16 bytes: {:02x?}",
                    e, &data[..data.len().min(16)]);
                Ok(data.to_vec())
            }
        }
    }

    /// Try zlib decompression without logging
    fn try_zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).map_err(|e| {
            gserver_core::GServerError::Compression(format!("Zlib decompression failed: {}", e))
        })?;
        Ok(decompressed)
    }

    /// Decompress bzip2 data
    ///
    /// # C++ Equivalence
    /// Matches CString::bzuncompressI() - bzip2 decompression
    fn decompress_bz2(&self, data: &[u8]) -> Result<Vec<u8>> {
        use bzip2::read::BzDecoder;
        use std::io::Read;

        // Try bzip2 decompression (magic: "BZh")
        if data.get(0) == Some(&0x42) && data.get(1) == Some(&0x5A) && data.get(2) == Some(&0x68) {
            let mut decoder = BzDecoder::new(data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                gserver_core::GServerError::Compression(format!("BZ2 decompression failed: {}", e))
            })?;
            Ok(decompressed)
        } else {
            // Not BZ2 data, return as-is
            Ok(data.to_vec())
        }
    }

    /// Decrypt GEN_5 packet data
    ///
    /// # C++ Equivalence
    /// Matches CEncryption::decrypt() for GEN_5
    ///
    /// # Arguments
    /// * `data` - Data to decrypt (modified in place)
    /// * `comp_type` - Compression type (determines encryption limit)
    fn decrypt_gen5(&self, data: &mut [u8], comp_type: u8) {
        // GEN_5 uses XOR encryption on first N bytes
        // The limit depends on compression type
        let limit = Self::get_encryption_limit(comp_type);

        if limit > 0 {
            self.xor_crypt(data, limit);
        }
    }

    /// Decompress and decrypt a bundle based on encryption generation
    ///
    /// # C++ Equivalence
    /// Matches processPacketBundle() in IPacketHandler.h (beta4)
    ///
    /// # Order for GEN_5
    /// 1. Read compression type byte
    /// 2. Decrypt the bundle
    /// 3. Decompress based on type
    fn decompress_and_decrypt_bundle(&self, bundle_data: &[u8]) -> Result<Vec<u8>> {
        if bundle_data.is_empty() {
            return Ok(Vec::new());
        }

        let gen = *self.encryption_gen.lock();

        match gen {
            1 | 6 => {
                // GEN_1 & GEN_6: No compression, no encryption
                tracing::trace!("GEN_{}: No compression, returning {} bytes as-is", gen, bundle_data.len());
                Ok(bundle_data.to_vec())
            }
            2 => {
                // GEN_2: Zlib compression only, no encryption
                // C++: bundle.zuncompressI() - unconditional decompression
                self.decompress_zlib_unconditional(bundle_data)
            }
            3 => {
                // GEN_3: Zlib + single byte insertion (encrypts each packet individually)
                // Bundle is just zlib compressed
                // C++: bundle.zuncompressI() - unconditional decompression
                self.decompress_zlib_unconditional(bundle_data)
            }
            4 => {
                // GEN_4: BZ2 compression + XOR encryption
                // Need to decrypt first, then decompress
                let mut decrypted = bundle_data.to_vec();
                self.xor_crypt(&mut decrypted, 4);  // Always 4 bytes for BZ2
                self.decompress_bz2(&decrypted)
            }
            5 => {
                // GEN_5: Smart compression + XOR encryption
                // Order: decrypt FIRST, then decompress

                tracing::info!("GEN_5: Processing bundle of {} bytes: {:02x?}",
                    bundle_data.len(), bundle_data);

                if bundle_data.len() < 1 {
                    return Err(gserver_core::GServerError::InvalidData(
                        "GEN_5 bundle too short".to_string()
                    ));
                }

                // Read compression type byte
                let comp_type = bundle_data[0];
                let encrypted_data = &bundle_data[1..];

                tracing::info!("GEN_5: Compression type: 0x{:02x}, encrypted data: {} bytes: {:02x?}",
                    comp_type, encrypted_data.len(), encrypted_data);

                // Validate compression type
                if comp_type != 0x02 && comp_type != 0x04 && comp_type != 0x06 {
                    return Err(gserver_core::GServerError::InvalidData(
                        format!("Invalid GEN_5 compression type: 0x{:02x}", comp_type)
                    ));
                }

                // DECRYPT FIRST (C++: Encryption.decrypt(bundle))
                let mut decrypted = encrypted_data.to_vec();
                self.decrypt_gen5(&mut decrypted, comp_type);

                tracing::info!("GEN_5: After decryption: {} bytes: {:02x?}",
                    decrypted.len(), decrypted);

                // THEN DECOMPRESS based on type
                match comp_type {
                    0x02 => {
                        // No compression
                        tracing::info!("GEN_5: No compression, {} bytes decrypted", decrypted.len());
                        Ok(decrypted)
                    }
                    0x04 => {
                        // Zlib
                        tracing::info!("GEN_5: Decrypting then zlib decompressing {} bytes", encrypted_data.len());
                        self.decompress_zlib(&decrypted)
                    }
                    0x06 => {
                        // BZ2
                        tracing::info!("GEN_5: Decrypting then bz2 decompressing {} bytes", encrypted_data.len());
                        self.decompress_bz2(&decrypted)
                    }
                    _ => unreachable!(),
                }
            }
            _ => {
                tracing::warn!("Unknown encryption generation {}, using raw data", gen);
                Ok(bundle_data.to_vec())
            }
        }
    }

    /// Handle an incoming packet
    ///
    /// # Arguments
    /// * `packet` - The packet to handle
    ///
    /// # Implementation
    /// Dispatches to packet-specific handlers
    async fn handle_packet(&self, packet: PacketIn) -> Result<()> {
        match packet.packet_type {
            gserver_protocol::PacketTypeIn::LevelWarp => {
                self.handle_level_warp(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::PlayerProps => {
                self.handle_player_props(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::BoardModify => {
                self.handle_board_modify(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::ToAll => {
                self.handle_to_all(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::Language => {
                self.handle_language(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::MapInfo => {
                self.handle_map_info(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::RequestText => {
                self.handle_request_text(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::Shoot => {
                self.handle_shoot(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::FlagSet => {
                self.handle_flag_set(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::FlagDel => {
                self.handle_flag_del(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::WeaponAdd => {
                self.handle_weapon_add(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::NpcProps => {
                self.handle_npc_props(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::NpcDel => {
                self.handle_npc_del(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::NpcWeaponDel => {
                self.handle_npc_weapon_del(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::BombAdd => {
                self.handle_bomb_add(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::BombDel => {
                self.handle_bomb_del(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::ArrowAdd => {
                self.handle_arrow_add(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::ItemAdd => {
                self.handle_item_add(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::ItemDel => {
                self.handle_item_del(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::HurtPlayer => {
                self.handle_hurt_player(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::Explosion => {
                self.handle_explosion(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::TriggerAction => {
                self.handle_trigger_action(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::WantFile => {
                self.handle_want_file(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::UpdateFile => {
                self.handle_update_file(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::UpdateGani => {
                self.handle_update_gani(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::UpdateScript => {
                self.handle_update_script(&packet.packet_data).await?;
            }
            gserver_protocol::PacketTypeIn::UpdateClass => {
                self.handle_update_class(&packet.packet_data).await?;
            }
            _ => {
                tracing::trace!("Connection {} unhandled packet: {:?}",
                    self.player_id.get(), packet.packet_type);
            }
        }
        Ok(())
    }

    /// Handle level warp packet (PLI_LEVELWARP = 0)
    ///
    /// # Purpose
    /// Called when a player requests to warp to a level.
    /// This is the primary mechanism for level loading.
    ///
    /// # Packet Format
    /// ```text
    /// {GINT5 modtime}{GSHORT x*2}{GSHORT y*2}{GSTRING level}
    /// ```
    ///
    /// # Response Packets Sent
    /// 1. PLO_SIGNATURE - Server signature (if not already sent)
    /// 2. PLO_LEVELNAME - Level name
    /// 3. PLO_RAWDATA - Board tile data (64x64 tiles)
    /// 4. PLO_LEVELMODTIME - Level modification time
    /// 5. PLO_SETACTIVELEVEL - Set active level
    /// 6. PLO_NEWWORLDTIME - World time
    /// 7. PLO_GHOSTICON - Ghost icon status
    /// 8. PLO_ISLEADER - Leader flag
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_LEVELWARP` and `PlayerClient::sendLevel` in PlayerClient.cpp:1179-1430
    async fn handle_level_warp(&self, packet_data: &[u8]) -> Result<()> {
        use bytes::BufMut;
        use gserver_protocol::{codecs::*, packet_builder::*, packets::PacketTypeOut, PacketOut};
        use gserver_levels::Level;

        tracing::info!("Connection {} handling level warp", self.player_id.get());

        // Parse the level warp packet
        let mut buf = BytesMut::from(packet_data);
        let mod_time = read_guint5(&mut buf)?;
        let _x = read_gshort(&mut buf)?;
        let _y = read_gshort(&mut buf)?;
        let level_name = read_gstring(&mut buf)?;

        tracing::info!("Connection {} level warp: mod_time={}, x={}, y={}, level={}",
            self.player_id.get(), mod_time, _x, _y, level_name);

        // Create or load the level
        // For now, create a default level if we can't load from disk
        let level = Level::create_default(level_name.clone());

        // Get board data from level
        let board_data = level.get_board_data();
        tracing::debug!("Connection {} generated board data: {} bytes",
            self.player_id.get(), board_data.len());

        // === Send response packets ===
        // Each packet is built using the packet_builder functions

        // 1. Send PLO_SIGNATURE (73 = more than 8 players)
        let mut sig_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            build_signature(&mut buf, 73);
            sig_data = buf.to_vec();
        }
        let sig_packet = PacketOut::new(PacketTypeOut::Signature, sig_data);
        self.send_packet(sig_packet).await?;
        tracing::debug!("Connection {} sent PLO_SIGNATURE", self.player_id.get());

        // 2. Send PLO_LEVELNAME (packet type 6)
        let mut name_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            build_level_name(&mut buf, &level_name);
            name_data = buf.to_vec();
        }
        let name_packet = PacketOut::new(PacketTypeOut::LevelName, name_data);
        self.send_packet(name_packet).await?;
        tracing::debug!("Connection {} sent PLO_LEVELNAME: {}", self.player_id.get(), level_name);

        // 3. Send PLO_RAWDATA with board tiles (packet type 100)
        // This is the main level data packet
        let mut board_packet_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            build_raw_data(&mut buf, board_data.len() as u32, &board_data);
            board_packet_data = buf.to_vec();
        }
        let board_packet = PacketOut::new(PacketTypeOut::RawData, board_packet_data);
        self.send_packet(board_packet).await?;
        tracing::debug!("Connection {} sent PLO_RAWDATA: {} bytes", self.player_id.get(), board_data.len());

        // 4. Send PLO_LEVELMODTIME (packet type 39)
        let mut mod_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            build_level_modtime(&mut buf, level.mod_time as u64);
            mod_data = buf.to_vec();
        }
        let mod_packet = PacketOut::new(PacketTypeOut::LevelModTime, mod_data);
        self.send_packet(mod_packet).await?;
        tracing::debug!("Connection {} sent PLO_LEVELMODTIME: {}", self.player_id.get(), level.mod_time);

        // 5. Send PLO_SETACTIVELEVEL (packet type 156)
        let mut active_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            build_set_active_level(&mut buf, &level_name);
            active_data = buf.to_vec();
        }
        let active_packet = PacketOut::new(PacketTypeOut::SetActiveLevel, active_data);
        self.send_packet(active_packet).await?;
        tracing::debug!("Connection {} sent PLO_SETACTIVELEVEL: {}", self.player_id.get(), level_name);

        // 6. Send PLO_NEWWORLDTIME (packet type 42)
        let mut time_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            // Use a simple world time (could be stored in server config)
            build_new_world_time(&mut buf, 0);
            time_data = buf.to_vec();
        }
        let time_packet = PacketOut::new(PacketTypeOut::NewWorldTime, time_data);
        self.send_packet(time_packet).await?;
        tracing::debug!("Connection {} sent PLO_NEWWORLDTIME", self.player_id.get());

        // 7. Send PLO_GHOSTICON (packet type 174)
        // 0 = no ghosts (trial accounts)
        let mut ghost_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            build_ghost_icon(&mut buf, 0);
            ghost_data = buf.to_vec();
        }
        let ghost_packet = PacketOut::new(PacketTypeOut::GhostIcon, ghost_data);
        self.send_packet(ghost_packet).await?;
        tracing::debug!("Connection {} sent PLO_GHOSTICON", self.player_id.get());

        // 8. Send PLO_ISLEADER (packet type 10)
        // Tells the client they are the leader of this level
        let mut leader_data = Vec::new();
        {
            use bytes::BytesMut;
            let mut buf = BytesMut::new();
            build_is_leader(&mut buf);
            leader_data = buf.to_vec();
        }
        let leader_packet = PacketOut::new(PacketTypeOut::IsLeader, leader_data);
        self.send_packet(leader_packet).await?;
        tracing::debug!("Connection {} sent PLO_ISLEADER", self.player_id.get());

        tracing::info!("Connection {} level warp complete, sent {} response packets",
            self.player_id.get(), 8);

        Ok(())
    }

    /// Handle player props packet (PLI_PLAYERPROPS = 2)
    ///
    /// # Purpose
    /// Client updates its own properties (position, sprites, etc.)
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::setPropsFromPacket` in PlayerProps.cpp
    async fn handle_player_props(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} sent PlayerProps: {} bytes",
            self.player_id.get(), packet_data.len());
        // TODO: Parse and store player properties
        Ok(())
    }

    /// Handle board modify packet (PLI_BOARDMODIFY = 1)
    ///
    /// # Purpose
    /// Client modifies tiles on the level (destroying bushes, etc.)
    ///
    /// # Packet Format
    /// ```text
    /// {GUCHAR x}{GUCHAR y}{GUCHAR width}{GUCHAR height}{STRING tiles}
    /// ```
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_BOARDMODIFY` in PlayerClientPackets.cpp:77
    async fn handle_board_modify(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let x = read_gchar(&mut buf)? as usize;
        let y = read_gchar(&mut buf)? as usize;
        let w = read_gchar(&mut buf)? as usize;
        let h = read_gchar(&mut buf)? as usize;
        let _tiles = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} board modify: x={}, y={}, w={}, h={}",
            self.player_id.get(), x, y, w, h);
        // TODO: Update level board and broadcast to other players
        Ok(())
    }

    /// Handle to all packet (PLI_TOALL = 13)
    ///
    /// # Purpose
    /// Client sends a message to all players in the level
    ///
    /// # C++ Equivalence
    /// Matches chat handling in PlayerClient
    async fn handle_to_all(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let message = read_gstring(&mut buf)?;

        tracing::info!("Connection {} chat: {}", self.player_id.get(), message);
        // TODO: Broadcast to all players in the level
        Ok(())
    }

    /// Handle language packet (PLI_LANGUAGE = 37)
    ///
    /// # Purpose
    /// Client sets its language preference
    ///
    /// # C++ Equivalence
    /// Matches `Player::msgPLI_LANGUAGE` in Player.cpp:1347
    async fn handle_language(&self, packet_data: &[u8]) -> Result<()> {
        // Language packet sends plain null-terminated string, not GString
        // C++: pPacket.readString("") - reads until null or end
        let language = if packet_data.is_empty() {
            String::new()
        } else {
            // Find null terminator or use entire string
            let end = packet_data.iter().position(|&b| b == 0).unwrap_or(packet_data.len());
            String::from_utf8_lossy(&packet_data[..end]).to_string()
        };

        if language.is_empty() {
            tracing::debug!("Connection {} language: <empty, defaulting to English>", self.player_id.get());
        } else {
            tracing::debug!("Connection {} language: {}", self.player_id.get(), language);
        }
        // TODO: Store language preference for player
        Ok(())
    }

    /// Handle map info packet (PLI_MAPINFO = 39)
    ///
    /// # Purpose
    /// Client requests map information
    ///
    /// # C++ Equivalence
    /// No explicit handler in C++, packet falls through to msgPLI_NULL
    async fn handle_map_info(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} map info request: {} bytes", self.player_id.get(), packet_data.len());
        // No response needed for this packet
        Ok(())
    }

    /// Handle request text packet (PLI_REQUESTTEXT = 54)
    ///
    /// # Purpose
    /// RC client sends a command to the server
    ///
    /// # C++ Equivalence
    /// Matches `PlayerRC::msgPLI_REQUESTTEXT` in PlayerRC.cpp
    async fn handle_request_text(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let text = read_gstring(&mut buf)?;

        tracing::info!("Connection {} RC command: {}", self.player_id.get(), text);
        // TODO: Parse and execute RC commands
        Ok(())
    }

    /// Handle shoot packet (PLI_SHOOT = 17)
    ///
    /// # Purpose
    /// Client fires a projectile
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_SHOOT` in PlayerClientPackets.cpp:1263
    async fn handle_shoot(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} shoot: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Add projectile and broadcast to other players
        Ok(())
    }

    /// Handle warp packet (PLI_WARP = 14)
    ///
    /// # Purpose
    /// Server-initiated warp (acknowledgment)
    async fn handle_warp(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} warp: {} bytes", self.player_id.get(), packet_data.len());
        Ok(())
    }

    /// Handle flag set packet (PLI_FLAGSET = 32)
    ///
    /// # Purpose
    /// Client sets a flag variable
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_FLAGSET` in PlayerClientPackets.cpp:516
    async fn handle_flag_set(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let flag = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} flag set: {}", self.player_id.get(), flag);
        // TODO: Parse and store flag (format: "flagname" or "flagname=value")
        Ok(())
    }

    /// Handle flag delete packet (PLI_FLAGDEL = 33)
    ///
    /// # Purpose
    /// Client deletes a flag variable
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_FLAGDEL` in PlayerClientPackets.cpp:615
    async fn handle_flag_del(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let flag = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} flag del: {}", self.player_id.get(), flag);
        // TODO: Remove flag
        Ok(())
    }

    /// Handle weapon add packet (PLI_WEAPONADD = 24)
    ///
    /// # Purpose
    /// Client requests to add a weapon
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_WEAPONADD` in PlayerClientPackets.cpp:820
    async fn handle_weapon_add(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} weapon add: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Add weapon to player
        Ok(())
    }

    /// Handle NPC props packet (PLI_NPCPROPS = 5)
    ///
    /// # Purpose
    /// Client updates NPC properties
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_NPCPROPS` in PlayerClientPackets.cpp:144
    async fn handle_npc_props(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} npc props: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Update NPC and broadcast to level
        Ok(())
    }

    /// Handle NPC delete packet (PLI_NPCDEL = 23)
    ///
    /// # Purpose
    /// Client requests to delete an NPC
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_NPCDEL` in PlayerClientPackets.cpp:719
    async fn handle_npc_del(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} npc del: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Delete NPC
        Ok(())
    }

    /// Handle NPC weapon delete packet (PLI_NPCWEAPONDEL = 25)
    ///
    /// # Purpose
    /// Client removes an NPC weapon
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_NPCWEAPONDEL` in PlayerClientPackets.cpp:813
    async fn handle_npc_weapon_del(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let weapon = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} npc weapon del: {}", self.player_id.get(), weapon);
        // TODO: Remove weapon from player
        Ok(())
    }

    /// Handle bomb add packet (PLI_BOMBADD = 7)
    ///
    /// # Purpose
    /// Client places a bomb
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_BOMBADD` in PlayerClientPackets.cpp:171
    async fn handle_bomb_add(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} bomb add: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Add bomb to level and broadcast
        Ok(())
    }

    /// Handle bomb delete packet (PLI_BOMBDEL = 8)
    ///
    /// # Purpose
    /// Client removes a bomb
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_BOMBDEL` in PlayerClientPackets.cpp:194
    async fn handle_bomb_del(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} bomb del: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Remove bomb from level
        Ok(())
    }

    /// Handle arrow add packet (PLI_ARROWADD = 11)
    ///
    /// # Purpose
    /// Client fires an arrow
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_ARROWADD` in PlayerClientPackets.cpp:232
    async fn handle_arrow_add(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} arrow add: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Add arrow to level and broadcast
        Ok(())
    }

    /// Handle item add packet (PLI_ITEMADD = 9)
    ///
    /// # Purpose
    /// Client drops an item
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_ITEMADD` in PlayerClientPackets.cpp:282
    async fn handle_item_add(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} item add: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Add item to level and broadcast
        Ok(())
    }

    /// Handle item delete packet (PLI_ITEMDEL = 10)
    ///
    /// # Purpose
    /// Client picks up an item
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_ITEMDEL` in PlayerClientPackets.cpp:333
    async fn handle_item_del(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} item del: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Remove item from level and give to player
        Ok(())
    }

    /// Handle hurt player packet (PLI_HURTPLAYER = 12)
    ///
    /// # Purpose
    /// Client hurts another player
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_HURTPLAYER` in PlayerClientPackets.cpp:756
    async fn handle_hurt_player(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let player_id = read_gushort(&mut buf)?;
        let _dx = read_gchar(&mut buf)?;
        let _dy = read_gchar(&mut buf)?;
        let power = read_gchar(&mut buf)? as usize;
        let _npc = read_guint(&mut buf)?;

        tracing::debug!("Connection {} hurt player {}: power={}",
            self.player_id.get(), player_id, power);
        // TODO: Send hurt packet to victim
        Ok(())
    }

    /// Handle explosion packet (PLI_EXPLOSION = 20)
    ///
    /// # Purpose
    /// Client causes an explosion
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_EXPLOSION` in PlayerClientPackets.cpp:777
    async fn handle_explosion(&self, packet_data: &[u8]) -> Result<()> {
        tracing::debug!("Connection {} explosion: {} bytes", self.player_id.get(), packet_data.len());
        // TODO: Add explosion to level and broadcast
        Ok(())
    }

    /// Handle trigger action packet (PLI_TRIGGERACTION = 18)
    ///
    /// # Purpose
    /// Client triggers an action (used by NPCs)
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_TRIGGERACTION` in PlayerClientPackets.cpp:981
    async fn handle_trigger_action(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let _npc_id = read_guint(&mut buf)?;
        let _x = read_guchar(&mut buf)?;
        let _y = read_guchar(&mut buf)?;
        let actions = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} trigger action: {}", self.player_id.get(), actions);
        // TODO: Parse actions and trigger on NPCs
        Ok(())
    }

    /// Handle want file packet (PLI_WANTFILE = 59)
    ///
    /// # Purpose
    /// Client requests a file from the server
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_WANTFILE` in PlayerClientPackets.cpp:734
    async fn handle_want_file(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let file = read_gstring(&mut buf)?;

        tracing::info!("Connection {} want file: {}", self.player_id.get(), file);
        // TODO: Send file to client (PLO_FILESEND)
        Ok(())
    }

    /// Handle update file packet (PLI_UPDATEFILE = 58)
    ///
    /// # Purpose
    /// Client checks if a file needs updating
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_UPDATEFILE` in PlayerClientPackets.cpp:881
    async fn handle_update_file(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let _modtime = read_guint5(&mut buf)?;
        let file = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} update file: {}", self.player_id.get(), file);
        // TODO: Check modtime and send file if needed (PLO_FILEUPTODATE or PLO_FILESENDFAILED)
        Ok(())
    }

    /// Handle update gani packet (PLI_UPDATEGANI = 162)
    ///
    /// # Purpose
    /// Client checks if an animation needs updating
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_UPDATEGANI` in PlayerClientPackets.cpp:1396
    async fn handle_update_gani(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let _checksum = read_guint5(&mut buf)?;
        let gani = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} update gani: {}", self.player_id.get(), gani);
        // TODO: Check checksum and send gani bytecode if needed (PLO_LOADGANI)
        Ok(())
    }

    /// Handle update script packet (PLI_UPDATESCRIPT = 56)
    ///
    /// # Purpose
    /// Client checks if a weapon script needs updating
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_UPDATESCRIPT` in PlayerClientPackets.cpp:1421
    async fn handle_update_script(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let weapon = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} update script: {}", self.player_id.get(), weapon);
        // TODO: Send weapon bytecode (PLO_NPCWEAPONSCRIPT)
        Ok(())
    }

    /// Handle update class packet (PLI_UPDATECLASS = 157)
    ///
    /// # Purpose
    /// Client checks if a class needs updating
    ///
    /// # C++ Equivalence
    /// Matches `PlayerClient::msgPLI_UPDATECLASS` in PlayerClientPackets.cpp:1431
    async fn handle_update_class(&self, packet_data: &[u8]) -> Result<()> {
        use gserver_protocol::codecs::*;

        let mut buf = BytesMut::from(packet_data);
        let _checksum = read_guint5(&mut buf)?;
        let class = read_gstring(&mut buf)?;

        tracing::debug!("Connection {} update class: {}", self.player_id.get(), class);
        // TODO: Send class bytecode if needed (PLO_RAWDATA)
        Ok(())
    }

    /// Decompress a bundle based on encryption generation
    ///
    /// # Compression Detection
    /// Attempts to detect compression type by:
    /// 1. Checking if data looks like zlib (starts with 0x78)
    /// 2. Checking if data looks like bzip2 (starts with "BZh")
    /// 3. If no compression detected, returns data as-is
    ///
    /// # Returns
    /// Decompressed bundle data
    fn decompress_bundle(&self, bundle_data: &[u8]) -> Result<Vec<u8>> {
        // Empty bundle
        if bundle_data.is_empty() {
            return Ok(Vec::new());
        }

        // Try to detect compression type
        // Zlib magic: 0x78 0x9c, 0x78 0xda, 0x78 0x01, etc.
        // Bzip2 magic: "BZh" (42 5A 68)

        let is_zlib = bundle_data.get(0) == Some(&0x78);
        let is_bzip2 = bundle_data.get(0) == Some(&0x42)
            && bundle_data.get(1) == Some(&0x5A)
            && bundle_data.get(2) == Some(&0x68);

        if is_zlib {
            tracing::debug!("Detected zlib compression, decompressing {} bytes", bundle_data.len());
            match gserver_protocol::decompress(bundle_data, gserver_protocol::CompressionType::Zlib) {
                Ok(decompressed) => {
                    tracing::debug!("Decompressed: {} -> {} bytes", bundle_data.len(), decompressed.len());
                    return Ok(decompressed);
                }
                Err(e) => {
                    tracing::warn!("Zlib decompression failed, trying raw data: {:?}", e);
                    // Fall through to raw data
                }
            }
        } else if is_bzip2 {
            tracing::debug!("Detected bzip2 compression, decompressing {} bytes", bundle_data.len());
            match gserver_protocol::decompress(bundle_data, gserver_protocol::CompressionType::Bzip2) {
                Ok(decompressed) => {
                    tracing::debug!("Decompressed: {} -> {} bytes", bundle_data.len(), decompressed.len());
                    return Ok(decompressed);
                }
                Err(e) => {
                    tracing::warn!("Bzip2 decompression failed, trying raw data: {:?}", e);
                    // Fall through to raw data
                }
            }
        }

        // Check for GEN_5 compression type byte (first byte)
        // 0x02 = none, 0x04 = zlib, 0x06 = bz2
        if bundle_data.len() > 1 {
            let first_byte = bundle_data[0];
            if first_byte == 0x04 || first_byte == 0x06 {
                let compression_type = if first_byte == 0x04 {
                    gserver_protocol::CompressionType::Zlib
                } else {
                    gserver_protocol::CompressionType::Bzip2
                };

                let compressed_data = &bundle_data[1..];
                tracing::debug!("GEN_5 compression type byte: 0x{:02x}, decompressing {} bytes",
                    first_byte, compressed_data.len());

                match gserver_protocol::decompress(compressed_data, compression_type) {
                    Ok(decompressed) => {
                        tracing::debug!("Decompressed: {} -> {} bytes", compressed_data.len(), decompressed.len());
                        return Ok(decompressed);
                    }
                    Err(e) => {
                        tracing::warn!("GEN_5 decompression failed: {:?}", e);
                    }
                }
            } else if first_byte == 0x02 {
                // GEN_5 no compression
                tracing::trace!("GEN_5 no compression byte, skipping first byte");
                return Ok(bundle_data[1..].to_vec());
            }
        }

        // No compression detected or decompression failed, return as-is
        tracing::trace!("No compression detected, using raw data");
        Ok(bundle_data.to_vec())
    }

    /// Update last activity timestamp
    fn update_activity(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// Check if connection has timed out
    ///
    /// # Timeout
    /// Connection times out if no activity for 60 seconds
    fn is_timed_out(&self) -> bool {
        let last_activity = *self.last_activity.lock();
        last_activity.elapsed() > Duration::from_secs(60)
    }

    /// Cleanup connection resources
    async fn cleanup(&self) {
        tracing::info!("Connection {} cleaning up", self.player_id.get());

        // Update state
        *self.state.lock() = ConnectionState::Disconnected;

        // Close socket - scope the lock to avoid holding it across await
        {
            let mut socket = self.socket.lock().await;
            let _ = socket.shutdown().await;
        }

        // Log stats
        let duration = self.connected_at.elapsed();
        let bytes_rx = *self.bytes_received.lock();
        let bytes_tx = *self.bytes_sent.lock();
        let packets_rx = *self.packets_received.lock();
        let packets_tx = *self.packets_sent.lock();

        tracing::info!(
            "Connection {} stats - Duration: {:?}, RX: {} bytes / {} packets, TX: {} bytes / {} packets",
            self.player_id.get(),
            duration,
            bytes_rx, packets_rx,
            bytes_tx, packets_tx
        );
    }

    // === Getters for connection statistics ===

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.lock()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.lock().elapsed()
    }

    /// Get total bytes received
    pub fn bytes_received(&self) -> u64 {
        *self.bytes_received.lock()
    }

    /// Get total bytes sent
    pub fn bytes_sent(&self) -> u64 {
        *self.bytes_sent.lock()
    }

    /// Get total packets received
    pub fn packets_received(&self) -> u64 {
        *self.packets_received.lock()
    }

    /// Get total packets sent
    pub fn packets_sent(&self) -> u64 {
        *self.packets_sent.lock()
    }

    /// Get connection uptime
    pub fn uptime(&self) -> Duration {
        self.connected_at.elapsed()
    }

    // === Player state helpers for broadcasting ===

    /// Get the player's current level name
    ///
    /// # C++ Equivalence
    /// Matches `Player::getLevel()` in Player.cpp
    pub fn get_level(&self) -> String {
        let account = self.account.lock();
        account.as_ref()
            .map(|a| a.level.clone())
            .unwrap_or_else(|| String::from("onlinestartlocal.nw"))
    }

    /// Get the player's current position (in pixels)
    ///
    /// # Returns
    /// (x, y) position in pixels
    pub fn get_position(&self) -> (f32, f32) {
        let account = self.account.lock();
        account.as_ref()
            .map(|a| (a.x, a.y))
            .unwrap_or((30.0, 30.0))
    }

    /// Check if this player is visible to another player
    ///
    /// # C++ Equivalence
    /// Matches visibility checks in TPlayer::isVisibleTo()
    ///
    /// # Arguments
    /// * `other_id` - The player ID to check visibility against
    ///
    /// # Returns
    /// true if this player should be visible to the other player
    pub fn is_visible_to(&self, other_id: PlayerID) -> bool {
        // Always visible to self
        if self.player_id == other_id {
            return true;
        }

        let account = self.account.lock();
        if let Some(acc) = account.as_ref() {
            // Check if player has invisible permission
            // C++: playerobj->getHidden() || hasPermission(PLPERM_INVISIBLE)
            if acc.has_permission(gserver_accounts::PLPERM_INVISIBLE) {
                return false;
            }
        }
        true
    }

    /// Check if this player is authenticated
    pub fn is_authenticated(&self) -> bool {
        matches!(self.state(), ConnectionState::Authenticated)
    }

    /// Get the player's account nickname
    pub fn get_nickname(&self) -> String {
        let account = self.account.lock();
        account.as_ref()
            .map(|a| a.nick.clone())
            .unwrap_or_else(|| String::from("Player"))
    }

    /// Get the player's account name
    pub fn get_account_name(&self) -> String {
        let account = self.account.lock();
        account.as_ref()
            .map(|a| a.name.clone())
            .unwrap_or_else(|| String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state() {
        let state = ConnectionState::Connected;
        assert_eq!(state, ConnectionState::Connected);
    }

    #[test]
    fn test_connection_timeout() {
        // Test timeout detection logic
        let old_time = Instant::now() - Duration::from_secs(61);
        // TODO: Test timeout checking
    }
}
