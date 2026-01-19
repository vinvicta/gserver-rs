//! # ListServer Client Implementation
//!
//! This module provides the listserver client that connects to the Graal Reborn listserver
//! and manages server registration, player list updates, and server-to-server communication.
//!
//! # Architecture
//!
//! The listserver client runs as a separate async task that:
//! 1. Connects to the listserver (listserver.graal.in:14900 by default)
//! 2. Sends registration packets with server info
//! 3. Maintains player list updates
//! 4. Handles incoming SVI_* packets
//! 5. Auto-reconnects on disconnect with exponential backoff
//!
//! # Protocol
//!
//! - **Compression**: zlib compression on all packets
//! - **Encryption**: Gen 1 for registration, Gen 2 for ongoing communication
//! - **Packet Format**: [length (2 bytes)][compressed data]
//!
//! # References
//!
//! - C++: `/home/versa/Desktop/GServer-v2/server/src/ServerList.cpp`
//! - C++: `/home/versa/Desktop/GServer-v2/server/include/ServerList.h`

use crate::config::ServerConfig;
use gserver_core::{Result, GServerError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;
use tracing::{info, warn, error, debug, trace};
use rand::Rng;

/// ListServer client configuration
#[derive(Debug, Clone)]
pub struct ListServerConfig {
    /// Listserver IP address
    pub list_ip: String,

    /// Listserver port
    pub list_port: u16,

    /// Server name
    pub server_name: String,

    /// Server description
    pub description: String,

    /// Server language
    pub language: String,

    /// Server URL
    pub url: String,

    /// Server IP (AUTO for auto-detection)
    pub server_ip: String,

    /// Server port
    pub server_port: u16,

    /// Local IP (optional, AUTO for auto-detection)
    pub local_ip: String,

    /// HQ level (0=Hidden, 1=Bronze, 2=Silver, 3=Gold)
    pub hq_level: u8,

    /// HQ password
    pub hq_password: String,

    /// Only staff mode
    pub only_staff: bool,
}

impl Default for ListServerConfig {
    fn default() -> Self {
        Self {
            list_ip: "listserver.graal.in".to_string(),
            list_port: 14900,
            server_name: "My Server".to_string(),
            description: "My Server".to_string(),
            language: "English".to_string(),
            url: "http://www.graal.in/".to_string(),
            server_ip: "AUTO".to_string(),
            server_port: 14802,
            local_ip: "AUTO".to_string(),
            hq_level: 1,
            hq_password: String::new(),
            only_staff: false,
        }
    }
}

/// ListServer client state
pub struct ListServerClient {
    /// Configuration
    config: ListServerConfig,

    /// TCP socket connection
    socket: Option<TcpStream>,

    /// Read buffer
    read_buffer: Vec<u8>,

    /// Outbound packet buffer (queued before compression)
    outbound_buffer: Vec<u8>,

    /// Connection state
    connected: bool,

    /// Reconnection state
    connection_attempts: u8,
    next_connection_attempt: Option<Instant>,

    /// Last data received timestamp
    last_data: Option<Instant>,

    /// Last timer event timestamp
    last_timer: Option<Instant>,

    /// Timestamp of last successful connection
    last_connect_time: Option<Instant>,

    /// Count of rapid disconnections (connection closed within 5 seconds)
    rapid_disconnection_count: u32,
}

impl ListServerClient {
    /// Create a new listserver client
    pub fn new(config: ListServerConfig) -> Self {
        Self {
            config,
            socket: None,
            read_buffer: Vec::new(),
            outbound_buffer: Vec::new(),
            connected: false,
            connection_attempts: 0,
            next_connection_attempt: None,
            last_data: None,
            last_timer: None,
            last_connect_time: None,
            rapid_disconnection_count: 0,
        }
    }

    /// Check if connected to listserver
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Connect to the listserver
    pub async fn connect(&mut self) -> Result<()> {
        if self.connected {
            return Ok(());
        }

        info!("Initializing listserver socket...");

        // Connect to listserver
        let address = format!("{}:{}", self.config.list_ip, self.config.list_port);
        debug!("Connecting to listserver at {}", address);

        match TcpStream::connect(&address).await {
            Ok(mut socket) => {
                // Disable Nagle's algorithm for low latency
                // This ensures small packets are sent immediately
                socket.set_nodelay(true).map_err(|e| {
                    GServerError::Network(format!("Failed to set TCP_NODELAY: {}", e))
                })?;

                self.socket = Some(socket);
                self.connected = true;
                self.connection_attempts = 0;
                self.last_connect_time = Some(Instant::now());

                info!("Listserver - Connected to {}:{}", self.config.list_ip, self.config.list_port);

                // Send registration packets
                self.send_registration().await?;

                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to listserver: {}", e);

                // Exponential backoff
                if self.connection_attempts < 8 {
                    self.connection_attempts += 1;
                }
                let wait_time = std::cmp::min(2u64.pow(self.connection_attempts as u32), 300);
                self.next_connection_attempt = Some(Instant::now() + Duration::from_secs(wait_time));

                Err(GServerError::Network(format!("Failed to connect to listserver: {}", e)))
            }
        }
    }

    /// Send registration packets
    async fn send_registration(&mut self) -> Result<()> {
        if !self.connected {
            return Err(GServerError::Network("Not connected to listserver".to_string()));
        }

        info!("Sending server registration to listserver...");

        // Get local IP
        let local_ip = if self.config.local_ip == "AUTO" {
            self.get_local_ip().await
        } else {
            self.config.local_ip.clone()
        };

        // Don't send localhost IP
        if local_ip == "127.0.0.1" || local_ip == "127.0.1.1" {
            warn!("Local IP is {} - not sending to listserver", local_ip);
        }

        // SVO_REGISTERV3 packet - MUST BE SENT IMMEDIATELY AND SEPARATELY
        // Format: [SVO_REGISTERV3][version]
        // This packet uses ENCRYPT_GEN_1 (no encryption, no compression)
        let version = "4.0.0"; // Match C++ version
        let mut register_packet = Vec::new();
        register_packet.push(0x1E + 32); // SVO_REGISTERV3 encoded (30 + 32 = 62)
        register_packet.extend_from_slice(version.as_bytes());
        register_packet.push(b'\n'); // Packet terminator

        info!("Sending REGISTERV3 packet immediately: version={}", version);
        debug!("REGISTERV3 packet data: {:02X?}", register_packet);

        // Send REGISTERV3 immediately without compression (Gen 1)
        // Gen 1: NO length prefix, just send raw packet data
        let socket = self.socket.as_mut().ok_or_else(|| {
            GServerError::Network("No socket".to_string())
        })?;

        info!("Sending REGISTERV3 raw: {:02X?}", register_packet);
        socket.write_all(&register_packet).await.map_err(|e| {
            GServerError::Network(format!("Failed to send REGISTERV3: {}", e))
        })?;
        info!("REGISTERV3 sent: {} bytes", register_packet.len());

        // Switch to Gen 2 encryption (simulated - actual encryption not implemented yet)
        // TODO: Implement Gen 2 encryption
        // m_fileQueue.setCodec(ENCRYPT_GEN_2, 0);

        // SVO_SERVERHQPASS packet
        if !self.config.hq_password.is_empty() {
            let mut packet = Vec::new();
            packet.push(23 + 32); // SVO_SERVERHQPASS (23) encoded
            packet.extend_from_slice(self.config.hq_password.as_bytes());

            debug!("Sending SERVERHQPASS packet");
            self.send_packet(&packet).await?;
        }

        // SVO_NEWSERVER packet with server info
        // Format: [SVO_NEWSERVER][name_len][name][desc_len][desc][lang_len][lang][ver_len][ver][url_len][url][ip_len][ip][port_len][port][localip_len][localip]
        let mut packet = Vec::new();
        packet.push(0x16 + 32); // SVO_NEWSERVER encoded (22 + 32 = 54)

        self.write_string(&mut packet, &self.config.server_name);
        self.write_string(&mut packet, &self.config.description);
        self.write_string(&mut packet, &self.config.language);
        self.write_string(&mut packet, version);
        self.write_string(&mut packet, &self.config.url);
        self.write_string(&mut packet, &self.config.server_ip);
        self.write_string(&mut packet, &self.config.server_port.to_string());
        self.write_string(&mut packet, &local_ip);

        info!("NEWSERVER packet raw bytes: {:02X?}", packet);
        info!("Sending NEWSERVER packet: name={}, port={}", self.config.server_name, self.config.server_port);
        self.send_packet(&packet).await?;

        // SVO_SERVERHQLEVEL packet
        let hq_level = if self.config.only_staff { 0 } else { self.config.hq_level };
        let mut packet = Vec::new();
        packet.push(24 + 32); // SVO_SERVERHQLEVEL (24) encoded
        packet.push(hq_level);

        debug!("Sending SERVERHQLEVEL packet: level={}", hq_level);
        self.send_packet(&packet).await?;

        // Send version configuration
        self.send_version_config().await?;

        // Send initial player list (clear + add players)
        self.send_players().await?;

        // Flush all packets and send them
        self.flush_packets().await?;

        info!("✓ Server registration sent to listserver");
        info!("Server name: {}", self.config.server_name);
        info!("Server port: {}", self.config.server_port);
        info!("Server IP: {}", self.config.server_ip);
        info!("Local IP: {}", local_ip);
        info!("HQ Level: {}", hq_level);
        info!("Description: {}", self.config.description);
        info!("URL: {}", self.config.url);

        Ok(())
    }

    /// Send version configuration to listserver
    async fn send_version_config(&mut self) -> Result<()> {
        if !self.connected {
            return Ok(());
        }

        // TODO: Get allowed versions from server config
        // For now, send default versions
        let version_text = "Listserver,settings,allowedversions,GNW13110,GNW03014:GNW28015,G3D22067,G3D14097:G3D0511C";
        self.send_text(version_text).await?;

        debug!("Sent version config to listserver");
        Ok(())
    }

    /// Send player list to listserver
    async fn send_players(&mut self) -> Result<()> {
        if !self.connected {
            return Ok(());
        }

        // Send SVO_SETPLYR to clear the player list
        let mut packet = Vec::new();
        packet.push(0x07 + 32); // SVO_SETPLYR encoded (7 + 32 = 39)
        self.send_packet(&packet).await?;

        // TODO: Add actual players when player system is implemented
        // For now, just send the clear packet (no players online yet)
        debug!("Sent player list update to listserver (0 players)");
        Ok(())
    }

    /// Send text message to listserver
    async fn send_text(&mut self, text: &str) -> Result<()> {
        let mut packet = Vec::new();
        packet.push(0x1F + 32); // SVO_SENDTEXT encoded (31 + 32 = 63)
        packet.extend_from_slice(text.as_bytes());
        self.send_packet(&packet).await?;
        Ok(())
    }

    /// Helper to write length-prefixed string using GChar encoding
    fn write_string(&self, packet: &mut Vec<u8>, s: &str) {
        // GChar encoding: add 32 to the value (same as writeGChar in C++)
        packet.push((s.len() as u8) + 32);
        packet.extend_from_slice(s.as_bytes());
    }

    /// Decode a GShort from 2 bytes
    /// GShort format: (byte0 << 7) + byte1 - 0x1020
    fn read_gshort(data: &[u8]) -> i16 {
        if data.len() < 2 {
            return 0;
        }
        let b0 = data[0] as i32;
        let b1 = data[1] as i32;
        ((b0 << 7) + b1 - 0x1020) as i16
    }

    /// Get local IP address
    async fn get_local_ip(&self) -> String {
        // Try to get local IP from socket
        if let Some(socket) = &self.socket {
            if let Ok(addr) = socket.local_addr() {
                let ip = addr.ip().to_string();
                // Don't return loopback addresses
                if !ip.starts_with("127.") {
                    return ip;
                }
            }
        }

        // Fallback to localhost
        "127.0.0.1".to_string()
    }

    /// Send a packet to the listserver
    async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if !self.connected {
            return Err(GServerError::Network("Not connected to listserver".to_string()));
        }

        info!("Sending packet: {:02X?} ({} bytes)", packet, packet.len());

        // Add to outbound buffer
        self.outbound_buffer.extend_from_slice(packet);
        self.outbound_buffer.push(b'\n');

        Ok(())
    }

    /// Flush the outbound buffer (compress and send)
    async fn flush_packets(&mut self) -> Result<()> {
        if self.outbound_buffer.is_empty() {
            return Ok(());
        }

        info!("Flushing {} bytes of outbound data", self.outbound_buffer.len());
        debug!("Raw outbound data: {:02X?}", self.outbound_buffer);

        // Compress the combined buffer
        let compressed = self.compress_packet(&self.outbound_buffer)?;

        info!("Compressed to: {} bytes", compressed.len());
        debug!("Compressed data: {:02X?}", compressed);

        // Format: [length (2 bytes, BIG ENDIAN)][compressed data]
        let len = compressed.len() as u16;
        let mut full_packet = Vec::with_capacity(2 + compressed.len());
        full_packet.extend_from_slice(&len.to_be_bytes());
        full_packet.extend_from_slice(&compressed);

        // Send packet
        let socket = self.socket.as_mut().ok_or_else(|| {
            GServerError::Network("No socket".to_string())
        })?;

        info!("Sending full packet: length={}, {} bytes total (2 length + {} compressed)",
              len, 2 + compressed.len(), compressed.len());
        debug!("Full packet bytes: {:02X?}", &full_packet[..full_packet.len().min(100)]);

        socket.write_all(&full_packet).await.map_err(|e| {
            // If we get a broken pipe or connection reset, the listserver closed the connection
            // This is normal during reconnection, so just mark as disconnected
            if e.kind() == std::io::ErrorKind::BrokenPipe
                || e.kind() == std::io::ErrorKind::ConnectionReset {
                self.connected = false;
                self.socket = None;
                GServerError::Network(format!("Listserver closed connection: {}", e))
            } else {
                GServerError::Network(format!("Failed to send packet: {}", e))
            }
        })?;

        info!("Sent {} bytes total", full_packet.len());

        // Clear the buffer
        self.outbound_buffer.clear();

        Ok(())
    }

    /// Compress packet using zlib
    fn compress_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(packet).map_err(|e| {
            GServerError::Compression(format!("Failed to compress packet: {}", e))
        })?;
        encoder.finish().map_err(|e| {
            GServerError::Compression(format!("Failed to finish compression: {}", e))
        })
    }

    /// Decompress packet using zlib
    fn decompress_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        let mut decoder = ZlibDecoder::new(packet);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).map_err(|e| {
            GServerError::Compression(format!("Failed to decompress packet: {}", e))
        })?;
        Ok(decompressed)
    }

    /// Receive and process packets from listserver
    /// Returns Ok(true) if connection is still open (should call again)
    /// Returns Ok(false) if connection was closed
    /// Returns Err(...) on error
    pub async fn process(&mut self) -> Result<bool> {
        if !self.connected {
            return Ok(false);
        }

        let socket = self.socket.as_mut().ok_or_else(|| {
            GServerError::Network("No socket".to_string())
        })?;

        // Block indefinitely waiting for data (like the C++ select() loop)
        // Don't use timeout - let it block until data arrives or connection closes
        let mut buf = [0u8; 4096];
        match socket.read(&mut buf).await {
            Ok(0) => {
                // Connection closed by listserver
                let connection_duration = self.last_connect_time
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::from_secs(0));

                warn!("Listserver closed connection (read returned 0 bytes)");
                info!("Connection was open for: {:?}", connection_duration);

                // Track rapid disconnections (within 5 seconds)
                if connection_duration < Duration::from_secs(5) {
                    self.rapid_disconnection_count += 1;
                    info!("Rapid disconnection detected (count: {})", self.rapid_disconnection_count);
                } else {
                    // Connection lasted a while, reset the counter
                    self.rapid_disconnection_count = 0;
                }

                self.connected = false;
                self.socket = None;

                // Set backoff to prevent spam connecting
                // Use 60 second minimum wait time
                let backoff_seconds = 60;
                // Add random jitter (0-30 seconds) to prevent servers from reconnecting in sync
                let jitter = rand::thread_rng().gen_range(0..30);
                let total_wait = backoff_seconds + jitter;
                info!("Waiting {} seconds (+ {} jitter) before reconnecting", backoff_seconds, jitter);
                self.next_connection_attempt = Some(Instant::now() + Duration::from_secs(total_wait));

                return Ok(false);
            }
            Ok(n) => {
                info!("Received {} bytes from listserver", n);
                debug!("Raw data: {:02X?}", &buf[..n]);

                self.read_buffer.extend_from_slice(&buf[..n]);
                self.last_data = Some(Instant::now());

                debug!("Read buffer now: {} bytes", self.read_buffer.len());

                // Process complete packets
                let mut packet_count = 0;
                while self.try_parse_packet().await? {
                    packet_count += 1;
                }
                if packet_count > 0 {
                    debug!("Processed {} packets", packet_count);
                }

                // CRITICAL: After processing packets, flush any outbound data
                // This matches the C++ behavior where onRecv() calls main() which
                // then calls updateSingle(this, false, true) to send queued data
                if !self.outbound_buffer.is_empty() {
                    debug!("Flushing {} bytes of outbound data after processing packets",
                           self.outbound_buffer.len());
                    self.flush_packets().await?;
                }

                // Return true - connection is still open, call process() again
                Ok(true)
            }
            Err(e) => {
                error!("Error reading from listserver: {}", e);
                if let Some(last_data) = self.last_data {
                    info!("Connection was open for: {:?}", last_data.elapsed());
                }
                self.connected = false;
                self.socket = None;
                return Err(GServerError::Network(format!("Read error: {}", e)));
            }
        }
    }

    /// Try to parse a complete packet from the read buffer
    async fn try_parse_packet(&mut self) -> Result<bool> {
        // Need at least 2 bytes for length
        if self.read_buffer.len() < 2 {
            return Ok(false);
        }

        // Read packet length (big endian)
        let len = u16::from_be_bytes([self.read_buffer[0], self.read_buffer[1]]) as usize;

        // Check if we have the complete packet
        if self.read_buffer.len() < 2 + len {
            return Ok(false);
        }

        // Extract packet data (copy to avoid borrow conflict)
        let packet_data: Vec<u8> = self.read_buffer[2..2 + len].to_vec();

        // Remove packet from buffer
        self.read_buffer.drain(..2 + len);

        // Decompress packet
        let decompressed = self.decompress_packet(&packet_data)?;

        // Parse packet
        self.handle_packet(&decompressed).await?;

        Ok(true)
    }

    /// Handle a decompressed packet from listserver
    async fn handle_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }

        // Decode packet ID (subtract 32 to reverse GChar encoding)
        let encoded_packet_id = packet[0];
        let packet_id = encoded_packet_id.saturating_sub(32);
        let data = &packet[1..];

        info!("Received listserver packet: encoded=0x{:02x}, decoded=0x{:02x} ({} bytes)", encoded_packet_id, packet_id, data.len());

        match packet_id {
            0x05 => self.handle_version_old(data).await?,
            0x06 => self.handle_version_current(data).await?,
            0x07 => self.handle_profile(data).await?,
            0x08 => self.handle_error(data).await?,
            0x13 => self.handle_requesttext(data).await?,    // SVI_REQUESTTEXT = 19
            0x14 => self.handle_sendtext(data).await?,      // SVI_SENDTEXT = 20
            0x63 => self.handle_ping(data).await?,           // SVI_PING = 99
            _ => {
                debug!("Unknown listserver packet: 0x{:02x} (decoded from 0x{:02x})", packet_id, encoded_packet_id);
            }
        }

        Ok(())
    }

    /// SVI_PING - Respond to ping with pong
    async fn handle_ping(&mut self, _data: &[u8]) -> Result<()> {
        // Send PONG (same packet), encoded with GChar
        let packet = vec![0x10 + 32]; // SVO_PING (16) encoded
        self.send_packet(&packet).await?;
        Ok(())
    }

    /// SVI_VERIACC - Account verification response
    async fn handle_veriacc(&mut self, data: &[u8]) -> Result<()> {
        debug!("SVI_VERIACC: {:?}", data);
        // TODO: Implement player account verification
        Ok(())
    }

    /// SVI_VERSIONOLD - Server is outdated
    async fn handle_version_old(&mut self, _data: &[u8]) -> Result<()> {
        warn!("You are running an old version of GServer. An updated version is available.");
        Ok(())
    }

    /// SVI_VERSIONCURRENT - Server is up to date
    async fn handle_version_current(&mut self, _data: &[u8]) -> Result<()> {
        info!("Server is running the latest version.");
        Ok(())
    }

    /// SVI_PROFILE - Profile request
    async fn handle_profile(&mut self, data: &[u8]) -> Result<()> {
        debug!("SVI_PROFILE: {:?}", data);
        // TODO: Implement profile lookup
        Ok(())
    }

    /// SVI_ERRMSG - Error message from listserver
    async fn handle_error(&mut self, data: &[u8]) -> Result<()> {
        let msg = String::from_utf8_lossy(data);
        warn!("Listserver error: {}", msg);
        Ok(())
    }

    /// SVI_SERVERINFO - Server info (for serverwarp)
    async fn handle_serverinfo(&mut self, data: &[u8]) -> Result<()> {
        debug!("SVI_SERVERINFO: {:?}", data);
        // TODO: Implement serverwarp functionality
        Ok(())
    }

    /// SVI_REQUESTTEXT - Request text/data from server
    async fn handle_requesttext(&mut self, data: &[u8]) -> Result<()> {
        // Log raw data
        debug!("SVI_REQUESTTEXT raw data: {:02X?}", &data[..data.len().min(50)]);

        // Format: [playerId (GShort, 2 bytes)][message (string)]
        if data.len() < 3 {
            debug!("SVI_REQUESTTEXT: data too short: {:?}", data);
            return Ok(());
        }

        // Read player ID (GShort encoded format)
        let player_id = Self::read_gshort(data);

        // Read message (null-terminated or rest of packet)
        let msg_bytes = &data[2..];
        let msg = String::from_utf8_lossy(msg_bytes);

        // Remove null terminator if present
        let msg = msg.trim_end_matches('\0');

        info!("SVI_REQUESTTEXT: player_id={}, message={}", player_id, msg);

        // Parse the message - format is "Listserver,command,options"
        let parts: Vec<&str> = msg.split(',').collect();

        if parts.len() >= 1 && parts[0] == "Listserver" {
            if parts.len() >= 2 {
                match parts[1] {
                    "SetRemote" => {
                        info!("Listserver confirmed: Remote mode enabled");
                        // Acknowledge by doing nothing - the connection staying open is our acknowledgment
                    }
                    _ => {
                        debug!("Unhandled listserver command: {}", parts[1]);
                    }
                }
            }
        }

        Ok(())
    }

    /// SVI_SENDTEXT - Text message from listserver
    async fn handle_sendtext(&mut self, data: &[u8]) -> Result<()> {
        // Format: [message (string)]
        let msg = String::from_utf8_lossy(data);

        info!("SVI_SENDTEXT: {}", msg);

        // Parse comma-separated message (but need to handle quoted strings)
        // The C++ code uses gCommaStrTokens() which handles tokenization properly
        // For now, use simple split and improve if needed
        let parts: Vec<&str> = msg.split(',').collect();

        if parts.len() >= 1 {
            match parts[0] {
                "GraalEngine" => {
                    // Handle IRC-style messages from listserver
                    if parts.len() >= 2 && parts[1] == "irc" {
                        // IRC protocol message
                        debug!("Listserver IRC message: {:?}", &parts[2..]);
                        // TODO: Implement IRC handling if needed
                    }
                }
                "Listserver" => {
                    // Listserver-specific messages
                    if parts.len() >= 2 {
                        match parts[1] {
                            "SetRemoteIp" => {
                                if parts.len() >= 3 {
                                    let remote_ip = parts[2].trim();
                                    info!("Listserver identified remote IP as: '{}'", remote_ip);
                                    // TODO: Store this for server reference
                                }
                            }
                            "Modify" => {
                                // Server list update
                                // Format: Listserver,Modify,"Server Name",key=value,key2=value2,...
                                if parts.len() >= 4 && parts[2] == "Server" {
                                    let server_name = parts[3].trim_matches('"');

                                    // Parse key=value pairs from remaining parts
                                    for i in 4..parts.len() {
                                        let part = parts[i].trim();
                                        if let Some(eq_pos) = part.find('=') {
                                            let key = &part[..eq_pos];
                                            let val = &part[eq_pos + 1..];

                                            if key == "players" {
                                                if let Ok(player_count) = val.parse::<i32>() {
                                                    if player_count >= 0 {
                                                        info!("Server '{}' has {} players", server_name, player_count);
                                                    } else {
                                                        info!("Server '{}' removed from list", server_name);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                debug!("Listserver command: {}", parts[1]);
                            }
                        }
                    }
                }
                _ => {
                    debug!("Unknown message type: {}", parts[0]);
                }
            }
        }

        Ok(())
    }

    /// Run timed events (called every second)
    pub async fn do_timed_events(&mut self) -> Result<()> {
        self.last_timer = Some(Instant::now());

        // Try to reconnect if disconnected
        if !self.connected {
            if let Some(next_attempt) = self.next_connection_attempt {
                if Instant::now() >= next_attempt {
                    debug!("Attempting to reconnect to listserver...");
                    let _ = self.connect().await;
                }
            } else {
                // No scheduled attempt, try now
                let _ = self.connect().await;
            }
        }

        // Process incoming data if connected (called frequently)
        if self.connected {
            self.process().await?;
        }

        Ok(())
    }

    /// Disconnect from listserver
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.shutdown().await;
        }
        self.connected = false;
        info!("Disconnected from listserver");
        Ok(())
    }
}

/// Spawn the listserver client task
pub fn spawn_listserver_client(
    config: ListServerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut client = ListServerClient::new(config);

        loop {
            // Try to connect
            if let Err(e) = client.connect().await {
                error!("Connection failed: {:?}", e);
                // Wait before retrying
                if let Some(next_attempt) = client.next_connection_attempt {
                    let delay = next_attempt.saturating_duration_since(Instant::now());
                    sleep(delay).await;
                } else {
                    sleep(Duration::from_secs(5)).await;
                }
                continue;
            }

            // Connected successfully - now process packets
            // This will block until the connection closes
            // The connection should stay persistent indefinitely
            info!("Listserver connection established, waiting for packets...");

            loop {
                match client.process().await {
                    Ok(true) => {
                        // Connection still open, continue processing
                        continue;
                    }
                    Ok(false) => {
                        // Connection closed
                        warn!("Listserver connection closed");
                        break;
                    }
                    Err(e) => {
                        error!("Error processing listserver packets: {:?}", e);
                        break;
                    }
                }
            }

            // Connection closed, wait before reconnecting
            info!("Connection closed loop: checking backoff...");
            // Check if there's a backoff timer set
            if let Some(next_attempt) = client.next_connection_attempt {
                let delay = next_attempt.saturating_duration_since(Instant::now());
                info!("Backoff timer set: delay={:?}", delay);
                if delay > Duration::ZERO {
                    info!("Waiting {:?} before reconnecting (backoff)", delay);
                    sleep(delay).await;
                } else {
                    info!("Backoff delay is zero, reconnecting immediately");
                }
            } else {
                // No backoff set, wait a bit before reconnecting
                info!("No backoff timer set, waiting 5 seconds before reconnecting");
                sleep(Duration::from_secs(5)).await;
            }
        }
    })
}
