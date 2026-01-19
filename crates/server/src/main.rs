//! GServer - Graal Online Server in Rust
//!
//! Main server binary - 1:1 parity with C++ version

use gserver_config::ServerConfig as GameServerConfig;
use gserver_network::{GServer, ServerConfig as NetworkConfig};
use tracing::{info, error, Level, warn};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("🚀 GServer Rust starting up...");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Load configuration from serveroptions.txt (just like C++ version)
    info!("📂 Loading configuration from servers/default/config/serveroptions.txt...");

    let game_config = match GameServerConfig::load_default() {
        Ok(config) => {
            info!("✓ Configuration loaded successfully");
            config
        }
        Err(e) => {
            warn!("⚠️  Failed to load serveroptions.txt: {}", e);
            warn!("   Using default configuration (port 14802)");
            info!("   Create servers/default/config/serveroptions.txt for custom configuration");
            GameServerConfig::default()
        }
    };

    // Display configuration
    game_config.display();

    // Convert to network config
    let network_config = NetworkConfig {
        bind_address: game_config.bind_address(),
        max_connections: game_config.max_players,
        ..Default::default()
    };

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Create listserver config
    let listserver_config = gserver_network::ListServerConfig {
        list_ip: game_config.list_ip.clone(),
        list_port: game_config.list_port,
        server_name: game_config.name.clone(),
        description: game_config.description.clone(),
        language: game_config.language.clone(),
        url: game_config.url.clone(),
        server_ip: game_config.server_ip.clone(),
        server_port: game_config.server_port,
        local_ip: game_config.local_ip.clone(),
        hq_level: game_config.hq_level,
        hq_password: game_config.hq_password.clone(),
        only_staff: game_config.only_staff,
    };

    // Spawn listserver client
    info!("🌐 Starting listserver client ({}:{})...", listserver_config.list_ip, listserver_config.list_port);
    let _listserver_handle = gserver_network::spawn_listserver_client(listserver_config);
    info!("✓ Listserver client started");

    // Create GServer instance
    info!("🔧 Initializing GServer...");
    let server = GServer::new(network_config).await?;
    info!("✓ GServer instance created");

    info!("🎮 Server is ready to accept connections!");
    info!("📡 Waiting for players on port {}...", game_config.server_port);
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Run the server
    if let Err(e) = server.run().await {
        error!("💥 Server error: {}", e);
        Err(e.into())
    } else {
        info!("👋 Server shutting down gracefully");
        Ok(())
    }
}
