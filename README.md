# GServer-RS

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

A complete, high-performance rewrite of the Graal Online game server in Rust.

> **⚠️ WORK IN PROGRESS** - This project is under active development. Not all features are implemented yet. See [Implementation Status](#implementation-status) for details.

## About

GServer-RS is a modern Rust implementation of the GServer (Graal Online) game server protocol. It maintains full binary protocol compatibility with existing Graal clients while providing significantly improved performance, memory safety, and maintainability compared to the original C++ codebase.

### Features

- **Full Protocol Compatibility** - Works with existing Graal clients (v1.x through v5.x)
- **High Performance** - Rust's zero-cost abstractions and memory safety without runtime overhead
- **GS1 Scripting Engine** - Complete GS1 scripting language support for NPCs and weapons
- **Remote Control (RC)** - Full RC protocol for server administration
- **NPC Server (NC)** - External NPC processing support
- **Map/GMap Support** - BIGMAP and GMAP level loading with terrain generation
- **Modern Architecture** - Clean, modular codebase using async/await

## Credits

This project is a reimplementation based on the original [GServer-v2](https://github.com/xtjoeytx/GServer-v2) C++ codebase by xtjoeytx. The original project serves as the reference implementation for protocol compatibility and feature parity.

## Implementation Status

### ✅ Completed

| Component | Status | Notes |
|-----------|--------|-------|
| Binary Protocol | ✅ Complete | All codecs (GChar, GShort, GInt, GUInt5, GString) |
| Packet Types | ✅ Complete | 160+ packet types defined |
| Encryption/Compression | ✅ Complete | GEN_1 through GEN_5 support |
| Login Flow | ✅ Complete | Account loading, authentication |
| Level Loading | ✅ Complete | GLEVNW01 format with base64 tiles |
| ShowImg System | ✅ Complete | Dynamic image overlays |
| Map/GMap System | ✅ Complete | BIGMAP and GMAP with terrain |
| Packet Broadcasting | ✅ Complete | Level-based, range-based filtering |
| GS1 Scripting | ✅ Complete | 140+ commands, variables, triggers |
| RC Protocol | ✅ Complete | 40+ administrative commands |
| NC Protocol | ✅ Complete | NPC server communication |

### 🚧 In Progress

| Component | Status | Notes |
|-----------|--------|-------|
| NPC System | 🚧 Partial | Basic NPCs working, advanced AI in progress |
| Weapon System | 🚧 Partial | Weapon loading done, scripts in progress |
| Board Modifications | 🚧 Partial | PLI_BOARDMODIFY handling |

### ❌ Planned

| Component | Status | Notes |
|-----------|--------|-------|
| GS2 Scripting | ❌ Planned | Object-oriented scripting language |
| Guild System | ❌ Planned | Guild management |
| Translation System | ❌ Planned | .po file support |
| File Transfer | ❌ Planned | Upload/download functionality |

## Getting Started

### Prerequisites

- **Rust** 1.70 or later ([install](https://www.rust-lang.org/tools/install))
- **Git** ([install](https://git-scm.com/downloads))

### Building from Source

```bash
# Clone the repository
git clone https://github.com/vinvicta/gserver-rs.git
cd gserver-rs

# Build the server
cargo build --release

# The binary will be at: target/release/gserver
```

### Initial Setup

#### 1. Configure Your Account

The server comes with a placeholder account file. You need to rename it to your account name:

```bash
cd servers/default/accounts
mv YOURACCOUNT.txt yourname.txt
```

Edit `yourname.txt` to set your account properties:

```text
GRACC001
NAME YourName
NICK YourName
LEVEL onlinestartlocal.nw
X 480
Y 352
MAXHP 3
HP 6
...
```

#### 2. Configure Server Options

Edit `servers/default/config/serveroptions.txt` to configure your server:

```text
// Server name
NAME=My Graal Server

// Server description
DESCRIPTION=Welcome to my server!

// Maximum players
MAXPLAYERS=32

// Server port
PORT=14902

// List server communication
LISTSERVER=graalonline.net
LISTSERVERNAME=MyServer

// Enable accounts
PLAYERACCOUNTS=true
```

See [Server Options](#server-options) below for all available settings.

#### 3. Run the Server

```bash
# From the project root
./target/release/gserver

# Or using the run script
./run_server.sh
```

The server will start on port 14902 (default). Connect with your Graal client using:
- Server IP: `127.0.0.1` (for local testing)
- Server Port: `14902`

## Server Options

### serveroptions.txt Settings

| Option | Description | Default |
|--------|-------------|---------|
| `NAME` | Server display name | `GServer` |
| `DESCRIPTION` | Server description | (empty) |
| `LANGUAGE` | Server language | `English` |
| `MAXPLAYERS` | Maximum concurrent players | `128` |
| `PORT` | Server listening port | `14902` |
| `LOCALONLY` | Only allow localhost connections | `false` |
| `PLAYERACCOUNTS` | Require player accounts | `true` |
| `NICKREG` | Require nickname registration | `false` |
| `ENABLESPAR` | Enable sparring/PvP | `true` |
| `ENABLEPK` | Enable player killing | `true` |
| `ENABLEBOMBS` | Enable bombs | `true` |
| `ENABLEHORSES` | Enable horse riding | `true` |
| `NPCSERVER` | NPC server address | `127.0.0.1:14903` |
| `ENABLEGMAP` | Enable gmap support | `false` |

### Folder Rights (foldersconfig.txt)

Configure which folders different user levels can access:

```text
// Format: permission_level folder_pattern
// Permissions: r (read), w (write), - (none)

// Admin can access everything
rw *

// Trusted users can read/write accounts
rw accounts/*
rw weapons/*
rw worlds/*

// Regular users can read some folders
r config/*
r documents/*
```

## Directory Structure

```
gserver-rs/
├── crates/                 # Rust crates
│   ├── gserver-core/       # Core types and error handling
│   ├── gserver-protocol/   # Protocol implementation
│   ├── gserver-accounts/   # Account management
│   ├── gserver-network/    # Networking layer
│   ├── gserver-scripting/  # Scripting engines
│   └── gserver-server/     # Main server binary
├── servers/                # Server data files
│   └── default/            # Default server instance
│       ├── accounts/       # Player accounts
│       ├── config/         # Server configuration
│       ├── worlds/         # Level files
│       ├── weapons/        # Weapon scripts
│       └── ...
├── target/                 # Build output (generated)
├── Cargo.toml              # Workspace manifest
├── README.md               # This file
├── LICENSE                  # GPL v3
└── run_server.sh           # Server startup script
```

## Connecting with a Client

### GraalClient

1. Open GraalClient
2. Click "Add Server"
3. Enter:
   - **Server IP:** `127.0.0.1` (or your server's public IP)
   - **Server Port:** `14902` (or your configured port)
4. Click "Connect"
5. Login with your account name

### RC (Remote Control)

For administrative access, use an RC client or connect with:
```
Server: 127.0.0.1
Port: 14902
Account: your_admin_account
```

Ensure your account has admin rights set in `accounts/yourname.txt`:
```
LOCALRIGHTS=16777215
```

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p gserver-protocol
cargo test -p gserver-network

# Run tests with output
cargo test -- --nocapture
```

### Code Formatting

```bash
# Format code
cargo fmt

# Check formatting without making changes
cargo fmt --check
```

### Linting

```bash
# Run clippy
cargo clippy

# Fix clippy warnings automatically
cargo clippy --fix
```

## Architecture

### Crate Organization

- **gserver-core**: Core data types (PlayerID, Result, GServerError)
- **gserver-protocol**: Binary protocol, packet types, codecs
- **gserver-accounts**: Account loading and management
- **gserver-network**: TCP connections, packet handling
- **gserver-scripting**: GS1/GS2 scripting engines
- **gserver-server**: Main server binary

### Protocol Layers

1. **Codecs Layer** - Binary encoding/decoding (GChar, GInt, etc.)
2. **Packet Types** - 160+ packet type definitions
3. **Compression** - Zlib and BZ2 compression
4. **Encryption** - GEN_1 through GEN_5 encryption

### Threading Model

- **Tokio** async runtime for I/O
- **One task per connection** (~8KB stack per connection)
- **Lock-free** shared state where possible (DashMap)
- **Mutex-protected** connection state

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- 🎯 **NPC AI** - Advanced NPC behaviors
- 🎯 **Weapon Scripts** - Weapon system enhancements
- 🎯 **GS2 Scripting** - Object-oriented scripting
- 🎯 **Testing** - Integration tests, fuzzing
- 🎯 **Documentation** - API docs, examples

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.

This is a derivative work based on [GServer-v2](https://github.com/xtjoeytx/GServer-v2) by xtjoeytx, used under the GPL v3.0.

## Acknowledgments

- **xtjoeytx** - Original GServer-v2 C++ implementation
- **Graal Online** - The game and protocol this server implements
- **Rust Community** - Excellent tools and libraries

## Disclaimer

This project is not affiliated with, endorsed by, or connected to Graal Online in any way. This is a community-driven reimplementation for educational purposes.

---

**Made with ❤️ by vinvicta and contributors**
