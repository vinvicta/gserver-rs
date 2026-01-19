# Getting Started with GServer-RS

This guide will help you get GServer-RS up and running on your system.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Initial Configuration](#initial-configuration)
- [Running the Server](#running-the-server)
- [Connecting with a Client](#connecting-with-a-client)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required

- **Rust** 1.70 or later
  - Download from: https://www.rust-lang.org/tools/install
  - Or install via: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

- **Git** (for cloning the repository)
  - Linux: `sudo apt install git` or `sudo yum install git`
  - macOS: `brew install git`
  - Windows: https://git-scm.com/downloads

### Optional (Recommended)

- **GraalClient** - For testing your server
- **RC Client** - For remote administration

## Installation

### Option 1: Download Pre-built Binary

1. Go to the [Releases](https://github.com/vinvicta/gserver-rs/releases) page
2. Download the latest binary for your platform
3. Extract the archive
4. Run the server: `./gserver`

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/vinvicta/gserver-rs.git
cd gserver-rs

# Build in release mode (optimized binary)
cargo build --release

# The binary will be at: target/release/gserver
```

## Initial Configuration

### 1. Account Setup

The server comes with a placeholder account file that you need to rename:

```bash
cd servers/default/accounts
mv YOURACCOUNT.txt yourname.txt
```

Open `yourname.txt` in a text editor and configure your account:

```text
GRACC001
NAME YourAccountName
NICK YourNickname
LEVEL onlinestartlocal.nw
X 480
Y 352
MAXHP 3
HP 6
ANI idle
SPRITE 2
GRALATS 0
ARROWS 0
BOMBS 0
GLOVEPOWER 0
SWORDPOWER 1
SHIELDPOWER 1
BOMBPOWER 1
BOWPOWER 1
BOW
HEAD
BODY
SWORD
SHIELD
COLORS 2,0,10,4,18
STATUS 20
MP 0
AP 0
APCOUNTER 0
ONSECS 0
IP
LANGUAGE English
KILLS 0
DEATHS 0
RATING 1500.0
DEVIATION 350.0
LASTSPARTIME 0
BANNED 0
BANREASON
BANLENGTH
COMMENTS
EMAIL
LOCALRIGHTS 0
IPRANGE
LOADONLY 0
WEAPON bomb
FOLDERRIGHT rw accounts/*
LASTFOLDER
GANI1
GANI2
GANI3
GANI4
GANI5
GANI6
GANI7
GANI8
GANI9
GANI10
GANI11
GANI12
GANI13
GANI14
GANI15
GANI16
GANI17
GANI18
GANI19
GANI20
GANI21
GANI22
GANI23
GANI24
GANI25
GANI26
GANI27
GANI28
GANI29
GANI30
```

#### Setting Admin Rights

To make yourself an admin, set `LOCALRIGHTS` to a high value:

```text
LOCALRIGHTS=16777215
```

This gives you all admin permissions including:
- Warping to levels/players
- Disconnecting players
- Setting player attributes
- Using RC (Remote Control)

### 2. Server Options

Edit `servers/default/config/serveroptions.txt`:

```text
// Basic server info
NAME=My Graal Server
DESCRIPTION=Welcome to my server!
LANGUAGE=English

// Connection settings
MAXPLAYERS=32
PORT=14902
LOCALONLY=false

// List server
LISTSERVER=graalonline.net
LISTSERVERNAME=MyServer

// Account settings
PLAYERACCOUNTS=true
NICKREG=false

// Gameplay settings
ENABLESPAR=true
ENABLEPK=true
ENABLEBOMBS=true
ENABLEHORSES=true
ENABLEPUSHBACK=true

// NPC Server (optional)
NPCSERVER=127.0.0.1:14903
NPCSERVERENABLED=false

// GMap support
ENABLEGMAP=false
KEEPALLLEVELSLOADED=false

// Rights
ENABLEFOLDERRIGHTS=true
DEFAULTRIGHTS=0
LEVELRIGHTS=0

// Weapons
ALLOWDROPWEAPONS=true
UNLIMITEDWEAPONS=false

// Other
ALLOWNICKCHANGE=true
ALLOWMULTIPLECONNECTIONS=true
KEEPBODIES=false
TEAMDAMAGE=false
SINGLEPLAYER=false
```

> For complete configuration details, see the [GServer-v2 codebase](https://github.com/xtjoeytx/GServer-v2). The `foldersconfig.txt` file defines folder structure mappings - refer to the C++ implementation for the correct format and usage.

## Running the Server

### From the Project Root

```bash
# If you built from source
./target/release/gserver

# Or use the provided script
./run_server.sh
```

### Specifying Server Directory

The server looks for the `servers/default` directory by default. You can also specify a custom server directory:

```bash
./target/release/gserver --server-dir /path/to/servers
```

### Server Output

When the server starts, you should see output like:

```
[2025-01-18T19:00:00Z INFO  GServer] GServer listening on 0.0.0.0:14902
[2025-01-18T19:00:00Z INFO  GServer] Configuration: max_connections=32, compression=true
[2025-01-18T19:00:00Z INFO  GServer] GServer starting main loop
```

## Connecting with a Client

### GraalClient

1. Open GraalClient
2. Click **"Add Server"** or go to **File → Server List → Add**
3. Enter the following:
   - **Server Name:** My Server (or whatever you want)
   - **Server IP:** `127.0.0.1` (for local) or your public IP
   - **Server Port:** `14902`
4. Click **"Connect"**
5. Enter your account name and password

### Direct Connection

In GraalClient, go to **File → Connect** and enter:
- **IP:** `127.0.0.1`
- **Port:** `14902`

## Remote Control (RC)

For server administration, you can connect via RC:

1. Use an RC client or connect with admin rights
2. The RC protocol runs on the same port as the game server
3. Your account must have `LOCALRIGHTS` set to a non-zero value

### Common RC Commands

```
/getserveroptions    - Get current server options
/setserveroptions    - Set server options
/getplayerprops       - Get player properties
/setplayerprops       - Set player properties
/disconnectplayer     - Disconnect a player
/warpto               - Warp to a level
/accountlistget       - List all accounts
/filebrowse           - Browse server files
```

## Troubleshooting

### Port Already in Use

If you get an error like "Address already in use", another process is using port 14902:

```bash
# Check what's using the port
sudo lsof -i :14902  # macOS/Linux
netstat -ano | findstr :14902  # Windows

# Either stop the other process or change the port in serveroptions.txt
PORT=14903
```

### Connection Refused

If clients can't connect:

1. Check that the server is running
2. Check the firewall:
   ```bash
   # Linux
   sudo ufw allow 14902/tcp

   # macOS
   # System Preferences → Security & Privacy → Firewall
   ```
3. For remote connections, ensure `LOCALONLY=false` in serveroptions.txt

### Account Not Found

If you get "Account not found":

1. Check that your account file exists in `servers/default/accounts/`
2. The filename should match your account name exactly
3. The file must start with `GRACC001`

### Level Not Found

If you get "Level not found":

1. Check that the level file exists in `servers/default/world/`
2. The file extension should be `.nw`
3. Check the `LEVEL` field in your account file

## Next Steps

- Read the [README.md](README.md) for more information about the project
- Check [CONTRIBUTING.md](CONTRIBUTING.md) if you want to contribute
- Explore the `servers/default/world/` folder to add your own levels
- Create custom weapons in `servers/default/weapons/`

## Getting Help

- **Issues:** https://github.com/vinvicta/gserver-rs/issues
- **Discussions:** https://github.com/vinvicta/gserver-rs/discussions
- **Credits:** Based on [GServer-v2](https://github.com/xtjoeytx/GServer-v2)

---

Happy hosting!
