package main

import (
	"context"
	"embed"
	"io/fs"

	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
)

// 用户结构
type User struct {
	Password  string `json:"password"`             // 用户密码
	MFASecret string `json:"mfa_secret,omitempty"` // MFA密钥
	MFAStatus string `json:"mfa_status,omitempty"` // MFA状态
}

// 配置结构
type Config struct {
	NginxPath string          `json:"nginx_path"` // Nginx配置文件路径
	Host      string          `json:"host"`       // 服务主机
	Port      int             `json:"port"`       // 服务端口
	JWTSecret string          `json:"jwt_secret"` // JWT密钥
	Users     map[string]User `json:"users"`      // 存储用户信息和MFA密钥
}

var config Config                 // 配置信息
var users = make(map[string]User) // 存储用户信息和MFA密钥
var jwtSecret []byte              // JWT密钥

//go:embed frontend/*
var frontendFS embed.FS // 嵌入前端文件

// 加载配置文件
func loadConfig() error {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	// 确保JWT密钥存在
	if config.JWTSecret == "" {
		config.JWTSecret = "default-secret-key-change-this-in-production"
	}
	// 确保用户映射存在
	if config.Users == nil {
		config.Users = make(map[string]User)
	}
	// 加载用户数据到全局变量
	users = config.Users
	jwtSecret = []byte(config.JWTSecret)
	return nil
}

// 保存配置文件
func saveConfig() error {
	// 先将当前用户数据保存到配置中
	config.Users = users
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("config.json", data, 0644)
}

// 定义上下文键类型和用户名键
type ctxKey string

const usernameKey ctxKey = "username"

// 认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 认证信息
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "认证信息缺失"})
			return
		}

		// 认证格式
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "认证格式错误"})
			return
		}

		// 解析和验证JWT令牌
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(parts[1], claims, func(token *jwt.Token) (interface{}, error) {
			// 验证签名算法
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "认证失败"})
			return
		}

		// 令牌有效，将用户信息添加到请求上下文
		username := claims.Subject
		ctx := context.WithValue(r.Context(), usernameKey, username)
		next(w, r.WithContext(ctx))
	}
}

// 执行Nginx命令
func executeNginxCommand(args ...string) (string, error) {
	var nginxExe string
	if runtime.GOOS == "windows" {
		nginxExe = filepath.Join(config.NginxPath, "nginx.exe")
	} else {
		nginxExe = filepath.Join(config.NginxPath, "nginx")
	}

	// 检查nginx.exe是否存在
	if _, err := os.Stat(nginxExe); os.IsNotExist(err) {
		return "", fmt.Errorf("nginx.exe not found at %s", nginxExe)
	}

	// Ensure logs directory exists
	logsDir := filepath.Join(config.NginxPath, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create logs directory: %v", err)
	}

	var cmd *exec.Cmd
	var output []byte
	var err error

	// For start command (no arguments), use Windows start with output redirection
	if len(args) == 0 {
		// Create temporary log file
		logFile := filepath.Join(logsDir, "nginx_start.log")
		defer os.Remove(logFile) // Clean up log file when done

		// Ensure temp directory exists
		tempDir := filepath.Join(config.NginxPath, "temp")
		err = os.MkdirAll(tempDir, 0755)
		if err != nil {
			return "", fmt.Errorf("failed to create temp directory: %v", err)
		}

		// Start Nginx with explicit prefix path and config path, redirect output
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/c", "start", "", "/b", nginxExe, "-p", config.NginxPath, "-c", "conf/nginx.conf", ">", logFile, "2>&1")
		} else {
			// For Linux, start Nginx in background with output redirection
			cmd = exec.Command("sh", "-c", fmt.Sprintf("nohup %s -p %q -c conf/nginx.conf > %q 2>&1 &", nginxExe, config.NginxPath, logFile))
		}
		cmd.Dir = config.NginxPath // Set working directory for the start command
		err = cmd.Run()

		// Wait for Nginx to initialize and write to log
		time.Sleep(1 * time.Second)

		// Read log file contents
		output, _ = os.ReadFile(logFile)
	} else {
		// For other commands, run normally
		cmd = exec.Command(nginxExe, args...)
		cmd.Dir = config.NginxPath // Set working directory to Nginx installation path
		output, err = cmd.CombinedOutput()
	}

	return string(output), err
}

// API处理函数 - 获取Nginx状态
func getStatus(w http.ResponseWriter, r *http.Request) {
	// 在Windows上检查Nginx进程是否运行
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist", "/FI", "IMAGENAME eq nginx.exe")
	} else {
		cmd = exec.Command("pgrep", "nginx")
	}
	output, err := cmd.CombinedOutput()

	status := "stopped"
	if err == nil {
		if runtime.GOOS == "windows" && strings.Contains(string(output), "nginx.exe") {
			status = "running"
		} else if runtime.GOOS != "windows" {
			status = "running"
		}
	} else if runtime.GOOS != "windows" && strings.Contains(err.Error(), "exit status 1") {
		// pgrep returns exit status 1 when no processes found
		status = "stopped"
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

// API处理函数 - 启动Nginx
func startNginx(w http.ResponseWriter, r *http.Request) {
	// First test Nginx configuration
	configTestOutput, err := executeNginxCommand("-t")
	if err != nil {
		errorMsg := fmt.Sprintf("Nginx configuration test failed: %v\nNginx Path: %s\nOutput: %s", err, config.NginxPath, configTestOutput)
		fmt.Println(errorMsg) // Log to console
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// Then start Nginx
	output, err := executeNginxCommand()
	if err != nil {
		errorMsg := fmt.Sprintf("Error starting Nginx: %v\nNginx Path: %s\nOutput: %s", err, config.NginxPath, output)
		fmt.Println(errorMsg) // Log to console
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// Verify pid file was created
	pidPath := filepath.Join(config.NginxPath, "logs", "nginx.pid")
	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		errorMsg := fmt.Sprintf("Nginx started but pid file not found at %s\nPlease check Nginx logs for details.", pidPath)
		fmt.Println(errorMsg)
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":             "started",
		"config_test_output": configTestOutput,
		"output":             output,
	})
}

// API处理函数 - 停止Nginx
func stopNginx(w http.ResponseWriter, r *http.Request) {
	// First try the standard stop command
	output, err := executeNginxCommand("-s", "stop")

	// If standard stop fails, check if we need to force stop
	if err != nil {
		var statusCmd *exec.Cmd
		if runtime.GOOS == "windows" {
			statusCmd = exec.Command("tasklist", "/FI", "IMAGENAME eq nginx.exe")
		} else {
			statusCmd = exec.Command("pgrep", "nginx")
		}
		statusOutput, _ := statusCmd.CombinedOutput()

		isRunning := false
		if runtime.GOOS == "windows" {
			isRunning = strings.Contains(string(statusOutput), "nginx.exe")
		} else {
			// pgrep returns exit code 0 if process found
			isRunning = statusCmd.Run() == nil
		}

		if isRunning {
			var killCmd *exec.Cmd
			if runtime.GOOS == "windows" {
				killCmd = exec.Command("taskkill", "/F", "/IM", "nginx.exe")
			} else {
				killCmd = exec.Command("pkill", "nginx")
			}
			killOutput, killErr := killCmd.CombinedOutput()

			if killErr != nil {
				output = fmt.Sprintf("Standard stop failed: %s\nForce stop failed: %s", output, string(killOutput))
			} else {
				output = fmt.Sprintf("Standard stop failed: %s\nForce stop succeeded: %s", output, string(killOutput))
				// Remove pid file since we killed the process
				pidPath := filepath.Join(config.NginxPath, "logs", "nginx.pid")
				os.Remove(pidPath)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped", "output": output})
}

// API处理函数 - 重新加载Nginx配置
func reloadNginx(w http.ResponseWriter, r *http.Request) {
	// Check if Nginx is running first
	var statusCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		statusCmd = exec.Command("tasklist", "/FI", "IMAGENAME eq nginx.exe")
	} else {
		statusCmd = exec.Command("pgrep", "nginx")
	}
	statusOutput, _ := statusCmd.CombinedOutput()

	isRunning := false
	if runtime.GOOS == "windows" {
		isRunning = strings.Contains(string(statusOutput), "nginx.exe")
	} else {
		// pgrep returns exit code 0 if process found
		isRunning = statusCmd.Run() == nil
	}

	if !isRunning {
		errorMsg := "Cannot reload Nginx: Nginx is not running"
		fmt.Println(errorMsg) // Log to console
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// Check if pid file exists
	pidPath := filepath.Join(config.NginxPath, "logs", "nginx.pid")
	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		errorMsg := fmt.Sprintf("Nginx is running but pid file not found at %s\nPlease restart Nginx instead of reloading.", pidPath)
		fmt.Println(errorMsg) // Log to console
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// Test configuration before reloading
	configTestOutput, err := executeNginxCommand("-t")
	if err != nil {
		errorMsg := fmt.Sprintf("Nginx configuration test failed: %v\nNginx Path: %s\nOutput: %s", err, config.NginxPath, configTestOutput)
		fmt.Println(errorMsg) // Log to console
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	// Then reload Nginx
	output, err := executeNginxCommand("-s", "reload")
	if err != nil {
		errorMsg := fmt.Sprintf("Error reloading Nginx: %v\nNginx Path: %s\nOutput: %s", err, config.NginxPath, output)
		fmt.Println(errorMsg) // Log to console
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":             "reloaded",
		"config_test_output": configTestOutput,
		"output":             output,
	})
}

// API处理函数 - 更新Nginx路径配置
func updateNginxPath(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if path, ok := data["path"]; ok {
		config.NginxPath = path
		if err := saveConfig(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "path": config.NginxPath})
}

// API处理函数 - 获取Nginx配置
func getNginxConfig(w http.ResponseWriter, r *http.Request) {
	configPath := filepath.Join(config.NginxPath, "conf", "nginx.conf")

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		http.Error(w, "Config file not found", http.StatusNotFound)
		return
	}

	// 读取配置文件内容
	content, err := os.ReadFile(configPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading config file: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"config": string(content)})
}

// API处理函数 - 更新Nginx配置
func updateNginxConfig(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configPath := filepath.Join(config.NginxPath, "conf", "nginx.conf")

	if configContent, ok := data["config"]; ok {
		// 备份当前配置
		backupPath := configPath + ".bak"
		content, err := os.ReadFile(configPath)
		if err == nil {
			os.WriteFile(backupPath, content, 0644)
		}

		// 写入新配置
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// API处理函数 - 注册用户
func registerUser(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username, hasUsername := data["username"]
	password, hasPassword := data["password"]

	if !hasUsername || !hasPassword || username == "" || password == "" {
		http.Error(w, "用户名和密码是必需的", http.StatusBadRequest)
		return
	}

	// 检查是否已存在用户数据，如果有则禁止注册
	if len(users) > 0 {
		http.Error(w, "注册已关闭，系统已部署", http.StatusForbidden)
		return
	}

	// 检查用户是否已存在
	if _, exists := users[username]; exists {
		http.Error(w, "用户名已存在", http.StatusConflict)
		return
	}

	// 创建新用户
	users[username] = User{
		Password: password,
	}

	// 保存配置到文件
	if err := saveConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "User registered successfully"})
}

// API处理函数 - 生成MFA密钥
func generateMFASecret(w http.ResponseWriter, r *http.Request) {
	// 从上下文中获取用户名
	username := r.Context().Value(usernameKey).(string)

	// 检查用户是否存在
	user, exists := users[username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 检查用户是否已生成MFA密钥
	if user.MFASecret == "" {
		// 生成新的随机密钥
		key := make([]byte, 10)
		_, err := rand.Read(key)
		if err != nil {
			http.Error(w, "Failed to generate MFA secret", http.StatusInternalServerError)
			return
		}

		// 编码为base32格式
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)

		// 保存密钥到用户信息
		user.MFASecret = secret
		user.MFAStatus = "pending" // 设置为待验证状态
		users[username] = user
		if err := saveConfig(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// 构建OTP Auth URL
	otpauthURL := fmt.Sprintf("otpauth://totp/1Pixel:%s?secret=%s&issuer=1Pixel", username, user.MFASecret)

	// 返回密钥和URL
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"secret":      user.MFASecret,
		"otpauth_url": otpauthURL,
	})
}

// API处理函数 - 禁用MFA
func disableMFA(w http.ResponseWriter, r *http.Request) {
	// 从上下文中获取用户名
	username := r.Context().Value(usernameKey).(string)

	// 解析请求体
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 获取MFA代码
	code, ok := data["code"]
	if !ok || code == "" {
		http.Error(w, "MFA code is required", http.StatusBadRequest)
		return
	}

	// 检查用户是否存在
	user, exists := users[username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 检查用户MFA状态是否为enabled
	if user.MFAStatus != "enabled" {
		http.Error(w, "MFA is not enabled", http.StatusBadRequest)
		return
	}

	// 检查用户是否有MFA密钥
	secret := user.MFASecret
	if secret == "" {
		http.Error(w, "No MFA secret found for user", http.StatusUnauthorized)
		return
	}

	// 验证MFA代码
	valid := totp.Validate(code, secret)
	if !valid {
		http.Error(w, "Invalid MFA code", http.StatusUnauthorized)
		return
	}

	// 更新MFA状态为已禁用
	user.MFAStatus = "disabled"
	users[username] = user
	if err := saveConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 返回结果
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "success",
		"mfa_status": user.MFAStatus,
		"message":    "MFA disabled successfully",
	})
}

// API处理函数 - 获取MFA状态
func getMFAStatus(w http.ResponseWriter, r *http.Request) {
	// 从上下文中获取用户名
	username := r.Context().Value(usernameKey).(string)

	// 检查用户是否存在
	user, exists := users[username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 返回MFA状态
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"mfa_status": user.MFAStatus,
	})
}

// API处理函数 - 验证MFA代码
func verifyMFACode(w http.ResponseWriter, r *http.Request) {
	// 从上下文中获取用户名
	username := r.Context().Value(usernameKey).(string)

	// 解析请求体
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 获取MFA代码
	code, ok := data["code"]
	if !ok || code == "" {
		http.Error(w, "MFA code is required", http.StatusBadRequest)
		return
	}

	// 检查用户是否存在
	user, exists := users[username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 检查用户MFA状态是否为pending
	if user.MFAStatus != "pending" && user.MFAStatus != "disabled" {
		http.Error(w, "MFA secret can only be generated for pending or disabled status", http.StatusBadRequest)
		return
	}

	// 检查用户是否有MFA密钥
	secret := user.MFASecret
	if secret == "" {
		http.Error(w, "No MFA secret found for user", http.StatusUnauthorized)
		return
	}

	// 验证MFA代码
	valid := totp.Validate(code, secret)
	if !valid {
		http.Error(w, "Invalid MFA code", http.StatusUnauthorized)
		return
	}

	// 更新MFA状态为已启用
	user.MFAStatus = "enabled"
	users[username] = user
	if err := saveConfig(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 返回验证结果
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "success",
		"mfa_status": user.MFAStatus,
		"message":    "MFA code verified successfully",
	})
}

// API处理函数 - 登录用户
func loginUser(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username, hasUsername := data["username"]
	password, hasPassword := data["password"]
	mfaCode, hasMFACode := data["mfa_code"]

	if !hasUsername || !hasPassword || username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// 检查用户凭据
	user, exists := users[username]
	if !exists {
		http.Error(w, "用户不存在", http.StatusUnauthorized)
		return
	}
	if user.Password != password {
		http.Error(w, "密码不正确", http.StatusUnauthorized)
		return
	}

	// 检查MFA状态
	switch user.MFAStatus {
	case "":
		// MFA未启用，直接继续登录流程
	case "disabled":
		// MFA未启用，直接继续登录流程
	case "pending":
		// MFA待验证，不需要验证代码，但提示用户完成MFA设置
		http.Error(w, "MFA pending setup, please complete MFA setup first", http.StatusUnauthorized)
		return
	case "enabled":
		// MFA已启用，需要验证代码
		if !hasMFACode || mfaCode == "" {
			http.Error(w, "MFA code is required", http.StatusBadRequest)
			return
		}

		// 验证MFA代码
		valid := totp.Validate(mfaCode, user.MFASecret)
		if !valid {
			http.Error(w, "Invalid MFA code", http.StatusUnauthorized)
			return
		}
	default:
		// 未知状态，返回错误
		http.Error(w, "Invalid MFA status", http.StatusUnauthorized)
		return
	}

	// 创建JWT令牌
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"token":    tokenString,
		"username": username,
	})
}

// API处理函数 - 获取Nginx日志
func getNginxLogs(w http.ResponseWriter, r *http.Request) {
	logPath := filepath.Join(config.NginxPath, "logs", "access.log")

	// 检查日志文件是否存在
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		http.Error(w, "Log file not found", http.StatusNotFound)
		return
	}

	// 读取日志文件内容，获取最后10行
	content, err := os.ReadFile(logPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading log file: %v", err), http.StatusInternalServerError)
		return
	}

	// 分割成行并获取最后10行
	lines := strings.Split(string(content), "\n")
	startLine := len(lines) - 10
	if startLine < 0 {
		startLine = 0
	}
	recentLogs := lines[startLine:]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"logs": recentLogs})
}

func main() {
	// 加载配置，如不存在则创建默认配置
	if err := loadConfig(); err != nil {
		fmt.Println("Using default configuration")
		config = Config{
			NginxPath: "C:\\nginx-1.24.0", // 默认Nginx路径
			Host:      "0.0.0.0",          // 监听IP地址
			Port:      8080,               // 监听端口
		}
		saveConfig()
	}

	// 创建嵌入文件系统的子目录访问器
	staticFS, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		fmt.Printf("前端资源处理错误: %v\n", err)
		return
	}

	// 认证相关路由（不需要中间件）
	http.HandleFunc("/api/register", registerUser)
	http.HandleFunc("/api/login", loginUser)

	// 受保护的API路由
	http.HandleFunc("/api/status", authMiddleware(getStatus))
	http.HandleFunc("/api/start", authMiddleware(startNginx))
	http.HandleFunc("/api/stop", authMiddleware(stopNginx))
	http.HandleFunc("/api/reload", authMiddleware(reloadNginx))
	http.HandleFunc("/api/set-path", authMiddleware(updateNginxPath))
	http.HandleFunc("/api/logs", authMiddleware(getNginxLogs))
	http.HandleFunc("/api/config", authMiddleware(getNginxConfig))
	http.HandleFunc("/api/config/save", authMiddleware(updateNginxConfig))
	http.HandleFunc("/api/mfa/generate", authMiddleware(generateMFASecret))
	http.HandleFunc("/api/mfa/verify", authMiddleware(verifyMFACode))
	http.HandleFunc("/api/mfa-status", authMiddleware(getMFAStatus))
	http.HandleFunc("/api/mfa/disable", authMiddleware(disableMFA))

	// 处理所有静态资源请求
	http.Handle("/", http.FileServer(http.FS(staticFS)))

	// 启动服务器
	fmt.Printf("1Pixel server starting on port %d\n", config.Port)
	fmt.Printf("Nginx path configured as: %s\n", config.NginxPath)
	fmt.Printf("Visit http://%s:%d or http://localhost:%d to manage Nginx\n", config.Host, config.Port, config.Port)
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", config.Host, config.Port), nil)
	if err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}
