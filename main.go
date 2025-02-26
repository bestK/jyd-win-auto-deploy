package main

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bestk/jyd-win-auto-deploy/config"
	"github.com/fsnotify/fsnotify"
)

// 添加文件状态结构
type FileState struct {
	ModTime   time.Time
	IsDeleted bool
	ChangedAt time.Time
}

// 添加认证凭据
var (
	validUsername = "admin"
	validPassword = "password123" // 默认密码

	// 根据操作系统设置默认目标目录
	defaultTargetDir = func() string {
		if runtime.GOOS == "windows" {
			// Windows 下使用当前目录下的 autoupdater 文件夹
			return "./autoupdater/"
		}
		return "./autoupdater/" // 修改为当前目录
	}()

	fileStates      = make(map[string]*FileState)
	stateMutex      sync.RWMutex
	excludePatterns []string // 添加排除模式列表

	appConfig *config.Config
)

// 添加认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != validUsername || password != validPassword {
			log.Printf("登录失败，用户名: %s，密码: %s", username, password) // 添加调试日志
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "未授权访问", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type DeployRequest struct {
	Hosts     []string `json:"hosts"`
	HostGroup string   `json:"host_group"` // 添加主机组字段
}

func main() {
	// 加载配置文件
	var err error
	appConfig, err = config.LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	// 使用配置文件中的值
	validPassword = appConfig.Autoupdater.Server.Password
	port := appConfig.Autoupdater.Server.Port

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		fmt.Fprintf(os.Stderr, "  -mode string\n")
		fmt.Fprintf(os.Stderr, "        启动模式，可选值: watch, server (默认 \"server\")\n")
		fmt.Fprintf(os.Stderr, "  -watch string\n")
		fmt.Fprintf(os.Stderr, "        监听目录路径，用于监控文件变化\n")
		fmt.Fprintf(os.Stderr, "  -port string\n")
		fmt.Fprintf(os.Stderr, "        HTTP 服务端口 (默认 \"8333\")\n")
		fmt.Fprintf(os.Stderr, "  -exclude string\n")
		fmt.Fprintf(os.Stderr, "        排除的文件支持正则，多个模式用逗号分隔 (例如: *.tmp,*.log)\n")
		fmt.Fprintf(os.Stderr, "  -h\n")
		fmt.Fprintf(os.Stderr, "        显示帮助信息\n\n")
		fmt.Fprintf(os.Stderr, "示例:\n")
		fmt.Fprintf(os.Stderr, "  %s -watch /path/to/watch -exclude \"*.tmp,*.log\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -port 8080\n", os.Args[0])
	}

	// 添加命令行参数
	watchPath := flag.String("watch", appConfig.Autoupdater.Watch.Path, "监听目录路径")
	mode := flag.String("mode", appConfig.Autoupdater.Mode, "启动模式")
	exclude := flag.String("exclude", appConfig.Autoupdater.Watch.Exclude, "排除的文件支持正则，多个模式用逗号分隔 (例如: *.tmp,*.log)")

	flag.Parse()

	if *mode == "watch" {
		if *watchPath == "" {
			log.Fatalf("监听目录路径不能为空")
		}

		excludePatterns = strings.Split(*exclude, ",")
		log.Printf("开始监听目录: %s", *watchPath)
		if err := startFileWatcher(*watchPath); err != nil {
			log.Fatalf("启动监听失败: %v", err)
		}
		// 阻塞主线程
		select {}
	} else if *mode == "server" {

		http.HandleFunc("/api/upload", authMiddleware(handleUpload))
		http.HandleFunc("/api/deploy", authMiddleware(handleDeploy))
		http.HandleFunc("/api/hosts", authMiddleware(handleGetHosts))
		http.Handle("/", http.FileServer(http.Dir("static")))
		fmt.Printf("Server starting on :%s...\npassword:%s", port, validPassword)
		http.ListenAndServe(":"+port, nil)
	} else {
		log.Fatalf("无效的启动模式: %s", *mode)
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许 POST 请求", http.StatusMethodNotAllowed)
		return
	}

	// 获取上传的文件
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "文件上传失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 确保目标目录存在
	targetDir := appConfig.Autoupdater.Server.UploadPath
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		http.Error(w, "创建目录失败", http.StatusInternalServerError)
		return
	}

	// 删除目标目录中的所有文件
	if err := removeContents(targetDir); err != nil {
		http.Error(w, "清理目录失败", http.StatusInternalServerError)
		return
	}

	// 保存上传的文件
	zipPath := filepath.Join(targetDir, header.Filename)
	dst, err := os.Create(zipPath)
	if err != nil {
		http.Error(w, "创建文件失败", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "保存文件失败", http.StatusInternalServerError)
		return
	}

	// 解压文件
	cmd := exec.Command("unzip", zipPath, "-d", targetDir)
	if err := cmd.Run(); err != nil {
		http.Error(w, "解压失败", http.StatusInternalServerError)
		return
	}

	// 删除压缩包
	if err := os.Remove(zipPath); err != nil {
		http.Error(w, "删除压缩包失败", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "文件上传并解压成功")
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只允许 POST 请求", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求体中的 JSON 数据
	var requestData DeployRequest
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "无法解析请求数据", http.StatusBadRequest)
		return
	}

	// 设置响应头，支持流式输出
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	c := appConfig.Autoupdater.Server

	// 构建 ansible-playbook 命令
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-i", c.Ansible.HostConfig.Path)

	if requestData.HostGroup != "" {
		// 检查主机组是否在允许列表中
		groupAllowed := false
		for _, allowedGroup := range c.Ansible.HostConfig.IncludeGroup {
			if requestData.HostGroup == allowedGroup {
				groupAllowed = true
				break
			}
		}
		if !groupAllowed {
			http.Error(w, "不允许的主机组", http.StatusBadRequest)
			return
		}
		cmdArgs = append(cmdArgs, "--limit", requestData.HostGroup)
	} else if len(requestData.Hosts) > 0 {
		cmdArgs = append(cmdArgs, "--limit", strings.Join(requestData.Hosts, ","))
	}

	cmdArgs = append(cmdArgs, fmt.Sprintf("--forks=%d", c.Ansible.PlaybookConfig.Forks))
	cmdArgs = append(cmdArgs, c.Ansible.PlaybookConfig.Path)

	cmd := exec.Command("ansible-playbook", cmdArgs...)

	// 获取命令的标准输出和标准错误管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, "无法创建输出管道", http.StatusInternalServerError)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		http.Error(w, "无法创建错误管道", http.StatusInternalServerError)
		return
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		http.Error(w, "命令启动失败", http.StatusInternalServerError)
		return
	}

	// 创建一个通道来接收输出完成的信号
	done := make(chan bool)

	// 处理标准输出
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fmt.Fprintf(w, "data: %s\n\n", scanner.Text())
			flusher.Flush()
		}
	}()

	// 处理标准错误
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Fprintf(w, "data: %s\n\n", scanner.Text())
			flusher.Flush()
		}
		done <- true
	}()

	// 等待命令完成
	<-done
	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(w, "data: 命令执行失败: %v\n\n", err)
		flusher.Flush()
		return
	}

	fmt.Fprintf(w, "data: 部署完成\n\n")
	flusher.Flush()
}

func removeContents(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return err
	}
	for _, file := range files {
		err = os.RemoveAll(file)
		if err != nil {
			return err
		}
	}
	return nil
}

// 添加IP地址验证函数
func isValidIPAddress(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		num := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
			num = num*10 + int(ch-'0')
		}
		if num > 255 {
			return false
		}
	}
	return true
}

func handleGetHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "只允许 GET 请求", http.StatusMethodNotAllowed)
		return
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	c := appConfig.Autoupdater.Server

	// 读取 hosts 文件
	hosts, err := os.ReadFile(c.Ansible.HostConfig.Path)
	if err != nil {
		http.Error(w, "无法读取 hosts 文件", http.StatusInternalServerError)
		return
	}

	var prodHosts []string
	var testHosts []string
	currentGroupEnv := ""
	scanner := bufio.NewScanner(strings.NewReader(string(hosts)))

	includeGroups := c.Ansible.HostConfig.IncludeGroup

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") {
			currentGroupEnv = ""
			// 检查是否匹配任何包含的组
			for _, group := range includeGroups {
				if strings.Contains(strings.ToLower(line), strings.ToLower(group)) {
					if strings.Contains(strings.ToLower(line), "prod") {
						currentGroupEnv = "prod"
					} else if strings.Contains(strings.ToLower(line), "test") {
						currentGroupEnv = "test"
					}
					break
				}
			}
			continue
		}

		if currentGroupEnv != "" && line != "" && !strings.HasPrefix(line, "#") {
			// 提取主机名（如果有其他配置，只取第一部分）
			host := strings.Split(line, " ")[0]
			// 只有当是有效的IP地址时才添加
			if isValidIPAddress(host) {
				if currentGroupEnv == "prod" {
					prodHosts = append(prodHosts, host)
				} else if currentGroupEnv == "test" {
					testHosts = append(testHosts, host)
				}
			}
		}
	}

	// 返回 JSON 响应
	response := map[string]interface{}{
		"prod": prodHosts,
		"test": testHosts,
	}

	json.NewEncoder(w).Encode(response)
}

func startFileWatcher(path string) error {
	path = filepath.Clean(path)

	// 初始化当前目录下所有文件的状态
	if err := initializeFileStates(path); err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	// 启动一个单独的 goroutine 来处理用户输入
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			log.Println("输入 'zip' 创建变更文件的压缩包:")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))

			if input == "zip" {
				if err := createZipFromChangedFiles(path); err != nil {
					log.Printf("创建压缩包失败: %v", err)
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) != 0 {
					handleFileChange(event, path)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("监听错误: %v", err)
			}
		}
	}()

	// 递归添加目录到监听列表
	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := watcher.Add(path); err != nil {
				log.Printf("添加目录到监听列表失败 %s: %v", path, err)
				return err
			}
			log.Printf("添加目录到监听列表: %s", path)
		}
		return nil
	})

	return err
}

func initializeFileStates(root string) error {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileStates[path] = &FileState{
				ModTime:   info.ModTime(),
				IsDeleted: false,
			}
		}
		return nil
	})
}

// 添加文件匹配检查函数
func shouldExcludeFile(path string) bool {
	// 获取文件名
	fileName := filepath.Base(path)

	for _, pattern := range excludePatterns {
		matched, err := filepath.Match(pattern, fileName)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func handleFileChange(event fsnotify.Event, root string) {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	path := filepath.Clean(event.Name)

	// 检查文件是否应该被排除
	if shouldExcludeFile(path) {
		return
	}

	// 处理文件删除
	if event.Op&fsnotify.Remove != 0 {
		if state, exists := fileStates[path]; exists {
			state.IsDeleted = true
			state.ChangedAt = time.Now()
		}
		return
	}

	// 处理文件创建或修改
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("获取文件信息失败 %s: %v", path, err)
		return
	}

	if info.IsDir() {
		return
	}

	state, exists := fileStates[path]
	if !exists {
		// 新文件
		fileStates[path] = &FileState{
			ModTime:   info.ModTime(),
			IsDeleted: false,
			ChangedAt: time.Now(),
		}
	} else if state.ModTime != info.ModTime() {
		// 文件被修改
		state.ModTime = info.ModTime()
		state.IsDeleted = false
		state.ChangedAt = time.Now()
	}
}

func createZipFromChangedFiles(root string) error {
	stateMutex.RLock()
	defer stateMutex.RUnlock()

	// 检查是否有变化的文件
	hasChanges := false
	for _, state := range fileStates {
		if !state.ChangedAt.IsZero() {
			hasChanges = true
			break
		}
	}

	if !hasChanges {
		log.Printf("没有检测到文件变化，跳过创建压缩包")
		return nil
	}

	// 使用当前目录下的 autoupdater 文件夹
	targetDir := filepath.Clean(defaultTargetDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %v", err)
	}

	zipPath := filepath.Join(targetDir, "auto_updated.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("创建压缩文件失败: %v", err)
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	changedFiles := 0
	for path, state := range fileStates {
		if state.ChangedAt.IsZero() {
			continue // 跳过未变化的文件
		}

		// 获取相对于监听目录的路径
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			log.Printf("获取相对路径失败 %s: %v", path, err)
			continue
		}
		// 统一使用正斜杠作为路径分隔符
		relPath = filepath.ToSlash(relPath)

		if state.IsDeleted {
			log.Printf("文件已删除: %s", relPath)
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			log.Printf("获取文件信息失败 %s: %v", path, err)
			continue
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			log.Printf("创建文件头失败 %s: %v", path, err)
			continue
		}

		// 设置压缩包中的文件路径为相对路径
		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := archive.CreateHeader(header)
		if err != nil {
			log.Printf("创建压缩文件记录失败 %s: %v", path, err)
			continue
		}

		file, err := os.Open(path)
		if err != nil {
			log.Printf("打开文件失败 %s: %v", path, err)
			continue
		}

		_, err = io.Copy(writer, file)
		file.Close()
		if err != nil {
			log.Printf("复制文件内容失败 %s: %v", path, err)
			continue
		}

		changedFiles++
		log.Printf("添加变化的文件到压缩包: %s", relPath)

		// 重置文件状态
		state.ChangedAt = time.Time{}
	}

	log.Printf("压缩包创建完成，共包含 %d 个变化的文件", changedFiles)
	return nil
}
