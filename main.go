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
)

// 添加认证中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != validUsername || password != validPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "未授权访问", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		fmt.Fprintf(os.Stderr, "  -watch string\n")
		fmt.Fprintf(os.Stderr, "        监听目录路径，用于监控文件变化\n")
		fmt.Fprintf(os.Stderr, "  -port string\n")
		fmt.Fprintf(os.Stderr, "        HTTP 服务端口 (默认 \"8333\")\n")
		fmt.Fprintf(os.Stderr, "  -pwd string\n")
		fmt.Fprintf(os.Stderr, "        设置访问密码 (默认 \"password123\")\n")
		fmt.Fprintf(os.Stderr, "  -exclude string\n")
		fmt.Fprintf(os.Stderr, "        排除的文件支持正则，多个模式用逗号分隔 (例如: *.tmp,*.log)\n")
		fmt.Fprintf(os.Stderr, "  -h\n")
		fmt.Fprintf(os.Stderr, "        显示帮助信息\n\n")
		fmt.Fprintf(os.Stderr, "示例:\n")
		fmt.Fprintf(os.Stderr, "  %s -watch /path/to/watch -exclude \"*.tmp,*.log\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -port 8080\n", os.Args[0])
	}

	// 添加命令行参数
	watchPath := flag.String("watch", "", "监听目录路径")
	port := flag.String("port", "8333", "HTTP 服务端口")
	password := flag.String("pwd", "password123", "访问密码")
	excludeFlag := flag.String("exclude", "", "排除的文件模式，多个模式用逗号分隔 (例如: *.tmp,*.log)")
	flag.Parse()

	// 设置密码
	validPassword = *password

	// 处理排除模式
	if *excludeFlag != "" {
		excludePatterns = strings.Split(*excludeFlag, ",")
		for i, pattern := range excludePatterns {
			excludePatterns[i] = strings.TrimSpace(pattern)
		}
	}

	// 如果提供了 watch 参数，启动文件监听
	if *watchPath != "" {
		log.Printf("开始监听目录: %s", *watchPath)
		if err := startFileWatcher(*watchPath); err != nil {
			log.Fatalf("启动监听失败: %v", err)
		}
		// 阻塞主线程
		select {}
	} else {
		// 原有的 HTTP 服务逻辑
		http.HandleFunc("/api/upload", authMiddleware(handleUpload))
		http.HandleFunc("/api/deploy", authMiddleware(handleDeploy))
		http.HandleFunc("/api/hosts", authMiddleware(handleGetHosts))
		http.Handle("/", http.FileServer(http.Dir("static")))
		fmt.Printf("Server starting on :%s...\n", *port)
		http.ListenAndServe(":"+*port, nil)
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
	targetDir := "/home/autoupdater/class/"
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
	var requestData struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "无法解析请求数据", http.StatusBadRequest)
		return
	}

	// 检查是否提供了主机列表
	if len(requestData.Hosts) == 0 {
		http.Error(w, "未提供目标主机", http.StatusBadRequest)
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

	// 修改命令，添加 --limit 参数和 --forks=1 参数
	hostsString := strings.Join(requestData.Hosts, ",")
	cmd := exec.Command("ansible-playbook",
		"-i", "/etc/ansible/hosts",
		"--limit", hostsString,
		"--forks=1",
		"/home/ansible-playbook/win_auto_update_tomcat.yml")

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

	// 读取 hosts 文件
	hosts, err := os.ReadFile("/etc/ansible/hosts")
	if err != nil {
		http.Error(w, "无法读取 hosts 文件", http.StatusInternalServerError)
		return
	}

	// 解析文件内容，提取 Windows 主机
	var windowsHosts []string
	inWindowsGroup := false
	scanner := bufio.NewScanner(strings.NewReader(string(hosts)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// 检查是否进入 Windows 主机组
		if strings.HasPrefix(line, "[") && strings.Contains(strings.ToLower(line), "windows") {
			inWindowsGroup = true
			continue
		} else if strings.HasPrefix(line, "[") {
			inWindowsGroup = false
			continue
		}

		// 如果在 Windows 组中且行不为空，添加主机
		if inWindowsGroup && line != "" && !strings.HasPrefix(line, "#") {
			// 提取主机名（如果有其他配置，只取第一部分）
			host := strings.Split(line, " ")[0]
			// 只有当是有效的IP地址时才添加
			if isValidIPAddress(host) {
				windowsHosts = append(windowsHosts, host)
			}
		}
	}

	// 返回 JSON 响应
	response := map[string]interface{}{
		"hosts": windowsHosts,
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
