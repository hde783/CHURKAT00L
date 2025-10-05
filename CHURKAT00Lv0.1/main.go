package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var logo = `
 $$$$$$\  $$\   $$\ $$\   $$\ $$$$$$$\  $$\   $$\  $$$$$$\ $$$$$$$$\  $$$$$$\   $$$$$$\  $$\       
$$  __$$\ $$ |  $$ |$$ |  $$ |$$  __$$\ $$ | $$  |$$  __$$\\__$$  __|$$$ __$$\ $$$ __$$\ $$ |      
$$ /  \__|$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |$$  / $$ /  $$ |  $$ |   $$$$\ $$ |$$$$\ $$ |$$ |      
$$ |      $$$$$$$$ |$$ |  $$ |$$$$$$$  |$$$$$  /  $$$$$$$$ |  $$ |   $$\$$\$$ |$$\$$\$$ |$$ |      
$$ |      $$  __$$ |$$ |  $$ |$$  __$$< $$  $$<   $$  __$$ |  $$ |   $$ \$$$$ |$$ \$$$$ |$$ |      
$$ |  $$\ $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |\$$\  $$ |  $$ |  $$ |   $$ |\$$$ |$$ |\$$$ |$$ |      
\$$$$$$  |$$ |  $$ |\$$$$$$  |$$ |  $$ |$$ | \$$\ $$ |  $$ |  $$ |   \$$$$$$  /\$$$$$$  /$$$$$$$$\ 
 \______/ \__|  \__| \______/ \__|  \__|\__|  \__|\__|  \__|  \__|    \______/  \______/ \________|
`

// createResultDir is implemented in result_files.go

// Structs
type IP2IPInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Latitude    string `json:"latitude"`
	Longitude   string `json:"longitude"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	Abuse       string `json:"abuse_email"`
}

type WebhookData struct {
	Content  string `json:"content"`
	Username string `json:"username"`
}

type TelegramData struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

// Utility function to get user input
func input(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func ipLookup() {
	fmt.Println("Айпи INFO (Временно не работает)")
	fmt.Println("Функция на доработке, используй другие опции.")
	dir := createResultDir("ip")
	logFile := filepath.Join(dir, "log.txt")
	os.WriteFile(logFile, []byte("Временно не работает\n"), 0644)
	fmt.Println("Лог сохранён в:", logFile)
	input("\nНажми Enter чтобы рестарнуть...")
}

func webhookSender() {
	fmt.Println("ВЕБХУК СЕНДЕР")
	url := input("ВЕБХУК URL: ")
	message := input("СООБЩЕНИЕ: ")
	name := input("НАЗВАНИЕ ВЕБХУКА: ")

	spam := strings.ToLower(input("Отправить несколько сообщений? (y/n): "))

	data := WebhookData{Content: message, Username: name}
	payload, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Ошибка создания JSON:", err)
		return
	}

	dir := createResultDir("webhook")
	logFile := filepath.Join(dir, "log.txt")

	if spam == "y" {
		countStr := input("Сколько хочешь отправить: ")
		count, _ := strconv.Atoi(countStr)

		delayStr := input("Задержка между сообщениями (секунды): ")
		delay, _ := strconv.ParseFloat(delayStr, 64)

		for i := 1; i <= count; i++ {
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
			entry := fmt.Sprintf("[%d/%d] Отправлено: %s\n", i, count, message)
			if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent) {
				body, _ := io.ReadAll(resp.Body)
				entry = fmt.Sprintf("[%d/%d] Ошибка отправки: %v, Статус: %s, Ответ: %s\n", i, count, err, resp.Status, string(body))
				if resp.StatusCode == http.StatusTooManyRequests {
					entry += "Rate limit, ждём 5 секунд...\n"
					time.Sleep(5 * time.Second)
				}
			}
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(entry)
			f.Close()

			fmt.Print(entry)
			time.Sleep(time.Duration(delay * float64(time.Second)))
		}
		fmt.Println("Спам закончен, логи сохранены в:", logFile)
	} else {
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
		entry := fmt.Sprintf("[Single] Сообщение: %s\n", message)
		if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent) {
			body, _ := io.ReadAll(resp.Body)
			entry = fmt.Sprintf("[Single] Ошибка отправки: %v, Статус: %s, Ответ: %s\n", err, resp.Status, string(body))
		}
		os.WriteFile(logFile, []byte(entry), 0644)
		fmt.Println(entry)
		fmt.Println("Логи сохранены в:", logFile)
	}
	input("Нажми Enter чтобы рестарнуть...")
}

func telegramSpammer() {
	fmt.Println("ТЕЛЕГРАМ БОТ СПАММЕР")
	token := input("Введи Bot Token: ")
	chatID := input("Введи Chat ID (@channel или ID): ")
	message := input("СООБЩЕНИЕ: ")

	spam := strings.ToLower(input("Отправить несколько сообщений? (y/n): "))

	data := TelegramData{ChatID: chatID, Text: message}
	payload, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Ошибка создания JSON:", err)
		return
	}

	dir := createResultDir("telegram")
	logFile := filepath.Join(dir, "log.txt")

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	if spam == "y" {
		countStr := input("Сколько хочешь отправить: ")
		count, _ := strconv.Atoi(countStr)

		delayStr := input("Задержка между сообщениями (секунды): ")
		delay, _ := strconv.ParseFloat(delayStr, 64)

		for i := 1; i <= count; i++ {
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
			entry := fmt.Sprintf("[%d/%d] Отправлено: %s\n", i, count, message)
			if err != nil || resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				entry = fmt.Sprintf("[%d/%d] Ошибка отправки: %v, Статус: %s, Ответ: %s\n", i, count, err, resp.Status, string(body))
			}
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(entry)
			f.Close()

			fmt.Print(entry)
			time.Sleep(time.Duration(delay * float64(time.Second)))
		}
		fmt.Println("Спам закончен, логи сохранены в:", logFile)
	} else {
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
		entry := fmt.Sprintf("[Single] Сообщение: %s\n", message)
		if err != nil || resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			entry = fmt.Sprintf("[Single] Ошибка отправки: %v, Статус: %s, Ответ: %s\n", err, resp.Status, string(body))
		}
		os.WriteFile(logFile, []byte(entry), 0644)
		fmt.Println(entry)
		fmt.Println("Логи сохранены в:", logFile)
	}
	input("Нажми Enter чтобы рестарнуть...")
}

func serverRaid() {
	fmt.Println("СЕРВЕР РЕЙД ЧЕРЕЗ ВЕБХУК")
	message := input("СООБЩЕНИЕ: ")
	name := input("НАЗВАНИЕ ВЕБХУКА: ")
	urls := input("Введи URL вебхуков (через запятую): ")

	spam := strings.ToLower(input("Отправить несколько сообщений? (y/n): "))

	webhookURLs := strings.Split(urls, ",")
	for i, url := range webhookURLs {
		webhookURLs[i] = strings.TrimSpace(url)
	}

	data := WebhookData{Content: message, Username: name}
	payload, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Ошибка создания JSON:", err)
		return
	}

	dir := createResultDir("raid")
	logFile := filepath.Join(dir, "log.txt")

	if spam == "y" {
		countStr := input("Сколько хочешь отправить на каждый вебхук: ")
		count, _ := strconv.Atoi(countStr)

		delayStr := input("Задержка между сообщениями (секунды): ")
		delay, _ := strconv.ParseFloat(delayStr, 64)

		for i := 1; i <= count; i++ {
			for _, url := range webhookURLs {
				resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
				entry := fmt.Sprintf("[%d/%d] Отправлено на %s: %s\n", i, count, url, message)
				if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent) {
					body, _ := io.ReadAll(resp.Body)
					entry = fmt.Sprintf("[%d/%d] Ошибка отправки на %s: %v, Статус: %s, Ответ: %s\n", i, count, url, err, resp.Status, string(body))
					if resp.StatusCode == http.StatusTooManyRequests {
						entry += "Rate limit, ждём 5 секунд...\n"
						time.Sleep(5 * time.Second)
					}
				}
				f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				f.WriteString(entry)
				f.Close()
				fmt.Print(entry)
				time.Sleep(time.Duration(delay * float64(time.Second)))
			}
		}
		fmt.Println("Рейд закончен, логи сохранены в:", logFile)
	} else {
		for _, url := range webhookURLs {
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
			entry := fmt.Sprintf("[Single] Отправлено на %s: %s\n", url, message)
			if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent) {
				body, _ := io.ReadAll(resp.Body)
				entry = fmt.Sprintf("[Single] Ошибка отправки на %s: %v, Статус: %s, Ответ: %s\n", url, err, resp.Status, string(body))
			}
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(entry)
			f.Close()
			fmt.Print(entry)
		}
		fmt.Println("Рейд закончен, логи сохранены в:", logFile)
	}
	input("Нажми Enter чтобы рестарнуть...")
}

func nescaScanner() {
	fmt.Println("NESCA - СКАНЕР ДИАПАЗОНОВ")
	network := input("Введи диапазон (например, 192.168.1.0/24): ")
	portsStr := input("Порты для сканирования (по умолчанию 80,443,22,21,23,3389): ")
	if portsStr == "" {
		portsStr = "80,443,22,21,23,3389"
	}
	ports := strings.Split(portsStr, ",")
	portNums := make([]int, len(ports))
	for i, p := range ports {
		num, _ := strconv.Atoi(strings.TrimSpace(p))
		portNums[i] = num
	}
	timeoutStr := input("Таймаут на хост (секунды, по умолчанию 2): ")
	timeout, _ := strconv.Atoi(timeoutStr)
	if timeout == 0 {
		timeout = 2
	}

	dir := createResultDir("nesca")
	logFile := filepath.Join(dir, "log.txt")
	result := fmt.Sprintf("NESCA СКАНИРОВАНИЕ: %s, порты: %v, таймаут: %dс\n", network, portNums, timeout)

	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		result += fmt.Sprintf("Ошибка парсинга диапазона: %v\n", err)
		fmt.Println(result)
		f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		f.WriteString(result)
		f.Close()
		return
	}

	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ipStr := ip.String()
		active := false
		openPorts := []int{}

		// Пинг (TCP SYN на порт 80 для простоты)
		conn, err := net.DialTimeout("tcp", ipStr+":80", time.Duration(timeout)*time.Second)
		if err == nil {
			conn.Close()
			active = true
		}

		if active {
			// Сканирование портов
			for _, port := range portNums {
				conn, err := net.DialTimeout("tcp", ipStr+":"+strconv.Itoa(port), time.Duration(timeout)*time.Second)
				if err == nil {
					openPorts = append(openPorts, port)
					conn.Close()
				}
			}

			// Reverse DNS
			hostname, _ := net.LookupAddr(ipStr)

			result += fmt.Sprintf("Хост найден: %s (%s) - Открытые порты: %v\n", ipStr, hostname[0], openPorts)
			fmt.Printf("Найден: %s (%s) - Порты: %v\n", ipStr, hostname[0], openPorts)
		}
	}

	fmt.Println("СКАНИРОВАНИЕ ЗАВЕРШЕНО")
	fmt.Println(result)

	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()
	fmt.Println("Лог сохранён в:", logFile)

	input("Нажми Enter чтобы рестарнуть...")
}

// incIP increments an IP address
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func remoteCommandServer() {
	fmt.Println("REMOTE COMMAND SERVER")
	port := input("Введи порт для сервера (например, 8080): ")

	dir := createResultDir("remotecommand")
	logFile := filepath.Join(dir, "log.txt")
	result := fmt.Sprintf("Запуск сервера на порту %s\n", port)

	http.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		cmdStr := r.URL.Query().Get("cmd")
		if cmdStr == "" {
			http.Error(w, "Команда не указана", http.StatusBadRequest)
			return
		}

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", cmdStr)
		} else {
			cmd = exec.Command("sh", "-c", cmdStr)
		}

		output, err := cmd.CombinedOutput()
		entry := fmt.Sprintf("Команда: %s\nВывод: %s\n", cmdStr, string(output))
		if err != nil {
			entry += fmt.Sprintf("Ошибка: %v\n", err)
		}

		f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		f.WriteString(entry)
		f.Close()

		fmt.Fprint(w, entry)
	})

	result += "Сервер запущен. Отправляй команды: http://localhost:" + port + "/cmd?cmd=<команда>\n"
	fmt.Println(result)
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()

	go func() {
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			result := fmt.Sprintf("Ошибка сервера: %v\n", err)
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(result)
			f.Close()
			fmt.Println(result)
		}
	}()

	input("Нажми Enter чтобы остановить сервер и рестарнуть...")
}

func systemMonitor() {
	fmt.Println("SYSTEM MONITOR")
	dir := createResultDir("sysmonitor")
	logFile := filepath.Join(dir, "log.txt")
	result := "Мониторинг системы:\n"

	hostname, _ := os.Hostname()
	result += fmt.Sprintf("Имя хоста: %s\n", hostname)
	result += fmt.Sprintf("OS: %s\n", runtime.GOOS)
	result += fmt.Sprintf("Архитектура: %s\n", runtime.GOARCH)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	result += fmt.Sprintf("Использовано памяти: %v MB\n", m.Alloc/1024/1024)
	result += fmt.Sprintf("Общее количество ядер: %d\n", runtime.NumCPU())

	fmt.Println("РЕЗУЛЬТАТЫ")
	fmt.Println(result)

	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()
	fmt.Println("Лог сохранён в:", logFile)

	input("Нажми Enter чтобы рестарнуть...")
}

func fileTransferServer() {
	fmt.Println("FILE TRANSFER SERVER")
	port := input("Введи порт для сервера (например, 8081): ")
	dirPath := input("Введи директорию для файлов (например, C:\\temp): ")

	dir := createResultDir("filetransfer")
	logFile := filepath.Join(dir, "log.txt")
	result := fmt.Sprintf("Запуск сервера на порту %s, директория: %s\n", port, dirPath)

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Только POST", http.StatusMethodNotAllowed)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Ошибка загрузки файла", http.StatusBadRequest)
			return
		}
		defer file.Close()

		filePath := filepath.Join(dirPath, header.Filename)
		out, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Ошибка сохранения файла", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		_, err = io.Copy(out, file)
		entry := fmt.Sprintf("Файл загружен: %s\n", filePath)
		if err != nil {
			entry = fmt.Sprintf("Ошибка загрузки файла %s: %v\n", header.Filename, err)
		}

		f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		f.WriteString(entry)
		f.Close()
		fmt.Fprint(w, entry)
	})

	http.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir(dirPath))))

	result += "Сервер запущен. Загрузка: curl -F \"file=@<путь>\" http://localhost:" + port + "/upload\n"
	result += "Скачивание: http://localhost:" + port + "/download/<имя_файла>\n"
	fmt.Println(result)
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()

	go func() {
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			result := fmt.Sprintf("Ошибка сервера: %v\n", err)
			f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			f.WriteString(result)
			f.Close()
			fmt.Println(result)
		}
	}()

	input("Нажми Enter чтобы остановить сервер и рестарнуть...")
}

func clipboardManager() {
	fmt.Println("CLIPBOARD MANAGER")
	webhookURL := input("Введи Discord Webhook URL: ")
	action := strings.ToLower(input("Действие (read/write): "))

	dir := createResultDir("clipboard")
	logFile := filepath.Join(dir, "log.txt")
	result := ""

	if action == "read" {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", "Get-Clipboard")
		} else {
			cmd = exec.Command("xclip", "-selection", "clipboard", "-o")
		}
		output, err := cmd.Output()
		if err != nil {
			result = fmt.Sprintf("Ошибка чтения буфера: %v\n", err)
		} else {
			result = fmt.Sprintf("Буфер обмена: %s\n", string(output))
			data := WebhookData{Content: string(output), Username: "Clipboard"}
			payload, _ := json.Marshal(data)
			resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
			if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent) {
				body, _ := io.ReadAll(resp.Body)
				result += fmt.Sprintf("Ошибка отправки в Discord: %v, Статус: %s, Ответ: %s\n", err, resp.Status, string(body))
			} else {
				result += "Буфер отправлен в Discord\n"
			}
		}
	} else if action == "write" {
		text := input("Введи текст для записи в буфер: ")
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", fmt.Sprintf("Set-Clipboard -Value '%s'", text))
		} else {
			cmd = exec.Command("xclip", "-selection", "clipboard")
			cmd.Stdin = strings.NewReader(text)
		}
		err := cmd.Run()
		if err != nil {
			result = fmt.Sprintf("Ошибка записи в буфер: %v\n", err)
		} else {
			result = fmt.Sprintf("Текст записан в буфер: %s\n", text)
		}
	} else {
		result = "Неверное действие\n"
	}

	fmt.Println("РЕЗУЛЬТАТЫ")
	fmt.Println(result)

	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()
	fmt.Println("Лог сохранён в:", logFile)

	input("Нажми Enter чтобы рестарнуть...")
}

func processKiller() {
	fmt.Println("PROCESS KILLER")
	processName := input("Введи имя процесса (например, notepad.exe): ")

	dir := createResultDir("processkill")
	logFile := filepath.Join(dir, "log.txt")
	result := fmt.Sprintf("Попытка завершить процесс: %s\n", processName)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("taskkill", "/IM", processName, "/F")
	} else {
		cmd = exec.Command("pkill", processName)
	}

	err := cmd.Run()
	if err != nil {
		result += fmt.Sprintf("Ошибка завершения процесса: %v\n", err)
	} else {
		result += "Процесс успешно завершён\n"
	}

	fmt.Println("РЕЗУЛЬТАТЫ")
	fmt.Println(result)

	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()
	fmt.Println("Лог сохранён в:", logFile)

	input("Нажми Enter чтобы рестарнуть...")
}

func keyPressSimulator() {
	fmt.Println("KEY PRESS SIMULATOR")
	key := input("Введи клавишу (например, enter, space): ")
	countStr := input("Сколько раз нажать: ")
	count, _ := strconv.Atoi(countStr)

	dir := createResultDir("keypress")
	logFile := filepath.Join(dir, "log.txt")
	result := fmt.Sprintf("Симуляция нажатия клавиши %s %d раз\n", key, count)

	for i := 1; i <= count; i++ {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", fmt.Sprintf("Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('%s')", key))
		} else {
			cmd = exec.Command("xdotool", "key", key)
		}
		err := cmd.Run()
		if err != nil {
			result += fmt.Sprintf("[%d/%d] Ошибка нажатия: %v\n", i, count, err)
		} else {
			result += fmt.Sprintf("[%d/%d] Клавиша %s нажата\n", i, count, key)
		}
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("РЕЗУЛЬТАТЫ")
	fmt.Println(result)

	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()
	fmt.Println("Лог сохранён в:", logFile)

	input("Нажми Enter чтобы рестарнуть...")
}

func envVariables() {
	fmt.Println("ENVIRONMENT VARIABLES")
	dir := createResultDir("envvars")
	logFile := filepath.Join(dir, "log.txt")
	result := "Переменные окружения:\n"

	for _, env := range os.Environ() {
		result += fmt.Sprintf("%s\n", env)
	}

	fmt.Println("РЕЗУЛЬТАТЫ")
	fmt.Println(result)

	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()
	fmt.Println("Лог сохранён в:", logFile)

	input("Нажми Enter чтобы рестарнуть...")
}

func tcpListener() {
	fmt.Println("TCP LISTENER")
	port := input("Введи порт для прослушивания (например, 8082): ")

	dir := createResultDir("tcplisten")
	logFile := filepath.Join(dir, "log.txt")
	result := fmt.Sprintf("Запуск TCP сервера на порту %s\n", port)

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		result += fmt.Sprintf("Ошибка запуска сервера: %v\n", err)
		fmt.Println(result)
		f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		f.WriteString(result)
		f.Close()
		return
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				data, _ := bufio.NewReader(conn).ReadString('\n')
				entry := fmt.Sprintf("Получено: %s", data)
				f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				f.WriteString(entry)
				f.Close()
				fmt.Println(entry)
			}(conn)
		}
	}()

	result += "Сервер запущен. Отправляй данные: nc localhost " + port + "\n"
	fmt.Println(result)
	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()

	input("Нажми Enter чтобы остановить сервер и рестарнуть...")
	listener.Close()
}

func logCleaner() {
	fmt.Println("LOG CLEANER")
	dirPath := "results"
	daysStr := input("Удалить логи старше скольки дней? (например, 7): ")
	days, _ := strconv.Atoi(daysStr)

	dir := createResultDir("logclean")
	logFile := filepath.Join(dir, "log.txt")
	result := fmt.Sprintf("Очистка логов старше %d дней в %s\n", days, dirPath)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && time.Since(info.ModTime()).Hours() > float64(days*24) {
			if err := os.Remove(path); err != nil {
				result += fmt.Sprintf("Ошибка удаления %s: %v\n", path, err)
			} else {
				result += fmt.Sprintf("Удалён лог: %s\n", path)
			}
		}
		return nil
	})

	if err != nil {
		result += fmt.Sprintf("Ошибка очистки: %v\n", err)
	}

	fmt.Println("РЕЗУЛЬТАТЫ")
	fmt.Println(result)

	f, _ := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	f.WriteString(result)
	f.Close()
	fmt.Println("Лог сохранён в:", logFile)

	input("Нажми Enter чтобы рестарнуть...")
}

func main() {
	for {
		fmt.Println(logo)
		fmt.Println("[1] Вебхук Sender")
		fmt.Println("[2] Айпи INFO (Временно не работает)")
		fmt.Println("[3] Telegram Bot Spammer")
		fmt.Println("[4] Сервер рейд через вебхук")
		fmt.Println("[5] Nesca Scanner")
		fmt.Println("[6] Remote Command Server")
		fmt.Println("[7] System Monitor")
		fmt.Println("[8] File Transfer Server")
		fmt.Println("[9] Clipboard Manager")
		fmt.Println("[10] Process Killer")
		fmt.Println("[11] Key Press Simulator")
		fmt.Println("[12] Environment Variables")
		fmt.Println("[13] TCP Listener")
		fmt.Println("[14] Log Cleaner")
		fmt.Println("[15] Выход")

		choice := input("Выбирай цифру: ")

		switch choice {
		case "1":
			webhookSender()
		case "2":
			ipLookup()
		case "3":
			telegramSpammer()
		case "4":
			serverRaid()
		case "5":
			nescaScanner()
		case "6":
			remoteCommandServer()
		case "7":
			systemMonitor()
		case "8":
			fileTransferServer()
		case "9":
			clipboardManager()
		case "10":
			processKiller()
		case "11":
			keyPressSimulator()
		case "12":
			envVariables()
		case "13":
			tcpListener()
		case "14":
			logCleaner()
		case "15":
			fmt.Println("Пока!")
			os.Exit(0)
		default:
			fmt.Println("Неверный выбор.")
			time.Sleep(1 * time.Second)
		}
	}
}