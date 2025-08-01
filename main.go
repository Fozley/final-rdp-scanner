package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Next IP increment
func nextIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		if newIP[i] != 0 {
			break
		}
	}
	return newIP
}

// RDP detection
func isRDP(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	packet := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00,
	}
	conn.Write(packet)

	reply := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, err = conn.Read(reply)
	return err == nil
}

// Scan worker
func scan(ip string, port int, timeout time.Duration, wg *sync.WaitGroup, openChan chan<- string) {
	defer wg.Done()
	if isRDP(ip, port, timeout) {
		openChan <- fmt.Sprintf("%s:%d", ip, port)
	}
}

// Keep-alive HTTP server
func keepAlive(currentIP *string, mu *sync.Mutex) {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			fmt.Fprintf(w, "")
		})
		http.ListenAndServe(":8080", nil)
	}()
}

func main() {
	var currentIP string
	var mu sync.Mutex

	startIPStr := "100.0.0.0"
	ports := []int{3389}
	threads := 50000

	keepAlive(&currentIP, &mu) // Start keep-alive web server

	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		fmt.Println("Invalid Start IP.")
		return
	}

	openFile, _ := os.OpenFile("open-rdp-ip.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer openFile.Close()
	openWriter := bufio.NewWriter(openFile)

	jobs := make(chan struct {
		IP   string
		Port int
	}, threads)

	openResults := make(chan string, threads)
	var wg sync.WaitGroup

	// Worker goroutines
	for w := 0; w < threads; w++ {
		go func() {
			for job := range jobs {
				scan(job.IP, job.Port, 3*time.Second, &wg, openResults)
			}
		}()
	}

	// Writer goroutine
	go func() {
		for result := range openResults {
			fmt.Println(result)
			openWriter.WriteString(result + "\n")
			openWriter.Flush()
		}
	}()

	// Keypress to show current IP
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			_, err := reader.ReadString('\n')
			if err == nil {
				mu.Lock()
				fmt.Println("[NOW SCANNING]:", currentIP)
				mu.Unlock()
			}
		}
	}()

	// Infinite IP scanner
	for ip := startIP; ; ip = nextIP(ip) {
		ipStr := ip.String()

		mu.Lock()
		currentIP = ipStr
		mu.Unlock()

		for _, port := range ports {
			wg.Add(1)
			jobs <- struct {
				IP   string
				Port int
			}{ipStr, port}
		}
	}
}
