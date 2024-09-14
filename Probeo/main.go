package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ProbeoCheck attempts to connect to a port and return a boolean indicating it is open
func ProbeoCheck(protocol, hostname string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", hostname, port)
	conn, err := net.DialTimeout(protocol, address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Probeo scans a range of ports on a given hostname concurrently
func Probeo(hostname string, startPort, endPort int, timeout time.Duration) {
	var wg sync.WaitGroup
	openPorts := []int{}

	// Create a mutex to protect the shared slice
	var mu sync.Mutex 

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)

		// Launch a goroutine for each port
		go func(p int) {
			defer wg.Done()
			if ProbeoCheck("tcp", hostname, p, timeout) {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Output open ports
	if len(openPorts) > 0 {
		fmt.Printf("Open ports on %s:\n", hostname)
		for _, port := range openPorts {
			fmt.Printf("Port %d is open\n", port)
		}
	} else {
		fmt.Printf("No open ports found on %s\n", hostname)
	}
}

func main() {
	hostname := "examplehost.com" // Change to target host
	startPort := 1
	endPort := 1024
	timeout := 500 * time.Millisecond

	fmt.Printf("Starting scan on %s.....\n", hostname)
	Probeo(hostname, startPort, endPort, timeout)
}
