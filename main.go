package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	rateLimit       = 30
	rateLimitPeriod = 30 * time.Second
	workerThreads   = 6
)

var (
	tlURL       string
	token       string
	requestChan = make(chan map[string]interface{})
	outputChan  = make(chan map[string]interface{})
	wg          = sync.WaitGroup{}
	debug       bool
)

func init() {
	flag.BoolVar(&debug, "debug", false, "show debug messages")
	flag.Parse()

	tlURL = os.Getenv("TL_URL")
	if tlURL == "" {
		log.Fatal("Missing TL_URL environment variable")
	}

	if debug {
		log.Println("Debug logging is enabled")
	}
}

func main() {
	pcIdentity := mustGetEnv("PC_IDENTITY")
	pcSecret := mustGetEnv("PC_SECRET")

	statusCode, cwpToken := generateCwpToken(pcIdentity, pcSecret)
	if statusCode != http.StatusOK || cwpToken == "" {
		log.Fatal("Failed to generate token")
	}
	token = cwpToken

	// Start producer thread
	wg.Add(1)
	go producer(cwpToken, 100)

	// Start consumer threads
	for i := 0; i < workerThreads; i++ {
		wg.Add(1)
		go consumer()
	}

	// Start output thread
	wg.Add(1)
	go outputter()

	wg.Wait()
}

func producer(token string, limit int) {
	defer wg.Done()

	offset := 0
	requestCount := 0
	startTime := time.Now()

	for {
		if requestCount >= rateLimit {
			elapsed := time.Since(startTime)
			if elapsed < rateLimitPeriod {
				sleepTime := rateLimitPeriod - elapsed
				log.Printf("Rate limit reached. Sleeping for %v seconds...\n", sleepTime.Seconds())
				time.Sleep(sleepTime)
			}
			requestCount = 0
			startTime = time.Now()
		}

		statusCode, response := getContainers(token, offset, limit)
		requestCount++

		if statusCode != http.StatusOK {
			log.Printf("Error fetching containers: %d\n", statusCode)
			break
		}

		var containers []map[string]interface{}
		if err := json.Unmarshal(response, &containers); err != nil {
			log.Printf("Error parsing response: %v\n", err)
			break
		}

		if len(containers) == 0 {
			break
		}

		for _, container := range containers {
			requestChan <- container
		}

		if len(containers) < limit {
			break
		}

		offset += limit
	}

	close(requestChan)
}

func consumer() {
	defer wg.Done()

	for container := range requestChan {
		containerInfo := extractNetworkInfo(container)
		if len(containerInfo) > 0 {
			outputChan <- containerInfo
		}
	}

	close(outputChan)
}

func outputter() {
	defer wg.Done()

	for containerInfo := range outputChan {
		output, err := json.MarshalIndent(containerInfo, "", "  ")
		if err != nil {
			log.Printf("Error encoding JSON: %v\n", err)
			continue
		}
		fmt.Println(string(output))
	}
}

func getContainers(token string, offset, limit int) (int, []byte) {
	containersURL := fmt.Sprintf("%s/api/v1/containers?offset=%d&limit=%d", tlURL, offset, limit)

	req, err := http.NewRequest("GET", containersURL, nil)
	if err != nil {
		log.Fatalf("Error creating request: %v\n", err)
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("HTTP request failed: %v\n", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v\n", err)
	}

	return resp.StatusCode, body
}

func extractNetworkInfo(container map[string]interface{}) map[string]interface{} {
	openPorts := []map[string]interface{}{}

	// Extract from 'network' object
	if network, ok := container["network"].(map[string]interface{}); ok {
		if ports, ok := network["ports"].([]interface{}); ok {
			for _, portObj := range ports {
				if port, ok := portObj.(map[string]interface{}); ok {
					openPorts = append(openPorts, map[string]interface{}{
						"port":     port["container"],
						"host_port": port["host"],
						"host_ip":   port["hostIP"],
						"nat":       port["nat"],
						"type":      "network",
					})
				}
			}
		}
	}

	// Extract from 'networkSettings' object
	if networkSettings, ok := container["networkSettings"].(map[string]interface{}); ok {
		if ports, ok := networkSettings["ports"].([]interface{}); ok {
			for _, portObj := range ports {
				if port, ok := portObj.(map[string]interface{}); ok {
					openPorts = append(openPorts, map[string]interface{}{
						"port":     port["containerPort"],
						"host_port": port["hostPort"],
						"host_ip":   port["hostIP"],
						"type":      "networkSettings",
					})
				}
			}
		}
	}

	// Extract from 'firewallProtection' object
	if firewallProtection, ok := container["firewallProtection"].(map[string]interface{}); ok {
		if ports, ok := firewallProtection["ports"].([]interface{}); ok {
			for _, port := range ports {
				openPorts = append(openPorts, map[string]interface{}{
					"port": port,
					"type": "firewallProtection",
				})
			}
		}

		if tlsPorts, ok := firewallProtection["tlsPorts"].([]interface{}); ok {
			for _, port := range tlsPorts {
				openPorts = append(openPorts, map[string]interface{}{
					"port": port,
					"type": "firewallProtection_tls",
				})
			}
		}

		if unprotectedProcesses, ok := firewallProtection["unprotectedProcesses"].([]interface{}); ok {
			for _, processObj := range unprotectedProcesses {
				if process, ok := processObj.(map[string]interface{}); ok {
					openPorts = append(openPorts, map[string]interface{}{
						"port":    process["port"],
						"process": process["process"],
						"tls":     process["tls"],
						"type":    "unprotectedProcess",
					})
				}
			}
		}
	}

	if len(openPorts) > 0 {
		return map[string]interface{}{
			"id":         container["_id"],
			"open_ports": openPorts,
		}
	}

	return nil
}

func generateCwpToken(accessKey, accessSecret string) (int, string) {
	if tlURL == "" {
		log.Fatalf("Missing TL_URL environment variable")
	}

	authURL := fmt.Sprintf("%s/api/v1/authenticate", tlURL)

	requestBody := map[string]string{
		"username": accessKey,
		"password": accessSecret,
	}
	requestBytes, _ := json.Marshal(requestBody)

	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(requestBytes))
	if err != nil {
		log.Fatalf("Error creating request: %v\n", err)
	}

	req.Header.Set("accept", "application/json; charset=UTF-8")
	req.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("HTTP request failed: %v\n", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v\n", err)
	}

	if resp.StatusCode == http.StatusOK {
		var responseData map[string]interface{}
		if err := json.Unmarshal(body, &responseData); err != nil {
			log.Fatalf("Error parsing response: %v\n", err)
		}
		return http.StatusOK, responseData["token"].(string)
	}

	log.Printf("Unable to acquire token: %d\n", resp.StatusCode)
	return resp.StatusCode, ""
}

func mustGetEnv(key string) string {
	value, found := os.LookupEnv(key)
	if !found {
		log.Fatalf("Missing %s environment variable", key)
	}
	return value
}