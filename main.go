package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"
)

func main() {
	configFile, err := ioutil.ReadFile("./config.json")
	if err != nil {
		log.Fatalf("failed to read configuration: %s", err)
	}
	var config struct {
		Endpoint string   `json:"endpoint"`
		Keys     []string `json:"keys"`
	}
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("failed to unmarshal configuration: %s", err)
	}

	rand.Seed(time.Now().Unix())

	cl := http.Client{
		Timeout: 10 * time.Second,
	}
	if req, err := http.NewRequest("HEAD", config.Endpoint+"/v1/sys/health", nil); err != nil {
		log.Panic(err)
	} else {
		res, err := cl.Do(req)
		if err != nil {
			log.Fatalf("failed to request vault health: %s", err)
		}
		defer res.Body.Close()
		switch res.StatusCode {
		case 503:
			log.Println("vault is sealed")
		default:
			log.Println("vault seems to be ok. exiting")
			return
		}
	}

	neededKeys := -1

	// Reset unseal state
	body, err := json.Marshal(struct {
		Reset bool `json:"reset"`
	}{true})
	if err != nil {
		log.Panic(err)
	}

	req, err := http.NewRequest("PUT", config.Endpoint+"/v1/sys/unseal", bytes.NewReader(body))
	if err != nil {
		log.Panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	log.Println("resetting unseal state")
	if res, err := cl.Do(req); err != nil {
		log.Fatalf("failed to reset unseal state: %s", err)
	} else {
		defer res.Body.Close()
		rb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Panicf("failed to parse response: %s", err)
		}
		var result UnsealResponse
		if err := json.Unmarshal(rb, &result); err != nil {
			log.Panicf("failed to unmarshal response: %s", err)
		}

		log.Printf("at least %d keys out of max %d needed, we have %d keys configured", result.Threshold, result.Shares, len(config.Keys))
		neededKeys = result.Threshold
	}

	// Fail fast if value unchanged or there aren't enough keys
	if neededKeys == -1 {
		log.Panic("neededKeys not changed!")
	}
	if neededKeys > len(config.Keys) {
		log.Fatal("there aren't enough keys in the config for proper unsealing")
	}

	// Pick three random keys
	keyIndexes := []int{}
	for len(keyIndexes) < neededKeys {
		n := rand.Int() % len(config.Keys)

		keyExists := false
		for _, e := range keyIndexes {
			if e == n {
				keyExists = true
			}
		}

		if !keyExists {
			keyIndexes = append(keyIndexes, n)
		}
	}

	// Attempt to unseal
	for i, keyIndex := range keyIndexes {
		key := config.Keys[keyIndex]
		body, err := json.Marshal(struct {
			Key string `json:"key"`
		}{key})
		if err != nil {
			log.Panic(err)
		}

		req, err := http.NewRequest("PUT", config.Endpoint+"/v1/sys/unseal", bytes.NewReader(body))
		if err != nil {
			log.Panic(err)
		}
		req.Header.Set("Content-Type", "application/json")

		log.Printf("unseal attempt %d...", i+1)
		if res, err := cl.Do(req); err != nil {
			log.Fatalf("failed to unseal: %s", err)
		} else {
			defer res.Body.Close()
			rb, err := ioutil.ReadAll(res.Body)
			if err != nil {
				log.Panicf("failed to parse response: %s", err)
			}
			var result UnsealResponse
			if err := json.Unmarshal(rb, &result); err != nil {
				log.Panicf("failed to unmarshal response: %s", err)
			}

			if !result.Sealed {
				log.Println("vault unsealed, exiting")
				return
			}
		}
	}

	log.Fatal("failed to unseal vault")
}

type UnsealResponse struct {
	Sealed    bool `json:"sealed"`
	Threshold int  `json:"t"`
	Shares    int  `json:"n"`
}
