package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/net/websocket"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PrivateKey string   `yaml:"private_key"`
	PublicKey  string   `yaml:"public_key"`
	MonitorRelays     []string `yaml:"monitor_relays"`
	OutboxRelays []string `yaml:"outbox_relays"`
	Frequency  int      `yaml:"frequency"`
}

type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

var (
	privateKey *btcec.PrivateKey
	publicKey  string
	relays     []string
	outboxRelays []string
	frequency  int
)

func main() {
	if err := LoadConfig("config.yml"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	for {
		log.Println("Checking relay statuses...")
		var wg sync.WaitGroup
		for _, relay := range relays {
			wg.Add(1)
			go func(relay string) {
				defer wg.Done()
				checkRelay(relay)
			}(relay)
		}
		wg.Wait()
		log.Printf("Sleeping for %d seconds...", frequency)
		time.Sleep(time.Duration(frequency) * time.Second)
	}
}

func checkRelay(relay string) {
	start := time.Now()
	conn, err := connectToRelay(relay)
	if err != nil {
		log.Printf("Relay offline: %s (%v)", relay, err)
		return
	}
	defer conn.Close()

	rtt := time.Since(start).Milliseconds()
	nip11Info := fetchNIP11(relay)
	event := createRelayDiscoveryEvent(relay, rtt, nip11Info)
	sendEvent(event)
}

// Connects to a relay via WebSocket with improved debugging
func connectToRelay(relay string) (*websocket.Conn, error) {
	log.Printf("Attempting to connect to relay: %s", relay)
	u, err := url.Parse(relay)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL %s: %w", relay, err)
	}

	conn, err := websocket.Dial(u.String(), "", "http://localhost/")
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", relay, err)
	}

	log.Printf("Successfully connected to relay: %s", relay)
	return conn, nil
}

func fetchNIP11(relay string) map[string]interface{} {
	httpURL := "https://" + relay[6:] // Convert wss:// to https://
	req, err := http.NewRequest("GET", httpURL, nil)
	if err != nil {
		log.Printf("Failed to create request for NIP-11: %v", err)
		return nil
	}
	req.Header.Set("Accept", "application/nostr+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to fetch NIP-11 from %s: %v", relay, err)
		return nil
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Printf("Error decoding NIP-11 JSON: %v", err)
		return nil
	}
	return data
}

func createRelayDiscoveryEvent(relay string, rtt int64, nip11Info map[string]interface{}) *Event {
	tags := [][]string{
		{"d", relay},
		{"rtt-open", fmt.Sprintf("%d", rtt)},
	}

	if nip11Info != nil {
		if name, ok := nip11Info["name"].(string); ok {
			tags = append(tags, []string{"n", name})
		}
		if supportedNIPs, ok := nip11Info["supported_nips"].([]interface{}); ok {
			for _, nip := range supportedNIPs {
				if nipStr, valid := nip.(float64); valid {
					tags = append(tags, []string{"N", fmt.Sprintf("%.0f", nipStr)})
				}
			}
		}
		if limitations, ok := nip11Info["limitation"].(map[string]interface{}); ok {
			if auth, exists := limitations["auth_required"].(bool); exists && auth {
				tags = append(tags, []string{"R", "auth"})
			} else {
				tags = append(tags, []string{"R", "!auth"})
			}
			if payment, exists := limitations["payment_required"].(bool); exists && payment {
				tags = append(tags, []string{"R", "payment"})
			} else {
				tags = append(tags, []string{"R", "!payment"})
			}
		}
	}

	event := &Event{
		PubKey:    publicKey,
		CreatedAt: time.Now().Unix(),
		Kind:      30166,
		Tags:      tags,
		Content:   "{}",
	}

	// Correctly serialize event before hashing
	serializedData, err := json.Marshal([]interface{}{
		0,
		event.PubKey,
		event.CreatedAt,
		event.Kind,
		event.Tags,
		event.Content,
	})
	if err != nil {
		log.Fatalf("Failed to serialize event: %v", err)
	}

	hash := sha256.Sum256(serializedData)
	event.ID = hex.EncodeToString(hash[:])
	event.Sig = signEvent(hash[:])

	return event
}


func signEvent(eventID []byte) string {
	sig, err := schnorr.Sign(privateKey, eventID)
	if err != nil {
		log.Printf("Failed to sign event: %v", err)
		return ""
	}
	return hex.EncodeToString(sig.Serialize())
}

// Sends the Nostr event to all relays concurrently with improved debugging
func sendEvent(event *Event) {
	if event == nil {
		log.Printf("Error: Attempted to send nil event")
		return
	}

	log.Printf("Starting to send event ID %s to %d relays", event.ID, len(relays))

	if len(relays) == 0 {
		log.Printf("Warning: No relays configured to send to")
		return
	}

	var wg sync.WaitGroup
	for _, relayURL := range outboxRelays {
		wg.Add(1)
		go func(relay string) {
			defer wg.Done()
			log.Printf("Connecting to relay: %s", relay)

			conn, err := connectToRelay(relay)
			if err != nil {
				log.Printf("Error connecting to relay %s: %v", relay, err)
				return
			}
			defer conn.Close()

			msg, err := json.Marshal([]interface{}{"EVENT", event})
			if err != nil {
				log.Printf("Error encoding event for relay %s: %v", relay, err)
				return
			}

			log.Printf("Sending to %s: %s", relay, string(msg))

			n, err := conn.Write(msg)
			if err != nil {
				log.Printf("Error sending event to relay %s: %v", relay, err)
				return
			}

			log.Printf("Successfully sent %d bytes to relay %s", n, relay)

			// Add a response listener for confirmation
			var response = make([]byte, 1024)
			n, err = conn.Read(response)
			if err != nil {
				log.Printf("Error reading response from relay %s: %v", relay, err)
				return
			}

			log.Printf("Received response from %s: %s", relay, string(response[:n]))
		}(relayURL)
	}

	log.Printf("Waiting for all relay operations to complete...")
	wg.Wait()
	log.Printf("Event %s sent to all available relays", event.ID)
}


func LoadConfig(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("error parsing config file: %w", err)
	}

	keyBytes, err := hex.DecodeString(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("error decoding private key: %w", err)
	}

	privateKey, _ = btcec.PrivKeyFromBytes(keyBytes)
	publicKey = cfg.PublicKey
	relays = cfg.MonitorRelays
	outboxRelays = cfg.OutboxRelays
	frequency = cfg.Frequency
	return nil
}