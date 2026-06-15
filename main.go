// SafeSplit Go node — Phase 3 (P2P).
//
// BLOC 3.0: peer table + bootstrap discovery + heartbeat + gossip.
// An event sent to ONE node is propagated (gossip, with seen-set de-dup) to all
// nodes. The entry node still anchors on Hardhat; PoW + 2/3 consensus arrive in 3.1.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type deployment struct {
	Address string          `json:"address"`
	ABI     json.RawMessage `json:"abi"`
	ChainID int64           `json:"chainId"`
}

// eventMsg is both the Laravel→node payload and the node→node gossip payload.
type eventMsg struct {
	EventID   string `json:"event_id"`
	EventHash string `json:"event_hash"`
	Canonical string `json:"canonical"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

type peer struct {
	Address  string `json:"address"`
	Active   bool   `json:"active"`
	LastSeen string `json:"last_seen"`
}

var (
	nodeID string
	self   string

	peersMu sync.RWMutex
	peers   = map[string]*peer{}

	seenMu sync.Mutex
	seen   = map[string]bool{}

	eventsMu sync.RWMutex
	events   = map[string]eventMsg{}

	client       *ethclient.Client
	contract     *bind.BoundContract
	auth         *bind.TransactOpts
	contractAddr common.Address

	httpClient = &http.Client{Timeout: 5 * time.Second}
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	nodeID = env("NODE_ID", "node")
	listen := env("NODE_LISTEN", ":8081")
	self = env("NODE_SELF", "http://localhost:8081")
	bootstrap := env("NODE_BOOTSTRAP", "")
	rpcURL := env("NODE_RPC_URL", "http://host.docker.internal:49545")
	deployPath := env("NODE_DEPLOYMENT_PATH", "/app/deployments/deployment.json")
	pkHex := env("NODE_PRIVATE_KEY", "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	chainID := big.NewInt(31337)

	initEth(rpcURL, deployPath, pkHex, chainID)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/peers", handlePeers)
	mux.HandleFunc("/announce", handleAnnounce)
	mux.HandleFunc("/events", handleEvents)
	mux.HandleFunc("/gossip", handleGossip)

	// Discover peers + start heartbeat in the background.
	go discover(bootstrap)
	go heartbeatLoop()

	log.Printf("[%s] listening on %s (self=%s) contract=%s", nodeID, listen, self, contractAddr.Hex())
	log.Fatal(http.ListenAndServe(listen, mux))
}

/* ---------- Ethereum / anchoring ---------- */

func initEth(rpcURL, deployPath, pkHex string, chainID *big.Int) {
	dep := loadDeployment(deployPath)
	contractAddr = common.HexToAddress(dep.Address)

	parsedABI, err := abi.JSON(strings.NewReader(string(dep.ABI)))
	if err != nil {
		log.Fatalf("parse abi: %v", err)
	}
	client, err = ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("dial %s: %v", rpcURL, err)
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(pkHex, "0x"))
	if err != nil {
		log.Fatalf("private key: %v", err)
	}
	auth, err = bind.NewKeyedTransactorWithChainID(key, chainID)
	if err != nil {
		log.Fatalf("transactor: %v", err)
	}
	contract = bind.NewBoundContract(contractAddr, parsedABI, client, client, client)
}

func loadDeployment(path string) deployment {
	for i := 0; i < 60; i++ {
		if b, err := os.ReadFile(path); err == nil {
			var d deployment
			if json.Unmarshal(b, &d) == nil && d.Address != "" {
				log.Printf("[%s] loaded deployment: %s", nodeID, d.Address)
				return d
			}
		}
		log.Printf("[%s] waiting for deployment file %s ...", nodeID, path)
		time.Sleep(2 * time.Second)
	}
	log.Fatalf("deployment file not found: %s", path)
	return deployment{}
}

func anchorEvent(ev eventMsg) (string, error) {
	var eventID [32]byte
	copy(eventID[:], crypto.Keccak256([]byte(ev.EventID)))
	var hash [32]byte
	copy(hash[:], common.FromHex("0x"+strings.TrimPrefix(ev.EventHash, "0x")))

	tx, err := contract.Transact(auth, "record", eventID, hash)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return "", err
	}
	if receipt.Status != 1 {
		return "", fmt.Errorf("anchoring transaction reverted")
	}
	return tx.Hash().Hex(), nil
}

/* ---------- verification (BLOC 2.2) ---------- */

func verifyEvent(ev eventMsg) error {
	if ev.EventID == "" || ev.EventHash == "" {
		return fmt.Errorf("event_id and event_hash are required")
	}
	if ev.Canonical != "" {
		sum := sha256.Sum256([]byte(ev.Canonical))
		if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimPrefix(ev.EventHash, "0x")) {
			return fmt.Errorf("hash mismatch: sha256(canonical) != event_hash")
		}
	}
	if ev.Signature != "" && ev.PublicKey != "" {
		signer, err := recoverDigestSigner(ev.EventHash, ev.Signature)
		if err != nil || !strings.EqualFold(signer, ev.PublicKey) {
			return fmt.Errorf("invalid signature")
		}
	}
	return nil
}

func recoverDigestSigner(eventHashHex, sigHex string) (string, error) {
	digest := common.FromHex("0x" + strings.TrimPrefix(eventHashHex, "0x"))
	if len(digest) != 32 {
		return "", fmt.Errorf("event_hash must be 32 bytes")
	}
	prefixed := append([]byte("\x19Ethereum Signed Message:\n"+strconv.Itoa(len(digest))), digest...)
	msgHash := crypto.Keccak256(prefixed)

	sig := common.FromHex("0x" + strings.TrimPrefix(sigHex, "0x"))
	if len(sig) != 65 {
		return "", fmt.Errorf("signature must be 65 bytes")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := crypto.SigToPub(msgHash, sig)
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(*pub).Hex(), nil
}

/* ---------- gossip / event store ---------- */

// ingest records an event once; returns true if it was new.
func ingest(ev eventMsg) bool {
	seenMu.Lock()
	if seen[ev.EventID] {
		seenMu.Unlock()
		return false
	}
	seen[ev.EventID] = true
	seenMu.Unlock()

	eventsMu.Lock()
	events[ev.EventID] = ev
	eventsMu.Unlock()
	return true
}

// gossip forwards an event to all known peers (best-effort).
func gossip(ev eventMsg) {
	body, _ := json.Marshal(ev)
	for _, addr := range peerAddrs() {
		go func(a string) {
			resp, err := httpClient.Post(a+"/gossip", "application/json", bytes.NewReader(body))
			if err == nil {
				resp.Body.Close()
			}
		}(addr)
	}
}

/* ---------- peer table / discovery / heartbeat ---------- */

func addPeer(addr string) {
	if addr == "" || addr == self {
		return
	}
	peersMu.Lock()
	defer peersMu.Unlock()
	if _, ok := peers[addr]; !ok {
		peers[addr] = &peer{Address: addr, Active: true, LastSeen: now()}
		log.Printf("[%s] peer added: %s", nodeID, addr)
	}
}

func peerAddrs() []string {
	peersMu.RLock()
	defer peersMu.RUnlock()
	out := make([]string, 0, len(peers))
	for a := range peers {
		out = append(out, a)
	}
	return out
}

func snapshotPeers() []peer {
	peersMu.RLock()
	defer peersMu.RUnlock()
	out := make([]peer, 0, len(peers))
	for _, p := range peers {
		out = append(out, *p)
	}
	return out
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// discover: contact the bootstrap node for its peer list, then announce ourselves.
func discover(bootstrap string) {
	if bootstrap == "" || bootstrap == self {
		return // we are the bootstrap node
	}
	for i := 0; i < 30; i++ {
		if exchangeWith(bootstrap) {
			log.Printf("[%s] bootstrapped via %s", nodeID, bootstrap)
			return
		}
		time.Sleep(2 * time.Second)
	}
	log.Printf("[%s] could not reach bootstrap %s", nodeID, bootstrap)
}

// exchangeWith announces self to a peer and merges its known peers.
func exchangeWith(addr string) bool {
	body, _ := json.Marshal(map[string]string{"address": self})
	resp, err := httpClient.Post(addr+"/announce", "application/json", bytes.NewReader(body))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var out struct {
		Peers []string `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	addPeer(addr)
	for _, p := range out.Peers {
		addPeer(p)
	}
	return true
}

func heartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		for _, addr := range peerAddrs() {
			active := ping(addr)
			peersMu.Lock()
			if p, ok := peers[addr]; ok {
				p.Active = active
				if active {
					p.LastSeen = now()
				}
			}
			peersMu.Unlock()
		}
	}
}

func ping(addr string) bool {
	resp, err := httpClient.Get(addr + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

/* ---------- HTTP handlers ---------- */

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "id": nodeID, "self": self, "contract": contractAddr.Hex(),
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	eventsMu.RLock()
	count := len(events)
	ids := make([]string, 0, count)
	for id := range events {
		ids = append(ids, id)
	}
	eventsMu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"id":           nodeID,
		"self":         self,
		"peers":        snapshotPeers(),
		"events_count": count,
		"event_ids":    ids,
	})
}

func handlePeers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"self": self, "peers": peerAddrs()})
}

func handleAnnounce(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	known := peerAddrs() // peers we knew BEFORE adding the newcomer
	addPeer(body.Address)
	writeJSON(w, http.StatusOK, map[string]any{"self": self, "peers": known})
}

// /events — entry point from Laravel: verify, ingest, gossip, anchor.
func handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var ev eventMsg
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := verifyEvent(ev); err != nil {
		log.Printf("[%s] rejected %s: %v", nodeID, ev.EventID, err)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if ingest(ev) {
		log.Printf("[%s] verified + ingested %s, gossiping", nodeID, ev.EventID)
		gossip(ev)
	}

	txHash, err := anchorEvent(ev)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("[%s] anchored %s → tx %s", nodeID, ev.EventID, txHash)
	writeJSON(w, http.StatusOK, map[string]any{"tx_hash": txHash, "event_id": ev.EventID, "anchored": true})
}

// /gossip — from a peer: verify, ingest, re-gossip (no anchoring).
func handleGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var ev eventMsg
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := verifyEvent(ev); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	if ingest(ev) {
		log.Printf("[%s] received via gossip: %s", nodeID, ev.EventID)
		gossip(ev) // flood onward; peers de-dup via seen-set
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
