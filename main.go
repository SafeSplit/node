// SafeSplit Go node — BLOC 2.0.
//
// A minimal node that receives an event from Laravel (or curl) and anchors its
// hash on Hardhat via go-ethereum. It uses the SAME on-chain eventId as the PHP
// AnchorService — keccak256(event_id uuid) — so both can read/write the same slot.
//
// Later blocs add P2P, gossip, PoW and 2/3 consensus on top of this.
package main

import (
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

type anchorRequest struct {
	EventID   string `json:"event_id"`
	EventHash string `json:"event_hash"`
	Canonical string `json:"canonical"`  // canonical event string (to recompute the hash)
	Signature string `json:"signature"`  // 0x + 130 hex
	PublicKey string `json:"public_key"` // expected signer address
}

type anchorResponse struct {
	TxHash   string `json:"tx_hash"`
	EventID  string `json:"event_id"`
	Anchored bool   `json:"anchored"`
}

var (
	client       *ethclient.Client
	contract     *bind.BoundContract
	auth         *bind.TransactOpts
	contractAddr common.Address
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	rpcURL := env("NODE_RPC_URL", "http://host.docker.internal:49545")
	deployPath := env("NODE_DEPLOYMENT_PATH", "/app/deployments/deployment.json")
	pkHex := env("NODE_PRIVATE_KEY", "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80") // Hardhat acct #0
	listen := env("NODE_LISTEN", ":8081")
	chainID := big.NewInt(31337)

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

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "ok",
			"contract": contractAddr.Hex(),
			"rpc":      rpcURL,
		})
	})
	http.HandleFunc("/events", handleEvents)

	log.Printf("safesplit-node listening on %s — contract %s", listen, contractAddr.Hex())
	log.Fatal(http.ListenAndServe(listen, nil))
}

func loadDeployment(path string) deployment {
	for i := 0; i < 60; i++ {
		if b, err := os.ReadFile(path); err == nil {
			var d deployment
			if json.Unmarshal(b, &d) == nil && d.Address != "" {
				log.Printf("loaded deployment: %s", d.Address)
				return d
			}
		}
		log.Printf("waiting for deployment file %s ...", path)
		time.Sleep(2 * time.Second)
	}
	log.Fatalf("deployment file not found after waiting: %s", path)
	return deployment{}
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req anchorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.EventID == "" || req.EventHash == "" {
		http.Error(w, "event_id and event_hash are required", http.StatusUnprocessableEntity)
		return
	}

	// BLOC 2.2 — verify the event before anchoring (reject if invalid).
	// (a) hash integrity: sha256(canonical) must equal the claimed event_hash.
	if req.Canonical != "" {
		sum := sha256.Sum256([]byte(req.Canonical))
		if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimPrefix(req.EventHash, "0x")) {
			log.Printf("rejected %s: hash mismatch", req.EventID)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "hash mismatch: sha256(canonical) != event_hash"})
			return
		}
	}
	// (b) signature: must recover the claimed signer over the digest (EIP-191).
	if req.Signature != "" && req.PublicKey != "" {
		signer, err := recoverDigestSigner(req.EventHash, req.Signature)
		if err != nil || !strings.EqualFold(signer, req.PublicKey) {
			log.Printf("rejected %s: invalid signature (got %s, want %s)", req.EventID, signer, req.PublicKey)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid signature"})
			return
		}
		log.Printf("verified signature of %s by %s", req.EventID, signer)
	}

	// On-chain eventId = keccak256(uuid) — must match the PHP AnchorService.
	var eventID [32]byte
	copy(eventID[:], crypto.Keccak256([]byte(req.EventID)))

	var hash [32]byte
	copy(hash[:], common.FromHex("0x"+strings.TrimPrefix(req.EventHash, "0x")))

	tx, err := contract.Transact(auth, "record", eventID, hash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if receipt.Status != 1 {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "anchoring transaction reverted"})
		return
	}

	log.Printf("anchored event %s → tx %s", req.EventID, tx.Hash().Hex())
	writeJSON(w, http.StatusOK, anchorResponse{
		TxHash:   tx.Hash().Hex(),
		EventID:  req.EventID,
		Anchored: true,
	})
}

// recoverDigestSigner recovers the address that signed the 32-byte digest (event_hash)
// via EIP-191 personal_sign — the same contract as PHP EthSignature::recoverFromDigest:
// keccak256("\x19Ethereum Signed Message:\n32" + digest), then secp256k1 recover.
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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
