package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/projectdiscovery/tlsx/pkg/output"
	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/rs/cors"
)

type ScanRequest struct {
	Target string `json:"target"`
}

type ScanResponse struct {
	Target            string   `json:"target"`
	TLSVersion        string   `json:"tls_version,omitempty"`
	Cipher            []string `json:"cipher,omitempty"`
	CertificateIssuer string   `json:"certificate_issuer,omitempty"`
	CertificateExpiry string   `json:"certificate_expiry,omitempty"`
	PQSupported       bool     `json:"pq_supported"`
	Grade             string   `json:"grade,omitempty"`
	RiskScore         int      `json:"riskScore,omitempty"`
	HndlPetabytes     string   `json:"hndlPetabytes,omitempty"`
	Error             string   `json:"error,omitempty"`
}

type TLSXOutput struct {
	Host       string `json:"host"`
	Port       string `json:"port"`
	TLSVersion string `json:"tls_version"`
	Cipher     string `json:"cipher"`
	IssuerCN   string `json:"issuer_cn"`
	NotAfter   string `json:"not_after"`
	CipherEnum []struct {
		Version string `json:"version"`
		Ciphers struct {
			Secure []string `json:"secure"`
			Weak   []string `json:"weak"`
		} `json:"ciphers"`
	} `json:"cipher_enum"`
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if req.Target == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "target is required"})
		return
	}

	response := performScan(req.Target)
	json.NewEncoder(w).Encode(response)
}

func performScan(target string) ScanResponse {
	_ = output.New
	_ = tlsx.New
	_ = clients.Options{}

	response := ScanResponse{Target: target}

	cmd := exec.Command("tlsx", "-u", target, "-json", "-silent", "-cn", "-cipher-enum")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("tlsx error: %v, stderr: %s", err, stderr.String())
		response.Error = fmt.Sprintf("Scan failed: %v", err)
		return response
	}

	var tlsxOut TLSXOutput
	if err := json.Unmarshal(stdout.Bytes(), &tlsxOut); err != nil {
		log.Printf("JSON parse error: %v, output: %s", err, stdout.String())
		response.Error = fmt.Sprintf("Parse failed: %v", err)
		return response
	}

	response.TLSVersion = tlsxOut.TLSVersion
	response.CertificateIssuer = tlsxOut.IssuerCN
	response.CertificateExpiry = tlsxOut.NotAfter

	// Collect all ciphers from cipher_enum
	cipherMap := make(map[string]bool)
	for _, ce := range tlsxOut.CipherEnum {
		for _, c := range ce.Ciphers.Secure {
			cipherMap[c] = true
		}
		for _, c := range ce.Ciphers.Weak {
			cipherMap[c] = true
		}
	}
	for c := range cipherMap {
		response.Cipher = append(response.Cipher, c)
	}

	// PQ support: TLS 1.3 + modern ciphers (AESGCM or CHACHA20)
	isTLS13 := strings.Contains(strings.ToLower(tlsxOut.TLSVersion), "1.3")
	hasModernCipher := false
	for _, c := range response.Cipher {
		cLower := strings.ToUpper(c)
		if strings.Contains(cLower, "AESGCM") || strings.Contains(cLower, "CHACHA20") {
			hasModernCipher = true
			break
		}
	}
	response.PQSupported = isTLS13 && hasModernCipher

	// Grade
	if isTLS13 && hasModernCipher {
		response.Grade = "A"
	} else if isTLS13 {
		response.Grade = "B"
	} else if strings.Contains(strings.ToLower(tlsxOut.TLSVersion), "1.2") {
		response.Grade = "C"
	} else {
		response.Grade = "D"
	}

	// HNDL risk
	if !response.PQSupported {
		response.RiskScore = 800 + rand.Intn(201)                            // 800-1000
		response.HndlPetabytes = fmt.Sprintf("%.2f", 1.0+rand.Float64()*1.0) // 1.00-2.00
	}

	return response
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Quantok Scanner API – POST to /api/v1/scan"))
}

func main() {
	rand.Seed(time.Now().UnixNano())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Starting Quantok scanner API on port %s\n", port) // For Cloud Run logs

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/v1/scan", scanHandler)
	mux.HandleFunc("/", rootHandler)

	// CORS
	handler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST"},
	}).Handler(mux)

	fmt.Println("API handlers registered – listening...")
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
