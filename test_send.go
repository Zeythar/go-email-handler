//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// This file is a convenience program for manual testing and is excluded from
// normal `go build` runs by the build tag above. Run it with:
//   go run -tags=ignore test_send.go
func main() {
    url := "http://localhost:8080/api/contact"
    if len(os.Args) > 1 {
        url = os.Args[1]
    }

    payload := map[string]string{
        // use an allowed subject value to exercise the happy path
        "subject": "subject1",
        "email":   "tester@example.com",
        "message": "Hello — this is a test message from test_send.go",
    }

    b, _ := json.Marshal(payload)
    resp, err := http.Post(url, "application/json", bytes.NewReader(b))
    if err != nil {
        fmt.Printf("request error: %v\n", err)
        return
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("status: %s\nbody: %s\n", resp.Status, string(body))
}
