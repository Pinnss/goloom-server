//go:build ignore

package main

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	// Force IPv4 to avoid IPv6 connectivity issues
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			DualStack: false,
		}).DialContext,
		TLSClientConfig: &tls.Config{},
		ForceAttemptHTTP2: true,
	}
	transport.DialContext = func(ctx interface{ Deadline() (time.Time, bool); Done() <-chan struct{}; Err() error; Value(interface{}) interface{} }, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 15 * time.Second}
		return d.DialContext(ctx, "tcp4", addr)
	}
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}

	url := "https://www.wintun.net/builds/wintun-0.14.1.zip"
	fmt.Println("downloading", url, "(IPv4 forced)")
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("download err:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("read err:", err)
		os.Exit(1)
	}
	fmt.Printf("downloaded %d bytes (status %d)\n", len(data), resp.StatusCode)

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		fmt.Println("zip err:", err)
		os.Exit(1)
	}
	for _, zf := range r.File {
		if zf.Name == "wintun/bin/amd64/wintun.dll" {
			rc, _ := zf.Open()
			out, _ := os.Create("wintun.dll")
			written, _ := io.Copy(out, rc)
			out.Close()
			rc.Close()
			fmt.Printf("extracted wintun.dll (%d bytes)\n", written)
			return
		}
	}
	fmt.Println("wintun.dll not found in archive")
}
