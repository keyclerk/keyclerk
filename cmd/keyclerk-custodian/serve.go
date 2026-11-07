// SPDX-License-Identifier: EUPL-1.2

package main

// The protocol (decision 0033 point 7): one JSON request per line, one answer per line, over a local socket only. A
// Unix socket is its user's only; over loopback TCP, which any local user can reach, every request carries a token
// (review 2026-11-07 exposure-1). Connections are bounded and every request has a deadline (dos-3); a live socket is
// never taken over (A5).

import (
	"bufio"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxRequest  = 4 << 20 // one request line: a follow chunk of links, base64 inside JSON
	maxConns    = 32
	idleTimeout = 60 * time.Second
)

var connIDs atomic.Uint64

func (c *Custodian) answer(line []byte, owner uint64) map[string]any {
	var req struct {
		Op    string `json:"op"`
		Data  string `json:"data"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return map[string]any{"refused": "a request is one JSON object per line"}
	}
	if c.token != "" && !hmac.Equal([]byte(req.Token), []byte(c.token)) {
		return map[string]any{"refused": "not the signer: wrong token"}
	}
	switch req.Op {
	case "public_key":
		return map[string]any{"key": pubHex(c.key)}
	case "state":
		c.mu.Lock()
		defer c.mu.Unlock()
		s := c.st
		return map[string]any{"realm": s.Realm, "origin": s.Origin, "size": s.Size, "head": s.Head, "fence": s.Fence,
			"root": hex.EncodeToString(s.root()), "checkpoint": s.Checkpoint, "key": s.Key, "witness": s.Witness.Size,
			"recovered": s.Recovered}
	case "sign":
		data, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			return map[string]any{"refused": "data is base64"}
		}
		sig, err := c.Sign(data)
		if err != nil {
			return map[string]any{"refused": err.Error()}
		}
		return map[string]any{"signature": hex.EncodeToString(sig)}
	case "follow_begin", "follow_links", "follow_end":
		return c.followOp(line, owner)
	}
	return map[string]any{"refused": "unknown op"}
}

func (c *Custodian) handle(conn net.Conn, slots chan struct{}) {
	owner := connIDs.Add(1)
	defer func() {
		c.dropFollow(owner)
		_ = conn.Close()
		<-slots
	}()
	r := bufio.NewReaderSize(conn, 64<<10)
	for {
		_ = conn.SetDeadline(time.Now().Add(idleTimeout))
		line, err := readLine(r, maxRequest)
		if err != nil {
			return
		}
		out, _ := json.Marshal(c.answer(line, owner))
		if _, err := conn.Write(append(out, '\n')); err != nil {
			return
		}
	}
}

func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		part, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		if len(buf)+len(part) > limit {
			return nil, errors.New("request too large")
		}
		buf = append(buf, part...)
		if !isPrefix {
			return buf, nil
		}
	}
}

func listen(addr, token string) (net.Listener, error) {
	switch {
	case strings.HasPrefix(addr, "unix:"):
		p := addr[5:]
		if conn, err := net.DialTimeout("unix", p, time.Second); err == nil {
			_ = conn.Close()
			return nil, errors.New("another custodian answers on " + p + ": it is never taken over")
		}
		_ = os.Remove(p) // a socket nobody answers on
		l, err := net.Listen("unix", p)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(p, 0o600); err != nil { // the umask made it so already; the socket's mode is the guard
			_ = l.Close()
			return nil, err
		}
		return l, nil
	case strings.HasPrefix(addr, "tcp:127.0.0.1:"), strings.HasPrefix(addr, "tcp:[::1]:"):
		if token == "" {
			return nil, errors.New("over TCP any local user reaches the custodian: give --token-file (the signer's " +
				"--custodian-token)")
		}
		return net.Listen("tcp", addr[4:])
	}
	return nil, errors.New("--listen is unix:PATH, or tcp:127.0.0.1:PORT with --token-file: local only")
}

func (c *Custodian) serve(l net.Listener) error {
	slots := make(chan struct{}, maxConns)
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case slots <- struct{}{}:
			go c.handle(conn, slots)
		default: // full: refused at once, never queued without bound
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte(`{"refused":"the custodian serves at most 32 connections at once"}` + "\n"))
			_ = conn.Close()
		}
	}
}
