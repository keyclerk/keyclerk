// SPDX-License-Identifier: EUPL-1.2

package main

// The bytes the custodian signs must be bytes every Python verifier accepts, or a compromised signer could stall the
// log at a position no store will ever hold (the 2026-11-07 review's differential findings). So the custodian checks
// what keyclerk/edge.py _parse and keyclerk/store/{link,snapshot,note}.py check, rule for rule: canonical JSON (sorted
// keys, no spaces, no floats, whole numbers 0 to 2^53-1, no duplicate key, UTF-8), the exact field set of each body,
// and C2SP checkpoint texts of exactly three lines. What it cannot check without the engine's knowledge (whether an
// op's kind is a kind of record, whether its key is the record's own id) stays with the stores (decision 0033 point 10).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxSignedInt = 1<<53 - 1 // keyclerk/edge.py MAX_SIGNED_INT: every language reads it exactly

var (
	keyRe     = regexp.MustCompile(`^[!-~]{1,256}$`)
	hex128    = regexp.MustCompile(`^[0-9a-f]{128}$`)
	decimalRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
	nodeRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	headKeys  = map[string]bool{"realm": true, "home": true, "connected_organisations": true, "root": true,
		"retired_places": true, "situation_feeds": true, "ha": true} // link.HEAD_FIELDS
	sideKinds = map[string]bool{"visits": true, "visit_events": true, "badges": true, "proof_tokens": true,
		"genesis_yaml": true, "anchor_map": true, "anchor_idp": true} // link.SIDE_KINDS: never in a link
	proofKinds = map[string]bool{"approval_proofs": true, "proposal_proofs": true}
)

// canonicalObject decodes raw as Python's json.loads would and requires that canonical(obj) == raw, exactly as
// edge._parse does; it returns the decoded object.
func canonicalObject(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("the signed bytes are not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, fmt.Errorf("the signed bytes are not canonical: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("the signed bytes are not canonical: trailing data")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("the signed bytes hold an object")
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, obj); err != nil {
		return nil, err
	}
	if !bytes.Equal(buf.Bytes(), raw) {
		return nil, errors.New("the signed bytes are not canonical")
	}
	return obj, nil
}

const maxDepth = 64

// decodeValue reads one JSON value: objects with no duplicate key, numbers only as whole numbers 0 to 2^53-1.
func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("nested too deep")
	}
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("an object key is a string")
				}
				if _, dup := obj[k]; dup {
					return nil, fmt.Errorf("the key %q twice", k)
				}
				if obj[k], err = decodeValue(dec, depth+1); err != nil {
					return nil, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				x, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, x)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, errors.New("an unexpected delimiter")
	case json.Number:
		s := string(v)
		if !decimalRe.MatchString(s) {
			return nil, errors.New("a number is a whole number 0 to 2^53-1, no float, no sign, no leading zero")
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > maxSignedInt {
			return nil, errors.New("a signed integer is 0 to 2^53-1")
		}
		return n, nil
	case string, bool, nil:
		return v, nil
	}
	return nil, errors.New("an unexpected token")
}

// encodeCanonical writes Python's json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).
func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case string:
		writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte order of valid UTF-8 is code-point order, as Python sorts
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("not a JSON value: %T", v)
	}
	return nil
}

// writeString escapes as Python's json with ensure_ascii=False: the quote, the backslash, and control characters
// below 0x20 (\n \r \t \b \f by name, the rest as \u00xx), everything else as it is.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// --- the bodies, field for field -------------------------------------------------------------------------------------

func count(v any, low int64) (int64, bool) {
	n, ok := v.(int64)
	return n, ok && n >= low
}

func str(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func keysAre(m map[string]any, want ...string) bool {
	if len(m) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func keysWithin(m map[string]any, must []string, may ...string) bool {
	for _, k := range must {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, must...), may...) {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return false
		}
	}
	return true
}

// linkBody checks what link._body checks of a link body (but the engine's kinds and record ids) and returns its seq,
// prev and fence.
func linkBody(raw []byte) (seq int64, prev string, fence int64, realm string, err error) {
	b, err := canonicalObject(raw)
	if err != nil {
		return 0, "", 0, "", refuse("%v", err)
	}
	if !keysAre(b, "format", "realm", "seq", "prev", "fence", "at", "change") || b["format"] != linkLabel {
		return 0, "", 0, "", refuse("not a %s body", linkLabel)
	}
	realm, ok1 := str(b["realm"])
	seq, ok2 := count(b["seq"], 0)
	if !ok1 || !ok2 {
		return 0, "", 0, "", refuse("realm is text and seq a whole number")
	}
	if fence, ok2 = count(b["fence"], 1); !ok2 {
		return 0, "", 0, "", refuse("fence is a whole number from 1")
	}
	if prev, ok1 = str(b["prev"]); !ok1 || !hex64.MatchString(prev) {
		return 0, "", 0, "", refuse("prev is 64 lower-case hex characters")
	}
	if at, ok := str(b["at"]); !ok || !utcTime.MatchString(at) {
		return 0, "", 0, "", refuse("at is a UTC time, YYYY-MM-DDTHH:MM:SSZ")
	}
	if err := change(b["change"], seq); err != nil {
		return 0, "", 0, "", err
	}
	return seq, prev, fence, realm, nil
}

func change(v any, seq int64) error {
	ch, ok := v.(map[string]any)
	if !ok || !keysWithin(ch, []string{"ops", "entry"}, "yaml", "migrate", "restore", "ha") {
		return refuse("change has ops and entry (and yaml, migrate, restore or ha in their links)")
	}
	if _, ok := ch["entry"].(map[string]any); !ok {
		return refuse("change.entry is an object")
	}
	ops, ok := ch["ops"].([]any)
	if !ok {
		return refuse("change.ops is a list")
	}
	if y, in := ch["yaml"]; in {
		ym, ok := y.(map[string]any)
		base := []string{"revision", "sha256", "signature", "parts"}
		if seq != 0 || !ok || !keysWithin(ym, base, "rekeyed") {
			return refuse("only the genesis names the YAML revision it starts from, as {revision, sha256, signature, parts}")
		}
		_, r1 := count(ym["revision"], 0)
		_, r2 := count(ym["parts"], 1)
		s1, _ := str(ym["sha256"])
		s2, _ := str(ym["signature"])
		_, rk := ym["rekeyed"]
		_, r3 := count(ym["rekeyed"], 0)
		if !r1 || !r2 || !hex64.MatchString(s1) || !hex128.MatchString(s2) || (rk && !r3) {
			return refuse("yaml is {revision, sha256, signature, parts, rekeyed?}")
		}
	}
	if m, in := ch["migrate"]; in {
		mm, ok := m.(map[string]any)
		part, p1 := count(mm["part"], 1)
		parts, p2 := count(mm["parts"], 1)
		if !ok || !keysAre(mm, "part", "parts") || !p1 || !p2 || part != seq || part > parts {
			return refuse("migrate is {part, parts}, part = seq, from 1 to parts")
		}
		for _, o := range ops {
			if op, ok := o.(map[string]any); ok && op["op"] != "put" {
				return refuse("a migrate link only puts records")
			}
		}
	}
	if r, in := ch["restore"]; in {
		_, y := ch["yaml"]
		_, m := ch["migrate"]
		if seq < 1 || len(ops) != 0 || y || m {
			return refuse("a restore link follows the genesis and carries no ops")
		}
		rm, ok := r.(map[string]any)
		if !ok || !keysWithin(rm, []string{"mark", "confirmations"}, "trustees") {
			return refuse("restore is {mark, confirmations, trustees?}")
		}
		if _, ok := count(rm["mark"], 1); !ok || !confirmations(rm["confirmations"]) || !trusteeSigs(rm) {
			return refuse("restore is {mark, confirmations, trustees?}: two confirmations by two different people")
		}
	}
	if err := opsShape(ops); err != nil {
		return err
	}
	return haChange(ch, ops, seq)
}

func confirmations(v any) bool {
	cs, ok := v.([]any)
	if !ok || len(cs) != 2 {
		return false
	}
	by := make([]string, 2)
	for i, c := range cs {
		cm, ok := c.(map[string]any)
		if !ok || !keysAre(cm, "by", "proof") {
			return false
		}
		b, ok1 := str(cm["by"])
		p, ok2 := str(cm["proof"])
		if !ok1 || !ok2 || len(b) < 1 || utf8.RuneCountInString(b) > 256 || !hex64.MatchString(p) {
			return false
		}
		by[i] = b
	}
	return by[0] != by[1]
}

func trusteeSigs(d map[string]any) bool {
	s, in := d["trustees"]
	if !in {
		return true
	}
	sigs, ok := s.([]any)
	if !ok || len(sigs) < 2 || len(sigs) > 4 {
		return false
	}
	for _, x := range sigs {
		xm, ok := x.(map[string]any)
		if !ok || !keysAre(xm, "trustee_id", "sig") {
			return false
		}
		id, ok1 := str(xm["trustee_id"])
		sig, ok2 := str(xm["sig"])
		if !ok1 || !ok2 || utf8.RuneCountInString(id) < 1 || utf8.RuneCountInString(id) > 64 ||
			utf8.RuneCountInString(sig) < 1 || utf8.RuneCountInString(sig) > 16384 {
			return false
		}
	}
	return true
}

// opsShape is link._ops without the engine's knowledge: put or del with exactly their fields, keys 1 to 256 printable
// ASCII, no side kind, head fields by name, proofs by digest, sorted by kind and key with one op per key, and at most
// 500 records of one kind (decision 0022).
func opsShape(ops []any) error {
	type kk struct{ kind, key string }
	var seen []kk
	n := map[string]int{}
	for _, o := range ops {
		op, ok := o.(map[string]any)
		if !ok || (op["op"] != "put" && op["op"] != "del") {
			return refuse("an op is put or del")
		}
		if (op["op"] == "put" && !keysAre(op, "op", "kind", "key", "record")) ||
			(op["op"] == "del" && !keysAre(op, "op", "kind", "key")) {
			return refuse("a %v op has exactly its fields", op["op"])
		}
		kind, ok1 := str(op["kind"])
		key, ok2 := str(op["key"])
		if !ok1 || !ok2 {
			return refuse("an op's kind and key are text")
		}
		if sideKinds[kind] {
			return refuse("%s: kept outside the log, never in a link", kind)
		}
		if !keyRe.MatchString(key) {
			return refuse("%s: a key is 1 to 256 printable ASCII characters", kind)
		}
		if kind == "head" {
			if !headKeys[key] {
				return refuse("head %s: not a head field", key)
			}
			if op["op"] == "put" {
				if rec, ok := op["record"].(map[string]any); !ok || !keysAre(rec, "value") {
					return refuse("head %s: the record is {\"value\": ...}", key)
				}
			}
		} else if op["op"] == "put" && proofKinds[kind] {
			if rec, ok := op["record"].(map[string]any); !ok || !keysAre(rec, "records", "by", "sha256") {
				return refuse("%s: a proof enters the log as records, by and the token's sha256", kind)
			}
		}
		if n[kind]++; n[kind] > maxPerKind {
			return refuse("a change touches more than %d records of %s (decision 0022)", maxPerKind, kind)
		}
		seen = append(seen, kk{kind, key})
	}
	for i := 1; i < len(seen); i++ { // sorted, one op per key: Python compares (kind, key) tuples
		a, b := seen[i-1], seen[i]
		if a.kind > b.kind || (a.kind == b.kind && a.key >= b.key) {
			return refuse("ops are sorted by kind and key, one op per key")
		}
	}
	return nil
}

func haChange(ch map[string]any, ops []any, seq int64) error {
	var touches []map[string]any
	for _, o := range ops {
		op := o.(map[string]any)
		if op["kind"] == "head" && op["key"] == "ha" {
			touches = append(touches, op)
		}
	}
	h, in := ch["ha"]
	if !in {
		_, m := ch["migrate"]
		if len(touches) > 0 && seq != 0 && !m {
			return refuse("the ha head record changes only by an HA change link")
		}
		return nil
	}
	_, y := ch["yaml"]
	_, m := ch["migrate"]
	_, r := ch["restore"]
	if seq < 1 || y || m || r {
		return refuse("an HA change link follows the genesis and is no migrate or restore link")
	}
	hm, ok := h.(map[string]any)
	mode, _ := str(hm["mode"])
	if !ok || (mode != "set" && mode != "off" && mode != "break_glass") {
		return refuse("ha is {mode: set, off or break_glass, ...}")
	}
	if mode == "break_glass" {
		node, ok := str(hm["node"])
		if !keysWithin(hm, []string{"mode", "confirmations", "node"}, "trustees") || !ok || !nodeRe.MatchString(node) {
			return refuse("a break-glass HA change names its node")
		}
	} else if !keysWithin(hm, []string{"mode", "confirmations"}, "trustees") {
		return refuse("ha is {mode, confirmations, trustees?}")
	}
	if !confirmations(hm["confirmations"]) || !trusteeSigs(hm) {
		return refuse("ha carries two confirmations by two different people")
	}
	want := "del"
	if mode == "set" {
		want = "put"
	}
	if len(ops) != 1 || len(touches) != 1 || touches[0]["op"] != want {
		return refuse("an HA change link of mode %s carries one op: %s head ha", mode, want)
	}
	return nil
}

// checkpointBody is link.open_checkpoint's shape.
func checkpointBody(raw []byte) (map[string]any, int64, error) {
	b, err := canonicalObject(raw)
	if err != nil {
		return nil, 0, refuse("%v", err)
	}
	if !keysAre(b, "format", "realm", "size", "root", "head", "fence", "at") || b["format"] != cpLabel {
		return nil, 0, refuse("not a %s body", cpLabel)
	}
	size, ok := count(b["size"], 1)
	if !ok {
		return nil, 0, refuse("a checkpoint covers at least one link")
	}
	if err := hexAndTime(b, "root", "head"); err != nil {
		return nil, 0, err
	}
	if _, ok := count(b["fence"], 1); !ok {
		return nil, 0, refuse("fence is a whole number from 1")
	}
	return b, size, nil
}

// snapshotBody is snapshot.open_snapshot's shape.
func snapshotBody(raw []byte) (map[string]any, int64, error) {
	b, err := canonicalObject(raw)
	if err != nil {
		return nil, 0, refuse("%v", err)
	}
	if !keysAre(b, "format", "realm", "size", "head", "root", "fence", "at", "parts", "migration", "restore", "state") ||
		b["format"] != snapLabel {
		return nil, 0, refuse("not a %s body", snapLabel)
	}
	size, ok1 := count(b["size"], 1)
	_, ok2 := count(b["fence"], 1)
	parts, ok3 := count(b["parts"], 0)
	if !ok1 || !ok2 || !ok3 || size <= parts {
		return nil, 0, refuse("size, fence and parts are whole numbers; a snapshot comes after the migration")
	}
	if err := hexAndTime(b, "head", "root"); err != nil {
		return nil, 0, err
	}
	if m := b["migration"]; m != nil {
		if s, ok := str(m); !ok || s == "" {
			return nil, 0, refuse("migration is the store's proof or null")
		}
	}
	if r := b["restore"]; r != nil {
		rl, ok := r.([]any)
		if !ok || len(rl) != 2 {
			return nil, 0, refuse("restore is [seq, mark] or null")
		}
		for _, x := range rl {
			if _, ok := count(x, 0); !ok {
				return nil, 0, refuse("restore is [seq, mark] or null")
			}
		}
	}
	st, ok := b["state"].(map[string]any)
	sha, _ := str(st["sha256"])
	_, s1 := count(st["bytes"], 0)
	_, s2 := count(st["records"], 0)
	if !ok || !keysAre(st, "sha256", "bytes", "records") || !hex64.MatchString(sha) || !s1 || !s2 {
		return nil, 0, refuse("state is {sha256, bytes, records}")
	}
	return b, size, nil
}

func hexAndTime(b map[string]any, keys ...string) error {
	for _, k := range keys {
		if s, ok := str(b[k]); !ok || !hex64.MatchString(s) {
			return refuse("%s is 64 lower-case hex characters", k)
		}
	}
	if at, ok := str(b["at"]); !ok || !utcTime.MatchString(at) {
		return refuse("at is a UTC time, YYYY-MM-DDTHH:MM:SSZ")
	}
	return nil
}

// checkName is note.check_name: 1 to 255 bytes, no space, plus or control character.
func checkName(name string) bool {
	if len(name) < 1 || len(name) > 255 || !utf8.ValidString(name) || strings.ContainsRune(name, '+') {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || r < 0x20 || unicode.Is(unicode.Zs, r) {
			return false
		}
	}
	return true
}

// checkpointText is note.parse_checkpoint: exactly origin, size, root and the empty line after them; a size with no
// leading zero; the root canonical base64 of 32 bytes. ok is false only when the text is no attempt at a checkpoint.
func checkpointText(data []byte) (origin string, size int64, root []byte, err error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return "", 0, nil, refuse("a checkpoint is three lines: origin, size, root (no extension lines)")
	}
	if !checkName(lines[0]) {
		return "", 0, nil, refuse("a name is 1 to 255 bytes with no space, plus or control character")
	}
	if !decimalRe.MatchString(lines[1]) {
		return "", 0, nil, refuse("the tree size is a decimal with no leading zero")
	}
	n, perr := strconv.ParseUint(lines[1], 10, 64)
	if perr != nil || n > maxSignedInt {
		return "", 0, nil, refuse("a tree size this custodian never signed")
	}
	root, berr := base64.StdEncoding.Strict().DecodeString(lines[2])
	if berr != nil || len(root) != 32 || base64.StdEncoding.EncodeToString(root) != lines[2] {
		return "", 0, nil, refuse("the root is canonical base64 of 32 bytes")
	}
	return lines[0], int64(n), root, nil
}
