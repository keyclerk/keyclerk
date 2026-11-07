// SPDX-License-Identifier: EUPL-1.2

// keyclerk-custodian holds the records key and refuses, on its own state alone, anything that would break the change
// log's structure (decision 0033). The checking signer stays the judge of every business rule and asks the custodian to
// sign; the custodian signs a link only at exactly the next position, naming the last link's hash, in its realm, with
// a fence never lower and in the exact canonical form every verifier accepts; a checkpoint, a C2SP note or a snapshot
// statement only over the size, root and head it computed itself; a log line's hash; and nothing else. It never goes
// below the witness's countersigned checkpoint and never signs a position twice. Its state, sealed under the key, is
// written before every answer; a missing state is never a first run.
//
//	keyclerk-custodian init    --state DIR --realm REALM --origin ORIGIN --key FILE
//	keyclerk-custodian serve   --state DIR --realm REALM --key FILE --listen unix:PATH|tcp:127.0.0.1:PORT
//	                           [--token-file FILE] (--witness URL --witness-vkey VKEY [--witness-log O] | --unwitnessed)
//	keyclerk-custodian recover --state DIR --realm REALM --origin ORIGIN --key FILE --links LINKS.jsonl
//	                           --trustees SET.json --statement STMT.json --sig ID=FILE --sig ID=FILE
//	                           [--origins O1,O2] [--retired HEX@UNTIL]... (--witness ... | --unwitnessed)
//	keyclerk-custodian rotate  --state DIR --realm REALM --key FILE --next FILE --origin NEW_ORIGIN --from-seq N
//	keyclerk-custodian export  --state DIR --key FILE --out FILE   (this custodian then never serves again)
//	keyclerk-custodian import  --state DIR --key FILE --from FILE  (only raises)
//	keyclerk-custodian state   --state DIR --key FILE
//	keyclerk-custodian seal-key --key FILE --out SEALED --tpm device [--pcrs 7]   (the key file sealed to this boot state)
//	keyclerk-custodian tpm-init --key FILE --tpm device --tpm-counter INDEX       (the counter, once per machine)
//
// Every command that reads the key takes --tpm device for a sealed key file, and --pkcs11 CONFIG.json in the PKCS#11
// build (the key in a token); serve, recover and import take --tpm-counter INDEX to bind the state to the TPM counter,
// raised every --counter-epoch (1h) and at recovery.
package main

import (
	"crypto"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

func open(dir, realm string, key crypto.Signer) (*Custodian, error) {
	st, err := load(dir, key)
	if err != nil {
		return nil, err
	}
	if st.Realm != realm {
		return nil, fmt.Errorf("this custodian's state is for realm %s, not %s: a key never serves another realm",
			st.Realm, realm)
	}
	pub := pubHex(key)
	for _, r := range st.Retired {
		if r.Key == pub {
			return nil, errors.New("this key was retired here: it never signs again (#41 F7)")
		}
	}
	if pub != st.Key {
		return nil, fmt.Errorf("the key file holds %s and the state names %s", short(pub), short(st.Key))
	}
	return &Custodian{dir: dir, key: key, st: st}, nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	debug.SetTraceback("none") // a crash prints no goroutine stacks, which could hold the key (exposure-6)
	harden()
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "keyclerk-custodian init|serve|recover|rotate|export|import|state|seal-key|tpm-init ... (see the package "+
			"documentation)")
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("state", "", "the custodian's state directory")
	realm := fs.String("realm", "", "the realm this custodian signs for")
	origin := fs.String("origin", "", "the log origin of this key")
	keyFile := fs.String("key", "", "the records key file (64 hex digits), the custodian's user's only")
	next := fs.String("next", "", "rotate: the next key file")
	addr := fs.String("listen", "", "serve: unix:PATH, or tcp:127.0.0.1:PORT with --token-file")
	tokenFile := fs.String("token-file", "", "serve: a token every request carries (required over TCP)")
	fromSeq := fs.Int64("from-seq", -1, "rotate: the switch the records-key history names (its new key's from_seq)")
	links := fs.String("links", "", "recover: the log's links, one sealed link per line (the commit witness's seed)")
	out := fs.String("out", "", "export: where the state goes")
	from := fs.String("from", "", "import: the exported state")
	witnessURL := fs.String("witness", "", "the commit witness, or the detection witness outside HA")
	witnessVkey := fs.String("witness-vkey", "", "the witness's verifier key")
	witnessLog := fs.String("witness-log", "", "the origin the witness keeps this log under (default: its first)")
	unwitnessed := fs.Bool("unwitnessed", false, "serve or recover without the witness: outside production only")
	setFile := fs.String("trustees", "", "recover: the pinned trustee set (kc-trustees-v1)")
	stmtFile := fs.String("statement", "", "recover: the recovery statement (kc-custodian-recovery-v1)")
	origins := fs.String("origins", "", "recover: this log's earlier origins, oldest first, comma-separated")
	tpmSpec := fs.String("tpm", "", "device, or tcp:HOST:PORT for a TPM simulator (tests only)")
	counterIdx := fs.String("tpm-counter", "", "the TPM NV counter binding the state, an index in hex (with --tpm)")
	epoch := fs.Duration("counter-epoch", time.Hour, "how often the TPM counter is raised (it wears; Q8)")
	pcrs := fs.String("pcrs", "7", "seal-key: the PCRs the key is sealed to, comma-separated")
	p11 := fs.String("pkcs11", "", "the PKCS#11 build: {module, token, key, pin_file} as JSON; replaces --key")
	var sigFiles, retired multi
	fs.Var(&sigFiles, "sig", "recover: ID=FILE, a trustee's signature over the statement; repeatable")
	fs.Var(&retired, "retired", "recover: HEX@UNTIL, an earlier key of this log and the link it stopped at; repeatable")
	_ = fs.Parse(os.Args[2:])
	fail := func(err error) {
		fmt.Fprintf(os.Stderr, "keyclerk-custodian %s: refused: %v\n", cmd, err)
		os.Exit(1)
	}
	key := func() crypto.Signer {
		var k crypto.Signer
		var err error
		if *p11 != "" {
			k, err = openPKCS11(*p11)
		} else {
			k, err = readKey(*keyFile, *tpmSpec)
		}
		if err == nil {
			err = checkKey(k)
		}
		if err != nil {
			fail(err)
		}
		return k
	}
	bind := func(c *Custodian, rebind bool) { // the TPM counter, checked (and on recovery and import raised) at start
		if *counterIdx != "" {
			idx, err := parseIndex(*counterIdx)
			if err == nil && *tpmSpec == "" {
				err = errors.New("--tpm-counter needs --tpm")
			}
			if err != nil {
				fail(err)
			}
			t, err := openTPM(*tpmSpec)
			if err != nil {
				fail(err)
			}
			c.counter, c.epoch = &tpmCounter{t: t, index: idx, auth: counterAuth(c.key)}, *epoch
		}
		if err := c.checkCounter(rebind); err != nil {
			fail(err)
		}
	}
	reopen := func(k crypto.Signer) { // after recover or import: bound to this machine's counter, raised once
		c, err := open(*dir, *realm, k)
		if err != nil {
			fail(err)
		}
		bind(c, true)
	}
	hold := func() func() {
		unlock, err := lockDir(*dir)
		if err != nil {
			fail(err)
		}
		return unlock
	}
	switch cmd {
	case "init": // a new log only: never over a state, never for a lost or retired one
		k := key()
		defer hold()()
		if _, err := os.Stat(statePath(*dir)); err == nil {
			fail(errors.New("a state exists: init starts a new log only; a lost state is recovered, never re-initialised"))
		}
		if _, err := os.Stat(tombPath(*dir)); err == nil {
			fail(errors.New("this directory's custodian is retired"))
		}
		if *realm == "" || !checkName(*origin) {
			fail(errors.New("give --realm and --origin (1 to 255 bytes, no space or plus)"))
		}
		st := &State{Format: stateFormat, Realm: *realm, Origin: *origin, Origins: []string{*origin},
			Key: pubHex(k), Retired: []Retired{}, Fence: 1, Frontier: []node{}}
		if err := save(*dir, st, k); err != nil {
			fail(err)
		}
		fmt.Printf("a custodian for realm %s under %s, at link 0\n", st.Realm, st.Origin)
	case "serve":
		k := key()
		unlock := hold()
		defer unlock()
		c, err := open(*dir, *realm, k)
		if err != nil {
			fail(err)
		}
		bind(c, false)
		if *tokenFile != "" {
			raw, err := os.ReadFile(*tokenFile)
			if err != nil {
				fail(err)
			}
			if c.token = strings.TrimSpace(string(raw)); len(c.token) < 16 {
				fail(errors.New("the token is at least 16 characters"))
			}
		}
		c.witnessVkey = *witnessVkey
		switch {
		case *witnessURL != "":
			log := *witnessLog
			if log == "" {
				log = c.st.Origins[0]
			}
			w, err := floor(c.st, *witnessURL, log, *witnessVkey)
			if err != nil {
				fail(err)
			}
			if w != c.st.Witness {
				n := c.st.clone()
				n.Witness = w
				if err := save(*dir, n, k); err != nil {
					fail(err)
				}
				c.st = n
			}
		case !*unwitnessed:
			fail(errors.New("the custodian reads the witness at start (--witness URL --witness-vkey VKEY): outside " +
				"production only, --unwitnessed"))
		}
		l, err := listen(*addr, c.token)
		if err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "keyclerk-custodian: realm %s at link %d (witness %d), listening on %s\n", c.st.Realm,
			c.st.Size, c.st.Witness.Size, l.Addr())
		if c.st.Size < c.st.Witness.Size {
			fmt.Fprintln(os.Stderr, "keyclerk-custodian: behind the witness: it signs nothing until it has followed the "+
				"committed log (a standby does so on its own; a single node is recovered by the ceremony)")
		}
		fail(c.serve(l))
	case "recover":
		k := key()
		defer hold()()
		sigs := map[string]string{}
		for _, sf := range sigFiles {
			id, file, ok := strings.Cut(sf, "=")
			if !ok {
				fail(errors.New("--sig is ID=FILE"))
			}
			b, err := os.ReadFile(file)
			if err != nil {
				fail(err)
			}
			sigs[id] = strings.TrimSpace(string(b))
		}
		var rs []Retired
		for _, r := range retired {
			h, u, ok := strings.Cut(r, "@")
			n, err := strconv.ParseInt(u, 10, 64)
			if !ok || err != nil || !hex64.MatchString(h) {
				fail(errors.New("--retired is HEX@UNTIL"))
			}
			rs = append(rs, Retired{Key: h, Until: n})
		}
		var olds []string
		if *origins != "" {
			olds = strings.Split(*origins, ",")
		}
		st, who, err := recovery{dir: *dir, realm: *realm, origin: *origin, origins: olds, retired: rs, key: k,
			links: *links, set: *setFile, stmt: *stmtFile, sigs: sigs, witnessURL: *witnessURL, wVkey: *witnessVkey,
			witnessLog: *witnessLog, unwitnessed: *unwitnessed}.run()
		if err != nil {
			fail(err)
		}
		reopen(k)
		fmt.Printf("recovered at link %d on the word of %s\n", st.Size, strings.Join(who, " and "))
	case "rotate": // a planned rotation: the next key from the next link on; the old key destroyed here (F7)
		if *p11 != "" {
			fail(errors.New("a key in a token is rotated by the token's own ceremony: generate the next key there, then " +
				"recover onto it; this command destroys a key file"))
		}
		k := key()
		defer hold()()
		c, err := open(*dir, *realm, k)
		if err != nil {
			fail(err)
		}
		nk, err := readKey(*next, "") // a plain file; seal it after the rotation
		if err != nil {
			fail(err)
		}
		if err := rotate(*dir, c, nk, *origin, *fromSeq, *keyFile); err != nil {
			fail(err)
		}
		fmt.Printf("the key under %s signs from link %d; the old key file is overwritten and removed (destroy its "+
			"copies in backups and snapshots too)\n", *origin, c.st.Size)
	case "export":
		k := key()
		defer hold()()
		if err := export(*dir, *out, k); err != nil {
			fail(err)
		}
		fmt.Printf("the state is in %s; this custodian is retired and never serves again\n", *out)
	case "import":
		k := key()
		defer hold()()
		st, err := importState(*dir, *from, k)
		if err != nil {
			fail(err)
		}
		*realm = st.Realm
		reopen(k)
		fmt.Printf("imported: realm %s at link %d\n", st.Realm, st.Size)
	case "state":
		k := key()
		st, err := load(*dir, k)
		if err != nil {
			fail(err)
		}
		fmt.Printf("realm %s, origin %s, %d links, fence %d, checkpoint %d, witness %d, key %s, TPM counter %#x at %d\n",
			st.Realm, st.Origin, st.Size, st.Fence, st.Checkpoint, st.Witness.Size, short(st.Key), st.TPMCounter, st.Counter)
	case "seal-key":
		k, err := readKey(*keyFile, "")
		if err != nil {
			fail(err)
		}
		var list []uint
		for _, x := range strings.Split(*pcrs, ",") {
			n, err := strconv.ParseUint(strings.TrimSpace(x), 10, 8)
			if err != nil || n > 23 {
				fail(errors.New("--pcrs: PCR numbers 0 to 23, comma-separated"))
			}
			list = append(list, uint(n))
		}
		t, err := openTPM(*tpmSpec)
		if err != nil {
			fail(err)
		}
		defer t.Close()
		sealed, err := sealKey(t, k.(interface{ Seed() []byte }).Seed(), list)
		if err == nil {
			err = writeSealed(*out, sealed)
		}
		if err != nil {
			fail(err)
		}
		fmt.Printf("the key is sealed to PCRs %v in %s: destroy the plain file here, keep its backup offline\n", list, *out)
	case "tpm-init":
		k := key()
		idx, err := parseIndex(*counterIdx)
		if err != nil {
			fail(err)
		}
		t, err := openTPM(*tpmSpec)
		if err != nil {
			fail(err)
		}
		defer t.Close()
		if err := defineCounter(t, idx, k); err != nil {
			fail(err)
		}
		fmt.Printf("the TPM counter at %#x is defined; the state binds to it at the next start\n", idx)
	default:
		fail(errors.New("unknown command"))
	}
}
