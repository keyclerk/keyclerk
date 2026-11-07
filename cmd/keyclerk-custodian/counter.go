// SPDX-License-Identifier: EUPL-1.2

// The state bound to the TPM counter (decision 0033 point 5, Q8). The state names the counter's value; at start they
// must agree, so a state copied back from an older backup or disk image (whose value is lower) is refused even when
// the witness cannot be read. A raise is written in two steps, "pending" before the TPM and the value after, so a
// crash between them is finished at the next start, never taken for a rollback.
package main

import (
	"errors"
	"fmt"
	"time"
)

// checkCounter runs at start. rebind: recovery and import may bind a state to a counter raised before (they are the
// ceremony and the raise-only move); a plain start binds only a counter never raised, or a state restored from before
// the binding would bind again and escape it.
func (c *Custodian) checkCounter(rebind bool) error {
	st := c.st
	if c.counter == nil {
		if st.TPMCounter != 0 {
			return fmt.Errorf("this state is bound to the TPM counter at %#x: start with --tpm and --tpm-counter",
				st.TPMCounter)
		}
		return nil
	}
	n, written, err := c.counter.read()
	if err != nil {
		return err
	}
	switch {
	case st.TPMCounter == 0:
		if written && !rebind {
			return errors.New("the TPM counter was raised before and this state is not bound to it: a state from " +
				"before the binding, restored; recover it through the ceremony")
		}
		return c.raiseCounter()
	case st.TPMCounter != c.counter.index:
		return fmt.Errorf("this state is bound to the TPM counter at %#x, not %#x", st.TPMCounter, c.counter.index)
	case !st.CounterPending && written && n == st.Counter:
		return nil
	case st.CounterPending && (!written || n == st.Counter):
		return c.raiseCounter() // the raise never reached the TPM
	case st.CounterPending && written && (n == st.Counter+1 || st.Counter == 0):
		return c.settle(n) // it reached the TPM; the state was not written after it
	case written && n > st.Counter:
		return fmt.Errorf("the TPM counter is at %d and this state at %d: the state is older than this custodian's "+
			"last (copied back from a backup or image); it signs nothing until the ceremony recovers it", n, st.Counter)
	}
	return fmt.Errorf("the TPM counter (%d) is behind this state (%d): another TPM, or a cleared one; recover through "+
		"the ceremony", n, st.Counter)
}

func (c *Custodian) raiseCounter() error {
	next := c.st.clone()
	next.TPMCounter, next.CounterPending = c.counter.index, true
	if err := save(c.dir, next, c.key); err != nil {
		return err
	}
	c.st = next
	n, err := c.counter.raise()
	if err != nil {
		return fmt.Errorf("the TPM counter was not raised (the state says pending; the next start finishes it): %w", err)
	}
	return c.settle(n)
}

func (c *Custodian) settle(n uint64) error {
	next := c.st.clone()
	next.Counter, next.CounterPending, next.CounterAt = n, false, time.Now().Unix()
	if err := save(c.dir, next, c.key); err != nil {
		return err
	}
	c.st = next
	return nil
}

// epochDue: a raise per checkpoint epoch, timed by the wall clock, which sets only the cadence (wear), never safety.
func (c *Custodian) epochDue() bool {
	return c.counter != nil && time.Since(time.Unix(c.st.CounterAt, 0)) >= c.epoch
}
