package mesh

import "sync"

// Credit is one direction of one stream's flow control, a port of the
// server's CreditStream (controlplane/credit.js). The sender may have at most
// window bytes outstanding; the receiver returns credit as it drains, batched
// at a quarter of the window so a peer with no credit always has at least
// one batch in flight. It is safe for concurrent use.
type Credit struct {
	mu         sync.Mutex
	window     int
	returnAt   int
	sendCredit int // bytes we may still send to the peer
	inWindow   int // bytes the peer sent that we have not credited back
	drained    int // bytes drained but not yet returned
}

// NewCredit makes a credit ledger with window bytes per direction. A window
// below 1 is treated as 1.
func NewCredit(window int) *Credit {
	if window < 1 {
		window = 1
	}
	returnAt := window / 4
	if returnAt < 1 {
		returnAt = 1
	}
	return &Credit{window: window, returnAt: returnAt, sendCredit: window}
}

// Window is the configured window.
func (c *Credit) Window() int { return c.window }

// Sendable is how much may go out now, at most max.
func (c *Credit) Sendable(max int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendCredit < max {
		return c.sendCredit
	}
	return max
}

// Take consumes n bytes of send credit; false when there is not enough.
func (c *Credit) Take(n int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n < 0 || n > c.sendCredit {
		return false
	}
	c.sendCredit -= n
	return true
}

// Grant records credit the peer returned. False is a violation: a
// non-positive amount, or more than the peer could owe.
func (c *Credit) Grant(n int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 || c.sendCredit+n > c.window {
		return false
	}
	c.sendCredit += n
	return true
}

// Receive records n bytes the peer sent. False is an overrun (violation).
func (c *Credit) Receive(n int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n < 0 || c.inWindow+n > c.window {
		return false
	}
	c.inWindow += n
	return true
}

// Drain records n received bytes handed onward and returns the credit to
// send back now, or 0 while still batching.
func (c *Credit) Drain(n int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 {
		return 0
	}
	c.drained += n
	if c.drained > c.inWindow {
		c.drained = c.inWindow
	}
	if c.drained < c.returnAt {
		return 0
	}
	return c.flushLocked()
}

// Flush returns every drained-but-unreturned byte now.
func (c *Credit) Flush() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flushLocked()
}

func (c *Credit) flushLocked() int {
	out := c.drained
	c.inWindow -= out
	c.drained = 0
	return out
}
