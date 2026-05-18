// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package ticketstore is a POC in-memory ticket registry for EIP-Blob-Streaming.
//
// The full EIP backs tickets with a system contract; this package short-circuits
// that with a fixed-size ring buffer kept in Go memory. On every ChainHeadEvent
// a single ticket is minted with hardcoded owner/BLS-pubkey/blob-count and
// written into the next ring slot, naturally evicting the ticket that was
// TICKET_LOOKAHEAD blocks old.
package ticketstore

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// TicketLookahead is the ring buffer length, in blocks. A ticket minted at
	// head H is evicted when head H+TicketLookahead is processed.
	TicketLookahead = 8

	// FixedBlobCount is the POC blob count attached to every minted ticket.
	FixedBlobCount uint8 = 2
)

// FixedOwner is the hardcoded ticket owner for the POC.
var FixedOwner = common.HexToAddress("0x8943545177806ED17B9F23F0a21ee5948eCaa776")

// FixedBLSPubkey is the hardcoded BLS pubkey bound to every POC ticket.
var FixedBLSPubkey = [48]byte{
	0x95, 0x7c, 0x1e, 0x93, 0xf3, 0x6f, 0x42, 0x3a,
	0xfa, 0x7c, 0xb6, 0xd7, 0xa4, 0x3b, 0xf8, 0x0d,
	0xdc, 0x26, 0x30, 0x16, 0x6c, 0x68, 0x5d, 0xb7,
	0x44, 0x40, 0x63, 0x3a, 0xe6, 0x40, 0x75, 0x95,
	0xf8, 0xa3, 0x6c, 0xfb, 0x7f, 0x6a, 0x55, 0x04,
	0x73, 0x1e, 0xfe, 0x91, 0x02, 0xed, 0x30, 0x64,
}

// Ticket mirrors the per-entry layout described in the EIP's V2 ticket contract,
// minus fields the POC doesn't need (target slot is derived externally from
// SellingTimestamp by the consensus client).
type Ticket struct {
	ID               uint64
	SellingTimestamp uint64
	Owner            common.Address
	BlobCount        uint8
	BLSPubkey        [48]byte
}

// chainHeadSubscriber is the subset of *core.BlockChain that TicketStore needs.
// Extracted so tests can drive the store with synthetic head events.
type chainHeadSubscriber interface {
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
}

// TicketStore is a fixed-capacity, head-driven ticket registry.
type TicketStore struct {
	mu     sync.RWMutex
	ring   [TicketLookahead]Ticket
	filled [TicketLookahead]bool
	head   int    // index of the most recently written bucket
	nextID uint64 // monotonic ticket id counter

	sub      event.Subscription
	headCh   chan core.ChainHeadEvent
	quit     chan struct{}
	stopOnce sync.Once
}

// New constructs and starts a TicketStore subscribed to chain.SubscribeChainHeadEvent.
// The caller must invoke Stop() during shutdown.
func New(chain chainHeadSubscriber) *TicketStore {
	ts := &TicketStore{
		head:   -1,
		headCh: make(chan core.ChainHeadEvent, 16),
		quit:   make(chan struct{}),
	}
	ts.sub = chain.SubscribeChainHeadEvent(ts.headCh)
	go ts.loop()
	log.Info("Initialized blob-streaming ticket store", "lookahead", TicketLookahead, "blobCount", FixedBlobCount)
	return ts
}

// Stop terminates the background goroutine and unsubscribes from chain events.
// Safe to call multiple times.
func (ts *TicketStore) Stop() {
	ts.stopOnce.Do(func() {
		ts.sub.Unsubscribe()
		close(ts.quit)
	})
}

// ActiveTickets returns a copy of the currently live tickets, oldest first.
// The slice is safe for the caller to retain and mutate.
func (ts *TicketStore) ActiveTickets() []Ticket {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	if ts.head < 0 {
		return nil
	}
	out := make([]Ticket, 0, TicketLookahead)
	// Walk the ring oldest-first: start one past head (the oldest slot) and wrap.
	for i := 1; i <= TicketLookahead; i++ {
		idx := (ts.head + i) % TicketLookahead
		if ts.filled[idx] {
			out = append(out, ts.ring[idx])
		}
	}
	return out
}

func (ts *TicketStore) loop() {
	for {
		select {
		case ev := <-ts.headCh:
			ts.onHead(ev.Header.Time)
		case <-ts.quit:
			return
		}
	}
}

func (ts *TicketStore) onHead(timestamp uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	next := (ts.head + 1) % TicketLookahead
	ts.ring[next] = Ticket{
		ID:               ts.nextID,
		SellingTimestamp: timestamp,
		Owner:            FixedOwner,
		BlobCount:        FixedBlobCount,
		BLSPubkey:        FixedBLSPubkey,
	}
	ts.filled[next] = true
	ts.head = next
	ts.nextID++
}
