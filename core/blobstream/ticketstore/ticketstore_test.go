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

package ticketstore

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// fakeChain feeds synthetic ChainHeadEvents to the store.
type fakeChain struct {
	feed event.Feed
}

func (f *fakeChain) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return f.feed.Subscribe(ch)
}

func (f *fakeChain) emit(t *testing.T, timestamp uint64) {
	t.Helper()
	f.feed.Send(core.ChainHeadEvent{Header: &types.Header{Time: timestamp}})
}

// waitForLatestID polls until the most recent ticket has the expected ID,
// then returns the full active set. Avoids racing the head event goroutine.
func waitForLatestID(t *testing.T, ts *TicketStore, wantID uint64) []Ticket {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := ts.ActiveTickets()
		if len(got) > 0 && got[len(got)-1].ID == wantID {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for latest ID %d, got %+v", wantID, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTicketStoreFillsRing(t *testing.T) {
	chain := &fakeChain{}
	ts := New(chain)
	defer ts.Stop()

	// Emit fewer events than the ring capacity; we should see exactly that many tickets.
	const count = TicketLookahead - 2
	for i := range count {
		chain.emit(t, uint64(1000+i))
	}
	tickets := waitForLatestID(t, ts, uint64(count-1))
	if len(tickets) != count {
		t.Fatalf("got %d tickets, want %d", len(tickets), count)
	}

	for i, tk := range tickets {
		if tk.ID != uint64(i) {
			t.Errorf("ticket %d: ID = %d, want %d", i, tk.ID, i)
		}
		if tk.SellingTimestamp != uint64(1000+i) {
			t.Errorf("ticket %d: timestamp = %d, want %d", i, tk.SellingTimestamp, 1000+i)
		}
		if tk.Owner != FixedOwner {
			t.Errorf("ticket %d: owner = %x, want %x", i, tk.Owner, FixedOwner)
		}
		if tk.BlobCount != FixedBlobCount {
			t.Errorf("ticket %d: blobCount = %d, want %d", i, tk.BlobCount, FixedBlobCount)
		}
		if tk.BLSPubkey != FixedBLSPubkey {
			t.Errorf("ticket %d: BLS pubkey mismatch", i)
		}
	}
}

func TestTicketStoreEvictsOldTickets(t *testing.T) {
	chain := &fakeChain{}
	ts := New(chain)
	defer ts.Stop()

	// Emit more events than the ring capacity. The oldest ones must be evicted.
	total := TicketLookahead + 3
	for i := range total {
		chain.emit(t, uint64(2000+i))
	}
	tickets := waitForLatestID(t, ts, uint64(total-1))
	if len(tickets) != TicketLookahead {
		t.Fatalf("got %d tickets, want %d", len(tickets), TicketLookahead)
	}

	// We expect tickets with IDs [total-TicketLookahead .. total-1], oldest first.
	firstID := uint64(total - TicketLookahead)
	for i, tk := range tickets {
		wantID := firstID + uint64(i)
		if tk.ID != wantID {
			t.Errorf("ticket %d: ID = %d, want %d", i, tk.ID, wantID)
		}
		wantTS := uint64(2000) + wantID
		if tk.SellingTimestamp != wantTS {
			t.Errorf("ticket %d: timestamp = %d, want %d", i, tk.SellingTimestamp, wantTS)
		}
	}
}

func TestTicketStoreStopIsIdempotent(t *testing.T) {
	chain := &fakeChain{}
	ts := New(chain)
	ts.Stop()
	ts.Stop() // must not panic
}
