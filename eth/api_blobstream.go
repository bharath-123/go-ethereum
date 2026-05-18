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

package eth

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/blobstream/ticketstore"
)

// BlobStreamAPI exposes EIP-Blob-Streaming POC state over JSON-RPC.
type BlobStreamAPI struct {
	eth *Ethereum
}

// NewBlobStreamAPI creates a new BlobStreamAPI bound to the given full node.
func NewBlobStreamAPI(eth *Ethereum) *BlobStreamAPI {
	return &BlobStreamAPI{eth: eth}
}

// TicketInfo is the JSON shape returned for each active ticket. The field names
// match the TicketInfoV1 object planned for engine_forkchoiceUpdatedV5.
type TicketInfo struct {
	TicketID              hexutil.Uint64 `json:"ticketId"`
	SellingBlockTimestamp hexutil.Uint64 `json:"sellingBlockTimestamp"`
	Owner                 common.Address `json:"owner"`
	BLSPubkey             hexutil.Bytes  `json:"blsPubkey"`
	BlobCount             hexutil.Uint64 `json:"blobCount"`
}

// ActiveTickets returns the set of currently live blob-streaming tickets,
// oldest first. The set is bounded by ticketstore.TicketLookahead.
func (api *BlobStreamAPI) ActiveTickets() []TicketInfo {
	tickets := api.eth.ticketStore.ActiveTickets()
	out := make([]TicketInfo, len(tickets))
	for i, t := range tickets {
		out[i] = ticketToInfo(t)
	}
	return out
}

func ticketToInfo(t ticketstore.Ticket) TicketInfo {
	pubkey := make(hexutil.Bytes, len(t.BLSPubkey))
	copy(pubkey, t.BLSPubkey[:])
	return TicketInfo{
		TicketID:              hexutil.Uint64(t.ID),
		SellingBlockTimestamp: hexutil.Uint64(t.SellingTimestamp),
		Owner:                 t.Owner,
		BLSPubkey:             pubkey,
		BlobCount:             hexutil.Uint64(t.BlobCount),
	}
}
