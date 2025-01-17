package optimistic

import (
	"github.com/ethereum/go-ethereum/grpc/shared"
	"testing"
)

func SetupAuctionService(t *testing.T, sharedService *shared.SharedServiceContainer) *AuctionServiceV1Alpha1 {
	t.Helper()

	return NewAuctionServiceV1Alpha1(sharedService)
}
