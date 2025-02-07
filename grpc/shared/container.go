package shared

import (
	auctionv1alpha1 "buf.build/gen/go/astria/execution-apis/protocolbuffers/go/astria/auction/v1alpha1"
	sequencerblockv1 "buf.build/gen/go/astria/sequencerblock-apis/protocolbuffers/go/astria/sequencerblock/v1"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/golang/protobuf/proto"
	"sync"
	"sync/atomic"
)

type SharedServiceContainer struct {
	eth *eth.Ethereum
	bc  *core.BlockChain

	commitmentUpdateLock sync.Mutex // Lock for the forkChoiceUpdated method
	blockExecutionLock   sync.Mutex // Lock for the NewPayload method

	genesisInfoCalled        bool
	getCommitmentStateCalled bool

	bridgeAddresses     map[string]*params.AstriaBridgeAddressConfig // astria bridge addess to config for that bridge account
	bridgeAllowedAssets map[string]struct{}                          // a set of allowed asset IDs structs are left empty

	// auctioneer address is a bech32m address
	auctioneerAddress atomic.Pointer[string]
	// this is set to the height at which the first auctioneer address is activated.
	// before `auctioneerStartHeight` any incoming `Allocations` will be ignored
	auctioneerStartHeight uint64

	nextFeeRecipient atomic.Pointer[common.Address] // Fee recipient for the next block
}

func NewSharedServiceContainer(eth *eth.Ethereum) (*SharedServiceContainer, error) {
	bc := eth.BlockChain()

	if bc.Config().AstriaRollupName == "" {
		return nil, errors.New("rollup name not set")
	}

	if bc.Config().AstriaSequencerInitialHeight == 0 {
		return nil, errors.New("sequencer initial height not set")
	}

	if bc.Config().AstriaCelestiaInitialHeight == 0 {
		return nil, errors.New("celestia initial height not set")
	}

	if bc.Config().AstriaCelestiaHeightVariance == 0 {
		return nil, errors.New("celestia height variance not set")
	}

	bridgeAddresses := make(map[string]*params.AstriaBridgeAddressConfig)
	bridgeAllowedAssets := make(map[string]struct{})
	if bc.Config().AstriaBridgeAddressConfigs == nil {
		log.Warn("bridge addresses not set")
	} else {
		nativeBridgeSeen := false
		for _, cfg := range bc.Config().AstriaBridgeAddressConfigs {
			err := cfg.Validate(bc.Config().AstriaSequencerAddressPrefix)
			if err != nil {
				return nil, fmt.Errorf("invalid bridge address config: %w", err)
			}

			if cfg.Erc20Asset == nil {
				if nativeBridgeSeen {
					return nil, errors.New("only one native bridge address is allowed")
				}
				nativeBridgeSeen = true
			}

			if cfg.Erc20Asset != nil && cfg.SenderAddress == (common.Address{}) {
				return nil, errors.New("astria bridge sender address must be set for bridged ERC20 assets")
			}

			bridgeCfg := cfg
			bridgeAddresses[cfg.BridgeAddress] = &bridgeCfg
			bridgeAllowedAssets[cfg.AssetDenom] = struct{}{}
			if cfg.Erc20Asset == nil {
				log.Info("bridge for sequencer native asset initialized", "bridgeAddress", cfg.BridgeAddress, "assetDenom", cfg.AssetDenom)
			} else {
				log.Info("bridge for ERC20 asset initialized", "bridgeAddress", cfg.BridgeAddress, "assetDenom", cfg.AssetDenom, "contractAddress", cfg.Erc20Asset.ContractAddress)
			}
		}
	}

	// To decrease compute cost, we identify the next fee recipient at the start
	// and update it as we execute blocks.
	nextFeeRecipient := common.Address{}
	nextBlock := uint32(bc.CurrentBlock().Number.Int64()) + 1
	if bc.Config().AstriaFeeCollectors == nil {
		log.Warn("fee asset collectors not set, assets will be burned")
	} else {
		maxHeightCollectorMatch := uint32(0)
		for height, collector := range bc.Config().AstriaFeeCollectors {
			if height <= nextBlock && height > maxHeightCollectorMatch {
				maxHeightCollectorMatch = height
				nextFeeRecipient = collector
			}
		}
	}

	auctioneerAddress := ""
	// the height at which the first auctioneer address is activated.
	// if auctioneer addresses are not set, this height will be set to ^uint64(0) which is the max value of uint64
	// this will cause all allocations to be ignored until auctioneer address is set
	auctioneerStartHeight := ^uint64(0)
	if bc.Config().AstriaAuctioneerAddresses == nil {
		log.Warn("auctioneer addresses not set. allocations will be ignored until auctioneer address is set")
	} else {

		maxHeightCollectorMatch := uint32(0)
		for height, address := range bc.Config().AstriaAuctioneerAddresses {
			if height <= nextBlock && height > maxHeightCollectorMatch {
				maxHeightCollectorMatch = height

				if err := ValidateBech32mAddress(address, bc.Config().AstriaSequencerAddressPrefix); err != nil {
					return nil, WrapError(err, fmt.Sprintf("auctioneer address %s at height %d is invalid", address, height))
				}
				auctioneerAddress = address
			}
		}

		for height := range bc.Config().AstriaAuctioneerAddresses {
			if uint64(height) < auctioneerStartHeight {
				auctioneerStartHeight = uint64(height)
			}
		}
	}

	sharedServiceContainer := &SharedServiceContainer{
		eth:                   eth,
		bc:                    bc,
		bridgeAddresses:       bridgeAddresses,
		bridgeAllowedAssets:   bridgeAllowedAssets,
		auctioneerStartHeight: auctioneerStartHeight,
	}

	sharedServiceContainer.SetAuctioneerAddress(auctioneerAddress)
	sharedServiceContainer.SetNextFeeRecipient(nextFeeRecipient)

	return sharedServiceContainer, nil
}

// `UnbundleRollupDataTransactions` takes in a list of rollup data transactions and returns the corresponding
// list of Ethereum transactions.
// If it finds any `Allocation` type, it validates it and places the txs in the `Allocation` at the top of block.
// Note that `UnbundleRollupDataTransactions` does not return any error on an invalid `RollupData`. If we find any invalid
// `RollupData` we log the error and continue processing the rest of the transactions. We do not want to break control flow
// for an invalid transaction as we do not want to interrupt block production.
func (s *SharedServiceContainer) UnbundleRollupDataTransactions(txs []*sequencerblockv1.RollupData, height uint64, prevBlockHash []byte) types.Transactions {

	processedTxs := types.Transactions{}
	allocationTxs := types.Transactions{}

	foundAllocation := false
	allocation := &auctionv1alpha1.Allocation{}

	for _, tx := range txs {

		switch {
		case tx.GetDeposit() != nil:
			depositTx, err := validateAndUnmarshalDepositTx(tx.GetDeposit(), height, s.BridgeAddresses(), s.BridgeAllowedAssets())
			if err != nil {
				log.Error("failed to validate and unmarshal deposit tx", "error", err)
				continue
			}
			processedTxs = append(processedTxs, depositTx)
		case !foundAllocation && height >= s.AuctioneerStartHeight() && proto.Unmarshal(tx.GetSequencedData(), allocation) == nil:
			unmarshalledAllocationTxs, err := unmarshalAllocationTxs(allocation, prevBlockHash, s.AuctioneerAddress(), s.Bc().Config().AstriaSequencerAddressPrefix)
			if err != nil {
				log.Error("failed to unmarshall allocation transactions", "error", err)
				continue
			}
			// we found the valid allocation, we should ignore any other allocations in this block
			allocationTxs = unmarshalledAllocationTxs
			foundAllocation = true
		default:
			ethtx, err := validateAndUnmarshalSequenceAction(tx)
			if err != nil {
				log.Error("failed to unmarshall sequence action", "error", err)
				continue
			}
			processedTxs = append(processedTxs, ethtx)
		}

		//if deposit := tx.GetDeposit(); deposit != nil {
		//	depositTx, err := validateAndUnmarshalDepositTx(deposit, height, s.BridgeAddresses(), s.BridgeAllowedAssets())
		//	if err != nil {
		//		log.Error("failed to validate and unmarshal deposit tx", "error", err)
		//		continue
		//	}
		//
		//	processedTxs = append(processedTxs, depositTx)
		//} else {
		//	sequenceData := tx.GetSequencedData()
		//
		//	if !foundAllocation && height >= s.AuctioneerStartHeight() {
		//		// check if sequence data is of type Allocation.
		//		// we should expect only one valid allocation per block. duplicate allocations should be ignored.
		//		allocation := &auctionv1alpha1.Allocation{}
		//		err := proto.Unmarshal(sequenceData, allocation)
		//		if err == nil {
		//			unmarshalledAllocationTxs, err := unmarshalAllocationTxs(allocation, prevBlockHash, s.AuctioneerAddress(), s.Bc().Config().AstriaSequencerAddressPrefix)
		//			if err != nil {
		//				log.Error("failed to unmarshall allocation transactions", "error", err)
		//				continue
		//			}
		//
		//			// we found the valid allocation, we should ignore any other allocations in this block
		//			allocationTxs = unmarshalledAllocationTxs
		//			foundAllocation = true
		//		} else {
		//			ethtx, err := validateAndUnmarshalSequenceAction(tx)
		//			if err != nil {
		//				log.Error("failed to unmarshall sequence action", "error", err)
		//				continue
		//			}
		//			processedTxs = append(processedTxs, ethtx)
		//		}
		//	} else {
		//		ethtx, err := validateAndUnmarshalSequenceAction(tx)
		//		if err != nil {
		//			log.Error("failed to unmarshall sequence action", "error", err)
		//			continue
		//		}
		//		processedTxs = append(processedTxs, ethtx)
		//	}
		//}
	}

	// prepend allocation txs to processedTxs
	processedTxs = append(allocationTxs, processedTxs...)

	return processedTxs
}

func (s *SharedServiceContainer) SyncMethodsCalled() bool {
	return s.genesisInfoCalled && s.getCommitmentStateCalled
}

func (s *SharedServiceContainer) Bc() *core.BlockChain {
	return s.bc
}

func (s *SharedServiceContainer) Eth() *eth.Ethereum {
	return s.eth
}

func (s *SharedServiceContainer) SetGenesisInfoCalled(value bool) {
	s.genesisInfoCalled = value
}

func (s *SharedServiceContainer) GenesisInfoCalled() bool {
	return s.genesisInfoCalled
}

func (s *SharedServiceContainer) SetGetCommitmentStateCalled(value bool) {
	s.getCommitmentStateCalled = value
}

func (s *SharedServiceContainer) CommitmentStateCalled() bool {
	return s.getCommitmentStateCalled
}

func (s *SharedServiceContainer) CommitmentUpdateLock() *sync.Mutex {
	return &s.commitmentUpdateLock
}

func (s *SharedServiceContainer) BlockExecutionLock() *sync.Mutex {
	return &s.blockExecutionLock
}

func (s *SharedServiceContainer) NextFeeRecipient() common.Address {
	return *s.nextFeeRecipient.Load()
}

func (s *SharedServiceContainer) SetNextFeeRecipient(nextFeeRecipient common.Address) {
	s.nextFeeRecipient.Store(&nextFeeRecipient)
}

func (s *SharedServiceContainer) BridgeAddresses() map[string]*params.AstriaBridgeAddressConfig {
	return s.bridgeAddresses
}

func (s *SharedServiceContainer) BridgeAllowedAssets() map[string]struct{} {
	return s.bridgeAllowedAssets
}

func (s *SharedServiceContainer) AuctioneerStartHeight() uint64 {
	return s.auctioneerStartHeight
}

func (s *SharedServiceContainer) AuctioneerAddress() string {
	return *s.auctioneerAddress.Load()
}

func (s *SharedServiceContainer) SetAuctioneerAddress(newAddress string) {
	s.auctioneerAddress.Store(&newAddress)
}
