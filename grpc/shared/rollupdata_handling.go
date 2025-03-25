package shared

import (
	auctionv1alpha1 "buf.build/gen/go/astria/execution-apis/protocolbuffers/go/astria/auction/v1alpha1"
	primitivev1 "buf.build/gen/go/astria/primitives/protocolbuffers/go/astria/primitive/v1"
	sequencerblockv1 "buf.build/gen/go/astria/sequencerblock-apis/protocolbuffers/go/astria/sequencerblock/v1"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"math/big"
	"time"
)

var (
	successfulUnbundledAllocations      = metrics.GetOrRegisterGauge("astria/optimistic/successful_unbundled_allocations", nil)
	allocationsWithInvalidPrevBlockHash = metrics.GetOrRegisterGauge("astria/optimistic/allocations_with_invalid_prev_block_hash", nil)
	allocationsWithInvalidPubKey        = metrics.GetOrRegisterGauge("astria/optimistic/allocations_with_invalid_pub_key", nil)
	allocationsWithInvalidSignature     = metrics.GetOrRegisterGauge("astria/optimistic/allocations_with_invalid_signature", nil)

	allocationUnbundlingTimer = metrics.GetOrRegisterTimer("astria/optimistic/allocation_unbundling_time", nil)
)

func WrapError(err error, msg string) error {
	return fmt.Errorf("%s: %w", msg, err)
}

func protoU128ToBigInt(u128 *primitivev1.Uint128) *big.Int {
	lo := big.NewInt(0).SetUint64(u128.Lo)
	hi := big.NewInt(0).SetUint64(u128.Hi)
	hi.Lsh(hi, 64)
	return lo.Add(lo, hi)
}

func validateAndUnmarshalDepositTx(
	deposit *sequencerblockv1.Deposit,
	height uint64,
	bridgeAddresses map[string]*params.AstriaBridgeAddressConfig,
	bridgeAllowedAssets map[string]struct{}) (*types.Transaction, error) {
	bridgeAddress := deposit.BridgeAddress.GetBech32M()
	bac, ok := bridgeAddresses[bridgeAddress]
	if !ok {
		return nil, fmt.Errorf("unknown bridge address: %s", bridgeAddress)
	}

	if height < uint64(bac.StartHeight) {
		return nil, fmt.Errorf("bridging asset %s from bridge %s not allowed before height %d", bac.AssetDenom, bridgeAddress, bac.StartHeight)
	}

	if _, ok := bridgeAllowedAssets[deposit.Asset]; !ok {
		return nil, fmt.Errorf("disallowed asset %s in deposit tx", deposit.Asset)
	}

	if deposit.Asset != bac.AssetDenom {
		return nil, fmt.Errorf("asset %s does not match bridge address %s asset", deposit.Asset, bridgeAddress)
	}

	recipient := common.HexToAddress(deposit.DestinationChainAddress)
	amount := bac.ScaledDepositAmount(protoU128ToBigInt(deposit.Amount))

	if bac.Erc20Asset != nil {
		log.Debug("creating deposit tx to mint ERC20 asset", "token", bac.AssetDenom, "erc20Address", bac.Erc20Asset.ContractAddress)
		abi, err := contracts.AstriaBridgeableERC20MetaData.GetAbi()
		if err != nil {
			// this should never happen, as the abi is hardcoded in the contract bindings
			return nil, fmt.Errorf("failed to get abi for erc20 contract for asset %s: %w", bac.AssetDenom, err)
		}

		// pack arguments for calling the `mint` function on the ERC20 contract
		args := []interface{}{recipient, amount}
		calldata, err := abi.Pack("mint", args...)
		if err != nil {
			return nil, err
		}

		txdata := types.DepositTx{
			From:  bac.SenderAddress,
			Value: new(big.Int), // don't need to set this, as we aren't minting the native asset
			// mints cost ~14k gas, however this can vary based on existing storage, so we add a little extra as buffer.
			//
			// the fees are spent from the "bridge account" which is not actually a real account, but is instead some
			// address defined by consensus, so the gas cost is not actually deducted from any account.
			Gas:                    64000,
			To:                     &bac.Erc20Asset.ContractAddress,
			Data:                   calldata,
			SourceTransactionId:    *deposit.SourceTransactionId,
			SourceTransactionIndex: deposit.SourceActionIndex,
		}

		tx := types.NewTx(&txdata)
		return tx, nil
	}

	txdata := types.DepositTx{
		From:                   bac.SenderAddress,
		To:                     &recipient,
		Value:                  amount,
		Gas:                    0,
		SourceTransactionId:    *deposit.SourceTransactionId,
		SourceTransactionIndex: deposit.SourceActionIndex,
	}
	return types.NewTx(&txdata), nil
}

func validateAndUnmarshalSequenceAction(tx *sequencerblockv1.RollupData) (*types.Transaction, error) {
	ethTx := new(types.Transaction)
	err := ethTx.UnmarshalBinary(tx.GetSequencedData())
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sequenced data into transaction: %w. tx hash: %s", err, sha256.Sum256(tx.GetSequencedData()))
	}

	if ethTx.Type() == types.DepositTxType {
		return nil, fmt.Errorf("deposit tx not allowed in sequenced data. tx hash: %s", sha256.Sum256(tx.GetSequencedData()))
	}

	if ethTx.Type() == types.BlobTxType {
		return nil, fmt.Errorf("blob tx not allowed in sequenced data. tx hash: %s", sha256.Sum256(tx.GetSequencedData()))
	}

	return ethTx, nil
}

func unmarshalAllocationTxs(allocation *auctionv1alpha1.Allocation, prevBlockHash []byte, auctioneerBech32Address string, addressPrefix string) (types.Transactions, error) {
	unbundlingStart := time.Now()
	defer allocationUnbundlingTimer.UpdateSince(unbundlingStart)

	processedTxs := types.Transactions{}
	bid := &auctionv1alpha1.Bid{}

	unprocessedBid := allocation.GetBid()

	err := anypb.UnmarshalTo(unprocessedBid, bid, proto.UnmarshalOptions{
		Merge:        false,
		AllowPartial: false,
	})
	if err != nil {
		return nil, WrapError(err, "failed to unmarshal bid")
	}

	log.Debug("Found a potential allocation in the rollup data. Checking if it is valid.", "prevBlockHash", common.BytesToHash(prevBlockHash).String(), "auctioneerBech32Address", auctioneerBech32Address)

	if !bytes.Equal(bid.GetRollupParentBlockHash(), prevBlockHash) {
		allocationsWithInvalidPrevBlockHash.Inc(1)
		return nil, errors.New("prev block hash in allocation does not match the previous block hash")
	}

	publicKey := ed25519.PublicKey(allocation.GetPublicKey())
	bech32Address, err := EncodeFromPublicKey(addressPrefix, publicKey)
	if err != nil {
		return nil, WrapError(err, fmt.Sprintf("failed to encode public key to bech32m address: %s", publicKey))
	}

	if auctioneerBech32Address != bech32Address {
		allocationsWithInvalidPubKey.Inc(1)
		return nil, fmt.Errorf("address in allocation does not match auctioneer address. expected: %s, got: %s", auctioneerBech32Address, bech32Address)
	}

	message, err := proto.Marshal(bid)
	if err != nil {
		return nil, WrapError(err, "failed to marshal allocation to verify signature")
	}

	signature := allocation.GetSignature()
	if !ed25519.Verify(publicKey, message, signature) {
		allocationsWithInvalidSignature.Inc(1)
		return nil, fmt.Errorf("signature in allocation is invalid")
	}

	log.Debug("Allocation is valid. Unmarshalling the transactions in the bid.")
	// unmarshall the transactions in the bid
	for _, allocationTx := range bid.GetTransactions() {
		ethtx := new(types.Transaction)
		err := ethtx.UnmarshalBinary(allocationTx)
		if err != nil {
			return nil, WrapError(err, "failed to unmarshall allocation transaction")
		}
		processedTxs = append(processedTxs, ethtx)
	}

	successfulUnbundledAllocations.Inc(1)

	return processedTxs, nil
}
