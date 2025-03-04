package optimistic

import (
	auctionGrpc "buf.build/gen/go/astria/execution-apis/grpc/go/astria/auction/v1alpha1/auctionv1alpha1grpc"
	optimisticExecutionGrpc "buf.build/gen/go/astria/execution-apis/grpc/go/astria/optimistic_execution/v1alpha1/optimistic_executionv1alpha1grpc"
	auctionPb "buf.build/gen/go/astria/execution-apis/protocolbuffers/go/astria/auction/v1alpha1"
	astriaPb "buf.build/gen/go/astria/execution-apis/protocolbuffers/go/astria/execution/v1"
	optimisticExecutionPb "buf.build/gen/go/astria/execution-apis/protocolbuffers/go/astria/optimistic_execution/v1alpha1"
	sequencerblockv1 "buf.build/gen/go/astria/sequencerblock-apis/protocolbuffers/go/astria/sequencerblock/v1"
	"context"
	"errors"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/grpc/shared"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/miner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"io"
	"math/big"
	"sync/atomic"
	"time"
)

type AuctionServiceV1Alpha1 struct {
	optimisticExecutionGrpc.UnimplementedOptimisticExecutionServiceServer
	auctionGrpc.UnimplementedAuctionServiceServer

	sharedServiceContainer *shared.SharedServiceContainer

	currentAuctionBlock atomic.Pointer[[]byte]
}

var (
	executeOptimisticBlockRequestCount = metrics.GetOrRegisterCounter("astria/optimistic/execute_optimistic_block_requests", nil)
	executeOptimisticBlockSuccessCount = metrics.GetOrRegisterCounter("astria/optimistic/execute_optimistic_block_success", nil)
	optimisticBlockHeight              = metrics.GetOrRegisterGauge("astria/execution/optimistic_block_height", nil)
	txsStreamedCount                   = metrics.GetOrRegisterCounter("astria/optimistic/txs_streamed", nil)
	txsTipTooLow                       = metrics.GetOrRegisterCounter("astria/optimistic/txs_tip_too_low", nil)

	executionOptimisticBlockTimer = metrics.GetOrRegisterTimer("astria/optimistic/execute_optimistic_block_time", nil)
)

func NewAuctionServiceV1Alpha1(sharedServiceContainer *shared.SharedServiceContainer) *AuctionServiceV1Alpha1 {
	auctionService := &AuctionServiceV1Alpha1{
		sharedServiceContainer: sharedServiceContainer,
	}

	auctionService.currentAuctionBlock.Store(&[]byte{})

	return auctionService
}

func (o *AuctionServiceV1Alpha1) GetBidStream(_ *auctionPb.GetBidStreamRequest, stream auctionGrpc.AuctionService_GetBidStreamServer) error {
	log.Debug("GetBidStream called")

	pendingTxEventCh := make(chan core.NewTxsEvent)
	pendingTxEvent := o.eth().TxPool().SubscribeTransactions(pendingTxEventCh, false)
	defer pendingTxEvent.Unsubscribe()

	for {
		select {
		case pendingTxs := <-pendingTxEventCh:
			// get the optimistic block
			// this is an in-memory read, so there shouldn't be a lot of concerns on speed
			optimisticBlock := o.eth().BlockChain().CurrentOptimisticBlock()

			for _, pendingTx := range pendingTxs.Txs {
				bid := auctionPb.Bid{}

				totalCost := big.NewInt(0)
				effectiveTip, err := pendingTx.EffectiveGasTip(optimisticBlock.BaseFee)
				if err != nil {
					txsTipTooLow.Inc(1)
					log.Debug("effective tip is too low", "effectiveTip", effectiveTip.String())
					// don't throw an error but we should avoid streaming this bid
					continue
				}
				totalCost = totalCost.Mul(effectiveTip, big.NewInt(int64(pendingTx.Gas())))

				marshalledTxs := [][]byte{}
				marshalledTx, err := pendingTx.MarshalBinary()
				if err != nil {
					log.Error("error marshalling tx", "err", err)
					return status.Errorf(codes.Internal, shared.WrapError(err, "error marshalling tx").Error())
				}
				marshalledTxs = append(marshalledTxs, marshalledTx)

				bid.Fee = totalCost.Uint64()
				bid.Transactions = marshalledTxs
				bid.SequencerParentBlockHash = *o.currentAuctionBlock.Load()
				bid.RollupParentBlockHash = optimisticBlock.Hash().Bytes()

				txsStreamedCount.Inc(1)
				log.Debug("streaming bid", "tx", pendingTx.Hash(), "tip", bid.Fee, "parent_block_hash", common.BytesToHash(bid.GetRollupParentBlockHash()).String(), "sequencer_block_hash", common.BytesToHash(bid.GetSequencerParentBlockHash()).String())
				err = stream.Send(&auctionPb.GetBidStreamResponse{Bid: &bid})
				if err != nil {
					log.Error("error sending bid over stream", "err", err)
					return status.Error(codes.Internal, shared.WrapError(err, "error sending bid over stream").Error())
				}
			}

		case err := <-pendingTxEvent.Err():
			if err != nil {
				log.Error("error waiting for pending transactions", "err", err)
				return status.Error(codes.Internal, shared.WrapError(err, "error waiting for pending transactions").Error())
			} else {
				log.Debug("tx pool subscription closed")
				return status.Error(codes.Internal, "tx pool subscription closed")
			}

		case <-stream.Context().Done():
			log.Error("stream closed", "err", stream.Context().Err())
			return stream.Context().Err()
		}
	}
}

func (o *AuctionServiceV1Alpha1) ExecuteOptimisticBlockStream(stream optimisticExecutionGrpc.OptimisticExecutionService_ExecuteOptimisticBlockStreamServer) error {
	log.Debug("ExecuteOptimisticBlockStream called")

	mempoolClearingEventCh := make(chan core.NewMempoolCleared)
	mempoolClearingEvent := o.eth().TxPool().SubscribeMempoolClearance(mempoolClearingEventCh)
	defer mempoolClearingEvent.Unsubscribe()

	for {
		msg, err := stream.Recv()
		// stream has been closed
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, shared.WrapError(err, "error receiving optimistic block stream").Error())
		}

		executeOptimisticBlockRequestCount.Inc(1)

		baseBlock := msg.GetBaseBlock()

		// execute the optimistic block and wait for the mempool clearing event
		optimisticBlock, err := o.ExecuteOptimisticBlock(stream.Context(), baseBlock)
		if err != nil {
			return status.Errorf(codes.Internal, shared.WrapError(err, "failed to execute optimistic block").Error())
		}
		optimisticBlockHash := common.BytesToHash(optimisticBlock.Hash)

		// listen to the mempool clearing event and send the response back to the auctioneer when the mempool is cleared
		select {
		case event := <-mempoolClearingEventCh:
			log.Debug("mempool cleared after optimistic block execution", "block_hash", optimisticBlockHash.String(), "new_head", event.NewHead.Hash().String())
			if event.NewHead.Hash() != optimisticBlockHash {
				log.Error("mempool not cleared after optimistic block execution", "expected_block_hash", optimisticBlockHash.String(), "actual_block_hash", event.NewHead.Hash().String())
				return status.Error(codes.Internal, "failed to clear mempool after optimistic block execution")
			}
			o.currentAuctionBlock.Store(&baseBlock.SequencerBlockHash)
			executeOptimisticBlockSuccessCount.Inc(1)
			log.Debug("sending optimistic block response", "block_hash", optimisticBlockHash.String(), "base_block_hash", common.BytesToHash(baseBlock.SequencerBlockHash).String())
			err = stream.Send(&optimisticExecutionPb.ExecuteOptimisticBlockStreamResponse{
				Block:                  optimisticBlock,
				BaseSequencerBlockHash: baseBlock.SequencerBlockHash,
			})
			if err != nil {
				log.Error("error sending optimistic block response", "err", err)
				return status.Error(codes.Internal, shared.WrapError(err, "error sending optimistic block response").Error())
			}
		case <-time.After(500 * time.Millisecond):
			log.Error("timed out waiting for mempool to clear after optimistic block execution")
			return status.Error(codes.DeadlineExceeded, "timed out waiting for mempool to clear after optimistic block execution")
		case err := <-mempoolClearingEvent.Err():
			if err != nil {
				log.Error("error waiting for mempool clearing event", "err", err)
				return status.Errorf(codes.Internal, shared.WrapError(err, "error waiting for mempool clearing event").Error())
			} else {
				log.Error("mempool clearance subscription closed")
				return status.Error(codes.Internal, "mempool clearance subscription closed")
			}
		case <-stream.Context().Done():
			log.Error("stream closed", "err", stream.Context().Err())
			return stream.Context().Err()
		}
	}
}

func (o *AuctionServiceV1Alpha1) ExecuteOptimisticBlock(ctx context.Context, req *optimisticExecutionPb.BaseBlock) (*astriaPb.Block, error) {
	// we need to execute the optimistic block
	log.Debug("ExecuteOptimisticBlock called", "timestamp", req.Timestamp, "sequencer_block_hash", common.BytesToHash(req.SequencerBlockHash).String())

	// Deliberately called after lock, to more directly measure the time spent executing
	executionStart := time.Now()
	defer executionOptimisticBlockTimer.UpdateSince(executionStart)

	if err := validateStaticExecuteOptimisticBlockRequest(req); err != nil {
		log.Error("ExecuteOptimisticBlock called with invalid BaseBlock", "err", err)
		return nil, status.Error(codes.InvalidArgument, shared.WrapError(err, "invalid BaseBlock").Error())
	}

	if !o.syncMethodsCalled() {
		return nil, status.Error(codes.PermissionDenied, "Cannot execute block until GetGenesisInfo && GetCommitmentState methods are called")
	}

	softBlock := o.bc().CurrentSafeBlock()

	nextFeeRecipient := o.nextFeeRecipient()

	// the height that this block will be at
	height := o.bc().CurrentBlock().Number.Uint64() + 1

	txsToProcess := o.unbundleRollupDataTransactions(req.Transactions, height, softBlock.Hash().Bytes())

	// Build a payload to add to the chain
	payloadAttributes := &miner.BuildPayloadArgs{
		Parent:                softBlock.Hash(),
		Timestamp:             uint64(req.GetTimestamp().GetSeconds()),
		Random:                common.Hash{},
		FeeRecipient:          nextFeeRecipient,
		OverrideTransactions:  txsToProcess,
		IsOptimisticExecution: true,
	}
	payload, err := o.eth().Miner().BuildPayload(payloadAttributes)
	if err != nil {
		log.Error("failed to build payload", "err", err)
		return nil, status.Errorf(codes.InvalidArgument, shared.WrapError(err, "failed to build payload").Error())
	}

	block, err := engine.ExecutableDataToBlock(*payload.Resolve().ExecutionPayload, nil, nil)
	if err != nil {
		log.Error("failed to convert executable data to block", err)
		return nil, status.Error(codes.Internal, shared.WrapError(err, "failed to convert executable data to block").Error())
	}

	// this will insert the optimistic block into the chain and persist its state without
	// setting it as the HEAD.
	err = o.bc().InsertBlockWithoutSetHead(block)
	if err != nil {
		log.Error("failed to insert block to chain", "hash", block.Hash(), "prevHash", block.ParentHash(), "err", err)
		return nil, status.Error(codes.Internal, shared.WrapError(err, "failed to insert block to chain").Error())
	}

	// we store a pointer to the optimistic block in the chain so that we can use it
	// to retrieve the state of the optimistic block
	// this method also sends an event which indicates that a new optimistic block has been set
	// the mempool clearing logic is triggered when this event is received
	o.bc().SetOptimistic(block)

	res := &astriaPb.Block{
		Number:          uint32(block.NumberU64()),
		Hash:            block.Hash().Bytes(),
		ParentBlockHash: block.ParentHash().Bytes(),
		Timestamp: &timestamppb.Timestamp{
			Seconds: int64(block.Time()),
		},
	}

	optimisticBlockHeight.Update(int64(block.NumberU64()))

	log.Info("ExecuteOptimisticBlock completed", "block_num", res.Number, "timestamp", res.Timestamp)

	return res, nil
}

func (o *AuctionServiceV1Alpha1) eth() *eth.Ethereum {
	return o.sharedServiceContainer.Eth()
}

func (o *AuctionServiceV1Alpha1) bc() *core.BlockChain {
	return o.sharedServiceContainer.Bc()
}

func (o *AuctionServiceV1Alpha1) nextFeeRecipient() common.Address {
	return o.sharedServiceContainer.NextFeeRecipient()
}

func (o *AuctionServiceV1Alpha1) syncMethodsCalled() bool {
	return o.sharedServiceContainer.SyncMethodsCalled()
}

func (o *AuctionServiceV1Alpha1) unbundleRollupDataTransactions(txs []*sequencerblockv1.RollupData, height uint64, prevBlockHash []byte) types.Transactions {
	return o.sharedServiceContainer.UnbundleRollupDataTransactions(txs, height, prevBlockHash)
}
