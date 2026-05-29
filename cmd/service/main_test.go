package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xssnick/archive-manager/pkg/index"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/pkg/storage"
	"github.com/xssnick/tonutils-storage-provider/pkg/transport"
)

func TestDoLoopAdvancesFromBlockAfterProcessingMaster(t *testing.T) {
	withLoopTestEnv(t)
	*replicas = 0
	*noTx = true

	bag := testBagDetailed()
	preloadBags(t, []*storage.BagDetailed{bag})

	var providerRequests atomic.Int32
	srv := newLoopHTTPServer(t, bag.BagID, nil, &providerRequests)
	defer srv.Close()

	api := &fakeAPI{}
	var waitCalls int
	deps := loopDeps{
		wallet:     testWallet(tlb.MustFromTON("100")),
		storage:    &fakeStorage{},
		provider:   &fakeProvider{},
		api:        api,
		httpClient: srv.Client(),
		waitMaster: func(ctx context.Context, api ton.APIClientWrapped, minSeqno uint32) (*ton.BlockIDExt, error) {
			waitCalls++
			if minSeqno != 0 {
				t.Fatalf("unexpected min seqno: got %d", minSeqno)
			}
			return testMaster(100), nil
		},
		sendManyWait: func(ctx context.Context, wl loopWallet, api ton.APIClientWrapped, messages []*wallet.Message, minSeqno uint32) (*tlb.Transaction, *ton.BlockIDExt, error) {
			t.Fatalf("unexpected transaction send with %d messages", len(messages))
			return nil, nil, nil
		},
	}

	next, err := doLoopWithDeps(deps, srv.URL+"/index", srv.URL+"/providers", 0)
	if err != nil {
		t.Fatalf("doLoopWithDeps returned error: %v", err)
	}
	if next != 101 {
		t.Fatalf("next fromBlock mismatch: got %d, want 101", next)
	}
	if waitCalls != 1 {
		t.Fatalf("waitMaster calls mismatch: got %d, want 1", waitCalls)
	}
	if got := api.getProvidersCalls.Load(); got != 2 {
		t.Fatalf("get_providers calls mismatch: got %d, want 2", got)
	}
	if got := providerRequests.Load(); got != 1 {
		t.Fatalf("providers HTTP calls mismatch: got %d, want 1", got)
	}
}

func TestDoLoopKeepsFromBlockWhenFreshMasterUnavailable(t *testing.T) {
	withLoopTestEnv(t)

	errFreshMaster := errors.New("fresh master unavailable")
	var waitCalls int
	deps := loopDeps{
		api: &fakeAPI{},
		waitMaster: func(ctx context.Context, api ton.APIClientWrapped, minSeqno uint32) (*ton.BlockIDExt, error) {
			waitCalls++
			if minSeqno != 101 {
				t.Fatalf("unexpected min seqno: got %d, want 101", minSeqno)
			}
			return nil, errFreshMaster
		},
	}

	next, err := doLoopWithDeps(deps, "http://127.0.0.1:1/index", "http://127.0.0.1:1/providers", 101)
	if !errors.Is(err, errFreshMaster) {
		t.Fatalf("error mismatch: got %v, want %v", err, errFreshMaster)
	}
	if next != 101 {
		t.Fatalf("fromBlock changed despite stale master: got %d, want 101", next)
	}
	if waitCalls != 1 {
		t.Fatalf("waitMaster calls mismatch: got %d, want 1", waitCalls)
	}
}

func TestDoLoopTxTimeoutAdvancesToNextScannedBlock(t *testing.T) {
	withLoopTestEnv(t)
	*replicas = 1
	*noTx = false

	bag := testBagDetailed()
	preloadBags(t, []*storage.BagDetailed{bag})

	providerKey := testKey(0x44)
	var providerRequests atomic.Int32
	srv := newLoopHTTPServer(t, bag.BagID, [][]byte{providerKey}, &providerRequests)
	defer srv.Close()

	fProvider := &fakeProvider{rates: testAvailableRates()}

	var waitMins []uint32
	var sendCalls int
	deps := loopDeps{
		wallet:     testWallet(tlb.MustFromTON("100")),
		storage:    &fakeStorage{},
		provider:   fProvider,
		api:        &fakeAPI{},
		httpClient: srv.Client(),
		waitMaster: func(ctx context.Context, api ton.APIClientWrapped, minSeqno uint32) (*ton.BlockIDExt, error) {
			waitMins = append(waitMins, minSeqno)
			return testMaster(200), nil
		},
		sendManyWait: func(ctx context.Context, wl loopWallet, api ton.APIClientWrapped, messages []*wallet.Message, minSeqno uint32) (*tlb.Transaction, *ton.BlockIDExt, error) {
			sendCalls++
			if len(messages) != 1 {
				t.Fatalf("messages mismatch: got %d, want 1", len(messages))
			}
			if minSeqno != 200 {
				t.Fatalf("send min seqno mismatch: got %d, want 200", minSeqno)
			}
			return nil, nil, &txConfirmationTimeoutError{nextSeqno: 205}
		},
	}

	next, err := doLoopWithDeps(deps, srv.URL+"/index", srv.URL+"/providers", 0)
	if err != nil {
		t.Fatalf("doLoopWithDeps returned error: %v", err)
	}
	if next != 205 {
		t.Fatalf("next fromBlock mismatch: got %d, want 205", next)
	}
	if sendCalls != 1 {
		t.Fatalf("send calls mismatch: got %d, want 1", sendCalls)
	}
	if got := fProvider.ratesCalls.Load(); got != 1 {
		t.Fatalf("rates calls mismatch: got %d, want 1", got)
	}
	if len(waitMins) != 2 || waitMins[0] != 0 || waitMins[1] != 200 {
		t.Fatalf("wait min seqnos mismatch: got %v, want [0 200]", waitMins)
	}
}

func TestDoLoopTxSendErrorReturnsNextBlockCheckpoint(t *testing.T) {
	withLoopTestEnv(t)
	*replicas = 1
	*noTx = false

	bag := testBagDetailed()
	preloadBags(t, []*storage.BagDetailed{bag})

	providerKey := testKey(0x44)
	var providerRequests atomic.Int32
	srv := newLoopHTTPServer(t, bag.BagID, [][]byte{providerKey}, &providerRequests)
	defer srv.Close()

	errSend := errors.New("send failed")
	deps := loopDeps{
		wallet:     testWallet(tlb.MustFromTON("100")),
		storage:    &fakeStorage{},
		provider:   &fakeProvider{rates: testAvailableRates()},
		api:        &fakeAPI{},
		httpClient: srv.Client(),
		waitMaster: func(ctx context.Context, api ton.APIClientWrapped, minSeqno uint32) (*ton.BlockIDExt, error) {
			return testMaster(200), nil
		},
		sendManyWait: func(ctx context.Context, wl loopWallet, api ton.APIClientWrapped, messages []*wallet.Message, minSeqno uint32) (*tlb.Transaction, *ton.BlockIDExt, error) {
			return nil, nil, errSend
		},
	}

	next, err := doLoopWithDeps(deps, srv.URL+"/index", srv.URL+"/providers", 0)
	if !errors.Is(err, errSend) {
		t.Fatalf("error mismatch: got %v, want %v", err, errSend)
	}
	if next != 201 {
		t.Fatalf("next fromBlock mismatch: got %d, want 201", next)
	}
}

func withLoopTestEnv(t *testing.T) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	oldLimitBags := *limitBags
	oldLimitProviders := *limitProviders
	oldReplicas := *replicas
	oldMaxBagsPerProvider := *maxBagsPerProvider
	oldEnableStats := *enableStats
	oldNoTx := *noTx
	oldNoRemoveBag := *noRemoveBag
	oldContractBalance := contractBalance
	oldGasFeeAdd := gasFeeAdd
	oldMaxPerMB := maxPerMB
	oldMinRewardToVerify := minRewardToVerify
	oldAddedProviders := addedProviders

	*limitBags = 10
	*limitProviders = 100
	*replicas = 0
	*maxBagsPerProvider = 10
	*enableStats = false
	*noTx = true
	*noRemoveBag = true
	contractBalance = tlb.MustFromTON("1")
	gasFeeAdd = tlb.MustFromTON("0.05")
	maxPerMB = tlb.MustFromTON("0.00015")
	minRewardToVerify = tlb.MustFromTON("0.055")
	addedProviders = make(map[string]time.Time)

	t.Cleanup(func() {
		*limitBags = oldLimitBags
		*limitProviders = oldLimitProviders
		*replicas = oldReplicas
		*maxBagsPerProvider = oldMaxBagsPerProvider
		*enableStats = oldEnableStats
		*noTx = oldNoTx
		*noRemoveBag = oldNoRemoveBag
		contractBalance = oldContractBalance
		gasFeeAdd = oldGasFeeAdd
		maxPerMB = oldMaxPerMB
		minRewardToVerify = oldMinRewardToVerify
		addedProviders = oldAddedProviders
	})
}

func newLoopHTTPServer(t *testing.T, bagID string, providerKeys [][]byte, providerRequests *atomic.Int32) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/index", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(index.Index{
			Blocks: []index.BlockSet{{Bag: bagID}},
		}); err != nil {
			t.Errorf("failed to write index response: %v", err)
		}
	})
	mux.HandleFunc("/providers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected providers method: %s", r.Method)
		}
		providerRequests.Add(1)

		list := make([]map[string]string, 0, len(providerKeys))
		for _, key := range providerKeys {
			list = append(list, map[string]string{"pubkey": hex.EncodeToString(key)})
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"providers": list}); err != nil {
			t.Errorf("failed to write providers response: %v", err)
		}
	})

	return httptest.NewServer(mux)
}

func preloadBags(t *testing.T, details []*storage.BagDetailed) {
	t.Helper()

	data, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("bags.json", data, 0644); err != nil {
		t.Fatal(err)
	}
}

func testBagDetailed() *storage.BagDetailed {
	bagID := hex.EncodeToString(testKey(0x11))
	merkleHash := hex.EncodeToString(testKey(0x22))

	return &storage.BagDetailed{
		Bag: storage.Bag{
			BagID:        bagID,
			HeaderLoaded: true,
		},
		PieceSize:  1024,
		BagSize:    1024 * 1024,
		MerkleHash: merkleHash,
	}
}

func testWallet(balance tlb.Coins) *fakeWallet {
	return &fakeWallet{
		addr:    address.NewAddress(0, 0, testKey(0x33)),
		balance: balance,
	}
}

func testAvailableRates() *transport.StorageRatesResponse {
	return &transport.StorageRatesResponse{
		Available:        true,
		RatePerMBDay:     tlb.MustFromTON("0.00001").Nano().Bytes(),
		MinBounty:        tlb.MustFromTON("0.01").Nano().Bytes(),
		SpaceAvailableMB: 2,
		MinSpan:          60,
		MaxSpan:          3600,
	}
}

func testMaster(seqno uint32) *ton.BlockIDExt {
	return &ton.BlockIDExt{
		Workchain: -1,
		Shard:     -9223372036854775808,
		SeqNo:     seqno,
		RootHash:  testKey(0x55),
		FileHash:  testKey(0x66),
	}
}

func testKey(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return key
}

type fakeWallet struct {
	addr    *address.Address
	balance tlb.Coins
}

func (w *fakeWallet) WalletAddress() *address.Address {
	return w.addr
}

func (w *fakeWallet) GetBalance(ctx context.Context, master *ton.BlockIDExt) (tlb.Coins, error) {
	return w.balance, nil
}

func (w *fakeWallet) BuildExternalMessageForMany(ctx context.Context, messages []*wallet.Message) (*tlb.ExternalMessage, error) {
	body := cell.BeginCell().MustStoreUInt(uint64(len(messages)), 32).EndCell()
	return &tlb.ExternalMessage{DstAddr: w.addr, Body: body}, nil
}

type fakeStorage struct {
	getCalls atomic.Int32
}

func (s *fakeStorage) GetBag(ctx context.Context, bag []byte) (*storage.BagDetailed, error) {
	s.getCalls.Add(1)
	return nil, fmt.Errorf("unexpected GetBag call for %x", bag)
}

func (s *fakeStorage) StartDownload(ctx context.Context, bag []byte, downloadAll bool) error {
	return fmt.Errorf("unexpected StartDownload call for %x", bag)
}

func (s *fakeStorage) RemoveBag(ctx context.Context, bag []byte, withFiles bool) error {
	return fmt.Errorf("unexpected RemoveBag call for %x", bag)
}

type fakeProvider struct {
	rates      *transport.StorageRatesResponse
	ratesCalls atomic.Int32
	infoCalls  atomic.Int32
}

func (p *fakeProvider) GetStorageRates(ctx context.Context, provider []byte, size uint64) (*transport.StorageRatesResponse, error) {
	p.ratesCalls.Add(1)
	if p.rates == nil {
		return nil, fmt.Errorf("unexpected GetStorageRates call for %x", provider)
	}
	return p.rates, nil
}

func (p *fakeProvider) RequestStorageInfo(ctx context.Context, provider []byte, contractAddr *address.Address, byteToProof uint64) (*transport.StorageResponse, error) {
	p.infoCalls.Add(1)
	return &transport.StorageResponse{Status: "active"}, nil
}

type fakeAPI struct {
	ton.APIClientWrapped

	getProvidersCalls atomic.Int32
	providersTuple    []any
	balanceNano       *big.Int
}

func (api *fakeAPI) WaitForBlock(seqno uint32) ton.APIClientWrapped {
	return api
}

func (api *fakeAPI) RunGetMethod(ctx context.Context, blockInfo *ton.BlockIDExt, addr *address.Address, method string, params ...interface{}) (*ton.ExecutionResult, error) {
	if method != "get_providers" {
		return nil, fmt.Errorf("unexpected run method: %s", method)
	}

	api.getProvidersCalls.Add(1)
	providers := api.providersTuple
	if providers == nil {
		providers = []any{}
	}
	balance := api.balanceNano
	if balance == nil {
		balance = big.NewInt(0)
	}
	return ton.NewExecutionResult([]any{providers, balance}), nil
}
