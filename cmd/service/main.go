package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/archive-manager/pkg/index"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"github.com/xssnick/tonutils-storage-provider/pkg/contract"
	"github.com/xssnick/tonutils-storage-provider/pkg/storage"
	"github.com/xssnick/tonutils-storage-provider/pkg/transport"
	"github.com/xssnick/tonutils-storage/provider"
)

type Provider struct {
	ID            []byte
	BagsNum       int
	WaitingForBag string
}

type StatBag struct {
	ID           string
	Contract     string
	ProvidersNum int
	Balance      string
	TotalPerDay  *big.Int
}

type StatProvider struct {
	ID               string
	BagsNum          int
	WaitingForBag    string
	ProofLongTimeAgo bool
	TotalPerDay      *big.Int
}

type MTPResponse struct {
	Providers []struct {
		PubKey string `json:"pubkey"`
	} `json:"providers"`
}

type NotifyProvider struct {
	ID      []byte
	Address *address.Address
	ToProof uint64
}

var contractBalanceStr = flag.String("contract-balance", "1", "Contract balance to maintain")
var gasFeeAddStr = flag.String("gas-fee", "0.05", "Additional gas fee per tx")
var maxSpanAllowed = flag.Int("max-span", 86400*14, "Maximum span allowed sec")
var maxPerMBStr = flag.String("max-per-mb", "0.00015", "Maximum price per MB")
var minRewardToVerifyStr = flag.String("max-reward-calc", "0.055", "Max reward after which we will calculate by per MB rate")
var walletKeyBase = flag.String("wallet-key", "", "Wallet private key in Base64 (32 bytes)")
var networkConfigUrl = flag.String("network-config-url", "https://ton.org/global.config.json", "TON Network configuration URL")
var storageUrl = flag.String("storage-url", "http://127.0.0.1:8081", "Tonutils Storage server URL")
var storageLogin = flag.String("storage-login", "1", "Tonutils Storage server login")
var storagePassword = flag.String("storage-password", "1", "Tonutils Storage server password")
var indexUrl = flag.String("index-url", "https://archival-dump.ton.org/index/mainnet.json", "Bags index URL")
var limitBags = flag.Int("limit-bags", 10, "Limit for bags to process (0 = all)")
var limitProviders = flag.Int("limit-providers", 100, "Limit for providers filter request (all fetched within single request)")
var replicas = flag.Int("replicas", 3, "Providers per bag")
var maxBagsPerProvider = flag.Int("max-bags-per-provider", 10, "Max bags per provider")
var enableStats = flag.Bool("enable-stats", false, "Enable stats write to csv")
var noTx = flag.Bool("no-tx", false, "Disable transactions")
var noRemoveBag = flag.Bool("no-remove-bag", false, "Not remove bag after header save")
var skipLiteserverHealthCheck = flag.Bool("skip-liteserver-health-check", false, "Skip startup lite server masterchain seqno health check")
var maxLiteserverLag = flag.Uint("max-liteserver-lag", 512, "Max lite server masterchain seqno lag behind the best server during startup health check")

var contractBalance, gasFeeAdd, maxPerMB, minRewardToVerify tlb.Coins

const (
	liteserverRequestTimeout = 15 * time.Second
	masterchainPollInterval  = 2 * time.Second
	walletTxScanLimit        = 100
)

var (
	bagHeaderWaitTimeout  = 60 * time.Second
	bagHeaderPollInterval = 500 * time.Millisecond
)

type freshWalletAPI struct {
	ton.APIClientWrapped
}

func logBagHeaderWaitTimeout(b string, waited time.Duration, detail *storage.BagDetailed) {
	evt := log.Warn().
		Str("bag", b).
		Dur("waited", waited).
		Dur("timeout", bagHeaderWaitTimeout)
	if detail != nil {
		evt = evt.
			Str("detail_bag", detail.BagID).
			Bool("info_loaded", detail.InfoLoaded).
			Bool("header_loaded", detail.HeaderLoaded).
			Bool("active", detail.Active).
			Uint64("peers", detail.Bag.Peers).
			Uint64("download_speed", detail.DownloadSpeed)
	}
	evt.Msg("bag header wait timed out, skipping for this loop")
}

type txConfirmationTimeoutError struct {
	nextSeqno uint32
}

func (e *txConfirmationTimeoutError) Error() string {
	return ton.ErrTxWasNotConfirmed.Error()
}

func (e *txConfirmationTimeoutError) Unwrap() error {
	return ton.ErrTxWasNotConfirmed
}

type loopWallet interface {
	WalletAddress() *address.Address
	GetBalance(context.Context, *ton.BlockIDExt) (tlb.Coins, error)
	BuildExternalMessageForMany(context.Context, []*wallet.Message) (*tlb.ExternalMessage, error)
}

type storageAPI interface {
	GetBag(context.Context, []byte) (*storage.BagDetailed, error)
	StartDownload(context.Context, []byte, bool) error
	RemoveBag(context.Context, []byte, bool) error
}

type providerAPI interface {
	RequestStorageInfo(context.Context, []byte, *address.Address, uint64) (*transport.StorageResponse, error)
	GetStorageRates(context.Context, []byte, uint64) (*transport.StorageRatesResponse, error)
}

type waitMasterFunc func(context.Context, ton.APIClientWrapped, uint32) (*ton.BlockIDExt, error)
type sendManyWaitFunc func(context.Context, loopWallet, ton.APIClientWrapped, []*wallet.Message, uint32) (*tlb.Transaction, *ton.BlockIDExt, error)

type loopDeps struct {
	wallet       loopWallet
	storage      storageAPI
	provider     providerAPI
	api          ton.APIClientWrapped
	httpClient   *http.Client
	waitMaster   waitMasterFunc
	sendManyWait sendManyWaitFunc
}

func (api freshWalletAPI) CurrentMasterchainInfo(ctx context.Context) (*ton.BlockIDExt, error) {
	return waitForMasterchainBlock(ctx, api.APIClientWrapped, 0)
}

func main() {
	flag.Parse()

	contractBalance = tlb.MustFromTON(*contractBalanceStr)
	gasFeeAdd = tlb.MustFromTON(*gasFeeAddStr)
	maxPerMB = tlb.MustFromTON(*maxPerMBStr)
	minRewardToVerify = tlb.MustFromTON(*minRewardToVerifyStr)

	if *walletKeyBase == "" {
		log.Error().Msg("wallet key is required")
		return
	}

	var walletKey, err = base64.StdEncoding.DecodeString(*walletKeyBase)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to decode wallet key")
		return
	}

	log.Logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger().Level(zerolog.DebugLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	lsCfg, err := liteclient.GetConfigFromUrl(ctx, *networkConfigUrl)
	cancel()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get lite client config")
		return
	}
	if !*skipLiteserverHealthCheck {
		lsCfg = filterHealthyLiteservers(context.Background(), lsCfg, uint32(*maxLiteserverLag))
	}

	lsClient := liteclient.NewConnectionPool()
	if err := lsClient.AddConnectionsFromConfig(context.Background(), lsCfg); err != nil {
		pterm.Error.Println("Failed to init LS client:", err.Error())
		os.Exit(1)
	}

	// initialize ton api lite connection wrapper with full proof checks
	api := ton.NewAPIClient(lsClient, ton.ProofCheckPolicyFast).WithRetry()

	wl, err := initWallet(freshWalletAPI{APIClientWrapped: api}, ed25519.NewKeyFromSeed(walletKey))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init wallet")
		return
	}
	log.Info().Str("addr", wl.WalletAddress().String()).Msg("wallet initialized")

	_, dhtKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to generate dht key")
		return
	}

	_, prvKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to generate provider key")
		return
	}

	dhtGate := adnl.NewGateway(dhtKey)
	if err = dhtGate.StartClient(); err != nil {
		log.Fatal().Err(err).Msg("failed to init dht adnl gateway")
		return
	}

	dhtClient, err := dht.NewClientFromConfig(dhtGate, lsCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to init dht client")
		return
	}

	providerGate := adnl.NewGateway(prvKey)
	if err = providerGate.StartClient(); err != nil {
		log.Fatal().Err(err).Msg("failed to init provider adnl gateway")
		return
	}

	pClient := transport.NewClient(providerGate, dhtClient)

	cl := storage.NewClient(*storageUrl, "./provider-store", nil, &storage.Credentials{
		Login:    *storageLogin,
		Password: *storagePassword,
	})

	var fromBlock uint32 = 0
	for {
		fromBlock, err = doLoop(wl, cl, pClient, api, *indexUrl, "https://mytonprovider.org/api/v1/providers/search", fromBlock)
		if err != nil {
			log.Error().Err(err).Msg("failed to do loop")
			time.Sleep(5 * time.Second)
			continue
		}

		log.Info().Msg("loop completed, sleeping 15s")

		time.Sleep(15 * time.Second)
	}
}

var addedProviders = make(map[string]time.Time)

func doLoop(wl *wallet.Wallet, storageClient *storage.Client, providerClient *transport.Client, api ton.APIClientWrapped, idxUrl, providersUrl string, fromBlock uint32) (uint32, error) {
	return doLoopWithDeps(loopDeps{
		wallet:       wl,
		storage:      storageClient,
		provider:     providerClient,
		api:          api,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		waitMaster:   waitForMasterchainBlock,
		sendManyWait: sendManyWaitTransactionFresh,
	}, idxUrl, providersUrl, fromBlock)
}

func doLoopWithDeps(deps loopDeps, idxUrl, providersUrl string, fromBlock uint32) (uint32, error) {
	bagStats := make(map[string]*StatBag)
	providerStats := make(map[string]*StatProvider)
	noRespCache := make(map[string]bool)

	if deps.httpClient == nil {
		deps.httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if deps.waitMaster == nil {
		deps.waitMaster = waitForMasterchainBlock
	}
	if deps.sendManyWait == nil {
		deps.sendManyWait = sendManyWaitTransactionFresh
	}

	loopMaster, err := deps.waitMaster(context.Background(), deps.api, fromBlock)
	if err != nil {
		return fromBlock, fmt.Errorf("failed to get fresh masterchain block: %w", err)
	}
	log.Info().Uint32("seqno", loopMaster.SeqNo).Uint32("min_seqno", fromBlock).Msg("using masterchain block")

	resp, err := deps.httpClient.Get(idxUrl)
	if err != nil {
		return 0, fmt.Errorf("failed to get index: %w", err)
	}
	defer resp.Body.Close()

	var idx index.Index
	if err = json.NewDecoder(resp.Body).Decode(&idx); err != nil {
		return 0, fmt.Errorf("failed to decode index: %w", err)
	}

	log.Info().Msg("index downloaded")

	var bags []string
	for _, b := range idx.Blocks {
		bags = append(bags, b.Bag)
	}
	for _, state := range idx.States {
		bags = append(bags, state.Bag)
	}

	var providers []*Provider
	var details []*storage.BagDetailed

	// Load details from a JSON file
	detailsFile, err := os.OpenFile("bags.json", os.O_RDWR, 0644)
	if os.IsNotExist(err) {
		detailsFile, err = os.Create("bags.json")
		if err != nil {
			log.Fatal().Err(err).Msg("failed to create bags.json file")
			return fromBlock, err
		}

		data, err := json.Marshal([]*storage.BagDetailed{})
		if err != nil {
			log.Fatal().Err(err).Msg("failed to marshal empty array to JSON")
			return fromBlock, err
		}

		if _, err = detailsFile.Write(data); err != nil {
			log.Fatal().Err(err).Msg("failed to write empty array JSON to bags.json file")
			return fromBlock, err
		}
	} else if err != nil {
		log.Fatal().Err(err).Msg("failed to open bags.json file")
		return fromBlock, err
	} else {
		if err := json.NewDecoder(detailsFile).Decode(&details); err != nil {
			log.Fatal().Err(err).Msg("failed to decode details from JSON file")
			return fromBlock, err
		}
	}
	defer detailsFile.Close()

	log.Info().Int("preloaded", len(details)).Msg("loading bags")

	if len(bags) > *limitBags && *limitBags > 0 {
		bags = bags[:*limitBags]
	}

	sem := make(chan struct{}, 10)

	var mx sync.Mutex
	wg := sync.WaitGroup{}
	for _, b := range bags {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()

			bag, err := hex.DecodeString(b)
			if err != nil {
				log.Fatal().Err(err).Str("bag", b).Msg("failed to decode bag")
			}

			mx.Lock()
			for _, detail := range details {
				if detail.BagID == b {
					// exists
					mx.Unlock()
					return
				}
			}
			mx.Unlock()

			log.Debug().Msgf("loading bag %s", b)

			headerWaitStarted := time.Now()
			isHeaderWaitTimedOut := func(detail *storage.BagDetailed) bool {
				waited := time.Since(headerWaitStarted)
				if waited < bagHeaderWaitTimeout {
					return false
				}
				logBagHeaderWaitTimeout(b, waited, detail)
				return true
			}

			for {
				detail, err := deps.storage.GetBag(context.Background(), bag)
				if err != nil {
					if errors.Is(err, storage.ErrNotFound) {
						log.Info().Msgf("downloading header of %s", b)
						if err = deps.storage.StartDownload(context.Background(), bag, false); err != nil {
							log.Error().Err(err).Str("bag", b).Msg("failed to download header")
							if isHeaderWaitTimedOut(nil) {
								return
							}
							time.Sleep(bagHeaderPollInterval)
							continue
						}
					} else {
						log.Error().Err(err).Str("bag", b).Msg("failed to get bag")
						if isHeaderWaitTimedOut(nil) {
							return
						}
						time.Sleep(bagHeaderPollInterval)
						continue
					}
				}

				if detail == nil || !detail.HeaderLoaded {
					waited := time.Since(headerWaitStarted)
					if isHeaderWaitTimedOut(detail) {
						return
					}

					log.Debug().Dur("waited", waited).Msgf("waiting bag %s", b)

					time.Sleep(bagHeaderPollInterval)
					continue
				}

				if !*noRemoveBag {
					if err = deps.storage.RemoveBag(context.Background(), bag, false); err != nil {
						log.Error().Err(err).Str("bag", b).Msg("failed to remove bag")
					}
				}

				// for smaller size
				detail.Files = nil
				detail.Peers = nil
				detail.Path = ""
				detail.HasPiecesMask = nil

				mx.Lock()
				details = append(details, detail)

				data, err := json.Marshal(details)
				if err != nil {
					log.Fatal().Err(err).Msg("failed to marshal bags to JSON")
				}

				if err = detailsFile.Truncate(0); err != nil {
					log.Fatal().Err(err).Msg("failed to truncate bags.json file")
				}
				if _, err = detailsFile.Seek(0, 0); err != nil {
					log.Fatal().Err(err).Msg("failed to seek to the beginning of bags.json file")
				}
				if _, err = detailsFile.Write(data); err != nil {
					log.Fatal().Err(err).Msg("failed to write JSON to bags.json file")
				}
				_ = detailsFile.Sync()
				mx.Unlock()
				break
			}
		}()
	}
	wg.Wait()

	log.Info().Msg("fetching providers")

	respProviders, err := deps.httpClient.Post(providersUrl, "application/json", bytes.NewBuffer([]byte(`{
		"filters": {
			"uptime_gt_percent": 40
		},
		"sort": {
			"column": "rating",
			"order": "desc"
		},
		"exact": [],
		"limit": `+fmt.Sprint(*limitProviders)+`,
		"offset": 0
	}`)))
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch providers")
		return 0, err
	}
	defer respProviders.Body.Close()

	var providersList MTPResponse
	if err = json.NewDecoder(respProviders.Body).Decode(&providersList); err != nil {
		return 0, fmt.Errorf("failed to decode index: %w", err)
	}

	for _, p := range providersList.Providers {
		key, err := hex.DecodeString(p.PubKey)
		if err != nil {
			continue
		}

		providers = append(providers, &Provider{
			ID: key,
		})
	}

	log.Info().Msg("checking bags num stored")

	for _, dt := range details {
		id, err := hex.DecodeString(dt.BagID)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to decode bag id")
			return 0, err
		}

		mHash, err := hex.DecodeString(dt.MerkleHash)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to decode merkle hash")
			return 0, err
		}

		addr, _, _, err := contract.PrepareV1DeployData(id, mHash, dt.BagSize, dt.PieceSize, deps.wallet.WalletAddress(), nil)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc contract address")
			return 0, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		curProviders, balance, err := contract.GetProvidersV1(ctx, deps.api, loopMaster, addr)
		cancel()
		if err != nil && !errors.Is(err, contract.ErrNotDeployed) {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to get providers")
			return 0, err
		}

		for _, cp := range curProviders {
			if *enableStats {
				m := new(big.Int).Mul(new(big.Int).SetUint64(dt.BagSize), cp.RatePerMB.Nano())
				// perProof := new(big.Int).Div(m.Mul(m, big.NewInt(int64(cp.MaxSpan))), big.NewInt(86400*1024*1024))
				perDay := new(big.Int).Div(m, big.NewInt(1024*1024))

				ps := providerStats[hex.EncodeToString(cp.Key)]
				if ps == nil {
					ps = &StatProvider{
						ID:          hex.EncodeToString(cp.Key),
						TotalPerDay: big.NewInt(0),
					}
					providerStats[hex.EncodeToString(cp.Key)] = ps
				}
				ps.BagsNum++
				ps.TotalPerDay.Add(ps.TotalPerDay, perDay)

				oldUnix := time.Unix(1, 0)
				if ps.WaitingForBag == "" && cp.LastProofAt.Before(oldUnix) {
					ps.WaitingForBag = dt.BagID
				}

				if !ps.ProofLongTimeAgo && !cp.LastProofAt.Before(oldUnix) {
					ps.ProofLongTimeAgo = cp.LastProofAt.Before(time.Now().Add(-time.Duration(cp.MaxSpan) * time.Second))
				}

				sb := bagStats[dt.BagID]
				if sb == nil {
					sb = &StatBag{
						ID:           dt.BagID,
						Contract:     addr.String(),
						ProvidersNum: len(curProviders),
						Balance:      balance.String(),
						TotalPerDay:  big.NewInt(0),
					}
					bagStats[dt.BagID] = sb
				}
				sb.TotalPerDay.Add(sb.TotalPerDay, perDay)
			}

			for _, p := range providers {
				if bytes.Equal(cp.Key, p.ID) {
					p.BagsNum++
				}
			}
		}
	}

	log.Info().Msg("checking bags providers")

	needBalance := tlb.MustFromTON("0.05")
	var notifications []*NotifyProvider
	var messages []*wallet.Message
	for _, dt := range details {
		if len(messages) >= 100 {
			log.Info().Msg("100 messages reached, skip other bags processing for now")
			break
		}

		log.Info().Str("id", dt.BagID).Msg("checking bag")

		id, err := hex.DecodeString(dt.BagID)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to decode bag id")
			continue
		}

		mHash, err := hex.DecodeString(dt.MerkleHash)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to decode merkle hash")
			continue
		}

		addr, _, _, err := contract.PrepareV1DeployData(id, mHash, dt.BagSize, dt.PieceSize, deps.wallet.WalletAddress(), nil)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc contract address")
			continue
		}

		log.Info().Str("id", dt.BagID).Str("addr", addr.String()).Msg("getting contract")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		curProviders, balance, err := contract.GetProvidersV1(ctx, deps.api, loopMaster, addr)
		cancel()
		if err != nil && !errors.Is(err, contract.ErrNotDeployed) {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc contract address")
			continue
		}

		minBalance := tlb.ZeroCoins
		maxBalance := tlb.ZeroCoins
		var validProviders []contract.ProviderDataV1
		for _, prv := range curProviders {
			toProof := uint64(rand.Int()) % dt.BagSize
			log.Debug().Str("bag", dt.BagID).Hex("provider", prv.Key).
				Str("per_mb", prv.RatePerMB.String()).Uint32("span", prv.MaxSpan).Uint64("sz_gb", dt.BagSize>>30).Msg("requesting provider info")

			var suspect bool
			if !noRespCache[string(prv.Key)] {
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
				stResp, err := deps.provider.RequestStorageInfo(ctx, prv.Key, addr, toProof)
				cancel()
				if err != nil {
					noRespCache[string(prv.Key)] = true
					suspect = true
					log.Warn().Err(err).Str("bag", dt.BagID).Hex("provider", prv.Key).Msg("failed to get storage info")
				} else if stResp.Status != "active" || !verifyStorageProof(mHash, dt.BagSize, stResp.Proof, toProof, dt.PieceSize) {
					suspect = true
					log.Debug().Str("bag", dt.BagID).Hex("provider", prv.Key).Str("status", stResp.Status).Str("reason", stResp.Reason).Msg("waiting for bag confirmation")
				}
			} else {
				suspect = true
				log.Debug().Str("bag", dt.BagID).Hex("provider", prv.Key).Msg("skipped, not respond before (cached)")
			}

			if suspect {
				// still downloading or not responding, remove provider from list for this loop, to not give him a new bag
				for _, pv := range providers {
					if bytes.Equal(pv.ID, prv.Key) {
						pv.WaitingForBag = dt.BagID
						break
					}
				}

				maxDelay := time.Duration(prv.MaxSpan*2) * time.Second
				if prv.LastProofAt.Add(maxDelay).Before(time.Now()) && time.Since(addedProviders[base64.StdEncoding.EncodeToString(prv.Key)+"_"+dt.BagID]) > 2*time.Hour {
					existsInList := false
					for _, p := range providers {
						if bytes.Equal(prv.Key, p.ID) {
							existsInList = true
							break
						}
					}

					// no proofs for too long, and not in list, removing it
					if !existsInList {
						log.Warn().Str("bag", dt.BagID).Hex("provider", prv.Key).Msg("last proof too long ago, and provider not in list anymore, removing")
						continue
					}
					log.Warn().Str("bag", dt.BagID).Hex("provider", prv.Key).Msg("last proof too long ago, but provider in trusted list, not removing")
				}
			} else {
				log.Info().Str("bag", dt.BagID).Hex("provider", prv.Key).Msg("storage confirmed")
			}

			bounty := new(big.Int).Mul(prv.RatePerMB.Nano(), big.NewInt(int64(dt.BagSize)))
			bounty = bounty.Mul(bounty, big.NewInt(int64(prv.MaxSpan)))
			bounty = bounty.Div(bounty, big.NewInt(24*60*60*1024*1024))

			if bounty.Cmp(minRewardToVerify.Nano()) > 0 {
				// not typical price, check per mb
				if prv.RatePerMB.Nano().Cmp(maxPerMB.Nano()) > 0 {
					log.Warn().Str("bag", dt.BagID).Hex("provider", prv.Key).Str("rate", prv.RatePerMB.String()).Msg("rate of existing provider is too high, removing")
					continue
				}
			}

			amt := tlb.MustFromNano(bounty, 9)
			maxBalance = maxBalance.MustAdd(amt)
			if amt.GreaterThan(minBalance) {
				minBalance = amt
			}

			validProviders = append(validProviders, prv)
		}

		if len(validProviders) < *replicas {
			var newProviders []contract.ProviderV1
			for _, prv := range validProviders {
				// add prev valid providers
				newProviders = append(newProviders, contract.ProviderV1{
					Address:       address.NewAddress(0, 0, prv.Key),
					MaxSpan:       prv.MaxSpan,
					PricePerMBDay: prv.RatePerMB,
				})
			}

			var providerUpdated bool
		nextProvider:
			for _, prv := range providers {
				if len(newProviders) == *replicas {
					break
				}
				if prv.WaitingForBag != "" {
					log.Debug().Str("bag", dt.BagID).Str("waiting", prv.WaitingForBag).Hex("provider", prv.ID).Msg("provider is waiting for another bag confirmation")
					continue
				}

				if prv.BagsNum >= *maxBagsPerProvider {
					log.Debug().Str("bag", dt.BagID).Hex("provider", prv.ID).Msg("provider has too many bags, skip")
					continue
				}

				for _, newProvider := range newProviders {
					if bytes.Equal(prv.ID, newProvider.Address.Data()) {
						// already exists
						continue nextProvider
					}
				}

				log.Debug().Str("bag", dt.BagID).Hex("provider", prv.ID).Msg("requesting provider storage rates")

				if noRespCache[string(prv.ID)] {
					log.Debug().Str("bag", dt.BagID).Hex("provider", prv.ID).Msg("skipped, not respond before (cached)")
					continue
				}

				ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
				rates, err := deps.provider.GetStorageRates(ctx, prv.ID, dt.BagSize)
				cancel()
				if err != nil {
					noRespCache[string(prv.ID)] = true
					log.Error().Err(err).Str("bag", dt.BagID).Hex("provider", prv.ID).Msg("failed to get rates")
					continue
				}

				if !rates.Available || rates.SpaceAvailableMB < dt.BagSize>>20 {
					log.Debug().Str("bag", dt.BagID).Hex("provider", prv.ID).Msg("not available")
					continue
				}

				if rates.MaxSpan > uint32(*maxSpanAllowed) {
					rates.MaxSpan = uint32(*maxSpanAllowed)
				}

				if rates.MaxSpan < rates.MinSpan {
					log.Debug().Str("bag", dt.BagID).Hex("provider", prv.ID).Msg("max span too low, skip")
					continue
				}

				perMB := tlb.FromNanoTON(new(big.Int).SetBytes(rates.RatePerMBDay))
				offer := provider.CalculateBestProviderOffer(&provider.ProviderRates{
					Available:        rates.Available,
					RatePerMBDay:     perMB,
					MinBounty:        tlb.FromNanoTON(new(big.Int).SetBytes(rates.MinBounty)),
					SpaceAvailableMB: rates.SpaceAvailableMB,
					MinSpan:          rates.MinSpan,
					MaxSpan:          rates.MaxSpan,
					Size:             dt.BagSize,
				})

				if offer.PerProofNano.Cmp(minRewardToVerify.Nano()) > 0 {
					// not typical price, check per mb
					if offer.RatePerMBNano.Cmp(maxPerMB.Nano()) > 0 {
						log.Debug().Str("bag", dt.BagID).Hex("provider", prv.ID).Msg("rate too high, skip")
						continue
					}
				}

				log.Info().Str("bag", dt.BagID).Hex("provider", prv.ID).Str("per_mb_day", perMB.String()).Msg("adding new provider")

				prv.BagsNum++
				newProviders = append(newProviders, contract.ProviderV1{
					Address:       address.NewAddress(0, 0, prv.ID),
					MaxSpan:       offer.Span,
					PricePerMBDay: tlb.FromNanoTON(offer.RatePerMBNano),
				})
				notifications = append(notifications, &NotifyProvider{
					ID:      prv.ID,
					Address: addr,
					ToProof: uint64(rand.Int()) % dt.BagSize,
				})

				bounty := new(big.Int).Mul(tlb.FromNanoTON(offer.RatePerMBNano).Nano(), big.NewInt(int64(dt.BagSize)))
				bounty = bounty.Mul(bounty, big.NewInt(int64(offer.Span)))
				bounty = bounty.Div(bounty, big.NewInt(24*60*60*1024*1024))

				amt := tlb.MustFromNano(bounty, 9)
				maxBalance = maxBalance.MustAdd(amt)
				if amt.GreaterThan(minBalance) {
					minBalance = amt
				}

				// remove provider for this loop, to not give him a new bag until he downloads it
				prv.WaitingForBag = dt.BagID
				addedProviders[base64.StdEncoding.EncodeToString(prv.ID)+"_"+dt.BagID] = time.Now()

				providerUpdated = true
			}

			if maxBalance.Nano().Cmp(contractBalance.Nano()) < 0 {
				maxBalance = contractBalance
			}

			if providerUpdated {
				_, si, body, err := contract.PrepareV1DeployData(id, mHash, dt.BagSize, dt.PieceSize, deps.wallet.WalletAddress(), newProviders)
				if err != nil {
					log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc deploy data")
					continue
				}

				amt := gasFeeAdd

				if balance.LessThan(maxBalance) {
					amt = amt.MustAdd(maxBalance.MustSub(balance))
				}

				needBalance = needBalance.MustAdd(amt)
				messages = append(messages, &wallet.Message{
					Mode: 1 + 2,
					InternalMessage: &tlb.InternalMessage{
						IHRDisabled: true,
						Bounce:      false,
						DstAddr:     addr,
						Amount:      amt,
						StateInit:   si,
						Body:        body,
					},
				})
				continue
			}
		}

		if len(validProviders) > 0 && balance.LessThan(minBalance) {
			topupAmt := maxBalance.MustSub(balance)
			topupAmt = topupAmt.MustAdd(gasFeeAdd)

			log.Info().Str("addr", addr.String()).Int("providers", len(validProviders)).Str("bag", dt.BagID).Str("topup", topupAmt.String()).Msg("adding message")

			needBalance = needBalance.MustAdd(topupAmt)
			messages = append(messages, &wallet.Message{
				Mode: 1 + 2,
				InternalMessage: &tlb.InternalMessage{
					IHRDisabled: true,
					Bounce:      true, // expected to be deployed
					DstAddr:     addr,
					Amount:      topupAmt,
				},
			})
		}
	}

	if len(messages) > 0 && !*noTx {
		if fromBlock <= loopMaster.SeqNo {
			fromBlock = loopMaster.SeqNo + 1
		}

		master, err := deps.waitMaster(context.Background(), deps.api, loopMaster.SeqNo)
		if err != nil {
			log.Error().Err(err).Msg("failed to get masterchain info for tx")
			return fromBlock, err
		}
		if fromBlock <= master.SeqNo {
			fromBlock = master.SeqNo + 1
		}

		balance, err := deps.wallet.GetBalance(context.Background(), master)
		if err != nil {
			log.Error().Err(err).Msg("failed to wallet get balance")
			return fromBlock, err
		}

		if balance.LessThan(needBalance) {
			err = fmt.Errorf("not enough balance for tx: balance %s, need %s", balance.String(), needBalance.String())
			log.Error().Err(err).Msg("not enough balance for tx")
			return fromBlock, err
		}

		tx, block, err := deps.sendManyWait(context.Background(), deps.wallet, deps.api, messages, master.SeqNo)
		if err != nil {
			var timeoutErr *txConfirmationTimeoutError
			if errors.As(err, &timeoutErr) {
				if fromBlock < timeoutErr.nextSeqno {
					fromBlock = timeoutErr.nextSeqno
				}
				log.Warn().Uint32("from_block", fromBlock).Msg("transaction confirmation timed out; waiting for a newer masterchain block before rebuilding messages")
				return fromBlock, nil
			}
			return fromBlock, fmt.Errorf("failed to send messages: %w", err)
		}
		fromBlock = block.SeqNo + 1

		go func(notifications []*NotifyProvider) {
			time.Sleep(20 * time.Second)
			for _, notify := range notifications {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err := deps.provider.RequestStorageInfo(ctx, notify.ID, notify.Address, notify.ToProof)
				cancel()
				if err != nil {
					log.Warn().Err(err).Hex("provider", notify.ID).Str("addr", notify.Address.String()).Msg("failed send notify to provider")
				} else {
					log.Debug().Hex("provider", notify.ID).Str("addr", notify.Address.String()).Uint64("to_proof", notify.ToProof).Msg("sent notify to provider for start download")
				}
			}
		}(notifications)

		log.Info().Str("hash", base64.StdEncoding.EncodeToString(tx.Hash)).Int("messages", len(messages)).Msg("executed transaction")
	}

	if *enableStats {
		var pStats []*StatProvider
		var bStats []*StatBag
		for _, v := range providerStats {
			pStats = append(pStats, v)
		}
		for _, v := range bagStats {
			bStats = append(bStats, v)
		}

		sort.Slice(pStats, func(i, j int) bool {
			return pStats[i].ID < pStats[j].ID
		})
		sort.Slice(bStats, func(i, j int) bool {
			return bStats[i].ID < bStats[j].ID
		})
		log.Info().Int("providers", len(pStats)).Int("bags", len(bStats)).Msg("saving stats")

		err = exportStatsToCSV(pStats, bStats, "provider_stats.csv", "bag_stats.csv")
		if err != nil {
			log.Error().Err(err).Msg("failed to export stats to CSV")
		}
	}

	if fromBlock <= loopMaster.SeqNo {
		fromBlock = loopMaster.SeqNo + 1
	}
	return fromBlock, nil
}

func filterHealthyLiteservers(ctx context.Context, cfg *liteclient.GlobalConfig, maxLag uint32) *liteclient.GlobalConfig {
	if cfg == nil || len(cfg.Liteservers) < 2 {
		return cfg
	}

	type result struct {
		index int
		seqno uint32
		err   error
	}

	results := make(chan result, len(cfg.Liteservers))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup

	for i, ls := range cfg.Liteservers {
		i, ls := i, ls
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			seqno, err := checkLiteserverMasterSeqno(ctx, cfg, ls)
			results <- result{index: i, seqno: seqno, err: err}
		}()
	}

	wg.Wait()
	close(results)

	byIndex := make(map[int]result, len(cfg.Liteservers))
	var bestSeqno uint32
	for res := range results {
		byIndex[res.index] = res
		if res.err == nil && res.seqno > bestSeqno {
			bestSeqno = res.seqno
		}
	}

	if bestSeqno == 0 {
		log.Warn().Msg("all lite server health checks failed, using original config")
		return cfg
	}

	filtered := make([]liteclient.LiteserverConfig, 0, len(cfg.Liteservers))
	for i, ls := range cfg.Liteservers {
		res := byIndex[i]
		addr := liteserverAddr(ls)
		if res.err != nil {
			log.Warn().Err(res.err).Str("addr", addr).Msg("lite server health check failed, excluding")
			continue
		}

		lag := bestSeqno - res.seqno
		if lag > maxLag {
			log.Warn().
				Str("addr", addr).
				Uint32("seqno", res.seqno).
				Uint32("best_seqno", bestSeqno).
				Uint32("lag", lag).
				Msg("excluding stale lite server")
			continue
		}

		filtered = append(filtered, ls)
	}

	if len(filtered) == 0 {
		log.Warn().Uint32("best_seqno", bestSeqno).Msg("no lite servers passed health check, using original config")
		return cfg
	}

	log.Info().
		Int("total", len(cfg.Liteservers)).
		Int("healthy", len(filtered)).
		Uint32("best_seqno", bestSeqno).
		Msg("lite server health check completed")

	next := *cfg
	next.Liteservers = filtered
	return &next
}

func checkLiteserverMasterSeqno(ctx context.Context, cfg *liteclient.GlobalConfig, ls liteclient.LiteserverConfig) (uint32, error) {
	checkCtx, cancel := context.WithTimeout(ctx, liteserverRequestTimeout)
	defer cancel()

	one := *cfg
	one.Liteservers = []liteclient.LiteserverConfig{ls}

	pool := liteclient.NewConnectionPool()
	defer pool.Stop()

	if err := pool.AddConnectionsFromConfig(checkCtx, &one); err != nil {
		return 0, err
	}

	api := ton.NewAPIClient(pool, ton.ProofCheckPolicyFast).WithRetry()
	reqCtx, reqCancel := context.WithTimeout(ctx, liteserverRequestTimeout)
	defer reqCancel()

	master, err := api.GetMasterchainInfo(reqCtx)
	if err != nil {
		return 0, err
	}
	return master.SeqNo, nil
}

func waitForMasterchainBlock(ctx context.Context, api ton.APIClientWrapped, minSeqno uint32) (*ton.BlockIDExt, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var lastLoggedSeqno uint32
	for {
		master, err := bestKnownMasterchainInfo(ctx, api)
		if err == nil {
			if minSeqno == 0 || master.SeqNo >= minSeqno {
				return master, nil
			}

			if master.SeqNo != lastLoggedSeqno {
				log.Warn().
					Uint32("seqno", master.SeqNo).
					Uint32("want_seqno", minSeqno).
					Msg("masterchain block is behind, waiting")
				lastLoggedSeqno = master.SeqNo
			}
		} else {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			log.Warn().Err(err).Uint32("want_seqno", minSeqno).Msg("failed to get masterchain block, retrying")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(masterchainPollInterval):
		}
	}
}

func bestKnownMasterchainInfo(ctx context.Context, api ton.APIClientWrapped) (*ton.BlockIDExt, error) {
	stickyCtx := api.Client().StickyContext(ctx)

	var best *ton.BlockIDExt
	var lastErr error
	for {
		reqCtx, cancel := context.WithTimeout(stickyCtx, liteserverRequestTimeout)
		master, err := api.GetMasterchainInfo(reqCtx)
		cancel()

		if err != nil {
			lastErr = err
			log.Debug().Err(err).Msg("failed to get masterchain info from lite server")
		} else if best == nil || master.SeqNo > best.SeqNo {
			best = master
		}

		nextCtx, err := api.Client().StickyContextNextNode(stickyCtx)
		if err != nil {
			break
		}
		stickyCtx = nextCtx
	}

	if best != nil {
		return best, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no lite server returned masterchain info")
}

func sendManyWaitTransactionFresh(ctx context.Context, wl loopWallet, api ton.APIClientWrapped, messages []*wallet.Message, minSeqno uint32) (*tlb.Transaction, *ton.BlockIDExt, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 180*time.Second)
		defer cancel()
	}

	ext, err := wl.BuildExternalMessageForMany(ctx, messages)
	if err != nil {
		return nil, nil, err
	}
	inMsgHash := ext.Body.Hash()

	master, err := waitForMasterchainBlock(ctx, api, minSeqno)
	if err != nil {
		return nil, nil, err
	}
	if err = api.SendExternalMessage(ctx, ext); err != nil {
		return nil, nil, fmt.Errorf("failed to send message: %w", err)
	}

	log.Debug().
		Str("hash", base64.StdEncoding.EncodeToString(inMsgHash)).
		Uint32("from_seqno", master.SeqNo+1).
		Msg("sent external message, waiting for wallet transaction")

	return waitForWalletInMsg(ctx, api, wl.WalletAddress(), inMsgHash, master.SeqNo+1)
}

func waitForWalletInMsg(ctx context.Context, api ton.APIClientWrapped, addr *address.Address, inMsgHash []byte, minSeqno uint32) (*tlb.Transaction, *ton.BlockIDExt, error) {
	nextSeqno := minSeqno
	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, &txConfirmationTimeoutError{nextSeqno: nextSeqno}
			}
			return nil, nil, err
		}

		master, err := waitForMasterchainBlock(ctx, api, nextSeqno)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, &txConfirmationTimeoutError{nextSeqno: nextSeqno}
			}
			return nil, nil, err
		}

		tx, err := findWalletInMsgAtBlock(ctx, api, master, addr, inMsgHash)
		if err == nil {
			return tx, master, nil
		}
		if !errors.Is(err, ton.ErrTxWasNotFound) {
			log.Warn().Err(err).Uint32("seqno", master.SeqNo).Msg("failed to scan wallet transactions")
		}

		nextSeqno = master.SeqNo + 1
	}
}

func findWalletInMsgAtBlock(ctx context.Context, api ton.APIClientWrapped, master *ton.BlockIDExt, addr *address.Address, inMsgHash []byte) (*tlb.Transaction, error) {
	acc, err := api.WaitForBlock(master.SeqNo).GetAccount(ctx, master, addr)
	if err != nil {
		return nil, fmt.Errorf("cannot get wallet account: %w", err)
	}
	if !acc.IsActive {
		return nil, ton.ErrTxWasNotFound
	}

	scanned := 0
	for lastLT, lastHash := acc.LastTxLT, acc.LastTxHash; ; {
		if lastLT == 0 {
			return nil, ton.ErrTxWasNotFound
		}

		txList, err := api.WaitForBlock(master.SeqNo).ListTransactions(ctx, addr, 15, lastLT, lastHash)
		if err != nil {
			if errors.Is(err, ton.ErrNoTransactionsWereFound) {
				return nil, ton.ErrTxWasNotFound
			}
			return nil, fmt.Errorf("cannot list wallet transactions: %w", err)
		}

		for i, tx := range txList {
			if i == 0 {
				lastLT, lastHash = tx.PrevTxLT, tx.PrevTxHash
			}
			if tx.IO.In != nil && bytes.Equal(tx.IO.In.Msg.Payload().Hash(), inMsgHash) {
				return tx, nil
			}
		}

		scanned += len(txList)
		if scanned >= walletTxScanLimit {
			return nil, ton.ErrTxWasNotFound
		}
	}
}

func liteserverAddr(ls liteclient.LiteserverConfig) string {
	return fmt.Sprintf("%d.%d.%d.%d:%d",
		(ls.IP>>24)&0xff,
		(ls.IP>>16)&0xff,
		(ls.IP>>8)&0xff,
		ls.IP&0xff,
		ls.Port,
	)
}

func exportStatsToCSV(providerStats []*StatProvider, bagStats []*StatBag, providerFilePath, bagFilePath string) error {
	providerFile, err := os.Create(providerFilePath)
	if err != nil {
		return fmt.Errorf("failed to create provider stats CSV file: %w", err)
	}
	defer providerFile.Close()

	providerWriter := csv.NewWriter(providerFile)
	defer providerWriter.Flush()

	err = providerWriter.Write([]string{"Provider ID", "Bags Num", "Waiting download", "Proof long time ago", "Per day"})
	if err != nil {
		return fmt.Errorf("failed to write provider stats header: %w", err)
	}

	for _, p := range providerStats {
		err = providerWriter.Write([]string{
			p.ID,
			fmt.Sprint(p.BagsNum),
			fmt.Sprint(p.WaitingForBag),
			fmt.Sprint(!p.ProofLongTimeAgo),
			tlb.FromNanoTON(p.TotalPerDay).String(),
		})
		if err != nil {
			return fmt.Errorf("failed to write provider stats row: %w", err)
		}
	}

	bagFile, err := os.Create(bagFilePath)
	if err != nil {
		return fmt.Errorf("failed to create bag stats CSV file: %w", err)
	}
	defer bagFile.Close()

	bagWriter := csv.NewWriter(bagFile)
	defer bagWriter.Flush()

	err = bagWriter.Write([]string{"Bag ID", "Contract", "Balance", "Providers", "Price per day"})
	if err != nil {
		return fmt.Errorf("failed to write bag stats header: %w", err)
	}

	for _, b := range bagStats {
		err = bagWriter.Write([]string{
			b.ID,
			b.Contract,
			fmt.Sprint(b.Balance),
			fmt.Sprint(b.ProvidersNum),
			tlb.FromNanoTON(b.TotalPerDay).String(),
		})
		if err != nil {
			return fmt.Errorf("failed to write bag stats row: %w", err)
		}
	}

	return nil
}

func initWallet(apiClient wallet.TonAPI, key ed25519.PrivateKey) (*wallet.Wallet, error) {
	walletAbstractSeqno := uint32(0)
	w, err := wallet.FromPrivateKey(apiClient, key, wallet.ConfigHighloadV3{
		MessageTTL: 3*60 + 30,
		MessageBuilder: func(ctx context.Context, subWalletId uint32) (id uint32, createdAt int64, err error) {
			createdAt = time.Now().UTC().Unix() - 30 // something older than last master block, to pass through LS external's time validation
			// TODO: store seqno in db
			id = uint32((createdAt%(3*60+30))<<15) | atomic.AddUint32(&walletAbstractSeqno, 1)%(1<<15)
			return
		},
	})
	if err != nil {
		return nil, err
	}
	return w, nil
}

func verifyStorageProof(hash []byte, sz uint64, proofBytes []byte, proofByte uint64, pieceSz uint32) bool {
	proof, err := cell.FromBOC(proofBytes)
	if err == nil {
		if proofData, err := cell.UnwrapProof(proof, hash); err == nil {
			piece := uint32(proofByte / uint64(pieceSz))
			pieces := uint32(sz / uint64(pieceSz))
			if sz%uint64(pieceSz) != 0 {
				pieces++
			}

			if err = checkProofBranch(proofData, piece, pieces); err == nil {
				return true
			}
		}
	}
	return false
}

func checkProofBranch(proof *cell.Cell, piece, piecesNum uint32) error {
	if piece >= piecesNum {
		return fmt.Errorf("piece is out of range %d/%d", piece, piecesNum)
	}

	tree, err := proof.BeginParse()
	if err != nil {
		return err
	}

	// calc tree depth
	depth := int(math.Log2(float64(piecesNum)))
	if piecesNum > uint32(math.Pow(2, float64(depth))) {
		// add 1 if pieces num is not exact log2
		depth++
	}

	// check bits from left to right and load branches
	for i := depth - 1; i >= 0; i-- {
		isLeft := piece&(1<<i) == 0

		b, err := tree.LoadRef()
		if err != nil {
			return err
		}

		if isLeft {
			tree = b
			continue
		}

		// we need right branch
		tree, err = tree.LoadRef()
		if err != nil {
			return err
		}
	}

	if tree.BitsLeft() != 256 {
		return fmt.Errorf("incorrect branch")
	}
	return nil
}
