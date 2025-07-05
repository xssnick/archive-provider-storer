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
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
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

var minBalanceStr = flag.String("min-contract-balance", "0.3", "Minimum contract balance to topup")
var maxBalanceStr = flag.String("contract-balance", "1", "Contract balance to maintain")
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

var minBalance, maxBalance, gasFeeAdd, maxPerMB, minRewardToVerify tlb.Coins

func main() {
	flag.Parse()

	minBalance = tlb.MustFromTON(*minBalanceStr)
	maxBalance = tlb.MustFromTON(*maxBalanceStr)
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

	lsClient := liteclient.NewConnectionPool()
	if err := lsClient.AddConnectionsFromConfig(context.Background(), lsCfg); err != nil {
		pterm.Error.Println("Failed to init LS client:", err.Error())
		os.Exit(1)
	}

	// initialize ton api lite connection wrapper with full proof checks
	api := ton.NewAPIClient(lsClient, ton.ProofCheckPolicyFast).WithRetry()

	wl, err := initWallet(api, ed25519.NewKeyFromSeed(walletKey))
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
	bagStats := make(map[string]*StatBag)
	providerStats := make(map[string]*StatProvider)

	hCli := http.Client{Timeout: 10 * time.Second}
	resp, err := hCli.Get(idxUrl)
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

			for {
				detail, err := storageClient.GetBag(context.Background(), bag)
				if err != nil {
					if errors.Is(err, storage.ErrNotFound) {
						log.Info().Msgf("downloading header of %s", b)
						if err = storageClient.StartDownload(context.Background(), bag, false); err != nil {
							log.Error().Err(err).Str("bag", b).Msg("failed to download header")
							time.Sleep(500 * time.Millisecond)
							continue
						}
					} else {
						log.Error().Err(err).Str("bag", b).Msg("failed to get bag")
						time.Sleep(500 * time.Millisecond)
						continue
					}
				}

				if detail == nil || !detail.HeaderLoaded {
					log.Debug().Msgf("waiting bag %s", b)

					time.Sleep(500 * time.Millisecond)
					continue
				}

				if !*noRemoveBag {
					if err = storageClient.RemoveBag(context.Background(), bag, false); err != nil {
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

	respProviders, err := hCli.Post(providersUrl, "application/json", bytes.NewBuffer([]byte(`{
		"filter": {},
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

	ac := api
	if fromBlock > 0 {
		ac = api.WaitForBlock(fromBlock)
	}

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

		addr, _, _, err := contract.PrepareV1DeployData(id, mHash, dt.BagSize, dt.PieceSize, wl.WalletAddress(), nil)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc contract address")
			return 0, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		master, err := ac.CurrentMasterchainInfo(ctx)
		cancel()
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to get masterchain info")
			return 0, err
		}

		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		curProviders, balance, err := contract.GetProvidersV1(ctx, api, master, addr)
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
						ID:          dt.BagID,
						TotalPerDay: big.NewInt(0),
					}
					providerStats[hex.EncodeToString(cp.Key)] = ps
				}
				ps.BagsNum++
				ps.TotalPerDay.Add(ps.TotalPerDay, perDay)

				if ps.WaitingForBag == "" && cp.LastProofAt.IsZero() {
					ps.WaitingForBag = dt.BagID
				}

				if !ps.ProofLongTimeAgo && !cp.LastProofAt.IsZero() {
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

		addr, _, _, err := contract.PrepareV1DeployData(id, mHash, dt.BagSize, dt.PieceSize, wl.WalletAddress(), nil)
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc contract address")
			continue
		}

		log.Info().Str("id", dt.BagID).Str("addr", addr.String()).Msg("getting contract")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		master, err := ac.CurrentMasterchainInfo(ctx)
		cancel()
		if err != nil {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to get masterchain info")
			continue
		}

		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		curProviders, balance, err := contract.GetProvidersV1(ctx, api, master, addr)
		cancel()
		if err != nil && !errors.Is(err, contract.ErrNotDeployed) {
			log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc contract address")
			continue
		}

		var validProviders []contract.ProviderDataV1
		for _, prv := range curProviders {
			existsInList := false
			for _, p := range providers {
				if bytes.Equal(prv.Key, p.ID) {
					existsInList = true
					break
				}
			}

			toProof := uint64(rand.Int()) % dt.BagSize
			log.Debug().Str("bag", dt.BagID).Hex("provider", prv.Key).
				Str("per_mb", prv.RatePerMB.String()).Uint32("span", prv.MaxSpan).Uint64("sz_gb", dt.BagSize>>30).Msg("requesting provider info")

			var suspect bool
			ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
			stResp, err := providerClient.RequestStorageInfo(ctx, prv.Key, addr, toProof)
			cancel()
			if err != nil {
				suspect = true
				log.Warn().Err(err).Str("bag", dt.BagID).Hex("provider", prv.Key).Msg("failed to get storage info")
			} else if stResp.Status != "active" || verifyStorageProof(id, dt.BagSize, stResp.Proof, toProof, dt.PieceSize) {
				suspect = true
				log.Debug().Str("bag", dt.BagID).Hex("provider", prv.Key).Str("status", stResp.Status).Str("reason", stResp.Reason).Msg("waiting for bag confirmation")
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

				ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
				rates, err := providerClient.GetStorageRates(ctx, prv.ID, dt.BagSize)
				cancel()
				if err != nil {
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

				// remove provider for this loop, to not give him a new bag until he downloads it
				prv.WaitingForBag = dt.BagID
				addedProviders[base64.StdEncoding.EncodeToString(prv.ID)+"_"+dt.BagID] = time.Now()

				providerUpdated = true
			}

			if providerUpdated {
				_, si, body, err := contract.PrepareV1DeployData(id, mHash, dt.BagSize, dt.PieceSize, wl.WalletAddress(), newProviders)
				if err != nil {
					log.Error().Err(err).Str("bag", dt.BagID).Msg("failed to calc deploy data")
					continue
				}

				amt := gasFeeAdd

				if balance.LessThan(&maxBalance) {
					amt = *amt.MustAdd(maxBalance.MustSub(&balance))
				}

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

		if len(validProviders) > 0 && balance.LessThan(&minBalance) {
			topupAmt := maxBalance.MustSub(&balance)

			log.Info().Str("addr", addr.String()).Int("providers", len(validProviders)).Str("bag", dt.BagID).Str("topup", topupAmt.String()).Msg("adding message")

			messages = append(messages, &wallet.Message{
				Mode: 1 + 2,
				InternalMessage: &tlb.InternalMessage{
					IHRDisabled: true,
					Bounce:      true, // expected to be deployed
					DstAddr:     addr,
					Amount:      *topupAmt,
				},
			})
		}
	}

	if len(messages) > 0 && !*noTx {
		tx, block, err := wl.SendManyWaitTransaction(context.Background(), messages)
		if err != nil {
			return 0, fmt.Errorf("failed to send messages: %w", err)
		}
		fromBlock = block.SeqNo

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

	return fromBlock, nil
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

	tree := proof.BeginParse()

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
