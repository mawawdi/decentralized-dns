package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain/bindings"
	"github.com/mawawdi/decentralized-dns/resolver/internal/pay"
)

// cmdChannelOpen opens a pay-per-query micropayment channel funding a resolver
// operator (FS §2.3). The client signs vouchers against it as it queries.
func cmdChannelOpen(args []string) {
	fs := flag.NewFlagSet("channel-open", flag.ExitOnError)
	co := addCommon(fs)
	resolverOp := fs.String("resolver-operator", "", "resolver operator address to fund (required)")
	amount := fs.String("amount", "", "deposit in ETH, e.g. 0.05 (required)")
	duration := fs.Duration("duration", 24*time.Hour, "channel lifetime before the client may reclaim")
	incFlag := fs.String("incentives", "", "ResolverIncentives address (overrides deployments)")
	_ = fs.Parse(reorder(args))
	if !common.IsHexAddress(*resolverOp) {
		fatal(errors.New("channel-open: --resolver-operator ADDR is required"))
	}
	wei := mustEth(*amount)

	c, ic, _ := dialIncentives(co, *incFlag)
	c.auth.Value = wei
	ctx := context.Background()
	tx, err := ic.OpenChannel(c.auth, common.HexToAddress(*resolverOp), uint64(duration.Seconds()))
	fatal(err)
	fmt.Printf("channel-open: tx %s submitted, waiting...\n", tx.Hash().Hex())
	rcpt, err := bind.WaitMined(ctx, c.eth, tx)
	fatal(err)
	if rcpt.Status != types.ReceiptStatusSuccessful {
		fatal(fmt.Errorf("channel-open reverted (tx %s)", tx.Hash().Hex()))
	}
	var id [32]byte
	for _, lg := range rcpt.Logs {
		if ev, err := ic.ParseChannelOpened(*lg); err == nil {
			id = ev.Id
			break
		}
	}
	idHex := hexutil.Encode(id[:])
	fmt.Printf("opened channel %s funding %s with %s wei\n", idHex, *resolverOp, wei)
	fmt.Printf("  per query, hand the resolver: ddns voucher --channel %s --amount <cumulative ETH>\n", idHex)
}

// cmdVoucher signs (offline) a voucher authorizing a cumulative amount on a
// channel — one bumped voucher per query, given to the resolver as payment.
func cmdVoucher(args []string) {
	fs := flag.NewFlagSet("voucher", flag.ExitOnError)
	co := addCommon(fs)
	channel := fs.String("channel", "", "channel id 0x<64hex> (required)")
	amount := fs.String("amount", "", "cumulative ETH authorized so far (required)")
	incFlag := fs.String("incentives", "", "ResolverIncentives address (overrides deployments)")
	_ = fs.Parse(reorder(args))
	id := mustChannelID(*channel)
	wei := mustEth(*amount)
	inc := incentivesAddr(*co.deployments, *incFlag)
	if inc == (common.Address{}) {
		fatal(errors.New("ResolverIncentives address unknown: set --incentives, --deployments, or RESOLVER_INCENTIVES_ADDRESS"))
	}
	sig, err := pay.SignVoucher(loadKey(*co.key), inc, id, wei)
	fatal(err)
	fmt.Println(hexutil.Encode(sig)) // stdout: the voucher, pipeable to the resolver
	fmt.Fprintf(os.Stderr, "voucher authorizes %s wei cumulative on channel %s\n", wei, *channel)
}

// cmdChannelClaim lets the resolver operator redeem a client voucher on-chain.
func cmdChannelClaim(args []string) {
	fs := flag.NewFlagSet("channel-claim", flag.ExitOnError)
	co := addCommon(fs)
	channel := fs.String("channel", "", "channel id 0x<64hex> (required)")
	amount := fs.String("amount", "", "cumulative ETH the voucher authorizes (required)")
	voucher := fs.String("voucher", "", "client voucher signature 0x<130hex> (required)")
	incFlag := fs.String("incentives", "", "ResolverIncentives address (overrides deployments)")
	_ = fs.Parse(reorder(args))
	id := mustChannelID(*channel)
	wei := mustEth(*amount)
	sig, err := hexutil.Decode(*voucher)
	fatal(err)

	c, ic, _ := dialIncentives(co, *incFlag)
	fmt.Printf("claiming %s wei (cumulative) from channel %s\n", wei, *channel)
	send(c, "channel-claim", func(o *bind.TransactOpts) (*types.Transaction, error) {
		return ic.Claim(o, id, wei, sig)
	})
}

// cmdChannelClose lets the client reclaim the unspent remainder after expiry.
func cmdChannelClose(args []string) {
	fs := flag.NewFlagSet("channel-close", flag.ExitOnError)
	co := addCommon(fs)
	channel := fs.String("channel", "", "channel id 0x<64hex> (required)")
	incFlag := fs.String("incentives", "", "ResolverIncentives address (overrides deployments)")
	_ = fs.Parse(reorder(args))
	id := mustChannelID(*channel)

	c, ic, _ := dialIncentives(co, *incFlag)
	fmt.Printf("closing channel %s and reclaiming the unspent remainder\n", *channel)
	send(c, "channel-close", func(o *bind.TransactOpts) (*types.Transaction, error) {
		return ic.CloseChannel(o, id)
	})
}

// dialIncentives builds a keyed transactor bound to ResolverIncentives.
func dialIncentives(co commonOpts, incFlag string) (*conn, *bindings.ResolverIncentives, common.Address) {
	inc := incentivesAddr(*co.deployments, incFlag)
	if inc == (common.Address{}) {
		fatal(errors.New("ResolverIncentives address unknown: set --incentives, --deployments, or RESOLVER_INCENTIVES_ADDRESS"))
	}
	key := loadKey(*co.key)
	ctx := context.Background()
	eth, err := ethclient.DialContext(ctx, *co.rpc)
	fatal(err)
	chainID, err := eth.ChainID(ctx)
	fatal(err)
	auth, err := bind.NewKeyedTransactorWithChainID(key, chainID)
	fatal(err)
	ic, err := bindings.NewResolverIncentives(inc, eth)
	fatal(err)
	return &conn{eth: eth, auth: auth, from: crypto.PubkeyToAddress(key.PublicKey)}, ic, inc
}

// incentivesAddr resolves the ResolverIncentives address from a flag, the
// deploy artifact, or RESOLVER_INCENTIVES_ADDRESS.
func incentivesAddr(deployments, flagVal string) common.Address {
	if flagVal != "" {
		return common.HexToAddress(flagVal)
	}
	if deployments != "" {
		if data, err := os.ReadFile(deployments); err == nil {
			var d struct {
				Contracts struct{ ResolverIncentives string } `json:"contracts"`
			}
			if json.Unmarshal(data, &d) == nil && d.Contracts.ResolverIncentives != "" {
				return common.HexToAddress(d.Contracts.ResolverIncentives)
			}
		}
	}
	if v := os.Getenv("RESOLVER_INCENTIVES_ADDRESS"); v != "" {
		return common.HexToAddress(v)
	}
	return common.Address{}
}

// mustChannelID parses a 0x-hex 32-byte channel id or aborts.
func mustChannelID(s string) [32]byte {
	b, err := hexutil.Decode(s)
	if err != nil || len(b) != 32 {
		fatal(fmt.Errorf("invalid --channel id %q (want 0x + 64 hex)", s))
	}
	var id [32]byte
	copy(id[:], b)
	return id
}

var decimalEth = regexp.MustCompile(`^\d+(\.\d+)?$`)

// mustEth converts a plain decimal ETH amount to wei exactly (no float), or
// aborts. It rejects hex/fraction/scientific forms that big.Rat would happily
// misparse (e.g. "0x10" → 16 ETH, "1/3", "1e3"), and rejects amounts that
// underflow to 0 wei.
func mustEth(s string) *big.Int {
	s = strings.TrimSpace(s)
	if s == "" {
		fatal(errors.New("--amount is required (ETH, e.g. 0.05)"))
	}
	if !decimalEth.MatchString(s) {
		fatal(fmt.Errorf("invalid --amount %q: want a decimal number of ETH, e.g. 0.05", s))
	}
	r, _ := new(big.Rat).SetString(s)
	r.Mul(r, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	wei := new(big.Int).Quo(r.Num(), r.Denom()) // floor to whole wei
	if wei.Sign() == 0 {
		fatal(fmt.Errorf("--amount %q is below 1 wei", s))
	}
	return wei
}
