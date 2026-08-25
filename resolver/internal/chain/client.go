package chain

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/mawawdi/decentralized-dns/resolver/internal/chain/bindings"
)

const (
	retryAttempts = 3
	retryBaseWait = 150 * time.Millisecond
)

// Client is the resolver's gateway to the blockchain (HLD §3.4). The
// resolver never holds owner keys: this client only performs reads and
// event watching; writes are submitted by owners through their own CLI.
type Client struct {
	eth      *ethclient.Client
	dapp     *bindings.NamespaceDApp
	registry *bindings.RecordSchemaRegistry
	dappAddr common.Address
	log      *slog.Logger
}

// Dial connects to the RPC endpoint and binds both contracts.
func Dial(ctx context.Context, rpcURL string, dappAddr, registryAddr common.Address, log *slog.Logger) (*Client, error) {
	eth, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial rpc %s: %w", rpcURL, err)
	}
	dapp, err := bindings.NewNamespaceDApp(dappAddr, eth)
	if err != nil {
		return nil, fmt.Errorf("bind NamespaceDApp: %w", err)
	}
	registry, err := bindings.NewRecordSchemaRegistry(registryAddr, eth)
	if err != nil {
		return nil, fmt.Errorf("bind RecordSchemaRegistry: %w", err)
	}
	return &Client{eth: eth, dapp: dapp, registry: registry, dappAddr: dappAddr, log: log}, nil
}

// Close releases the underlying RPC connection.
func (c *Client) Close() { c.eth.Close() }

// ChainHead returns the current block number.
func (c *Client) ChainHead(ctx context.Context) (uint64, error) {
	return retry(ctx, c.log, "blockNumber", func() (uint64, error) {
		return c.eth.BlockNumber(ctx)
	})
}

// Resolve performs the combined record+identity lookup used on cache miss.
func (c *Client) Resolve(ctx context.Context, name, recordType, selector string) (*ResolveResult, error) {
	out, err := retry(ctx, c.log, "resolve", func() (struct {
		Record bindings.NamespaceDAppRecord
		Owner  common.Address
		PubKey []byte
	}, error) {
		return c.dapp.Resolve(&bind.CallOpts{Context: ctx}, name, recordType, selector)
	})
	if err != nil {
		return nil, fmt.Errorf("resolve %s/%s: %w", name, recordType, err)
	}
	return &ResolveResult{Record: fromBinding(out.Record), Owner: out.Owner, PubKey: out.PubKey}, nil
}

// GetDomain returns raw domain state (including expired domains).
func (c *Client) GetDomain(ctx context.Context, name string) (*Domain, error) {
	out, err := retry(ctx, c.log, "getDomain", func() (struct {
		Owner      common.Address
		PubKey     []byte
		Expiry     uint64
		Generation uint64
	}, error) {
		return c.dapp.GetDomain(&bind.CallOpts{Context: ctx}, name)
	})
	if err != nil {
		return nil, fmt.Errorf("getDomain %s: %w", name, err)
	}
	return &Domain{Owner: out.Owner, PubKey: out.PubKey, Expiry: out.Expiry, Generation: out.Generation}, nil
}

// ListRecords returns all live records of an active domain.
func (c *Client) ListRecords(ctx context.Context, name string) ([]Record, error) {
	out, err := retry(ctx, c.log, "listRecords", func() ([]bindings.NamespaceDAppRecord, error) {
		return c.dapp.ListRecords(&bind.CallOpts{Context: ctx}, name)
	})
	if err != nil {
		return nil, fmt.Errorf("listRecords %s: %w", name, err)
	}
	records := make([]Record, len(out))
	for i, r := range out {
		records[i] = fromBinding(r)
	}
	return records, nil
}

// ListTypes returns every declared record-type name.
func (c *Client) ListTypes(ctx context.Context) ([]string, error) {
	return retry(ctx, c.log, "listTypes", func() ([]string, error) {
		return c.registry.ListTypes(&bind.CallOpts{Context: ctx})
	})
}

// retry runs fn with bounded exponential back-off (HLD §3.4 RPC retries).
func retry[T any](ctx context.Context, log *slog.Logger, op string, fn func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		if attempt > 0 {
			wait := retryBaseWait << (attempt - 1)
			log.Debug("rpc retry", "op", op, "attempt", attempt, "wait", wait)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return zero, ctx.Err()
			}
		}
		out, err := fn()
		if err == nil {
			return out, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
	}
	return zero, fmt.Errorf("%s failed after %d attempts: %w", op, retryAttempts, lastErr)
}
