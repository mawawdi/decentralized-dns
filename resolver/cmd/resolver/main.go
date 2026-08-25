// Command resolver runs the Decentralized DNS Resolver Server: REST/UDP
// query APIs backed by a TTL cache, the blockchain client, the BitTorrent
// engine, and the PKI/ZK verifier (HLD §3).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mawawdi/decentralized-dns/resolver/internal/config"
	"github.com/mawawdi/decentralized-dns/resolver/internal/server"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := server.New(ctx, cfg, log)
	if err != nil {
		log.Error("boot failed", "err", err)
		os.Exit(1)
	}
	if err := srv.Run(ctx); err != nil {
		log.Error("server exited", "err", err)
		os.Exit(1)
	}
}
