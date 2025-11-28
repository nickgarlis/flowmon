package nft

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

func getOrCreateTable(conn *nftables.Conn, tableName string, family nftables.TableFamily) (*nftables.Table, error) {
	table, err := conn.ListTableOfFamily(tableName, family)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, fmt.Errorf("get table %s: %v", tableName, err)
	}

	if table == nil || errors.Is(err, unix.ENOENT) {
		table = &nftables.Table{
			Name:   tableName,
			Family: family,
		}
		conn.AddTable(table)
	}
	return table, nil
}

func getOrCreateChain(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain) (*nftables.Chain, error) {
	got, err := conn.ListChain(table, chain.Name)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, fmt.Errorf("get chain %s: %v", chain.Name, err)
	}

	// If the chain exists, replace it
	// TODO: Could only replace if the existing chain parameters differ
	// from the desired ones.
	if got != nil && !errors.Is(err, unix.ENOENT) {
		conn.FlushChain(got)
		conn.DelChain(got)
	}

	chain = conn.AddChain(chain)
	return chain, nil
}
