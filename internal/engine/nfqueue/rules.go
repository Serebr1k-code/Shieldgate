package nfqueue

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	tableName = "shieldgate"
	chainName = "input-queue"
)

// RuleManager programmatically manages nftables rules redirecting
// traffic for service ports into NFQUEUEs.
type RuleManager struct {
	conn       *nftables.Conn
	queueStart uint16
}

func NewRuleManager(queueStart uint16) *RuleManager {
	return &RuleManager{conn: &nftables.Conn{}, queueStart: queueStart}
}

// ensureBase creates the shieldgate table and hook chain if missing.
func (r *RuleManager) ensureBase() (*nftables.Table, *nftables.Chain, error) {
	t := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	chains, err := r.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, nil, fmt.Errorf("list chains: %w", err)
	}
	for _, c := range chains {
		if c.Table.Name == tableName && c.Name == chainName {
			return c.Table, c, nil
		}
	}
	t = r.conn.AddTable(t)
	c := r.conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	if err := r.conn.Flush(); err != nil {
		return nil, nil, fmt.Errorf("flush base rules: %w", err)
	}
	return t, c, nil
}

// InstallPorts adds (or replaces) queueing rules for the given TCP ports.
// Each port gets its own NFQUEUE number starting from queueStart.
func (r *RuleManager) InstallPorts(ports []uint16) error {
	t, c, err := r.ensureBase()
	if err != nil {
		return err
	}
	if err := r.RemovePorts(); err != nil {
		return err
	}
	for i, port := range ports {
		r.conn.AddRule(&nftables.Rule{
			Table: t,
			Chain: c,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(port)},
				&expr.Queue{Num: uint16(int(r.queueStart) + i), Flag: expr.QueueFlagBypass},
			},
		})
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("install queue rules: %w", err)
	}
	return nil
}

// RemovePorts deletes all shieldgate queue rules.
func (r *RuleManager) RemovePorts() error {
	t, c, err := r.ensureBase()
	if err != nil {
		return err
	}
	rules, err := r.conn.GetRules(t, c)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}
	for _, rule := range rules {
		if rule.Chain.Name == chainName && len(rule.Exprs) > 0 {
			if _, isQueue := rule.Exprs[len(rule.Exprs)-1].(*expr.Queue); isQueue {
				if err := r.conn.DelRule(rule); err != nil {
					return fmt.Errorf("del rule: %w", err)
				}
			}
		}
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush removal: %w", err)
	}
	_ = c
	return nil
}

// Teardown removes table and chain entirely.
func (r *RuleManager) Teardown() error {
	t := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	if err := r.RemovePorts(); err != nil {
		return err
	}
	r.conn.DelTable(t)
	return r.conn.Flush()
}

func be16(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}
