package nfqueue

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const tableName = "shieldgate"

// RuleManager programmatically manages nftables rules redirecting
// traffic for service ports into NFQUEUEs.
//
// Rules are installed in TWO hooks:
//   - input   (services running on the host itself)
//   - forward (traffic DNAT'ed by Docker into containers)
type RuleManager struct {
	conn       *nftables.Conn
	queueStart uint16
	chains     []*nftables.Chain
	table      *nftables.Table
}

func NewRuleManager(queueStart uint16) *RuleManager {
	return &RuleManager{conn: &nftables.Conn{}, queueStart: queueStart}
}

func (r *RuleManager) ensureBase() error {
	if r.table != nil {
		return nil
	}
	t := r.conn.AddTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet})
	input := r.conn.AddChain(&nftables.Chain{
		Name:     "input-queue",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	forward := r.conn.AddChain(&nftables.Chain{
		Name:     "forward-queue",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("create base chains: %w", err)
	}
	r.table = t
	r.chains = []*nftables.Chain{input, forward}
	return nil
}

// InstallPorts adds (or replaces) queueing rules for the given TCP ports.
// Each port gets its own NFQUEUE number starting from queueStart.
func (r *RuleManager) InstallPorts(ports []uint16) error {
	if len(ports) == 0 {
		return nil
	}
	if err := r.ensureBase(); err != nil {
		return err
	}
	if err := r.RemovePorts(); err != nil {
		return err
	}
	for _, chain := range r.chains {
		for i, port := range ports {
			r.conn.AddRule(&nftables.Rule{
				Table: r.table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(port)},
					&expr.Queue{Num: uint16(int(r.queueStart) + i), Flag: expr.QueueFlagBypass},
				},
			})
		}
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("install queue rules: %w", err)
	}
	return nil
}

// RemovePorts deletes all shieldgate queue rules.
func (r *RuleManager) RemovePorts() error {
	if r.table == nil {
		return nil // nothing installed yet
	}
	for _, c := range r.chains {
		rules, err := r.conn.GetRules(r.table, c)
		if err != nil {
			return fmt.Errorf("get rules: %w", err)
		}
		for _, rule := range rules {
			if len(rule.Exprs) > 0 {
				if _, isQueue := rule.Exprs[len(rule.Exprs)-1].(*expr.Queue); isQueue {
					if err := r.conn.DelRule(rule); err != nil {
						return fmt.Errorf("del rule: %w", err)
					}
				}
			}
		}
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush removal: %w", err)
	}
	return nil
}

// Teardown removes table and chains entirely.
func (r *RuleManager) Teardown() error {
	if err := r.RemovePorts(); err != nil {
		return err
	}
	if r.table == nil {
		return nil
	}
	r.conn.DelTable(r.table)
	r.table = nil
	r.chains = nil
	return r.conn.Flush()
}

func be16(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}
