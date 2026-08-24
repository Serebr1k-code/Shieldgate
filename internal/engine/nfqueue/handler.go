package nfqueue

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/florianl/go-nfqueue/v2"
)

// PacketHandler makes a decision about a packet.
type PacketHandler interface {
	Handle(pkt *Packet) Verdict
}

// Queue binds an NFQUEUE to a PacketHandler and applies verdicts.
type Queue struct {
	queueNum uint16
	nf       *nfqueue.Nfqueue
	handler  PacketHandler
	ctx      context.Context
	cancel   context.CancelFunc
	closed   atomic.Bool
}

// Open attaches to kernel NFQUEUE with the given number.
func Open(queueNum, maxSize, batchSize uint32, h PacketHandler) (*Queue, error) {
	config := nfqueue.Config{
		NfQueue:      uint16(queueNum),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  maxSize,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 0,
	}
	nf, err := nfqueue.Open(&config)
	if err != nil {
		return nil, fmt.Errorf("open nfqueue %d: %w", queueNum, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &Queue{queueNum: uint16(queueNum), nf: nf, handler: h, ctx: ctx, cancel: cancel}
	if err := nf.RegisterWithErrorFunc(ctx, q.packetFn, q.errFn); err != nil {
		cancel()
		nf.Close()
		return nil, fmt.Errorf("register nfqueue callback: %w", err)
	}
	return q, nil
}

func (q *Queue) packetFn(a nfqueue.Attribute) int {
	id := *a.PacketID
	if a.Payload == nil || len(*a.Payload) == 0 {
		if err := q.nf.SetVerdict(id, nfqueue.NfAccept); err != nil {
			log.Printf("nfqueue: set verdict failed: %v", err)
			return 1
		}
		return 0
	}
	var mark uint32
	if a.Mark != nil {
		mark = *a.Mark
	}
	v := q.handler.Handle(&Packet{ID: id, Mark: mark, Data: *a.Payload})
	kv := nfqueue.NfAccept
	if v == Drop {
		kv = nfqueue.NfDrop
	}
	if err := q.nf.SetVerdict(id, kv); err != nil {
		log.Printf("nfqueue: set verdict %s failed: %v", v, err)
		return 1
	}
	return 0
}

func (q *Queue) errFn(e error) int {
	if q.closed.Load() {
		return 1 // expected during shutdown; stay quiet
	}
	log.Printf("nfqueue: error: %v", e)
	return 1
}

// Close detaches from the queue.
func (q *Queue) Close() error {
	if q.nf == nil {
		return nil
	}
	q.cancel()
	q.closed.Store(true)
	err := q.nf.Close()
	q.nf = nil
	return err
}
