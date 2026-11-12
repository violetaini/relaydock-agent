package udp

import (
	"github.com/xtls/xray-core/common/buf"
	udp "github.com/xtls/xray-core/common/protocol/udp"
	"sync/atomic"
	"testing"
)

func TestChitandaHubAllocationBudgetAndRelease(t *testing.T) {
	baseline := atomic.LoadInt64(&globalUDPQueueBytes)
	h := &Hub{budgeted: true}
	b := buf.NewWithSize(1200)
	b.Extend(1200)
	cost := int64(buf.Size) + 128
	if !h.reserveQueueBytes(cost) {
		t.Fatal("valid reservation rejected")
	}
	if bytes, _ := h.QueueStats(); bytes != cost {
		t.Fatalf("reserved %d", bytes)
	}
	h.ReleaseQueuedPacket(&udp.Packet{Payload: b})
	b.Release()
	if bytes, _ := h.QueueStats(); bytes != 0 || atomic.LoadInt64(&globalUDPQueueBytes) != baseline {
		t.Fatal("reservation leak")
	}
	if h.reserveQueueBytes(16<<20 + 1) {
		t.Fatal("per-hub limit exceeded")
	}
}
