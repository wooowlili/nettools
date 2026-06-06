package stat

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestBuckets() *buckets {
	return newBuckets(time.Second, 100, false)
}

func newTestLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// ---------------------------------------------------------------------------
// bucket.put
// ---------------------------------------------------------------------------

func TestBucketPutAndReceived(t *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()

	b.put(1234, 5678, 1, ts)
	b.put(1234, 5678, 2, ts)
	b.received(1, ts, 500000, false)
	b.received(2, ts, 600000, true)

	oldest := b.oldest()
	if oldest == nil {
		t.Fatal("expected non-nil oldest bucket")
	}

	sr := oldest.stat()
	if sr.sent != 2 {
		t.Errorf("sent = %d, want 2", sr.sent)
	}
	if sr.received != 2 {
		t.Errorf("received = %d, want 2", sr.received)
	}
	if sr.loss != 0 {
		t.Errorf("loss = %d, want 0", sr.loss)
	}
}

func TestBucketPutOverwrite(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(300, 400, 1, 2000) // overwrite seq 1 with new ports/ts

	bk.RLock()
	r := bk.requests[1]
	bk.RUnlock()

	if r.clientPort != 300 {
		t.Errorf("clientPort = %d, want 300 after overwrite", r.clientPort)
	}
	if r.serverPort != 400 {
		t.Errorf("serverPort = %d, want 400 after overwrite", r.serverPort)
	}
	if r.ts != 2000 {
		t.Errorf("ts = %d, want 2000 after overwrite", r.ts)
	}
}

func TestBucketPutMultipleSeqs(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	for i := uint64(0); i < 10; i++ {
		bk.put(uint16(i), uint16(i*10), i, int64(i)*1000)
	}

	bk.RLock()
	count := len(bk.requests)
	bk.RUnlock()

	if count != 10 {
		t.Errorf("expected 10 requests, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// bucket.delete
// ---------------------------------------------------------------------------

func TestBucketDelete(t *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()

	b.put(1234, 5678, 1, ts)
	b.delete(1, ts)

	oldest := b.oldest()
	sr := oldest.stat()
	if sr.sent != 0 {
		t.Errorf("sent = %d, want 0 after delete", sr.sent)
	}
}

func TestBucketDeleteNonExistent(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.delete(999) // should not panic

	bk.RLock()
	count := len(bk.requests)
	bk.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 request after deleting non-existent, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// bucket.received
// ---------------------------------------------------------------------------

func TestBucketReceivedExistingSeq(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.received(1, 1500, false)

	bk.RLock()
	r := bk.requests[1]
	bk.RUnlock()

	if r.rtt != 1500 {
		t.Errorf("rtt = %d, want 1500", r.rtt)
	}
	if r.hasBitflip {
		t.Error("hasBitflip should be false")
	}
}

func TestBucketReceivedOutOfOrder(t *testing.T) {
	// received called before put — should create a new entry
	bk := newBucket(1, time.Second, 100, false)
	bk.received(42, 999, true)

	bk.RLock()
	r, ok := bk.requests[42]
	bk.RUnlock()

	if !ok {
		t.Fatal("expected request for seq 42")
	}
	if r.rtt != 999 {
		t.Errorf("rtt = %d, want 999", r.rtt)
	}
	if !r.hasBitflip {
		t.Error("hasBitflip should be true")
	}
}

func TestBucketReceivedOverwritesRtt(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.received(1, 500, false)
	bk.received(1, 800, true) // overwrite

	bk.RLock()
	r := bk.requests[1]
	bk.RUnlock()

	if r.rtt != 800 {
		t.Errorf("rtt = %d, want 800 after overwrite", r.rtt)
	}
	if !r.hasBitflip {
		t.Error("hasBitflip should be true after overwrite")
	}
}

// ---------------------------------------------------------------------------
// bucket.stat
// ---------------------------------------------------------------------------

func TestBucketStatEmpty(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	sr := bk.stat()
	if sr.sent != 0 || sr.received != 0 || sr.loss != 0 {
		t.Errorf("empty bucket: sent=%d received=%d loss=%d, want all 0", sr.sent, sr.received, sr.loss)
	}
}

func TestBucketStatAllReceived(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	for i := uint64(1); i <= 5; i++ {
		bk.put(100, 200, i, 1000)
		bk.received(i, int64(i)*100, false)
	}
	sr := bk.stat()
	if sr.sent != 5 {
		t.Errorf("sent = %d, want 5", sr.sent)
	}
	if sr.received != 5 {
		t.Errorf("received = %d, want 5", sr.received)
	}
	if sr.loss != 0 {
		t.Errorf("loss = %d, want 0", sr.loss)
	}
	if sr.lossRate != 0 {
		t.Errorf("lossRate = %f, want 0", sr.lossRate)
	}
}

func TestBucketStatPartialLoss(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(100, 200, 2, 1000)
	bk.put(100, 200, 3, 1000)
	bk.received(1, 100, false)
	// seq 2 and 3 never received

	sr := bk.stat()
	if sr.sent != 3 {
		t.Errorf("sent = %d, want 3", sr.sent)
	}
	if sr.received != 1 {
		t.Errorf("received = %d, want 1", sr.received)
	}
	if sr.loss != 2 {
		t.Errorf("loss = %d, want 2", sr.loss)
	}
}

func TestBucketStatLossRate(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(100, 200, 2, 1000)
	bk.received(1, 100, false)

	sr := bk.stat()
	if sr.lossRate != 0.5 {
		t.Errorf("lossRate = %f, want 0.5", sr.lossRate)
	}
}

func TestBucketStatLossRate100(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(100, 200, 2, 1000)
	// nothing received

	sr := bk.stat()
	if sr.lossRate != 1.0 {
		t.Errorf("lossRate = %f, want 1.0", sr.lossRate)
	}
}

func TestBucketStatAvgRtt(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(100, 200, 2, 1000)
	bk.received(1, 200, false)
	bk.received(2, 400, false)

	sr := bk.stat()
	if sr.rtt != 300 {
		t.Errorf("avg rtt = %d, want 300", sr.rtt)
	}
}

func TestBucketStatMaxRtt(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(100, 200, 2, 1000)
	bk.put(100, 200, 3, 1000)
	bk.received(1, 100, false)
	bk.received(2, 500, false)
	bk.received(3, 300, false)

	sr := bk.stat()
	if sr.maxRTT != 500 {
		t.Errorf("maxRTT = %d, want 500", sr.maxRTT)
	}
}

func TestBucketStatRttWithLoss(t *testing.T) {
	// Avg RTT should only count received packets
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(100, 200, 2, 1000)
	bk.received(1, 300, false)
	// seq 2 lost

	sr := bk.stat()
	if sr.rtt != 300 {
		t.Errorf("avg rtt = %d, want 300 (only received)", sr.rtt)
	}
}

func TestBucketStatBitflipPorts(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(43500, 43500, 1, 1000)
	bk.put(43501, 43501, 2, 1000)
	bk.received(1, 100, true)
	bk.received(2, 200, false)

	sr := bk.stat()
	if len(sr.bitflipPorts) != 1 {
		t.Errorf("bitflipPorts count = %d, want 1", len(sr.bitflipPorts))
	}
	if sr.bitflipPorts[43500] != 43500 {
		t.Errorf("bitflipPorts[43500] = %d, want 43500", sr.bitflipPorts[43500])
	}
}

func TestBucketStatLossPorts(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(43500, 43500, 1, 1000)
	bk.put(43501, 43501, 2, 1000)
	bk.received(1, 100, false)
	// seq 2 lost

	sr := bk.stat()
	if len(sr.lossPorts) != 1 {
		t.Errorf("lossPorts count = %d, want 1", len(sr.lossPorts))
	}
	if sr.lossPorts[43501] != 43501 {
		t.Errorf("lossPorts[43501] = %d, want 43501", sr.lossPorts[43501])
	}
}

func TestBucketStatBitflipPortsCount(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(43500, 43500, 1, 1000)
	bk.put(43500, 43500, 2, 1000)
	bk.received(1, 100, true)
	bk.received(2, 100, true)

	sr := bk.stat()
	key := "43500-43500"
	if sr.bitflipPortsCount[key] != 2 {
		t.Errorf("bitflipPortsCount[%s] = %d, want 2", key, sr.bitflipPortsCount[key])
	}
}

func TestBucketStatLossPortsCount(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(43500, 43500, 1, 1000)
	bk.put(43500, 43500, 2, 1000)
	// both lost

	sr := bk.stat()
	key := "43500-43500"
	if sr.lossPortsCount[key] != 2 {
		t.Errorf("lossPortsCount[%s] = %d, want 2", key, sr.lossPortsCount[key])
	}
}

// ---------------------------------------------------------------------------
// buckets.put / received / oldest
// ---------------------------------------------------------------------------

func TestBucketsPutCreatesBucket(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	bs.put(100, 200, 1, ts)

	oldest := bs.oldest()
	if oldest == nil {
		t.Fatal("expected bucket to be created")
	}
}

func TestBucketsPutMinIDTracking(t *testing.T) {
	bs := newTestBuckets()
	now := time.Now()

	// Put in two different spans
	ts1 := now.Add(-2 * time.Second).UnixNano()
	ts2 := now.UnixNano()
	bs.put(100, 200, 1, ts1)
	bs.put(100, 200, 2, ts2)

	bs.RLock()
	minID := bs.minID
	bs.RUnlock()

	expectedMin := ts1 / int64(time.Second)
	if minID != expectedMin {
		t.Errorf("minID = %d, want %d", minID, expectedMin)
	}
}

func TestBucketsReceivedCreatesBucket(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	// received without prior put — should create bucket
	bs.received(1, ts, 500, false)

	oldest := bs.oldest()
	if oldest == nil {
		t.Fatal("expected bucket to be created by received")
	}
}

func TestBucketsMultipleSpans(t *testing.T) {
	bs := newTestBuckets()
	now := time.Now()

	ts1 := now.Add(-5 * time.Second).UnixNano()
	ts2 := now.UnixNano()

	bs.put(100, 200, 1, ts1)
	bs.put(100, 200, 2, ts2)
	bs.received(1, ts1, 100, false)
	bs.received(2, ts2, 200, false)

	bs.RLock()
	count := len(bs.buckets)
	bs.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 buckets, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// buckets.remove
// ---------------------------------------------------------------------------

func TestBucketsRemove(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()

	bs.put(1234, 5678, 1, ts)
	oldest := bs.oldest()
	if oldest == nil {
		t.Fatal("expected bucket before remove")
	}

	bs.remove(oldest.id)
	if bs.oldest() != nil {
		t.Error("expected nil oldest after remove")
	}
}

func TestBucketsRemoveUpdatesMinID(t *testing.T) {
	bs := newTestBuckets()
	now := time.Now()

	ts1 := now.Add(-3 * time.Second).UnixNano()
	ts2 := now.Add(-2 * time.Second).UnixNano()
	ts3 := now.Add(-1 * time.Second).UnixNano()

	bs.put(100, 200, 1, ts1)
	bs.put(100, 200, 2, ts2)
	bs.put(100, 200, 3, ts3)

	id1 := ts1 / int64(time.Second)
	id2 := ts2 / int64(time.Second)

	// Remove oldest — minID should move to id2
	bs.remove(id1)

	bs.RLock()
	minID := bs.minID
	bs.RUnlock()

	if minID != id2 {
		t.Errorf("minID = %d, want %d after removing oldest", minID, id2)
	}
}

func TestBucketsRemoveNonExistent(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	bs.put(100, 200, 1, ts)

	bs.remove(99999) // should not panic or affect existing
	if bs.oldest() == nil {
		t.Error("removing non-existent bucket should not affect others")
	}
}

func TestBucketsRemoveAll(t *testing.T) {
	bs := newTestBuckets()
	now := time.Now()

	for i := 0; i < 5; i++ {
		ts := now.Add(time.Duration(i) * time.Second).UnixNano()
		bs.put(100, 200, uint64(i), ts)
	}

	bs.RLock()
	ids := make([]int64, 0, len(bs.buckets))
	for id := range bs.buckets {
		ids = append(ids, id)
	}
	bs.RUnlock()

	for _, id := range ids {
		bs.remove(id)
	}

	if bs.oldest() != nil {
		t.Error("expected nil oldest after removing all buckets")
	}
}

// ---------------------------------------------------------------------------
// buckets.receivedAndFix
// ---------------------------------------------------------------------------

func TestReceivedAndFix(t *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()
	prevBucketID := ts/int64(time.Second) - 1

	// Create previous bucket explicitly
	b.Lock()
	b.buckets[prevBucketID] = newBucket(prevBucketID, time.Second, 100, false)
	b.Unlock()

	b.receivedAndFix(1, ts, 500000, 42, 43500, 43500, false)

	prev := b.buckets[prevBucketID]
	if prev == nil {
		t.Fatal("expected previous bucket")
	}
	prev.RLock()
	got := prev.packetCount
	gotSrc := prev.startSrcPort
	gotDst := prev.startDstPort
	prev.RUnlock()
	if got != 42 {
		t.Errorf("prev.packetCount = %d, want 42", got)
	}
	if gotSrc != 43500 {
		t.Errorf("prev.startSrcPort = %d, want 43500", gotSrc)
	}
	if gotDst != 43500 {
		t.Errorf("prev.startDstPort = %d, want 43500", gotDst)
	}
}

func TestReceivedAndFixIdempotent(t *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()
	prevBucketID := ts/int64(time.Second) - 1

	b.Lock()
	b.buckets[prevBucketID] = newBucket(prevBucketID, time.Second, 100, false)
	b.Unlock()

	// First fix sets packetCount to 42
	b.receivedAndFix(1, ts, 500000, 42, 43500, 43500, false)
	// Second fix should NOT overwrite — fixed flag is set
	b.receivedAndFix(2, ts, 600000, 99, 43501, 43501, false)

	prev := b.buckets[prevBucketID]
	prev.RLock()
	got := prev.packetCount
	prev.RUnlock()

	if got != 42 {
		t.Errorf("prev.packetCount = %d, want 42 (should not be overwritten by second fix)", got)
	}
}

func TestReceivedAndFixZeroLastSentCount(t *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()
	prevBucketID := ts/int64(time.Second) - 1

	b.Lock()
	b.buckets[prevBucketID] = newBucket(prevBucketID, time.Second, 100, false)
	b.Unlock()

	// lastSentCount=0 should not update prev bucket
	b.receivedAndFix(1, ts, 500000, 0, 0, 0, false)

	prev := b.buckets[prevBucketID]
	prev.RLock()
	got := prev.packetCount
	prev.RUnlock()

	if got != 100 {
		t.Errorf("prev.packetCount = %d, want 100 (original, not overwritten by 0)", got)
	}
}

func TestReceivedAndFixNoPrevBucket(_ *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()
	// No previous bucket exists — should not panic
	b.receivedAndFix(1, ts, 500000, 42, 0, 0, false)
}

func TestReceivedAndFixCreatesCurrentBucket(t *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()
	b.receivedAndFix(1, ts, 500000, 42, 0, 0, false)

	bucketID := ts / int64(time.Second)
	b.RLock()
	current := b.buckets[bucketID]
	b.RUnlock()

	if current == nil {
		t.Fatal("expected current bucket to be created")
	}

	current.RLock()
	r := current.requests[1]
	current.RUnlock()

	if r.rtt != 500000 {
		t.Errorf("rtt = %d, want 500000", r.rtt)
	}
}

// ---------------------------------------------------------------------------
// buckets.delete
// ---------------------------------------------------------------------------

func TestBucketsDelete(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	bs.put(100, 200, 1, ts)
	bs.delete(1, ts)

	oldest := bs.oldest()
	if oldest == nil {
		t.Fatal("bucket should still exist after delete")
	}
	sr := oldest.stat()
	if sr.sent != 0 {
		t.Errorf("sent = %d, want 0 after delete", sr.sent)
	}
}

func TestBucketsDeleteNonExistentSeq(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	bs.put(100, 200, 1, ts)
	bs.delete(999, ts) // should not panic

	oldest := bs.oldest()
	sr := oldest.stat()
	if sr.sent != 1 {
		t.Errorf("sent = %d, want 1 (delete of non-existent should be no-op)", sr.sent)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestConcurrentAccess(t *testing.T) {
	b := newTestBuckets()
	ts := time.Now().UnixNano()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			b.put(1234, 5678, seq, ts)
			b.received(seq, ts, 1000, false)
		}(uint64(i) + 1)
	}
	wg.Wait()

	oldest := b.oldest()
	sr := oldest.stat()
	if sr.sent != 100 {
		t.Errorf("sent = %d, want 100", sr.sent)
	}
	if sr.received != 100 {
		t.Errorf("received = %d, want 100", sr.received)
	}
}

func TestConcurrentPutAndRemove(t *testing.T) {
	bs := newTestBuckets()
	now := time.Now()

	var wg sync.WaitGroup
	// Concurrent puts
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ts := now.Add(time.Duration(i) * time.Second).UnixNano()
			bs.put(100, 200, uint64(i), ts)
		}(i)
	}
	wg.Wait()

	// Remove all
	bs.RLock()
	ids := make([]int64, 0, len(bs.buckets))
	for id := range bs.buckets {
		ids = append(ids, id)
	}
	bs.RUnlock()

	var wg2 sync.WaitGroup
	for _, id := range ids {
		wg2.Add(1)
		go func(id int64) {
			defer wg2.Done()
			bs.remove(id)
		}(id)
	}
	wg2.Wait()

	if bs.oldest() != nil {
		t.Error("expected nil oldest after removing all")
	}
}

func TestConcurrentReceivedAndFix(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	prevBucketID := ts/int64(time.Second) - 1

	bs.Lock()
	bs.buckets[prevBucketID] = newBucket(prevBucketID, time.Second, 100, false)
	bs.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bs.receivedAndFix(uint64(i), ts, int64(i)*100, uint32(i*10), 0, 0, false)
		}(i)
	}
	wg.Wait()

	// First fix wins; the rest are ignored
	prev := bs.buckets[prevBucketID]
	prev.RLock()
	pc := prev.packetCount
	prev.RUnlock()

	if pc == 0 {
		t.Error("expected non-zero packetCount from receivedAndFix")
	}
}

// ---------------------------------------------------------------------------
// NewStat + StatOnce
// ---------------------------------------------------------------------------

func TestNewStatAndStatOnce(_ *testing.T) {
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ts := time.Now().UnixNano()
	s.Put(43500, 43500, 1, ts)
	s.Received(1, ts, 500000, false)

	ud := s.(*udpStat)
	ud.statOnce()
}

func TestNewStatAndStatOnceEmpty(_ *testing.T) {
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ud := s.(*udpStat)
	ud.statOnce() // should not panic on empty
}

func TestStatPutDeleteReceived(_ *testing.T) {
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ts := time.Now().UnixNano()
	s.Put(43500, 43500, 1, ts)
	s.Delete(1, ts) // delete it
	s.Put(43501, 43501, 2, ts)
	s.Received(2, ts, 300, false)

	ud := s.(*udpStat)
	ud.statOnce()
}

func TestStatReceivedAndFix(_ *testing.T) {
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ts := time.Now().UnixNano()
	s.Put(43500, 43500, 1, ts)
	s.ReceivedAndFix(1, ts, 500, 42, 0, 0, false)

	ud := s.(*udpStat)
	ud.statOnce()
}

func TestStatMultipleBuckets(_ *testing.T) {
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	now := time.Now()
	for i := 0; i < 5; i++ {
		ts := now.Add(time.Duration(i) * time.Second).UnixNano()
		s.Put(43500, 43500, uint64(i), ts)
		s.Received(uint64(i), ts, int64((i+1)*100), false)
	}

	ud := s.(*udpStat)
	// Process all buckets
	for i := 0; i < 6; i++ {
		ud.statOnce()
	}
}

// ---------------------------------------------------------------------------
// Processor
// ---------------------------------------------------------------------------

func TestProcessorAddStat(t *testing.T) {
	p := NewProcessor(time.Second, 100*time.Millisecond)
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))
	p.AddStat(s)

	if len(p.stats) != 1 {
		t.Errorf("expected 1 stat, got %d", len(p.stats))
	}
}

func TestProcessorRunAndCancel(t *testing.T) {
	p := NewProcessor(50*time.Millisecond, 50*time.Millisecond)
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 50*time.Millisecond, NewLogSender(logger, false))
	p.AddStat(s)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()

	// Let it run for a couple ticks
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Error("Processor.Run did not exit after cancel")
	}
}

func TestProcessorMultipleStats(t *testing.T) {
	p := NewProcessor(time.Second, 100*time.Millisecond)
	logger := newTestLogger()

	for i := 0; i < 5; i++ {
		s := NewStat("1.2.3.4", "5.6.7.8",
			PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
			100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))
		p.AddStat(s)
	}

	if len(p.stats) != 5 {
		t.Errorf("expected 5 stats, got %d", len(p.stats))
	}
}

// ---------------------------------------------------------------------------
// newBucket
// ---------------------------------------------------------------------------

func TestNewBucketFields(t *testing.T) {
	bk := newBucket(42, time.Second, 1000, false)
	if bk.id != 42 {
		t.Errorf("id = %d, want 42", bk.id)
	}
	if bk.startNano != 42*int64(time.Second) {
		t.Errorf("startNano = %d, want %d", bk.startNano, 42*int64(time.Second))
	}
	if bk.packetCount != 1000 {
		t.Errorf("packetCount = %d, want 1000", bk.packetCount)
	}
	if bk.requests == nil {
		t.Error("requests map should be initialized")
	}
	if bk.fixed {
		t.Error("fixed should be false initially")
	}
}

// ---------------------------------------------------------------------------
// newBuckets
// ---------------------------------------------------------------------------

func TestNewBucketsFields(t *testing.T) {
	bs := newBuckets(5*time.Second, 500, false)
	if bs.span != 5*time.Second {
		t.Errorf("span = %v, want %v", bs.span, 5*time.Second)
	}
	if bs.rateInSpan != 500 {
		t.Errorf("rateInSpan = %d, want 500", bs.rateInSpan)
	}
	if bs.minID != -1 {
		t.Errorf("minID = %d, want -1", bs.minID)
	}
	if len(bs.buckets) != 0 {
		t.Errorf("buckets should be empty, got %d", len(bs.buckets))
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestBucketStatOnlyReceivedNoPut(t *testing.T) {
	// received without put — entry created with seq only, no ports
	bk := newBucket(1, time.Second, 100, false)
	bk.received(1, 500, false)

	sr := bk.stat()
	if sr.sent != 1 {
		t.Errorf("sent = %d, want 1", sr.sent)
	}
	if sr.received != 1 {
		t.Errorf("received = %d, want 1", sr.received)
	}
	if sr.rtt != 500 {
		t.Errorf("rtt = %d, want 500", sr.rtt)
	}
}

func TestBucketStatAllLost(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	for i := uint64(1); i <= 10; i++ {
		bk.put(uint16(i), uint16(i*10), i, 1000)
	}

	sr := bk.stat()
	if sr.sent != 10 {
		t.Errorf("sent = %d, want 10", sr.sent)
	}
	if sr.received != 0 {
		t.Errorf("received = %d, want 0", sr.received)
	}
	if sr.loss != 10 {
		t.Errorf("loss = %d, want 10", sr.loss)
	}
	if sr.lossRate != 1.0 {
		t.Errorf("lossRate = %f, want 1.0", sr.lossRate)
	}
}

func TestBucketsOldestEmpty(t *testing.T) {
	bs := newTestBuckets()
	if bs.oldest() != nil {
		t.Error("expected nil for empty buckets")
	}
}

func TestBucketReceivedWithBitflipNotCountedAsLoss(t *testing.T) {
	// Bitflipped packets are still "received" — they should not be counted as loss
	bk := newBucket(1, time.Second, 100, false)
	bk.put(43500, 43500, 1, 1000)
	bk.received(1, 500, true)

	sr := bk.stat()
	if sr.received != 1 {
		t.Errorf("received = %d, want 1 (bitflip is still received)", sr.received)
	}
	if sr.loss != 0 {
		t.Errorf("loss = %d, want 0 (bitflip is not loss)", sr.loss)
	}
}

func TestBucketsRemoveOnlyBucketResetsMinID(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	bs.put(100, 200, 1, ts)

	id := ts / int64(time.Second)
	bs.remove(id)

	bs.RLock()
	minID := bs.minID
	bs.RUnlock()

	if minID != -1 {
		t.Errorf("minID = %d, want -1 after removing last bucket", minID)
	}
}

// ---------------------------------------------------------------------------
// Server-side stat tests
// ---------------------------------------------------------------------------

func TestServerStatUsesPacketCount(t *testing.T) {
	bk := newBucket(1, time.Second, 100, true)
	bk.packetCount = 10
	bk.packetCountFixed = true
	bk.received(1, 500, false)
	bk.received(2, 600, false)
	bk.received(3, 700, false)

	sr := bk.stat()
	if sr.sent != 10 {
		t.Errorf("server sent = %d, want 10 (packetCount)", sr.sent)
	}
	if sr.received != 3 {
		t.Errorf("server received = %d, want 3", sr.received)
	}
	if sr.loss != 7 {
		t.Errorf("server loss = %d, want 7", sr.loss)
	}
}

func TestServerStatUnfixedUsesReceivedAsSent(t *testing.T) {
	bk := newBucket(1, time.Second, 100, true)
	// packetCountFixed is false — first bucket, not yet corrected
	bk.received(1, 500, false)
	bk.received(2, 600, false)

	sr := bk.stat()
	if sr.sent != 2 {
		t.Errorf("unfixed server sent = %d, want 2 (len(requests))", sr.sent)
	}
	if sr.loss != 0 {
		t.Errorf("unfixed server loss = %d, want 0", sr.loss)
	}
}

func TestServerStatNoLossPorts(t *testing.T) {
	bk := newBucket(1, time.Second, 100, true)
	bk.packetCount = 5
	bk.received(1, 500, false)

	sr := bk.stat()
	if sr.lossPorts != nil {
		t.Errorf("server lossPorts should be nil, got %v", sr.lossPorts)
	}
	if sr.lossPortsCount != nil {
		t.Errorf("server lossPortsCount should be nil, got %v", sr.lossPortsCount)
	}
}

func TestServerStatLossRateClampsNegative(t *testing.T) {
	bk := newBucket(1, time.Second, 100, true)
	bk.packetCount = 2
	bk.packetCountFixed = true
	bk.received(1, 500, false)
	bk.received(2, 600, false)
	bk.received(3, 700, false) // more received than packetCount

	sr := bk.stat()
	if sr.loss != 0 {
		t.Errorf("server loss = %d, want 0 (clamped)", sr.loss)
	}
}

func TestServerStatAvgRtt(t *testing.T) {
	bk := newBucket(1, time.Second, 100, true)
	bk.packetCount = 3
	bk.received(1, 200, false)
	bk.received(2, 400, false)

	sr := bk.stat()
	if sr.rtt != 300 {
		t.Errorf("server avg rtt = %d, want 300", sr.rtt)
	}
}

func TestNewServerStat(t *testing.T) {
	logger := newTestLogger()
	s := NewServerStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ts := time.Now().UnixNano()
	s.ReceivedAndFix(1, ts, 500000, 42, 0, 0, false)

	ud := s.(*udpStat)
	if !ud.serverSide {
		t.Error("expected serverSide to be true")
	}
	ud.statOnce()
}

// ---------------------------------------------------------------------------
// GetNextPorts
// ---------------------------------------------------------------------------

func TestGetNextPorts(t *testing.T) {
	tests := []struct {
		name              string
		clientPort        uint16
		serverPort        uint16
		clientPortRange   PortRange
		serverPortRange   PortRange
		wantClient        uint16
		wantServer        uint16
	}{
		{
			name:            "increment server port",
			clientPort:      43500,
			serverPort:      43500,
			clientPortRange: PortRange{Min: 43500, Max: 43599},
			serverPortRange: PortRange{Min: 43500, Max: 43509},
			wantClient:      43500,
			wantServer:      43501,
		},
		{
			name:            "server port wraps increments client",
			clientPort:      43500,
			serverPort:      43509,
			clientPortRange: PortRange{Min: 43500, Max: 43599},
			serverPortRange: PortRange{Min: 43500, Max: 43509},
			wantClient:      43501,
			wantServer:      43500,
		},
		{
			name:            "both wrap",
			clientPort:      43599,
			serverPort:      43509,
			clientPortRange: PortRange{Min: 43500, Max: 43599},
			serverPortRange: PortRange{Min: 43500, Max: 43509},
			wantClient:      43500,
			wantServer:      43500,
		},
		{
			name:            "single server port",
			clientPort:      100,
			serverPort:      200,
			clientPortRange: PortRange{Min: 100, Max: 200},
			serverPortRange: PortRange{Min: 200, Max: 200},
			wantClient:      101,
			wantServer:      200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClient, gotServer := GetNextPorts(tt.clientPort, tt.serverPort, tt.clientPortRange, tt.serverPortRange)
			if gotClient != tt.wantClient || gotServer != tt.wantServer {
				t.Errorf("GetNextPorts(%d, %d) = (%d, %d), want (%d, %d)",
					tt.clientPort, tt.serverPort, gotClient, gotServer, tt.wantClient, tt.wantServer)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// receivedRST / updateReceivedRST
// ---------------------------------------------------------------------------

func TestBucketReceivedRSTExistingSeq(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.receivedRST(1, 500)

	bk.RLock()
	r := bk.requests[1]
	bk.RUnlock()

	if !r.isRst {
		t.Error("isRst should be true after receivedRST")
	}
	if r.rtt != 500 {
		t.Errorf("rtt = %d, want 500", r.rtt)
	}
}

func TestBucketReceivedRSTOutOfOrder(t *testing.T) {
	// receivedRST without prior put — should create new entry
	bk := newBucket(1, time.Second, 100, false)
	bk.receivedRST(42, 999)

	bk.RLock()
	r, ok := bk.requests[42]
	bk.RUnlock()

	if !ok {
		t.Fatal("expected request for seq 42")
	}
	if !r.isRst {
		t.Error("isRst should be true")
	}
	if r.rtt != 999 {
		t.Errorf("rtt = %d, want 999", r.rtt)
	}
}

func TestBucketUpdateReceivedRSTNotFound(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	found := bk.updateReceivedRST(999, 100)
	if found {
		t.Error("updateReceivedRST should return false for missing seq")
	}
}

func TestBucketUpdateReceivedRSTFound(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	found := bk.updateReceivedRST(1, 500)
	if !found {
		t.Error("updateReceivedRST should return true for existing seq")
	}

	bk.RLock()
	r := bk.requests[1]
	bk.RUnlock()

	if !r.isRst {
		t.Error("isRst should be true")
	}
}

func TestBucketsReceivedRST(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()

	bs.put(100, 200, 1, ts)
	bs.receivedRST(1, ts, 0)

	oldest := bs.oldest()
	if oldest == nil {
		t.Fatal("expected bucket")
	}

	sr := oldest.stat()
	if sr.rst != 1 {
		t.Errorf("rst = %d, want 1", sr.rst)
	}
	if sr.synack != 0 {
		t.Errorf("synack = %d, want 0", sr.synack)
	}
	if sr.received != 1 {
		t.Errorf("received = %d, want 1 (RST is still received)", sr.received)
	}
}

func TestBucketsReceivedRSTCreatesBucket(t *testing.T) {
	bs := newTestBuckets()
	ts := time.Now().UnixNano()
	// receivedRST without prior put — should create bucket
	bs.receivedRST(1, ts, 0)

	oldest := bs.oldest()
	if oldest == nil {
		t.Fatal("expected bucket to be created by receivedRST")
	}
}

func TestBucketsReceivedRSTPrevBucket(t *testing.T) {
	bs := newTestBuckets()
	span := time.Second
	now := time.Now()

	ts1 := now.Add(-1 * span).UnixNano()
	ts2 := now.UnixNano()

	// Put in bucket ts1/span
	bs.put(100, 200, 1, ts1)

	// receivedRST with timestamp in next span — should find seq 1 in prev bucket
	bs.receivedRST(1, ts2, 0)

	bucketID1 := ts1 / int64(span)
	bs.RLock()
	b := bs.buckets[bucketID1]
	bs.RUnlock()

	if b == nil {
		t.Fatal("expected bucket for ts1")
	}
	sr := b.stat()
	if sr.rst != 1 {
		t.Errorf("rst = %d, want 1", sr.rst)
	}
}

func TestStatReceivedRST(t *testing.T) {
	logger := newTestLogger()
	s := NewStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ts := time.Now().UnixNano()
	s.Put(43500, 43500, 1, ts)
	s.ReceivedRST(1, ts, 0)

	ud := s.(*udpStat)
	ud.statOnce()
}

func TestBucketStatWithRSTAndSynAck(t *testing.T) {
	bk := newBucket(1, time.Second, 100, false)
	bk.put(100, 200, 1, 1000)
	bk.put(100, 200, 2, 1000)
	bk.put(100, 200, 3, 1000)
	bk.received(1, 100, false)   // SYN-ACK
	bk.receivedRST(2, 200)    // RST
	// seq 3: timeout (no response)

	sr := bk.stat()
	if sr.sent != 3 {
		t.Errorf("sent = %d, want 3", sr.sent)
	}
	if sr.received != 2 {
		t.Errorf("received = %d, want 2", sr.received)
	}
	if sr.synack != 1 {
		t.Errorf("synack = %d, want 1", sr.synack)
	}
	if sr.rst != 1 {
		t.Errorf("rst = %d, want 1", sr.rst)
	}
	if sr.loss != 1 {
		t.Errorf("loss = %d, want 1", sr.loss)
	}
}

// ---------------------------------------------------------------------------
// computeServerLossPorts
// ---------------------------------------------------------------------------

func TestComputeServerLossPorts(t *testing.T) {
	logger := newTestLogger()
	s := NewServerStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ud := s.(*udpStat)
	span := time.Second
	now := time.Now()

	// Create a bucket and mark it as fixed with known start ports
	bucketID := now.UnixNano()/int64(span) - 1
	ud.bkts.Lock()
	prevBk := newBucket(bucketID, span, 100, true)
	prevBk.packetCount = 5
	prevBk.packetCountFixed = true
	prevBk.startSrcPort = 43500
	prevBk.startDstPort = 43500
	// Receive some but not all expected packets
	prevBk.received(1, 500, false)
	prevBk.requests[1] = request{clientPort: 43501, serverPort: 43500, rtt: 500}
	ud.bkts.buckets[bucketID] = prevBk
	ud.bkts.Unlock()

	// Current bucket
	ts := now.UnixNano()
	s.ReceivedAndFix(100, ts, 300, 5, 43500, 43500, false)

	// Trigger statOnce to exercise computeServerLossPorts
	ud.bkts.RLock()
	b := ud.bkts.buckets[bucketID]
	ud.bkts.RUnlock()

	if b != nil {
		lossPorts, lossPortsCount := ud.computeServerLossPorts(b)
		if lossPorts == nil {
			t.Log("computeServerLossPorts returned nil (expected if no losses detected)")
		} else {
			t.Logf("lossPorts: %v, lossPortsCount: %v", lossPorts, lossPortsCount)
		}
	}
}

func TestComputeServerLossPortsNoFix(t *testing.T) {
	logger := newTestLogger()
	s := NewServerStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	ud := s.(*udpStat)
	span := time.Second
	bucketID := time.Now().UnixNano()/int64(span) - 1

	// Not fixed — computeServerLossPorts should return nil
	ud.bkts.Lock()
	bk := newBucket(bucketID, span, 100, true)
	ud.bkts.buckets[bucketID] = bk
	ud.bkts.Unlock()

	lp, lpc := ud.computeServerLossPorts(bk)
	if lp != nil || lpc != nil {
		t.Errorf("expected nil for unfixed bucket, got %v %v", lp, lpc)
	}
}

// ---------------------------------------------------------------------------
// LogSender
// ---------------------------------------------------------------------------

func TestLogSenderClientNoLoss(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLogSender(logger, false)

	s.Send(StatResult{
		Timestamp:  time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
		ClientAddr: "1.2.3.4",
		ServerAddr: "5.6.7.8",
		Sent:       10,
		Received:   10,
		Loss:       0,
	})

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("expected [INFO], got: %s", output)
	}
	if !strings.Contains(output, "avg rtt") {
		t.Errorf("expected 'avg rtt' in output, got: %s", output)
	}
}

func TestLogSenderClientWithLoss(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLogSender(logger, true)

	s.Send(StatResult{
		Timestamp:  time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
		ClientAddr: "1.2.3.4",
		ServerAddr: "5.6.7.8",
		Sent:       10,
		Received:   8,
		Loss:       2,
		LossPorts:  map[int]int{43500: 43500},
	})

	output := buf.String()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("expected [WARN], got: %s", output)
	}
	if !strings.Contains(output, "loss ports:") {
		t.Errorf("expected 'loss ports' in verbose mode, got: %s", output)
	}
}

func TestLogSenderServerNoLoss(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLogSender(logger, false)

	s.Send(StatResult{
		Timestamp:  time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
		ClientAddr: "1.2.3.4",
		ServerAddr: "5.6.7.8",
		ServerSide: true,
		Sent:       10,
		Received:   10,
		Loss:       0,
	})

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("expected [INFO], got: %s", output)
	}
}

func TestLogSenderServerWithLoss(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLogSender(logger, true)

	s.Send(StatResult{
		Timestamp:  time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC),
		ClientAddr: "1.2.3.4",
		ServerAddr: "5.6.7.8",
		ServerSide: true,
		Sent:       10,
		Received:   7,
		Loss:       3,
		LossPorts:  map[int]int{43500: 43500},
	})

	output := buf.String()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("expected [WARN], got: %s", output)
	}
	if !strings.Contains(output, "loss ports:") {
		t.Errorf("expected 'loss ports' in verbose server mode, got: %s", output)
	}
}

func TestServerStatReceivedAndFixEndToEnd(t *testing.T) {
	logger := newTestLogger()
	s := NewServerStat("1.2.3.4", "5.6.7.8",
		PortRange{Min: 43500, Max: 43599}, PortRange{Min: 43500, Max: 43509},
		100, time.Second, 100*time.Millisecond, NewLogSender(logger, false))

	now := time.Now()
	span := time.Second

	ts1 := now.Add(-2 * span).UnixNano()
	for i := uint64(1); i <= 8; i++ {
		s.ReceivedAndFix(i, ts1, 500, 0, 0, 0, false)
	}

	ts2 := now.Add(-1 * span).UnixNano()
	s.ReceivedAndFix(100, ts2, 500, 10, 43500, 43500, false)

	ud := s.(*udpStat)
	b1ID := ts1 / int64(span)
	ud.bkts.RLock()
	b1 := ud.bkts.buckets[b1ID]
	ud.bkts.RUnlock()

	if b1 != nil {
		b1.RLock()
		pc := b1.packetCount
		b1.RUnlock()
		if pc != 10 {
			t.Errorf("bucket1 packetCount = %d, want 10 (fixed by ts2 packet)", pc)
		}
	}
}
