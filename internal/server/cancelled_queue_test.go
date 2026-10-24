package server

import (
	"context"
	"github.com/relux-works/swarma-credential-broker/internal/lease"
	"github.com/relux-works/swarma-credential-broker/internal/testutil"
	"github.com/relux-works/swarma-credential-broker/internal/wire"
	"net"
	"reflect"
	"sync"
	"testing"
)

// Claim: disconnect/reconnect churn for one queued lease cannot accumulate more queue entries than the 64-operation bound; live work and recovery remain usable.
func TestReviewCancelledQueueBound(t *testing.T) {
	t.Run("no-churn-control", func(t *testing.T) { cancelledQueueProbe(t, 0) })
	t.Run("disconnect-churn", func(t *testing.T) { cancelledQueueProbe(t, 128) })
}
func cancelledQueueProbe(t *testing.T, cycles int) {
	e := testutil.New(t, lease.Options{})
	running := e.Issue(t)
	queued := e.Issue(t)
	disk, _ := e.Store.Account(e.Account, false)
	before, err := disk.Records()
	if err != nil {
		t.Fatal("before metadata read")
	}
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	var once sync.Once
	unblock := func() { once.Do(func() { close(gate) }) }
	defer unblock()
	done := make(chan lease.Outcome, 1)
	var runningWorker sync.WaitGroup
	runningWorker.Add(1)
	defer func() { unblock(); runningWorker.Wait() }()
	go func() {
		defer runningWorker.Done()
		done <- e.Renew(context.Background(), running, lease.Digest(running.Payload.AccessToken))
	}()
	testutil.Await(t, func() bool { n, _ := e.Owner.Counts(); return n == 1 })
	path := start(t, e, nil)
	for i := 0; i < cycles; i++ {
		c := dial(t, path)
		hello(t, c)
		b, _ := wire.Encode(wire.Renew{LeaseID: queued.LeaseID, RejectedSHA256: lease.Digest(queued.Payload.AccessToken)})
		if wire.Write(c, wire.Request{Method: "lease.renew", ID: "queued", Params: b}) != nil {
			t.Fatal("queued request failed")
		}
		testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 2 && w == 2 })
		c.Close()
		testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 1 && w == 1 })
	}
	// The account worker is parked inside the controlled owner Refresh; after
	// the final detachment no queue writer is active. Reflect reads only size/IDs.
	a := reflect.ValueOf(e.Manager).Elem().FieldByName("accounts").MapIndex(reflect.ValueOf(e.Account)).Elem()
	q := a.FieldByName("queue")
	n := q.Len()
	unique := map[string]bool{}
	for i := 0; i < n; i++ {
		unique[q.Index(i).Elem().FieldByName("id").String()] = true
	}
	t.Logf("actual retained queue=%d unique leases=%d; advertised pending=1 waiters=1", n, len(unique))
	if n > 64 {
		t.Errorf("cancelled operations escaped queue bound: retained=%d limit=64", n)
	}
	// Finish the admitted refresh, then verify abandoned calls did not mutate
	// the queued lease and an ordinary renewal can make progress.
	unblock()
	if out := <-done; out.Err != nil {
		t.Fatal("active refresh control failed")
	}
	testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == 0 && w == 0 })
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Error("canceled requests caused extra refresh")
	}
	after, err := disk.Records()
	if err != nil || string(before["lease-"+queued.LeaseID+".json"]) != string(after["lease-"+queued.LeaseID+".json"]) {
		t.Error("canceled renewals changed queued lease metadata")
	}
	if out := e.Renew(context.Background(), queued, lease.Digest(queued.Payload.AccessToken)); out.Err != nil {
		t.Error("reconnect recovery control failed")
	}
}

// Claim: concurrent disconnects of eight queued leases across 24 admission waves
// reclaim physical entries without reordering two live survivors, refreshing an
// abandoned lease, or changing its durable metadata; reconnect still succeeds.
func TestCancelledQueueConcurrentLeases(t *testing.T) {
	var orderMu sync.Mutex
	var order []string
	e := testutil.New(t, lease.Options{Observe: func(event lease.Event) {
		if event.Kind == "dequeue" {
			orderMu.Lock()
			order = append(order, event.LeaseID)
			orderMu.Unlock()
		}
	}})
	running, first, last := e.Issue(t), e.Issue(t), e.Issue(t)
	abandoned := make([]wire.LeaseResult, 8)
	for i := range abandoned {
		abandoned[i] = e.Issue(t)
	}
	disk, err := e.Store.Account(e.Account, false)
	if err != nil {
		t.Fatal(err)
	}
	before, err := disk.Records()
	if err != nil {
		t.Fatal(err)
	}
	orderMu.Lock()
	order = nil
	orderMu.Unlock()
	gate := make(chan struct{})
	e.Owner.Gate(gate)
	var once sync.Once
	unblock := func() { once.Do(func() { close(gate) }) }
	defer unblock()
	done := make(chan lease.Outcome, 1)
	var runningWorker sync.WaitGroup
	runningWorker.Add(1)
	defer func() { unblock(); runningWorker.Wait() }()
	go func() {
		defer runningWorker.Done()
		done <- e.Renew(context.Background(), running, lease.Digest(running.Payload.AccessToken))
	}()
	testutil.Await(t, func() bool { n, _ := e.Owner.Counts(); return n == 1 })
	path := start(t, e, nil)
	enqueue := func(r wire.LeaseResult) *net.UnixConn {
		c := dial(t, path)
		hello(t, c)
		b, _ := wire.Encode(wire.Renew{LeaseID: r.LeaseID, RejectedSHA256: lease.Digest(r.Payload.AccessToken)})
		if err := wire.Write(c, wire.Request{Method: "lease.renew", ID: "renew", Params: b}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	await := func(n int) {
		testutil.Await(t, func() bool { p, w := e.Manager.Stats(e.Account); return p == n && w == n })
	}
	firstClient := enqueue(first)
	await(2)
	var lastClient *net.UnixConn
	for wave := 0; wave < 24; wave++ {
		clients := make([]*net.UnixConn, len(abandoned))
		stable := 3
		if wave == 0 {
			stable = 2
		}
		for i, r := range abandoned {
			clients[i] = enqueue(r)
			await(stable + i + 1)
		}
		if wave == 0 {
			lastClient = enqueue(last)
			await(11)
		}
		var closed sync.WaitGroup
		for _, c := range clients {
			closed.Add(1)
			go func(c *net.UnixConn) { defer closed.Done(); c.Close() }(c)
		}
		closed.Wait()
		await(3)
		// The only worker is held in Refresh and all asynchronous detachments have
		// completed before this quiescent inspection of the physical FIFO.
		a := reflect.ValueOf(e.Manager).Elem().FieldByName("accounts").MapIndex(reflect.ValueOf(e.Account)).Elem()
		q := a.FieldByName("queue")
		if q.Len() != 2 {
			t.Fatalf("wave %d retained=%d expected two live survivors", wave, q.Len())
		}
		if q.Cap() > 64 {
			t.Fatal("physical queue allocation exceeded pending bound")
		}
		storage := q.Slice(0, q.Cap())
		for i := q.Len(); i < storage.Len(); i++ {
			if !storage.Index(i).IsNil() {
				t.Fatal("unused queue storage retained an operation")
			}
		}
		for i, id := range []string{first.LeaseID, last.LeaseID} {
			if q.Index(i).Elem().FieldByName("id").String() != id {
				t.Fatal("cancellation reordered live queue")
			}
		}
	}
	unblock()
	if out := <-done; out.Err != nil {
		t.Fatal("running control failed")
	}
	for _, c := range []*net.UnixConn{firstClient, lastClient} {
		if out := reply(t, c); out.Error != nil {
			t.Fatal("live survivor refused")
		}
	}
	await(0)
	orderMu.Lock()
	got := append([]string(nil), order...)
	orderMu.Unlock()
	want := []string{running.LeaseID, first.LeaseID, last.LeaseID}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("worker FIFO changed or abandoned work ran")
	}
	if n, _ := e.Owner.Counts(); n != 1 {
		t.Fatal("abandoned calls started another refresh")
	}
	after, err := disk.Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range abandoned {
		name := "lease-" + r.LeaseID + ".json"
		if string(before[name]) != string(after[name]) {
			t.Fatal("abandoned lease metadata changed")
		}
		if out := e.Renew(context.Background(), r, lease.Digest(r.Payload.AccessToken)); out.Err != nil {
			t.Fatal("reconnect recovery refused")
		}
	}
}
