package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/xsaveopt/latency_exporter/internal/config"
)

const (
	defaultPayloadSize = 56
	tokenSize          = 16
	maxPayloadSize     = 65000
)

type icmpProber struct {
	host        string
	ipVersion   int
	payloadSize int
	id          int
	seq         uint16
}

func newICMP(t *config.Target) (*icmpProber, error) {
	if t.Host == "" {
		return nil, errors.New("host is required")
	}
	size := t.PayloadSize
	if size == 0 {
		size = defaultPayloadSize
	}
	if size < tokenSize || size > maxPayloadSize {
		return nil, fmt.Errorf("payload_size must be between %d and %d", tokenSize, maxPayloadSize)
	}
	return &icmpProber{
		host:        t.Host,
		ipVersion:   t.IPVersion,
		payloadSize: size,
		id:          os.Getpid() & 0xffff,
	}, nil
}

func (p *icmpProber) Probe(ctx context.Context) Result {
	addr, err := resolve(ctx, p.host, p.ipVersion)
	if err != nil {
		return Result{Err: err}
	}

	network, listen := "udp4", "0.0.0.0"
	var echoType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if addr.Is6() {
		network, listen = "udp6", "::"
		echoType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}

	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		reason := Reason(err)
		if reason == ReasonPermission {
			err = fmt.Errorf("open unprivileged ping socket (is the process gid inside net.ipv4.ping_group_range?): %w", err)
		}
		return fail(reason, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	payload := make([]byte, p.payloadSize)
	token := payload[:tokenSize]
	_, _ = rand.Read(token)

	p.seq++
	seq := int(p.seq)
	msg := icmp.Message{
		Type: echoType,
		Body: &icmp.Echo{ID: p.id, Seq: seq, Data: payload},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return fail(ReasonError, err)
	}

	dst := &net.UDPAddr{IP: addr.AsSlice(), Zone: addr.Zone()}
	sent := time.Now()
	if _, err := conn.WriteTo(wire, dst); err != nil {
		return Result{Err: ctxErr(ctx, err)}
	}

	buf := make([]byte, p.payloadSize+512)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return Result{Err: ctxErr(ctx, err)}
		}
		rtt := time.Since(sent)
		reply, err := icmp.ParseMessage(replyType.Protocol(), buf[:n])
		if err != nil || reply.Type != replyType {
			continue
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if !ok || echo.Seq != seq || !bytes.HasPrefix(echo.Data, token) {
			continue
		}
		return Result{Duration: rtt}
	}
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return &Error{Reason: ReasonTimeout, Err: fmt.Errorf("%w: %w", ctx.Err(), err)}
	}
	return err
}
