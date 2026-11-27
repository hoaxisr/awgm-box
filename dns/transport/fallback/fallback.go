package fallback

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.FallbackDNSServerOptions](registry, C.DNSTypeFallback, NewTransport)
}

var _ adapter.DNSTransport = (*Transport)(nil)

type Transport struct {
	dns.TransportAdapter
	manager  adapter.DNSTransportManager
	logger   logger.ContextLogger
	options  option.FallbackDNSServerOptions
	strategy ExchangeStrategy
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.FallbackDNSServerOptions) (adapter.DNSTransport, error) {
	if len(options.Servers) == 0 {
		return nil, E.New("missing servers")
	}
	return &Transport{
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeFallback, tag, options.Servers),
		manager:          service.FromContext[adapter.DNSTransportManager](ctx),
		logger:           logger,
		options:          options,
	}, nil
}

func (t *Transport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	servers := make([]adapter.DNSTransport, len(t.options.Servers))
	for i, tag := range t.options.Servers {
		server, loaded := t.manager.Transport(tag)
		if !loaded {
			return E.New("server ", tag, " not found")
		}
		servers[i] = server
	}
	strategy, err := CreateStrategy(t.options.Strategy, servers, t.logger, t.options.Timeout.Build())
	if err != nil {
		return err
	}
	t.strategy = strategy
	return nil
}

func (t *Transport) Reset() {
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return t.strategy(ctx, message)
}

func (t *Transport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	callback(t.Exchange(ctx, message))
}
