//go:build integration

package fallback_test

import (
	"context"
	"fmt"
	"testing"

	mDNS "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func TestFallbackForwardReferences(t *testing.T) {
	for _, strategy := range []string{"sequential", "parallel"} {
		t.Run(strategy, func(t *testing.T) {
			ctx := include.Context(service.ContextWithDefaultRegistry(context.Background()))
			config := fmt.Sprintf(`{
				"log": {"disabled": true},
				"dns": {"servers": [
					{"type": "fallback", "tag": "fallback", "servers": ["upstream"], "strategy": %q},
					{"type": "hosts", "tag": "upstream", "predefined": {"forward.example": "192.0.2.7"}}
				]}
			}`, strategy)
			var options option.Options
			if err := json.UnmarshalContext(ctx, []byte(config), &options); err != nil {
				t.Fatal(err)
			}
			instance, err := box.New(box.Options{Options: options, Context: ctx})
			if err != nil {
				t.Fatalf("construct Box with forward DNS reference: %v", err)
			}
			t.Cleanup(func() { _ = instance.Close() })
			if err = instance.Start(); err != nil {
				t.Fatalf("start Box with forward DNS reference: %v", err)
			}
			transport := service.FromContext[adapter.DNSTransportManager](ctx).Default()
			if transport.Type() != C.DNSTypeFallback {
				t.Fatalf("default DNS transport = %s, want fallback", transport.Type())
			}
			request := new(mDNS.Msg)
			request.SetQuestion("forward.example.", mDNS.TypeA)
			response, err := transport.Exchange(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Answer) != 1 {
				t.Fatalf("unexpected DNS answers: %v", response.Answer)
			}
			answer, ok := response.Answer[0].(*mDNS.A)
			if !ok || answer.A.String() != "192.0.2.7" {
				t.Fatalf("unexpected DNS answer: %v", response.Answer[0])
			}
		})
	}
}
