package chitanda

import (
	"context"

	"github.com/xtls/xray-core/common/session"
)

// A carrier's context contains mutable core state. Preserve routing policy and
// inbound identity, but never share per-request targets or sniffed attributes.
func requestContext(ctx context.Context) context.Context {
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	content := &session.Content{}
	if previous := session.ContentFromContext(ctx); previous != nil {
		content.SniffingRequest = previous.SniffingRequest
		content.SniffingRequest.OverrideDestinationForProtocol = append([]string(nil), previous.SniffingRequest.OverrideDestinationForProtocol...)
		content.SkipDNSResolve = previous.SkipDNSResolve
	}
	ctx = session.ContextWithContent(ctx, content)
	inbound := &session.Inbound{Tag: "chitanda-inbound"}
	if previous := session.InboundFromContext(ctx); previous != nil {
		*inbound = *previous
		if inbound.Tag == "" {
			inbound.Tag = "chitanda-inbound"
		}
	}
	// The physical connection is not a logical cleartext stream. Never allow
	// a core outbound to splice bytes around Chitanda's framing/encryption.
	inbound.Conn, inbound.Timer, inbound.CanSpliceCopy = nil, nil, 3
	return session.ContextWithInbound(ctx, inbound)
}
