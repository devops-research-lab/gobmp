package message

import (
	"net"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func parsedNHC(t *testing.T, value []byte) *bgp.NHC {
	t.Helper()
	nhc, err := bgp.UnmarshalNHC(value)
	if err != nil {
		t.Fatalf("UnmarshalNHC: %v", err)
	}
	return nhc
}

func TestValidateNHC(t *testing.T) {
	tlv := []byte{0, 4, 0, 0}
	t.Run("matching next hop retained", func(t *testing.T) {
		value := append([]byte{0, 1, 1, 4, 198, 51, 100, 1}, tlv...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		validateNHC(update, 1, 1, []byte{198, 51, 100, 1}, nil)
		if update.BaseAttributes.NHC == nil || update.BaseAttributes.NHCDiscarded {
			t.Fatal("matching NHC was discarded")
		}
	})
	t.Run("mismatching next hop discarded", func(t *testing.T) {
		value := append([]byte{0, 1, 1, 4, 198, 51, 100, 1}, tlv...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		validateNHC(update, 1, 1, []byte{198, 51, 100, 2}, nil)
		if update.BaseAttributes.NHC != nil || !update.BaseAttributes.NHCDiscarded {
			t.Fatal("mismatching NHC was not discarded")
		}
	})
	t.Run("link-local uses inbound peer identity", func(t *testing.T) {
		nextHop := net.ParseIP("fe80::1").To16()
		value := append([]byte{0, 2, 1, 16}, nextHop...)
		value = append(value, []byte{0, 3, 0, 8, 192, 0, 2, 1, 0, 0, 253, 232}...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		ph := &bmp.PerPeerHeader{PeerAS: 65000, PeerBGPID: []byte{192, 0, 2, 1}}
		validateNHC(update, 2, 1, nextHop, ph)
		if update.BaseAttributes.NHC == nil || update.BaseAttributes.NHCDiscarded || update.BaseAttributes.NHCUnverified {
			t.Fatal("link-local NHC with matching inbound peer identity was not verified")
		}
	})
	t.Run("link-local outbound identity unavailable", func(t *testing.T) {
		nextHop := net.ParseIP("fe80::1").To16()
		value := append([]byte{0, 2, 1, 16}, nextHop...)
		value = append(value, []byte{0, 3, 0, 8, 192, 0, 2, 1, 0, 0, 253, 232}...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		validateNHC(update, 2, 1, nextHop, makePeerHeader(t, bmp.PeerType0, 0x10))
		if update.BaseAttributes.NHC == nil || update.BaseAttributes.NHCDiscarded || !update.BaseAttributes.NHCUnverified {
			t.Fatal("unverifiable outbound link-local NHC was not retained and marked")
		}
	})
}
