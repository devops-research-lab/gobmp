package bgp

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func nhcTLV(code uint16, value []byte) []byte {
	return append([]byte{byte(code >> 8), byte(code), byte(len(value) >> 8), byte(len(value))}, value...)
}

func nhcValue(afi uint16, safi uint8, nextHop []byte, characteristics ...[]byte) []byte {
	b := []byte{byte(afi >> 8), byte(afi), safi, byte(len(nextHop))}
	b = append(b, nextHop...)
	for _, characteristic := range characteristics {
		b = append(b, characteristic...)
	}
	return b
}

func TestUnmarshalNHC(t *testing.T) {
	bgpID := []byte{192, 0, 2, 1, 0, 0, 253, 232}
	value := nhcValue(1, 1, []byte{198, 51, 100, 1},
		nhcTLV(5, []byte{0xaa}),
		nhcTLV(NHCCharacteristicBGPID, bgpID),
		nhcTLV(65000, nil),
	)

	nhc, err := UnmarshalNHC(value)
	if err != nil {
		t.Fatalf("UnmarshalNHC: %v", err)
	}
	if nhc.AFI != 1 || nhc.SAFI != 1 || !bytes.Equal(nhc.NextHop, []byte{198, 51, 100, 1}) {
		t.Fatalf("unexpected NHC header: %+v", nhc)
	}
	if len(nhc.Characteristics) != 3 {
		t.Fatalf("len(Characteristics) = %d, want 3", len(nhc.Characteristics))
	}
	if nhc.Characteristics[0].Code != 5 || nhc.Characteristics[2].Code != 65000 {
		t.Fatalf("out-of-order or unknown characteristics were not retained: %+v", nhc.Characteristics)
	}
	if nhc.BGPID == nil || nhc.BGPID.Identifier != "192.0.2.1" || nhc.BGPID.AS != 65000 {
		t.Fatalf("BGPID = %+v, want 192.0.2.1/65000", nhc.BGPID)
	}
}

func TestUnmarshalNHCRejectsMalformedAttribute(t *testing.T) {
	tests := map[string][]byte{
		"short header":         {0, 1, 1},
		"truncated next hop":   {0, 1, 1, 4, 192, 0},
		"truncated TLV header": nhcValue(1, 1, []byte{192, 0, 2, 1}, []byte{0, 1, 0}),
		"truncated TLV value":  nhcValue(1, 1, []byte{192, 0, 2, 1}, []byte{0, 1, 0, 2, 0xff}),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalNHC(value); err == nil {
				t.Fatal("UnmarshalNHC returned nil error")
			}
		})
	}
}

func TestUnmarshalNHCRejectsEmptyCharacteristics(t *testing.T) {
	value := nhcValue(1, 1, []byte{192, 0, 2, 1})
	if _, err := UnmarshalNHC(value); err == nil {
		t.Fatal("UnmarshalNHC returned nil error")
	}
	baseAttrs, err := UnmarshalBGPBaseAttributes(buildAttr(0xc0, NHCAttributeType, value))
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
	}
	if baseAttrs.NHC != nil || baseAttrs.NHCMalformed || !baseAttrs.NHCEmpty || baseAttrs.NHCDiscarded || !bytes.Equal(baseAttrs.NHCAttr, value) {
		t.Fatalf("empty NHC was not discarded and retained for forensics: %+v", baseAttrs)
	}
}

func TestUnmarshalNHCBGPIDDiscardRules(t *testing.T) {
	valid := []byte{192, 0, 2, 1, 0, 0, 253, 232}
	t.Run("malformed first", func(t *testing.T) {
		value := nhcValue(2, 1, net.ParseIP("fe80::1").To16(),
			nhcTLV(NHCCharacteristicBGPID, []byte{1, 2, 3}),
			nhcTLV(4, []byte{0xaa}),
			nhcTLV(NHCCharacteristicBGPID, valid),
		)
		nhc, err := UnmarshalNHC(value)
		if err != nil {
			t.Fatalf("UnmarshalNHC: %v", err)
		}
		if nhc.BGPID != nil || len(nhc.Characteristics) != 1 || nhc.Characteristics[0].Code != 4 {
			t.Fatalf("malformed first BGPID or later instance was retained: %+v", nhc)
		}
	})
	t.Run("zero identifier", func(t *testing.T) {
		value := nhcValue(2, 1, net.ParseIP("fe80::1").To16(),
			nhcTLV(NHCCharacteristicBGPID, []byte{0, 0, 0, 0, 0, 0, 0, 1}),
			nhcTLV(4, nil),
		)
		nhc, err := UnmarshalNHC(value)
		if err != nil {
			t.Fatalf("UnmarshalNHC: %v", err)
		}
		if nhc.BGPID != nil || len(nhc.Characteristics) != 1 {
			t.Fatalf("zero BGP identifier was retained: %+v", nhc)
		}
	})
	t.Run("valid first", func(t *testing.T) {
		value := nhcValue(2, 1, net.ParseIP("fe80::1").To16(),
			nhcTLV(NHCCharacteristicBGPID, valid),
			nhcTLV(NHCCharacteristicBGPID, []byte{192, 0, 2, 2, 0, 0, 0, 2}),
		)
		nhc, err := UnmarshalNHC(value)
		if err != nil {
			t.Fatalf("UnmarshalNHC: %v", err)
		}
		if nhc.BGPID == nil || nhc.BGPID.Identifier != "192.0.2.1" || nhc.BGPID.AS != 65000 {
			t.Fatalf("BGPID = %+v, want first BGPID", nhc.BGPID)
		}
		if len(nhc.Characteristics) != 1 {
			t.Fatalf("duplicate BGPID was retained: %+v", nhc.Characteristics)
		}
	})
}

func TestNHCSemanticallyMatchesNextHop(t *testing.T) {
	peerID := net.ParseIP("192.0.2.1")
	t.Run("IPv4 exact", func(t *testing.T) {
		nhc, err := UnmarshalNHC(nhcValue(1, 1, []byte{198, 51, 100, 1}, nhcTLV(4, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if !nhc.SemanticallyMatchesNextHop(1, 1, []byte{198, 51, 100, 1}, nil, 0) {
			t.Fatal("exact IPv4 next hop did not match")
		}
		if nhc.SemanticallyMatchesNextHop(1, 2, []byte{198, 51, 100, 1}, nil, 0) {
			t.Fatal("different SAFI matched")
		}
	})
	t.Run("IPv6 global component", func(t *testing.T) {
		global := net.ParseIP("2001:db8::1").To16()
		combined := append(append([]byte{}, global...), net.ParseIP("fe80::1").To16()...)
		nhc, err := UnmarshalNHC(nhcValue(2, 1, combined, nhcTLV(4, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if !nhc.SemanticallyMatchesNextHop(2, 1, global, nil, 0) {
			t.Fatal("global-only IPv6 next hop did not semantically match global+link-local")
		}
	})
	t.Run("IPv4 NLRI with IPv6 next hop", func(t *testing.T) {
		global := net.ParseIP("2001:db8::1").To16()
		combined := append(append([]byte{}, global...), net.ParseIP("fe80::1").To16()...)
		nhc, err := UnmarshalNHC(nhcValue(1, 1, combined, nhcTLV(4, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if !nhc.SemanticallyMatchesNextHop(1, 1, global, nil, 0) {
			t.Fatal("IPv4 NLRI global-only IPv6 next hop did not semantically match global+link-local")
		}
	})
	t.Run("VPN IPv6 global component", func(t *testing.T) {
		rd := []byte{0, 0, 0, 0, 0, 0, 0, 1}
		global := append(append([]byte{}, rd...), net.ParseIP("2001:db8::1").To16()...)
		combined := append(append([]byte{}, global...), rd...)
		combined = append(combined, net.ParseIP("fe80::1").To16()...)
		nhc, err := UnmarshalNHC(nhcValue(2, 128, combined, nhcTLV(4, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if !nhc.SemanticallyMatchesNextHop(2, 128, global, nil, 0) {
			t.Fatal("VPN global-only IPv6 next hop did not semantically match global+link-local")
		}
	})
	t.Run("link-local requires BGPID", func(t *testing.T) {
		linkLocal := net.ParseIP("fe80::1").To16()
		bgpID := []byte{192, 0, 2, 1, 0, 0, 253, 232}
		nhc, err := UnmarshalNHC(nhcValue(2, 1, linkLocal, nhcTLV(NHCCharacteristicBGPID, bgpID)))
		if err != nil {
			t.Fatal(err)
		}
		if !nhc.SemanticallyMatchesNextHop(2, 1, linkLocal, peerID, 65000) {
			t.Fatal("link-local next hop with matching BGPID did not match")
		}
		if nhc.SemanticallyMatchesNextHop(2, 1, linkLocal, peerID, 65001) {
			t.Fatal("link-local next hop with wrong peer AS matched")
		}
		withoutBGPID, err := UnmarshalNHC(nhcValue(2, 1, linkLocal, nhcTLV(4, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if withoutBGPID.SemanticallyMatchesNextHop(2, 1, linkLocal, peerID, 65000) {
			t.Fatal("link-local next hop without BGPID matched")
		}
	})
}

func TestNHCBaseAttributesIntegration(t *testing.T) {
	value := nhcValue(1, 1, []byte{198, 51, 100, 1}, nhcTLV(65000, []byte{1, 2}))
	baseAttrs, err := UnmarshalBGPBaseAttributes(buildAttr(0xc0, NHCAttributeType, value))
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes: %v", err)
	}
	if baseAttrs.NHC == nil || baseAttrs.NHCMalformed || !bytes.Equal(baseAttrs.NHCAttr, value) {
		t.Fatalf("NHC integration failed: %+v", baseAttrs)
	}
	encoded, err := json.Marshal(baseAttrs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"nhc":`) || !strings.Contains(string(encoded), `"code":65000`) {
		t.Fatalf("NHC missing from JSON: %s", encoded)
	}

	different, err := UnmarshalBGPBaseAttributes(buildAttr(0xc0, NHCAttributeType,
		nhcValue(1, 1, []byte{198, 51, 100, 1}, nhcTLV(65000, []byte{2, 1}))))
	if err != nil {
		t.Fatal(err)
	}
	if equal, _ := baseAttrs.Equal(different); equal {
		t.Fatal("BaseAttributes.Equal ignored different NHC values")
	}

	largeValue := bytes.Repeat([]byte{0xaa}, 260)
	extended := nhcValue(1, 1, []byte{198, 51, 100, 1}, nhcTLV(65000, largeValue))
	extendedAttrs, err := UnmarshalBGPBaseAttributes(buildAttrExtLen(0xc0, NHCAttributeType, extended))
	if err != nil {
		t.Fatalf("extended-length NHC: %v", err)
	}
	if extendedAttrs.NHC == nil || len(extendedAttrs.NHC.Characteristics[0].Value) != len(largeValue) {
		t.Fatalf("extended-length NHC was not decoded: %+v", extendedAttrs.NHC)
	}
}

func TestGetNLRITypePreservesAttributeOrder(t *testing.T) {
	update := &Update{PathAttributes: []PathAttribute{
		{AttributeType: MP_UNREACH_NLRI},
		{AttributeType: MP_REACH_NLRI},
	}}
	attributeType, index := update.GetNLRIType()
	if attributeType != MP_UNREACH_NLRI || index != 0 {
		t.Fatalf("GetNLRIType() = %d, %d, want %d, 0", attributeType, index, MP_UNREACH_NLRI)
	}
}

func TestMalformedNHCUsesAttributeDiscard(t *testing.T) {
	value := nhcValue(1, 1, []byte{198, 51, 100, 1}, []byte{0, 1, 0, 2, 0xff})
	baseAttrs, err := UnmarshalBGPBaseAttributes(buildAttr(0xc0, NHCAttributeType, value))
	if err != nil {
		t.Fatalf("malformed NHC rejected the containing attributes: %v", err)
	}
	if baseAttrs.NHC != nil || !baseAttrs.NHCMalformed || !bytes.Equal(baseAttrs.NHCAttr, value) {
		t.Fatalf("malformed NHC was not discarded and retained for forensics: %+v", baseAttrs)
	}
}
