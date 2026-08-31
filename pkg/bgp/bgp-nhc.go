package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	NHCAttributeType         uint8  = 39
	NHCCharacteristicELCv3   uint16 = 1
	NHCCharacteristicNNHN    uint16 = 2
	NHCCharacteristicBGPID   uint16 = 3
	NHCCharacteristicIFIT    uint16 = 4
	NHCCharacteristicAMetric uint16 = 5
)

type NHC struct {
	AFI                      uint16              `json:"afi"`
	SAFI                     uint8               `json:"safi"`
	NextHop                  []byte              `json:"next_hop"`
	Characteristics          []NHCCharacteristic `json:"characteristics"`
	BGPID                    *NHCBGPID           `json:"bgp_id,omitempty"`
	DiscardedCharacteristics uint16              `json:"discarded_characteristics,omitempty"`
}

type NHCCharacteristic struct {
	Code   uint16 `json:"code"`
	Length uint16 `json:"length"`
	Value  []byte `json:"value,omitempty"`
}

type NHCBGPID struct {
	Identifier string `json:"identifier"`
	AS         uint32 `json:"as"`
}

func UnmarshalNHC(b []byte) (*NHC, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("NHC too short: need 4 bytes for header, have %d", len(b))
	}
	nextHopLength := int(b[3])
	if len(b) < 4+nextHopLength {
		return nil, fmt.Errorf("NHC next hop truncated: need %d bytes, have %d", nextHopLength, len(b)-4)
	}
	nhc := &NHC{
		AFI:     binary.BigEndian.Uint16(b[:2]),
		SAFI:    b[2],
		NextHop: append([]byte(nil), b[4:4+nextHopLength]...),
	}
	bgpIDSeen := false
	for p := 4 + nextHopLength; p < len(b); {
		if len(b)-p < 4 {
			return nil, fmt.Errorf("NHC characteristic header truncated at offset %d: need 4 bytes, have %d", p, len(b)-p)
		}
		code := binary.BigEndian.Uint16(b[p : p+2])
		length := binary.BigEndian.Uint16(b[p+2 : p+4])
		p += 4
		if int(length) > len(b)-p {
			return nil, fmt.Errorf("NHC characteristic %d truncated at offset %d: need %d bytes, have %d", code, p, length, len(b)-p)
		}
		value := b[p : p+int(length)]
		p += int(length)
		if code == NHCCharacteristicBGPID {
			if bgpIDSeen {
				nhc.DiscardedCharacteristics++
				continue
			}
			bgpIDSeen = true
			if len(value) != 8 {
				nhc.DiscardedCharacteristics++
				continue
			}
			if binary.BigEndian.Uint32(value[:4]) == 0 {
				nhc.DiscardedCharacteristics++
				continue
			}
			nhc.BGPID = &NHCBGPID{
				Identifier: net.IP(value[:4]).String(),
				AS:         binary.BigEndian.Uint32(value[4:8]),
			}
		}
		nhc.Characteristics = append(nhc.Characteristics, NHCCharacteristic{
			Code:   code,
			Length: length,
			Value:  append([]byte(nil), value...),
		})
	}
	return nhc, nil
}

func (n *NHC) SemanticallyMatchesNextHop(afi uint16, safi uint8, nextHop []byte, peerBGPID net.IP, peerAS uint32) bool {
	matches, requiresBGPID := n.nextHopAddressMatches(afi, safi, nextHop)
	if !matches {
		return false
	}
	if !requiresBGPID {
		return true
	}
	return n.BGPID != nil && peerBGPID.To4() != nil && n.BGPID.Identifier == peerBGPID.To4().String() && n.BGPID.AS == peerAS
}

func (n *NHC) nextHopAddressMatches(afi uint16, safi uint8, nextHop []byte) (bool, bool) {
	if n == nil || n.AFI != afi || n.SAFI != safi {
		return false, false
	}
	nhcComparable, nhcLinkLocal := comparableNHCNextHop(n.NextHop)
	routeComparable, routeLinkLocal := comparableNHCNextHop(nextHop)
	if nhcComparable == nil || routeComparable == nil || !bytes.Equal(nhcComparable, routeComparable) {
		return false, false
	}
	return true, nhcLinkLocal || routeLinkLocal
}

func comparableNHCNextHop(nextHop []byte) ([]byte, bool) {
	switch len(nextHop) {
	case net.IPv6len:
		ip := net.IP(nextHop)
		return nextHop, ip.IsLinkLocalUnicast()
	case 2 * net.IPv6len:
		ip := net.IP(nextHop[:net.IPv6len])
		return nextHop[:net.IPv6len], ip.IsLinkLocalUnicast()
	case 8 + net.IPv6len:
		ip := net.IP(nextHop[8:])
		return nextHop, ip.IsLinkLocalUnicast()
	case 2 * (8 + net.IPv6len):
		ip := net.IP(nextHop[8 : 8+net.IPv6len])
		return nextHop[:8+net.IPv6len], ip.IsLinkLocalUnicast()
	default:
		if len(nextHop) == 0 {
			return nil, false
		}
		return nextHop, false
	}
}
