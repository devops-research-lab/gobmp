package message

import (
	"crypto/md5"
	"encoding/hex"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) producePeerMessage(op int, msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
		return
	}
	action := "add"
	if op == peerDown {
		action = "del"
	}

	var m PeerStateChange
	if op == peerUP {
		peerUpMsg, ok := msg.Payload.(*bmp.PeerUpMessage)
		if !ok {
			glog.Errorf("got invalid Payload type in bmp.Message %+v", msg.Payload)
			return
		}
		m = PeerStateChange{
			Action:         action,
			RemoteASN:      msg.PeerHeader.PeerAS,
			PeerType:       uint8(msg.PeerHeader.PeerType),
			PeerRD:         msg.PeerHeader.GetPeerDistinguisherString(),
			RemotePort:     int(peerUpMsg.RemotePort),
			Timestamp:      msg.PeerHeader.GetPeerTimestamp(),
			LocalPort:      int(peerUpMsg.LocalPort),
			AdvHolddown:    int(peerUpMsg.SentOpen.HoldTime),
			RemoteHolddown: int(peerUpMsg.ReceivedOpen.HoldTime),
		}
		if f, err := msg.PeerHeader.IsAdjRIBInPost(); err == nil {
			m.IsAdjRIBInPost = f
		}
		if f, err := msg.PeerHeader.IsAdjRIBOutPost(); err == nil {
			m.IsAdjRIBOutPost = f
		}
		if f, err := msg.PeerHeader.IsAdjRIBOut(); err == nil {
			m.IsAdjRIBOut = f
		}
		if f, err := msg.PeerHeader.IsLocRIB(); err == nil {
			m.IsLocRIB = f
		}
		if f, err := msg.PeerHeader.IsLocRIBFiltered(); err == nil {
			m.IsLocRIBFiltered = f
		}
		m.RemoteIP = msg.PeerHeader.GetPeerAddrString()
		m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
		m.LocalBGPID = net.IP(peerUpMsg.SentOpen.BGPID).To4().String()
		m.IsIPv4 = !msg.PeerHeader.IsRemotePeerIPv6()
		m.LocalIP = peerUpMsg.GetLocalAddressString()
		// Saving local bgp speaker identities inside sync.Once so the writes
		// happen exactly once and happen-before the channel close.  After the
		// first PeerUp the fields are immutable — no data race with readers
		// that wait on speakerReady.
		p.speakerReadyOnce.Do(func() {
			p.speakerIP = speakerAddress(m.LocalIP, msg.SpeakerIP)
			md5Sum := md5.Sum([]byte(p.speakerIP))
			p.speakerHash = hex.EncodeToString(md5Sum[:])
			close(p.speakerReady)
		})
		m.RouterIP = p.speakerIP
		m.RouterHash = p.speakerHash

		m.LocalASN = uint32(peerUpMsg.SentOpen.MyAS)
		if lasn, ok := peerUpMsg.SentOpen.Is4BytesASCapable(); ok {
			// Local BGP speaker is 4 bytes AS capable
			m.LocalASN = lasn
		}

		// Create per-table properties for this VRF
		// Per RFC 9069: Each table identified by BGP-ID + Peer Distinguisher
		// Per RFC 7911: AddPath capability is per BGP session (not global)
		p.tableLock.Lock()
		ptp := PerTableProperties{
			addPathCapable: make(map[int]bool),
		}

		// Check AddPath capability for this specific peer/table
		// Only enable AddPath for AFI/SAFI types where BOTH peers support it
		if lAddPath := peerUpMsg.SentOpen.AddPathCapability(); len(lAddPath) != 0 {
			if rAddPath := peerUpMsg.ReceivedOpen.AddPathCapability(); len(rAddPath) != 0 {
				for k := range lAddPath {
					if capable, ok := rAddPath[k]; ok {
						ptp.addPathCapable[k] = capable
					}
				}
			}
		}

		// Copy table informational TLVs (includes Table Name per RFC 9069 Section 5)
		ptp.tableInfoTLVs = make([]bmp.InformationalTLV, len(peerUpMsg.Information))
		copy(ptp.tableInfoTLVs, peerUpMsg.Information)

		// Store properties for this table
		p.tableProperties[msg.PeerHeader.GetTableKey()] = ptp
		p.tableLock.Unlock()

		m.AdvCapabilities = peerUpMsg.SentOpen.GetCapabilities()
		m.RcvCapabilities = peerUpMsg.ReceivedOpen.GetCapabilities()
		if glog.V(6) {
			glog.Infof("producer for speaker ip: %s table: %s add path: %+v",
				p.speakerIP,
				msg.PeerHeader.GetTableKey(),
				ptp.addPathCapable)
		}
	} else {
		peerDownMsg, ok := msg.Payload.(*bmp.PeerDownMessage)
		if !ok {
			glog.Errorf("got invalid Payload type in bmp.Message")
			return
		}
		m = PeerStateChange{
			Action:     "down",
			RouterIP:   p.speakerIP,
			PeerType:   uint8(msg.PeerHeader.PeerType),
			RouterHash: p.speakerHash,
			BMPReason:  int(peerDownMsg.Reason),
			RemoteASN:  msg.PeerHeader.PeerAS,
			PeerRD:     msg.PeerHeader.GetPeerDistinguisherString(),
			Timestamp:  msg.PeerHeader.GetPeerTimestamp(),
		}
		m.RemoteIP = msg.PeerHeader.GetPeerAddrString()
		m.RemoteBGPID = msg.PeerHeader.GetPeerBGPIDString()
		m.IsIPv4 = !msg.PeerHeader.IsRemotePeerIPv6()
		m.InfoData = make([]byte, len(peerDownMsg.Data))
		copy(m.InfoData, peerDownMsg.Data)

		// Clean up table properties when peer goes down
		// This prevents memory leaks and ensures stale data isn't used
		p.tableLock.Lock()
		delete(p.tableProperties, msg.PeerHeader.GetTableKey())
		p.tableLock.Unlock()
	}
	if err := p.marshalAndPublish(&m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
		glog.Errorf("failed to process peer message with error: %+v", err)
		return
	}
}

// speakerAddress picks the address that identifies the BMP speaker for this
// connection.  The Peer Up Local Address is preferred, so the identity of an
// established session is unchanged, but it is not always an address: RFC 9069
// Section 5.2 has a Loc-RIB Instance Peer zero-fill it, and a speaker whose
// first Peer Up describes the Loc-RIB therefore latches on 0.0.0.0 (or :: for
// an IPv6 peer).  Every such speaker then hashes to md5("0.0.0.0") and two of
// them become indistinguishable to a collector that keys on router_hash.
//
// connIP is the remote address of the TCP connection the message arrived on,
// which the server already resolves per client.  It identifies the speaker
// whenever the Peer Up does not, and it cannot collide between two connections.
func speakerAddress(localIP, connIP string) string {
	if isSpecificAddress(localIP) {
		return localIP
	}
	if isSpecificAddress(connIP) {
		return connIP
	}
	// Neither identifies anything.  Keep the Peer Up value rather than invent
	// one, leaving the message exactly as it was before this fallback existed.
	return localIP
}

// isSpecificAddress reports whether s is an IP address that names one host,
// as opposed to being absent or the unspecified address 0.0.0.0 / ::.
func isSpecificAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsUnspecified()
}
