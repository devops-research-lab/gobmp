package message

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

const (
	// AddPrefix defines a const for Add Prefix operation
	AddPrefix = iota
	// DelPrefix defines a const for Delete Prefix operation
	DelPrefix
)

func (p *producer) produceRouteMonitorMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
		return
	}
	routeMonitorMsg, ok := msg.Payload.(*bmp.RouteMonitor)
	if !ok {
		glog.Errorf("got invalid Payload type in bmp.Message")
		return
	}
	if routeMonitorMsg == nil {
		glog.Errorf("route monitor message is nil")
		return
	}
	if routeMonitorMsg.Update == nil {
		return
	}
	attrType := uint8(0)
	index := 0
	if len(routeMonitorMsg.Update.PathAttributes) != 0 {
		// If PathAttribute is present in Update, then take the value of Attribute Type
		attrType, index = routeMonitorMsg.Update.GetNLRIType()
	}
	// Using first attribute type to select which nlri processor to call
	switch attrType {
	case 14:
		// MP_REACH_NLRI - Use per-table AddPath capability
		nlri, err := bgp.UnmarshalMPReachNLRI(
			routeMonitorMsg.Update.PathAttributes[index].Attribute,
			routeMonitorMsg.Update.HasPrefixSID(),
			p.GetAddPathCapability(msg.PeerHeader.GetTableKey()))
		if err != nil {
			glog.Errorf("failed to process MP_REACH_NLRI with error: %+v", err)
			return
		}
		if reach, ok := nlri.(*bgp.MPReachNLRI); ok {
			validateNHC(routeMonitorMsg.Update, reach.AddressFamilyID, reach.SubAddressFamilyID, reach.NextHopAddress, msg.PeerHeader)
		}
		p.processMPUpdate(nlri, AddPrefix, msg.PeerHeader, routeMonitorMsg.Update)
	case 15:
		// MP_UNREACH_NLRI - Use per-table AddPath capability
		nlri, err := bgp.UnmarshalMPUnReachNLRI(
			routeMonitorMsg.Update.PathAttributes[index].Attribute,
			p.GetAddPathCapability(msg.PeerHeader.GetTableKey()),
			routeMonitorMsg.Update.HasPrefixSID())
		if err != nil {
			glog.Errorf("failed to process MP_UNREACH_NLRI with error: %+v", err)
			return
		}
		if unreachable, ok := nlri.(*bgp.MPUnReachNLRI); ok {
			validateNHC(routeMonitorMsg.Update, unreachable.AddressFamilyID, unreachable.SubAddressFamilyID, nil, msg.PeerHeader)
		}
		p.processMPUpdate(nlri, DelPrefix, msg.PeerHeader, routeMonitorMsg.Update)
	default:
		var nextHop []byte
		if len(routeMonitorMsg.Update.NLRI) != 0 && routeMonitorMsg.Update.BaseAttributes != nil {
			nextHop = net.ParseIP(routeMonitorMsg.Update.BaseAttributes.Nexthop).To4()
		}
		validateNHC(routeMonitorMsg.Update, 1, 1, nextHop, msg.PeerHeader)
		t := bmp.UnicastPrefixMsg
		if p.splitAF {
			t = bmp.UnicastPrefixV4Msg
		}
		// Original BGP's NLRI messages processing
		msgs := make([]*UnicastPrefix, 0)
		if routeMonitorMsg.Update.WithdrawnRoutesLength != 0 {
			msg, err := p.nlri(DelPrefix, msg.PeerHeader, routeMonitorMsg.Update)
			if err != nil {
				glog.Errorf("failed to produce original NLRI Withdraw message with error: %+v", err)
				return
			}
			msgs = append(msgs, msg...)
		}
		msg, err := p.nlri(AddPrefix, msg.PeerHeader, routeMonitorMsg.Update)
		if err != nil {
			glog.Errorf("failed to produce original NLRI Withdraw message with error: %+v", err)
			return
		}
		msgs = append(msgs, msg...)
		// Loop through and publish all collected messages
		for _, m := range msgs {
			if err := p.marshalAndPublish(&m, t, []byte(m.RouterHash)); err != nil {
				glog.Errorf("failed to process Unicast Prefix message with error: %+v", err)
				return
			}
		}
	}
}

func validateNHC(update *bgp.Update, afi uint16, safi uint8, nextHop []byte, ph *bmp.PerPeerHeader) {
	if update == nil || update.BaseAttributes == nil || update.BaseAttributes.NHC == nil {
		return
	}
	var peerBGPID net.IP
	var peerAS uint32
	authoritativePeer := false
	if ph != nil {
		if inbound, err := ph.IsAdjRIBIn(); err == nil && inbound {
			peerBGPID = net.IP(ph.PeerBGPID)
			peerAS = ph.PeerAS
			authoritativePeer = true
		}
	}
	nhc := update.BaseAttributes.NHC
	if nhc.SemanticallyMatchesNextHop(afi, safi, nextHop, peerBGPID, peerAS) {
		return
	}
	if !authoritativePeer && nhc.BGPID != nil && nhc.SemanticallyMatchesNextHop(afi, safi, nextHop, net.ParseIP(nhc.BGPID.Identifier), nhc.BGPID.AS) {
		update.BaseAttributes.NHCUnverified = true
		return
	}
	update.BaseAttributes.NHC = nil
	update.BaseAttributes.NHCDiscarded = true
	glog.Warningf("discarded NHC attribute whose embedded next hop did not semantically match AFI %d SAFI %d route next hop", afi, safi)
}

func (p *producer) marshalAndPublish(msg interface{}, msgType int, hash []byte) error {
	ensureMessageHash(msg)
	j, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal a message of type %d with error: %w", msgType, err)
	}
	if err := p.publisher.PublishMessage(msgType, hash, j); err != nil {
		return fmt.Errorf("failed to push a message of type %d to kafka with error: %w", msgType, err)
	}
	return nil
}
