// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/osrg/gobgp/zebra"
	"net"
	"strconv"
	"strings"
	"time"
)

type broadcastZapiMsg struct {
	client *zebra.Client
	msg    *zebra.Message
}

func (m *broadcastZapiMsg) send() {
	m.client.Send(m.msg)
}

func newBaseMassage(cli *zebra.Client, c zebra.API_TYPE, b zebra.Body, v table.VRF_ID_YTPE) *zebra.Message {
	log.WithFields(log.Fields{
		"Topic":   "Zebra",
		"Command": c.String(),
		"Body":    b,
		"Version": cli.GetVersion(),
	}).Debug("send command to zebra")
	return &zebra.Message{
		Header: cli.CreateHeader(c, v),
		Body:   b,
	}
}

func newRouterIdAddMassage(cli *zebra.Client, vrfId table.VRF_ID_YTPE) *zebra.Message {
	command := zebra.ROUTER_ID_ADD
	var body zebra.Body = nil
	return newBaseMassage(cli, command, body, vrfId)
}

func newInterfaceAddMassage(cli *zebra.Client, vrfId table.VRF_ID_YTPE) *zebra.Message {
	command := zebra.INTERFACE_ADD
	var body zebra.Body = nil
	return newBaseMassage(cli, command, body, vrfId)
}

func newRedistributedAddMassage(cli *zebra.Client, vrfId table.VRF_ID_YTPE, t zebra.ROUTE_TYPE) *zebra.Message {
	command := zebra.REDISTRIBUTE_ADD
	var body zebra.Body = nil
	if cli.GetRedistDefault() != t {
		body = &zebra.RedistributeBody{
			Redist: t,
		}
	} else {
		return nil
	}
	return newBaseMassage(cli, command, body, vrfId)
}

func newRedistributedDeleteMassage(cli *zebra.Client, vrfId table.VRF_ID_YTPE, t zebra.ROUTE_TYPE) *zebra.Message {
	command := zebra.REDISTRIBUTE_DELETE
	var body zebra.Body = nil
	if t < zebra.ROUTE_MAX {
		body = &zebra.RedistributeBody{
			Redist: t,
		}
	} else {
		return nil
	}
	return newBaseMassage(cli, command, body, vrfId)
}

func newRedistributedDefaultAddMassage(cli *zebra.Client, vrfId table.VRF_ID_YTPE) *zebra.Message {
	command := zebra.REDISTRIBUTE_DEFAULT_ADD
	var body zebra.Body = nil
	return newBaseMassage(cli, command, body, vrfId)
}

func newRedistributedDefaultDeleteMassage(cli *zebra.Client, vrfId table.VRF_ID_YTPE) *zebra.Message {
	command := zebra.REDISTRIBUTE_DEFAULT_DELETE
	var body zebra.Body = nil
	return newBaseMassage(cli, command, body, vrfId)
}

func newIPRouteMessage(cli *zebra.Client, path *table.Path, vrfs map[string]*table.Vrf) *zebra.Message {
	f := func() table.VRF_ID_YTPE {
		for _, vrf := range vrfs {
			ok := table.CanImportToVrf(vrf, path)
			if ok {
				return vrf.VrfId
			}
		}
		return table.VRF_ID_DEFAULT
	}

	nlri := path.GetNlri()
	l := strings.SplitN(nlri.String(), "/", 2)
	var command zebra.API_TYPE
	var prefix net.IP
	nexthops := []net.IP{}
	vrfId := table.VRF_ID_DEFAULT
	switch true {
	case path.GetRouteFamily() == bgp.RF_IPv4_UC:
		if path.IsWithdraw == true {
			command = zebra.IPV4_ROUTE_DELETE
		} else {
			command = zebra.IPV4_ROUTE_ADD
		}
		prefix = net.ParseIP(l[0]).To4()
		nexthops = append(nexthops, path.GetNexthop().To4())
	case path.GetRouteFamily() == bgp.RF_IPv6_UC:
		if path.IsWithdraw == true {
			command = zebra.IPV6_ROUTE_DELETE
		} else {
			command = zebra.IPV6_ROUTE_ADD
		}
		prefix = net.ParseIP(l[0]).To16()
		nexthops = append(nexthops, path.GetNexthop().To16())
	case path.GetRouteFamily() == bgp.RF_IPv4_VPN && cli.GetVersion() == 3:
		if path.IsWithdraw == true {
			command = zebra.IPV4_ROUTE_DELETE
		} else {
			command = zebra.IPV4_ROUTE_ADD
		}
		prefix = nlri.(*bgp.LabeledVPNIPAddrPrefix).Prefix
		nexthops = append(nexthops, path.GetNexthop().To4())
		vrfId = f()
	case path.GetRouteFamily() == bgp.RF_IPv6_VPN && cli.GetVersion() == 3:
		if path.IsWithdraw == true {
			command = zebra.IPV6_ROUTE_DELETE
		} else {
			command = zebra.IPV6_ROUTE_ADD
		}
		prefix = nlri.(*bgp.LabeledVPNIPv6AddrPrefix).Prefix
		nexthops = append(nexthops, path.GetNexthop().To16())
		vrfId = f()
	default:
		return nil
	}

	flags := uint8(zebra.MESSAGE_NEXTHOP)
	plen, _ := strconv.Atoi(l[1])
	med, err := path.GetMed()
	if err == nil {
		flags |= zebra.MESSAGE_METRIC
	}

	log.WithFields(log.Fields{
		"Topic":        "Zebra",
		"Type":         zebra.ROUTE_BGP,
		"SAFI":         zebra.SAFI_UNICAST,
		"VrfId":        vrfId,
		"Message":      flags,
		"Prefix":       prefix,
		"PrefixLength": uint8(plen),
		"Nexthop":      nexthops,
		"Metric":       med,
	}).Debugf("create ip route message from path.")

	return &zebra.Message{
		Header: cli.CreateHeader(command, vrfId),
		Body: &zebra.IPRouteBody{
			Type:         zebra.ROUTE_BGP,
			SAFI:         zebra.SAFI_UNICAST,
			Message:      flags,
			Prefix:       prefix,
			PrefixLength: uint8(plen),
			Nexthops:     nexthops,
			Metric:       med,
		},
	}
}

func createPathFromIPRouteMessage(m *zebra.Message, peerInfo *table.PeerInfo, vrfs map[string]*table.Vrf) *table.Path {

	header := m.Header
	body := m.Body.(*zebra.IPRouteBody)

	var nlri bgp.AddrPrefixInterface
	pattr := make([]bgp.PathAttributeInterface, 0)
	var mpnlri *bgp.PathAttributeMpReachNLRI
	var isWithdraw bool = header.GetCommand() == zebra.IPV4_ROUTE_DELETE || header.GetCommand() == zebra.IPV6_ROUTE_DELETE

	origin := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP)
	pattr = append(pattr, origin)

	log.WithFields(log.Fields{
		"Topic":        "Zebra",
		"RouteType":    body.Type.String(),
		"VrfId":        header.GetVrf(),
		"Flag":         body.Flags.String(),
		"Message":      body.Message,
		"Prefix":       body.Prefix,
		"PrefixLength": body.PrefixLength,
		"Nexthop":      body.Nexthops,
		"IfIndex":      body.Ifindexs,
		"Metric":       body.Metric,
		"Distance":     body.Distance,
		"api":          header.GetCommand().String(),
	}).Debugf("create path from ip route message.")

	isV4 := header.GetCommand() == zebra.IPV4_ROUTE_ADD || header.GetCommand() == zebra.IPV4_ROUTE_DELETE
	haveVrfId := header.GetVrf() != table.VRF_ID_DEFAULT

	switch true {
	case isV4 && haveVrfId:
		matched := false
		var vrf *table.Vrf
		for _, v := range vrfs {
			if v.VrfId == header.GetVrf() {
				matched = true
				vrf = v
				break
			}
		}
		if matched {
			nlri = bgp.NewIPAddrPrefix(body.PrefixLength, body.Prefix.String())
			n := nlri.(*bgp.IPAddrPrefix)
			nlri = bgp.NewLabeledVPNIPAddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(vrf.LabelMap[vrf.Name]), vrf.Rd)
		} else {
			nlri = bgp.NewIPAddrPrefix(body.PrefixLength, body.Prefix.String())
			nexthop := bgp.NewPathAttributeNextHop(body.Nexthops[0].String())
			pattr = append(pattr, nexthop)
		}
	case isV4:
		nlri = bgp.NewIPAddrPrefix(body.PrefixLength, body.Prefix.String())
		nexthop := bgp.NewPathAttributeNextHop(body.Nexthops[0].String())
		pattr = append(pattr, nexthop)
	case !isV4 && haveVrfId:
		matched := false
		var vrf *table.Vrf
		for _, v := range vrfs {
			if v.VrfId == header.GetVrf() {
				matched = true
				vrf = v
				break
			}
		}
		if matched {
			nlri = bgp.NewIPv6AddrPrefix(body.PrefixLength, body.Prefix.String())
			n := nlri.(*bgp.IPv6AddrPrefix)
			nlri = bgp.NewLabeledVPNIPv6AddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(vrf.LabelMap[vrf.Name]), vrf.Rd)
		} else {
			nlri = bgp.NewIPv6AddrPrefix(body.PrefixLength, body.Prefix.String())
			mpnlri = bgp.NewPathAttributeMpReachNLRI(body.Nexthops[0].String(), []bgp.AddrPrefixInterface{nlri})
			pattr = append(pattr, mpnlri)
		}
	case !isV4:
		nlri = bgp.NewIPv6AddrPrefix(body.PrefixLength, body.Prefix.String())
		mpnlri = bgp.NewPathAttributeMpReachNLRI(body.Nexthops[0].String(), []bgp.AddrPrefixInterface{nlri})
		pattr = append(pattr, mpnlri)
	}

	med := bgp.NewPathAttributeMultiExitDisc(body.Metric)
	pattr = append(pattr, med)

	p := table.NewPath(peerInfo, nlri, isWithdraw, pattr, false, time.Now(), false)
	p.IsFromZebra = true
	return p
}

func newBroadcastZapiBestMsg(cli *zebra.Client, path *table.Path, vrfs map[string]*table.Vrf) *broadcastZapiMsg {
	if cli == nil {
		return nil
	}
	m := newIPRouteMessage(cli, path, vrfs)
	if m == nil {
		return nil
	}
	return &broadcastZapiMsg{
		client: cli,
		msg:    m,
	}
}

func handleZapiMsg(msg *zebra.Message, server *BgpServer) []*SenderMsg {

	switch b := msg.Body.(type) {
	case *zebra.IPRouteBody:
		pi := &table.PeerInfo{
			AS:      server.bgpConfig.Global.GlobalConfig.As,
			LocalID: server.bgpConfig.Global.GlobalConfig.RouterId,
		}

		//		if b.Prefix != nil && len(b.Nexthops) > 0 && b.Type != zebra.ROUTE_KERNEL {
		if b.Prefix != nil && len(b.Nexthops) > 0 {
			p := createPathFromIPRouteMessage(msg, pi, server.globalRib.Vrfs)
			msgs := server.propagateUpdate(nil, []*table.Path{p})
			return msgs
		}
	}

	return nil
}

func newVrfZapiMsg(cli *zebra.Client, vrfId table.VRF_ID_YTPE, redists []string) []*broadcastZapiMsg {
	msgs := make([]*broadcastZapiMsg, 0)
	for _, typ := range redists {
		t, err := zebra.RouteTypeFromString(typ)
		if err != nil {
			return nil
		}
		if m := newRedistributedAddMassage(cli, vrfId, t); m != nil {
			b := &broadcastZapiMsg{
				client: cli,
				msg:    m,
			}
			msgs = append(msgs, b)
		}
	}
	b := &broadcastZapiMsg{
		client: cli,
		msg:    newRedistributedDefaultAddMassage(cli, vrfId),
	}
	msgs = append(msgs, b)
	return msgs
}
