// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vxlan/VXLAN.h"
#include "zeek/packet_analysis/protocol/vxlan/events.bif.h"
#include "zeek/RunState.h"

using namespace zeek::packet_analysis::VXLAN;

VXLAN_Analyzer::VXLAN_Analyzer()
	: zeek::packet_analysis::Analyzer("VXLAN")
	{
	}

bool VXLAN_Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( packet->encap &&
	     packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	constexpr uint16_t hdr_size = 8;

	if ( hdr_size > len )
		{
		// TODO
		// ProtocolViolation("VXLAN header truncation", (const char*) data, len);
		Weird("truncated_vxlan", packet);
		return false;
		}

	if ( (data[0] & 0x08) == 0 )
		{
		// TODO
		//ProtocolViolation("VXLAN 'I' flag not set", (const char*) data, len);
		return false;
		}

	pkt_timeval ts;
	ts.tv_sec = static_cast<time_t>(run_state::current_timestamp);
	ts.tv_usec = static_cast<suseconds_t>((run_state::current_timestamp - static_cast<double>(ts.tv_sec)) * 1000000);
	Packet inner_packet(DLT_EN10MB, &ts, len-hdr_size, len-hdr_size, data+hdr_size);

	if ( packet->session )
		{
		EncapsulatingConn inner(static_cast<Connection*>(packet->session), BifEnum::Tunnel::GENEVE);

		if ( ! packet->encap )
			packet->encap = std::make_shared<EncapsulationStack>();

		packet->encap->Add(inner);
		inner_packet.encap = packet->encap;
		}

	inner_packet.gre_version = -1;
	inner_packet.tunnel_type = BifEnum::Tunnel::VXLAN;
	inner_packet.tunnel_tag = GetAnalyzerTag();

	// Note here so i don't forget what's going on. The same thing needs to happen in any of the other
	// analyzers that handle tunnels, basically:
	//
	// Ideally, ForwardPacket here would just forward the existing packet down into the next analyzer
	// which should be IPTunnel. That would allow us to track duplicate tunnels, tunnels with responses,
	// etc. Except we can't do that because we need to get the inner packet's IP header back from the
	// processing, so we can send the event. We don't keep that information around anywhere after the
	// remaining packet's been processed. Perhaps EncapsulatingConn could be extended to keep more
	// information about the encapsulated packet? It already keeps the src/dst addr/port. Could it just
	// keep a full IP_Hdr instead?
	//
	// We shouldn't be forwarding directly to Ethernet, for example, because IPTunnel is kind of a
	// utility analyzer for any protocol that was tunneled through IP. It calls that to set up the
	// encapsulation and whatnot, plus set any necessary fields in the outer connection. That avoids
	// the need to do it manually here. The problem then, is how to define forwarding rules for
	// tunnel analyzers? If we're always going to forward into IPTunnel, do we define the forwarding
	// rules as if that wasn't going to happen, and then use that analyzer to lookup and and forward
	// on? Should the tunnel analyzers extend IPTunnel in some way? IPTunnel has to exist as an analyzer
	// on its own, because IP-in-IP tunnels go directly through it.
	//
	// Along those same veins, does a tunnel really *have* to encapsulate IP? Or is that a bigger project?

	// Skip the header and pass on to the next analyzer. It's possible for VXLAN to
	// just be a header and nothing after it, so check for that case.
	bool fwd_ret_val = true;
	if ( len != hdr_size )
		fwd_ret_val = ForwardPacket(len-hdr_size, data+hdr_size, &inner_packet);

	if ( fwd_ret_val && vxlan_packet && packet->session && inner_packet.ip_hdr )
		{
		int vni = (data[4] << 16) + (data[5] << 8) + (data[6] << 0);
		inner_packet.session->EnqueueEvent(vxlan_packet, nullptr, packet->session->GetVal(),
		                                   inner_packet.ip_hdr->ToPktHdrVal(), val_mgr->Count(vni));

		// TODO protocol confirmation
		}

	return fwd_ret_val;
	}
