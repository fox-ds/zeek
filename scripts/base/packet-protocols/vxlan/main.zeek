module PacketAnalyzer::VXLAN;

export {
	# There's no indicator in the VXLAN packet header format about what the next protocol
	# in the chain is. All of the documentation just lists Ethernet, so default to that.
        const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_ETHERNET &redef;
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_UDP, 4789, PacketAnalyzer::ANALYZER_VXLAN);
	}
