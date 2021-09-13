module PacketAnalyzer::TEREDO;

# This needs to be loaded here so the function is available. Function BIFs normally aren't
# loaded until after the packet analysis init scripts are run, and then zeek complains it
# can't find the function.
@load base/bif/plugins/Zeek_Teredo.functions.bif

# Needed for port registration for BPF
@load base/frameworks/analyzer/main

export {
        ## Default analyzer
        const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
}

const teredo_ports = { 3544/udp };
redef likely_server_ports += { teredo_ports };

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_protocol_detection(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_TEREDO);

	for ( p in teredo_ports )
		{
		PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_UDP, port_to_count(p),
		                                         PacketAnalyzer::ANALYZER_TEREDO);
		Analyzer::add_port_to_table(PacketAnalyzer::ANALYZER_TEREDO, p);
		}
	}

event connection_state_remove(c: connection)
	{
	remove_teredo_connection(c$id);
	}
