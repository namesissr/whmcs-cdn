"""Rendering of the edge config: nginx http/site/stream files, the njs data module and the nftables
guard rulesets. Every renderer is a pure function of the edge config and agent.conf settings (plus
the node's nginx capabilities), so an identical config renders byte-identical files."""
