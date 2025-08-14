#!/usr/bin/env python3
import argparse
import logging
import os
import random
import socket
import threading
import time
from typing import Dict, Tuple

from scapy.all import AsyncSniffer, IP, TCP, UDP, get_if_list  # type: ignore
# from scapy.compat import raw  # type: ignore
# from scapy.layers.netflow import NetflowHeaderV5, NetflowRecordV5  # type: ignore
import struct

# ===== Logging =====
logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s [%(levelname)s] %(message)s",
	datefmt="%H:%M:%S",
)

# ===== Flow store =====
FlowKey = Tuple[str, str, int, int, int]
flows: Dict[FlowKey, Dict[str, int]] = {}
flow_sequence: int = 0  # Monotonically increasing per exported record, as per NetFlow v5 spec
BOOT_TIME_MS = int(time.time() * 1000)  # Local epoch to make 'first'/'last' relative to header.sysUptime


def clamp_32bit(value: int) -> int:
	return max(0, min(value, 0xFFFFFFFF))


def ip_to_int(ip: str) -> int:
	return struct.unpack("!I", socket.inet_aton(ip))[0]


def get_default_interface() -> str:
	candidates = get_if_list()
	# Prefer common physical interfaces if available
	preferred = [
		"eth0",
		"en0",
		"wlan0",
		"Wi-Fi",
	]
	for name in preferred:
		if name in candidates:
			return name
	# Fallback to first non-loopback
	for name in candidates:
		if name not in {"lo", "lo0", "any"}:
			return name
	# Last resort
	return candidates[0] if candidates else "lo"


def packet_callback(pkt) -> None:
	if IP not in pkt:
		return

	src_ip = pkt[IP].src
	dst_ip = pkt[IP].dst
	ip_proto = int(pkt[IP].proto)
	tos_val = int(pkt[IP].tos) if hasattr(pkt[IP], "tos") else 0

	src_port = 0
	dst_port = 0
	tcp_flags_val = 0

	if TCP in pkt:
		src_port = int(pkt[TCP].sport)
		dst_port = int(pkt[TCP].dport)
		# scapy exposes flags as an int-like object; coerce to int
		tcp_flags_val = int(pkt[TCP].flags)
	elif UDP in pkt:
		src_port = int(pkt[UDP].sport)
		dst_port = int(pkt[UDP].dport)

	flow_key: FlowKey = (src_ip, dst_ip, src_port, dst_port, ip_proto)
	current_time_ms = int(time.time() * 1000)

	# Count L3 (IP) bytes; fallback to len(bytes(IP)) if header len not present
	try:
		ip_bytes = int(pkt[IP].len)
	except Exception:
		ip_bytes = len(bytes(pkt[IP]))

	if flow_key not in flows:
		flows[flow_key] = {
			"packets": 1,
			"bytes": ip_bytes,
			"start_time_ms": current_time_ms,
			"end_time_ms": current_time_ms,
			"tcp_flags": tcp_flags_val,
			"proto": ip_proto,
			"src_port": src_port,
			"dst_port": dst_port,
			"tos": tos_val,
		}
	else:
		flow = flows[flow_key]
		flow["packets"] += 1
		flow["bytes"] += ip_bytes
		flow["end_time_ms"] = current_time_ms
		flow["tcp_flags"] |= tcp_flags_val



def build_netflow_v5_header(count: int, sys_uptime: int, unix_secs: int, unix_nsecs: int, sequence: int,
						    engine_type: int = 0, engine_id: int = 0, sampling_interval: int = 0) -> bytes:
	# NetFlow v5 header (24 bytes)
	# version(2), count(2), sys_uptime(4), unix_secs(4), unix_nsecs(4), flow_sequence(4), engine_type(1), engine_id(1), sampling_interval(2)
	return struct.pack("!HHIIIIBBH", 5, count, sys_uptime, unix_secs, unix_nsecs, sequence, engine_type, engine_id, sampling_interval)


def build_netflow_v5_record(src_ip: str, dst_ip: str, nexthop_ip: str, input_if: int, output_if: int,
						   d_pkts: int, d_octets: int, first_ms: int, last_ms: int,
						   src_port: int, dst_port: int, tcp_flags: int, proto: int, tos: int,
						   src_as: int = 0, dst_as: int = 0, src_mask: int = 0, dst_mask: int = 0) -> bytes:
	# NetFlow v5 record (48 bytes)
	# srcaddr(4), dstaddr(4), nexthop(4), input(2), output(2), dPkts(4), dOctets(4), first(4), last(4),
	# srcport(2), dstport(2), pad1(1), tcp_flags(1), prot(1), tos(1), src_as(2), dst_as(2), src_mask(1), dst_mask(1), pad2(2)
	return struct.pack(
		"!IIIHHIIIIHHBBBBHHBBH",
		ip_to_int(src_ip),
		ip_to_int(dst_ip),
		ip_to_int(nexthop_ip),
		int(input_if),
		int(output_if),
		int(d_pkts),
		int(d_octets),
		int(first_ms),
		int(last_ms),
		int(src_port),
		int(dst_port),
		0,  # pad1
		int(tcp_flags) & 0xFF,
		int(proto) & 0xFF,
		int(tos) & 0xFF,
		int(src_as) & 0xFFFF,
		int(dst_as) & 0xFFFF,
		int(src_mask) & 0xFF,
		int(dst_mask) & 0xFF,
		0,  # pad2
	)



def build_and_send_exports(collector_ip: str, collector_port: int, max_records_per_pkt: int = 30) -> None:
	global flow_sequence

	if not flows:
		logging.debug("No flows to export")
		return

	now_ms = int(time.time() * 1000)
	sys_uptime = clamp_32bit(now_ms - BOOT_TIME_MS)
	unix_secs = int(time.time())
	unix_nsecs = int((time.time() - unix_secs) * 1_000_000_000)

	records_bytes = []
	for (src_ip, dst_ip, src_port, dst_port, proto), flow in list(flows.items()):
		first_rel = clamp_32bit(int(flow["start_time_ms"]) - BOOT_TIME_MS)
		last_rel = clamp_32bit(int(flow["end_time_ms"]) - BOOT_TIME_MS)

		record_bytes = build_netflow_v5_record(
			src_ip=src_ip,
			dst_ip=dst_ip,
			nexthop_ip="0.0.0.0",
			input_if=0,
			output_if=0,
			d_pkts=int(flow["packets"]),
			d_octets=int(flow["bytes"]),
			first_ms=first_rel,
			last_ms=last_rel,
			src_port=int(flow["src_port"]),
			dst_port=int(flow["dst_port"]),
			tcp_flags=int(flow["tcp_flags"]),
			proto=int(flow["proto"]),
			tos=int(flow.get("tos", 0)),
			src_as=0,
			dst_as=0,
			src_mask=0,
			dst_mask=0,
		)
		records_bytes.append(record_bytes)

	if not records_bytes:
		logging.debug("No records to export")
		return

	# Chunk into valid NetFlow v5 datagrams: header + up to 30 records
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		for i in range(0, len(records_bytes), max_records_per_pkt):
			chunk = records_bytes[i : i + max_records_per_pkt]
			header = build_netflow_v5_header(
				count=len(chunk),
				sys_uptime=sys_uptime,
				unix_secs=unix_secs,
				unix_nsecs=unix_nsecs,
				sequence=flow_sequence,
				engine_type=0,
				engine_id=0,
				sampling_interval=0,
			)
			payload = header + b"".join(chunk)

			# Send UDP datagram
			sock.sendto(payload, (collector_ip, int(collector_port)))
			logging.info(
				"Exported %d flows (seq=%d) -> %s:%d payload=%dB",
				len(chunk),
				flow_sequence,
				collector_ip,
				collector_port,
				len(payload),
			)

			# Increment sequence by number of records sent in this datagram
			flow_sequence = (flow_sequence + len(chunk)) & 0xFFFFFFFF
	finally:
		sock.close()

	# Optionally keep flows for ongoing aggregation. To clear exported state, uncomment:
	# flows.clear()



def export_timer(collector_ip: str, collector_port: int, interval_seconds: int) -> None:
	while True:
		try:
			build_and_send_exports(collector_ip, collector_port)
		except Exception as exc:
			logging.exception("Export error: %s", exc)
		finally:
			time.sleep(interval_seconds)



def main() -> None:
	parser = argparse.ArgumentParser(description="Simple NetFlow v5 exporter using Scapy")
	parser.add_argument("--iface", default=os.environ.get("NETFLOW_IFACE", ""), help="Interface to sniff (default: auto)")
	parser.add_argument("--collector-ip", default=os.environ.get("NETFLOW_COLLECTOR", "127.0.0.1"), help="Collector IPv4 address")
	parser.add_argument("--collector-port", type=int, default=int(os.environ.get("NETFLOW_PORT", "2055")), help="Collector UDP port (default: 2055)")
	parser.add_argument("--interval", type=int, default=int(os.environ.get("NETFLOW_INTERVAL", "15")), help="Export interval in seconds (default: 15)")
	args = parser.parse_args()

	iface = args.iface or get_default_interface()
	if iface not in get_if_list():
		raise RuntimeError(f"Interface {iface} is not available. Available: {get_if_list()}")

	logging.info("Interfaces available: %s", get_if_list())
	logging.info("Using interface: %s", iface)
	logging.info("Collector: %s:%d | interval=%ss", args.collector_ip, args.collector_port, args.interval)

	# Start exporter thread
	t = threading.Thread(target=export_timer, args=(args.collector_ip, args.collector_port, args.interval), daemon=True)
	t.start()

	# Start sniffer
	bpf = "ip"  # capture IPv4 only
	sniffer = AsyncSniffer(iface=iface, prn=packet_callback, filter=bpf, store=False)
	sniffer.start()

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		logging.info("Stopping sniffer...")
		sniffer.stop()


if __name__ == "__main__":
	main()