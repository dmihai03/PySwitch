#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

trunk_interfaces = []
own_bridge_id = 0
root_bridge_id = 0
root_path_cost = 0
bpdu_source_mac = b'\x00\x00\x00\x00\x00\x00'
bpdu_destination_mac = b'\x01\x80\xc2\x00\x00\x00'
i_am_root = True

def parse_config(switch_id):
	cfg_file = open("configs/switch" + switch_id + ".cfg", "r")

	VLAN_TABLE = {}

	for line in cfg_file:
		if line.startswith("r"):
			line = line[:len(line) - 1]
			split_line = line.split()
			interface = split_line[0]
			vlan = split_line[1]
			VLAN_TABLE[interface] = vlan

		else:
			priority = int.from_bytes(line[:len(line) - 1].encode(), 'little')

	return VLAN_TABLE, trunk_interfaces, priority

def can_forward(v_table, src_int, dest_int):
	if	v_table[get_interface_name(dest_int)] == "T" or \
		v_table[get_interface_name(src_int)] == "T" or \
		v_table[get_interface_name(src_int)] == v_table[get_interface_name(dest_int)]:
		return True

	return False

def in_same_vlan(v_table, dest_int, vlan_id):
	return int(v_table[get_interface_name(dest_int)]) == vlan_id

def trunk_interface(v_table, interface):
	if v_table[get_interface_name(interface)] == "T":
		return True

	return False

def access_interface(v_table, interface):
	if v_table[get_interface_name(interface)] != "T":
		return True

	return False

def parse_ethernet_header(data):
	# Unpack the header fields from the byte array
	#dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
	dest_mac = data[0:6]
	src_mac = data[6:12]

	# Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
	ether_type = (data[12] << 8) + data[13]

	vlan_id = -1
	# Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
	if ether_type == 0x8200:
		vlan_tci = int.from_bytes(data[14:16], byteorder='big')
		vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
		ether_type = (data[16] << 8) + data[17]

	return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
	# 0x8100 for the Ethertype for 802.1Q
	# vlan_id & 0x0FFF ensures that only the last 12 bits are used
	return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bpdu_frame():
	bpdu_frame = bpdu_destination_mac+ \
				 bpdu_source_mac + \
				 struct.pack('!I', own_bridge_id) + \
				 struct.pack('!I', own_bridge_id) + \
				 struct.pack('!I', 0)

	bpdu_frame_len = len(bpdu_frame)

	return bpdu_frame, bpdu_frame_len

def parse_bpdu_frame(data):
	sender_mac = data[0:6]
	receiver_mac = data[6:12]
	recv_root_id = int.from_bytes(data[12:16], 'big')
	recv_bridge_id = int.from_bytes(data[16:20], 'big')
	recv_cost = int.from_bytes(data[20:24], 'big')

	return sender_mac, receiver_mac, recv_root_id, recv_bridge_id, recv_cost

def send_bpdu_every_sec():
	while True:
		if i_am_root:
			bpdu_frame, bpdu_len = create_bpdu_frame()

			for i in trunk_interfaces:
				send_to_link(int(i), bpdu_len, bpdu_frame)

		time.sleep(1)

def received_bpdu(dest_mac):
	return dest_mac == bpdu_destination_mac

def main():
	# init returns the max interface number. Our interfaces
	# are 0, 1, 2, ..., init_ret value + 1
	switch_id = sys.argv[1]

	num_interfaces = wrapper.init(sys.argv[2:])
	interfaces = range(0, num_interfaces)

	global bpdu_source_mac
	bpdu_source_mac = get_switch_mac()

	global trunk_interfaces, own_bridge_id, root_bridge_id, root_path_cost, i_am_root

	VLAN_TABLE, trunk_interfaces, switch_priority = parse_config(switch_id)

	for i in interfaces:
		if trunk_interface(VLAN_TABLE, i):
			trunk_interfaces.append(i)

	MAC_TABLE = {}

	INT_STATE = {}

	# Set the state of each interface to "LISTENING" because currently we are root
	for i in interfaces:
		INT_STATE[get_interface_name(i)] = "LISTENING"

	root_port = -1
	own_bridge_id = switch_priority
	root_bridge_id = own_bridge_id

	# Create and start a new thread that deals with sending BPdU
	t = threading.Thread(target=send_bpdu_every_sec)
	t.start()

	while True:
		# Note that data is of type bytes([...]).
		# b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
		# b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
		# b3 = b1[0:2] + b[3:4].
		interface, data, length = recv_from_any_link()

		dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
		dest_mac_bpdu, src_mac_bpdu, recv_root_id, recv_bridge_id, recv_cost = parse_bpdu_frame(data)

		dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
		src_mac = ':'.join(f'{b:02x}' for b in src_mac)

		# Note. Adding a VLAN tag can be as easy as
		# tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

		# Update MAC table
		MAC_TABLE[src_mac] = interface

		# Check if received bpdu frame
		if received_bpdu(dest_mac_bpdu):
			if recv_root_id < root_bridge_id:
				root_bridge_id = recv_root_id
				root_path_cost = recv_cost + 10
				root_port = interface

				if i_am_root:
					i_am_root = False
					for i in trunk_interfaces:
						if i != root_port:
							INT_STATE[get_interface_name(i)] = "BLOCKING"

				if INT_STATE[get_interface_name(root_port)] == "BLOCKING":
					INT_STATE[get_interface_name(root_port)] = "LISTENING"

				bpdu_frame, bpdu_len = create_bpdu_frame()

				for i in trunk_interfaces:
					if i != interface:
						send_to_link(int(i), bpdu_len, bpdu_frame)

			elif recv_root_id == root_bridge_id:
				if interface == root_port and recv_cost + 10 < root_path_cost:
					root_path_cost = recv_cost + 10

				elif interface != root_port:
					if recv_cost > root_path_cost:
						if INT_STATE[get_interface_name(interface)] == "BLOCKING":
							INT_STATE[get_interface_name(interface)] = "LISTENING"

			elif recv_bridge_id == own_bridge_id:
				INT_STATE[get_interface_name(interface)] = "BLOCKING"

			else:
				continue

			if own_bridge_id == root_bridge_id:
				i_am_root = True
				for i in trunk_interfaces:
					INT_STATE[get_interface_name(i)] = "LISTENING"

			continue

		# Unicast
		if int.from_bytes(dest_mac[0].encode(), 'big') & 1 == 0:
			if dest_mac in MAC_TABLE and INT_STATE[get_interface_name(MAC_TABLE[dest_mac])] == "LISTENING" and \
			   can_forward(VLAN_TABLE, interface, MAC_TABLE[dest_mac]):
				if access_interface(VLAN_TABLE, interface) and trunk_interface(VLAN_TABLE, MAC_TABLE[dest_mac]):
					# Add VLAN tag
					tagged_frame = data[0:12] + create_vlan_tag(int(VLAN_TABLE[get_interface_name(interface)])) + data[12:]
					# 4 bytes added to the length
					new_length = length + 4
					send_to_link(MAC_TABLE[dest_mac], new_length, tagged_frame)
					continue

				if trunk_interface(VLAN_TABLE, interface) and access_interface(VLAN_TABLE, MAC_TABLE[dest_mac]) and \
				   in_same_vlan(VLAN_TABLE, MAC_TABLE[dest_mac], vlan_id):
					# Remove VLAN tag
					untagged_frame = data[0:12] + data[16:]
					# 4 bytes removed from the length
					new_length = length - 4
					send_to_link(MAC_TABLE[dest_mac], new_length, untagged_frame)
					continue

				send_to_link(MAC_TABLE[dest_mac], length, data)

			else:
				for i in interfaces:
					if i != interface and INT_STATE[get_interface_name(i)] == "LISTENING" and\
					   can_forward(VLAN_TABLE, interface, i):
						if access_interface(VLAN_TABLE, interface) and trunk_interface(VLAN_TABLE, i):
							# Add VLAN tag
							tagged_frame = data[0:12] + create_vlan_tag(int(VLAN_TABLE[get_interface_name(interface)])) + data[12:]
							# 4 bytes added to the length
							new_length = length + 4
							send_to_link(i, new_length, tagged_frame)
							continue

						if trunk_interface(VLAN_TABLE, interface) and access_interface(VLAN_TABLE, i) and \
						   in_same_vlan(VLAN_TABLE, i, vlan_id):
							# Remove VLAN tag
							untagged_frame = data[0:12] + data[16:]
							# 4 bytes removed from the length
							new_length = length - 4
							send_to_link(i, new_length, untagged_frame)
							continue

						send_to_link(i, length, data)

		# Broadcast
		else:
			for i in interfaces:
				if i != interface and INT_STATE[get_interface_name(i)] == "LISTENING" and\
				   can_forward(VLAN_TABLE, interface, i):
					if access_interface(VLAN_TABLE, interface) and trunk_interface(VLAN_TABLE, i):
						# Add VLAN tag
						tagged_frame = data[0:12] + create_vlan_tag(int(VLAN_TABLE[get_interface_name(interface)])) + data[12:]
						# 4 bytes added to the length
						new_length = length + 4
						send_to_link(i, new_length, tagged_frame)
						continue

					if trunk_interface(VLAN_TABLE, interface) and access_interface(VLAN_TABLE, i) and \
					   in_same_vlan(VLAN_TABLE, i, vlan_id):
						# Remove VLAN tag
						untagged_frame = data[0:12] + data[16:]
						# 4 bytes removed from the length
						new_length = length - 4
						send_to_link(i, new_length, untagged_frame)
						continue

					send_to_link(i, length, data)

		# data is of type bytes.
		# send_to_link(i, length, data)

if __name__ == "__main__":
	main()
