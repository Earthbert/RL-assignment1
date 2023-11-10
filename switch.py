#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from enum import Enum
from types import SimpleNamespace
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

bpdu_length = 39

class INT_State(Enum):
    BLOCKING = 0
    LISTENING = 1

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]
    
    print(f'ETHER TYPE: {int.to_bytes(ether_type, 2, "big")}')

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def parse_bpdu(data):
    dst_mac = data[0 : 6]
    
    if (dst_mac != b'\x01\x80\xC2\x00\x00\x00'):
        return None
    
    src_mac = data[6 : 12]
    llc_length = data[12 : 14]
    llc_header_dsap = data[14]
    llc_header_ssap = data[15]
    control = data[16]
    
    if (llc_header_dsap != 0x42 or llc_header_ssap != 0x42 or control != 0x03):
        return None
    
    root_bridge_id = data[17 : 25]
    root_bridge_cost = data[25 : 29]
    bridge_id = data[29 : 37]
    port_id = data[37 : 39]
    
    return root_bridge_id, int.from_bytes(root_bridge_cost, 'big'), bridge_id, int.from_bytes(port_id, 'big')

def create_bpdu(root_bridge_id, root_bridge_cost, bridge_id, port_id):
    data = b'\x01\x80\xC2\x00\x00\x00'
    data += get_switch_mac()
    data += int.to_bytes(bpdu_length, 2, 'big')
    data += int.to_bytes(0x42, 1, 'big')
    data += int.to_bytes(0x42, 1, 'big')
    data += int.to_bytes(0x03, 1, 'big')
    data += root_bridge_id
    data += int.to_bytes(root_bridge_cost, 4, 'big')
    data += bridge_id
    data += int.to_bytes(port_id, 2, 'big')
    return data

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec(stp_data: SimpleNamespace, interfaces, vlan_interfaces):
    while True:
        time.sleep(1)
        stp_data.lock.acquire()
        
        if stp_data.bridge_id == stp_data.root_bridge:
            for interface in interfaces:
                if (vlan_interfaces[get_interface_name(interface)] == 'T'):
                    data = create_bpdu(stp_data.root_bridge, 0, stp_data.bridge_id, interface)
                    send_to_link(interface, data, bpdu_length)
        stp_data.lock.release()

def parse_switch_conf(path):
    interfaces = {}
    with open(path) as f:
        i = 0;
        for line in f:
            if i == 0:
                priority = int(line)
            else:
                words = line.split()
                if (words[1] != 'T'):
                    interfaces[words[0]] = int(words[1])
                else:
                    interfaces[words[0]] = words[1]
            i += 1;
    return priority, interfaces

def process_data_and_send(vlan_interfaces, send_interface, frame_vlan, data, length):
    if vlan_interfaces[get_interface_name(send_interface)] == 'T':
        vlan_header = create_vlan_tag(frame_vlan)
        data = data[0 : 12] + vlan_header + data[12 : length]
        send_to_link(send_interface, data, length + 4)
    elif vlan_interfaces[get_interface_name(send_interface)] == frame_vlan:
        send_to_link(send_interface, data, length)

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    
    priority, vlan_interfaces = parse_switch_conf("configs/switch{}.cfg".format(switch_id))
        
    cam_table = {}
    for inter, vlan in vlan_interfaces.items():
        if (vlan != 'T'):
            cam_table[vlan] = {}

    stp_data = SimpleNamespace()
    stp_data.bridge_id = priority.to_bytes(2, 'big') + get_switch_mac()
    stp_data.root_bridge = stp_data.bridge_id
    stp_data.cost = 0
    stp_data.lock = threading.Lock()
    stp_data.root_port = -1
        
    # Create and start a new thread that deals with sending BDPUF    
    t = threading.Thread(target=send_bdpu_every_sec, args=(stp_data, interfaces, vlan_interfaces,))
    t.start()
    
    interface_states = {}
    
    for interface in interfaces:
        interface_states[interface] = INT_State.LISTENING

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        result = parse_bpdu(data)
        
        if (result == None and interface_states[interface] != INT_State.BLOCKING):
                        
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            # Print the MAC src and MAC dst in human readable format
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)
            
            # Note. Adding a VLAN tag can be as easy as
            # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

            # Implement forwarding with learning
            # Implement VLAN support
            
            if vlan_id != -1:
                if (vlan_id not in cam_table):
                    cam_table[vlan_id] = {}
                data = data[0 : 12] + data[16 : length]
                length -= 4
            
            if vlan_interfaces[get_interface_name(interface)] == 'T':
                frame_vlan = vlan_id
            else:
                frame_vlan = vlan_interfaces[get_interface_name(interface)]

            cam_table[frame_vlan][src_mac] = interface

            if dest_mac in cam_table[frame_vlan]:
                i = cam_table[frame_vlan][dest_mac]
                process_data_and_send(vlan_interfaces, i, frame_vlan, data, length)
            else:
                for i in interfaces:
                    if (i != interface):
                        process_data_and_send(vlan_interfaces, i, frame_vlan, data, length)
        elif (result != None):
            root_bridge_id, root_bridge_cost, bridge_id, port_id = result
            
            stp_data.lock.acquire()
            
            print(f'BPDU ROOT: {root_bridge_id} CURRENT_ROOT: {stp_data.root_bridge}')

            if (root_bridge_id < stp_data.root_bridge):
                # Set root port
                stp_data.root_port = interface
                
                if (stp_data.root_bridge == stp_data.bridge_id):
                    for i in interfaces:
                        if (vlan_interfaces[get_interface_name(i)] == 'T' and \
                            i != stp_data.root_port):
                            interface_states[i] = INT_State.BLOCKING

                stp_data.root_bridge = root_bridge_id
                stp_data.cost = root_bridge_cost + 10
                
                if (interface_states[stp_data.root_port] == INT_State.BLOCKING):
                    interface_states[stp_data.root_port] = INT_State.LISTENING
                
                for i in interfaces:
                    if (vlan_interfaces[get_interface_name(i)] == 'T'):
                        data = create_bpdu(stp_data.root_bridge, stp_data.cost, stp_data.bridge_id, i)
                        
            elif root_bridge_id == stp_data.root_bridge:
                if (interface == stp_data.root_port and root_bridge_cost + 10 < stp_data.cost):
                    stp_data.cost = root_bridge_cost + 10
                elif interface != stp_data.root_port:
                    if root_bridge_cost > stp_data.cost:
                        if interface_states[interface] == INT_State.BLOCKING:
                            interface_states[interface] = INT_State.LISTENING
            
            elif bridge_id == stp_data.bridge_id:
                interface_states[interface] = INT_State.BLOCKING
            
            if (stp_data.bridge_id == stp_data.root_bridge):
                for i in interfaces:
                    interface_states[i] = INT_State.LISTENING
             
            stp_data.lock.release()

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
