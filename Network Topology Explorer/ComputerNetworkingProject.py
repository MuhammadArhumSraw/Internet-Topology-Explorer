
#@denizacarkostem April 2025

#THE ENGINE IMPLEMENTATION 
#libraries needed
import argparse
import os
import sys
import signal
import socket
import logging
from optparse import OptionParser
from scapy.all import *
from scapy.data import IP_PROTOS
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backend_bases import MouseButton
import re

with open("trace_output.txt", "w"):
    pass

# Console color codes
Green = '\033[92m'
Yellow = '\033[93m'
Red = '\033[91m'
End = '\033[0m'

#color functions should apply  globally
def green(word):
    return Green + word + End 

def yellow(word):
    return Yellow + word + End

def red(word):
    return Red + word + End 

#timeout context manager
class Timeout:
    class Timeout(Exception): pass

    def __init__(self, sec):
        self.sec = sec

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.raise_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)

    def raise_timeout(self, *args):
        raise Timeout.Timeout()

# Main traceroute engine implememntation classs
class TraceRouteEngine:
    def __init__(self):
        pass

    def start_trace(self, target_ip, protocol="icmp", find=False, hops=None, output_file = "trace_output.txt"):
        ttl_id = 0 #use default ttl just in case and base icmp
        protocol = protocol.upper()

        while True: #run sending loop
            ttl_id += 1 
            send_time = time.time()
            p = None
            extra_info = ""
            #initialize the key information to output

            try:
                with Timeout(8):
                    if protocol == "ICMP": #grab data for ICMP
                        p = sr1(IP(dst=target_ip, ttl=ttl_id)/ICMP(), verbose=False)
                        if p:
                            icmp_layer = p.getlayer(ICMP)
                            extra_info = f"ICMP type={icmp_layer.type}, code={icmp_layer.code}" if icmp_layer else ""
                            code = icmp_layer.type if icmp_layer else None

                    elif protocol == "UDP": #grab data for UDP
                        p = sr1(IP(dst=target_ip, ttl=ttl_id)/UDP(dport=33434), verbose=False)
                        if p:
                            code = p.getlayer(ICMP).type if p.haslayer(ICMP) else None
                            extra_info = "UDP probe"

                    elif protocol == "TCP": #grap data dor TCP
                        p = sr1(IP(dst=target_ip, ttl=ttl_id)/TCP(flags="S", dport=80), verbose=False)
                        if p:
                            tcp_layer = p.getlayer(TCP)
                            flags = tcp_layer.sprintf("%TCP.flags%") if tcp_layer else "N/A"
                            extra_info = f"TCP flags={flags}"
                            code = 1 if tcp_layer and tcp_layer.flags == 0x12 else None  # SYN-ACK

                if p: #count the rtt of the package received 
                    rtt = (time.time() - send_time) * 1000
                    try:
                        hostname = socket.gethostbyaddr(p.src)[0]
                    except socket.error:
                        hostname = p.src
                        #get the hostname if resolved 

                    result = f"{ttl_id})\t{yellow(hostname)} ({yellow(p.src)})\t{green(f'{rtt:.2f} ms')}\t[{protocol}] {extra_info}"
                    print(result)
                    if output_file:
                        with open(output_file, 'a') as f:
                            f.write(result + '\n')

                    if find and p.src == find: 
                        print(green("\nIP Found:\n\t") + result)
                        break

                    if (protocol == "ICMP" and code == 0) or \
                    (protocol == "UDP" and code == 3) or \
                    (protocol == "TCP" and code == 1): #match the protocol and their codes 
                        break
                else:
                    line = f"{ttl_id}) \t* * *"
                    print(line)
                    if output_file:
                        with open(output_file, 'a') as f:
                            f.write(line + '\n')


            except Exception as e: #handle the timeout for problematic packet
                line =  f"{ttl_id}) \t* * *  ({red('Timeout or Error')})"
                print(line)
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(line + '\n')

            if hops and ttl_id == int(hops):
                break

# Remove ANSI escape codes
def remove_ansi(text):
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

# Parse traceroute results from file
def parse_results(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        lines = [remove_ansi(line.strip()) for line in f.readlines() if line.strip()]
    nodes = []
    for line in lines:
        match = re.match(r"\d+\)\s+(.+?) \(([\d.]+)\)\s+([\d.]+) ms\s+\[(\w+)\]", line)
        if match:
            hostname, ip, rtt, protocol = match.groups()
            nodes.append({'hostname': hostname, 'ip': ip, 'rtt': float(rtt), 'protocol': protocol})
    return nodes

# Draw the graph
def draw_graph(nodes):
    G = nx.DiGraph()

    for i, node in enumerate(nodes):
        label = f"{node['hostname']}\n({node['ip']})"
        G.add_node(i, **node, label=label)
        if i > 0:
            G.add_edge(i-1, i, protocol=node['protocol'])

    pos = nx.spring_layout(G, k=1.5, iterations=100, seed=42)

    fig, ax = plt.subplots(figsize=(16, 9))
    manager = plt.get_current_fig_manager()
    try:
        manager.full_screen_toggle()
    except:
        try:
            manager.window.state('zoomed')
        except:
            pass

    ax.set_facecolor('white')
    ax.axis('off')

    protocol_colors = {'ICMP': 'blue', 'TCP': 'green', 'UDP': 'red'}
    patches = [mpatches.Patch(color=c, label=p) for p, c in protocol_colors.items()]
    ax.legend(handles=patches, loc='lower left')

    ax.text(0.5, 1.05, 'Topology', horizontalalignment='center', fontsize=20, fontweight='bold', transform=ax.transAxes)

    detail_box = ax.text(1.01, 0.8, '', transform=ax.transAxes, fontsize=10,
                         verticalalignment='top', bbox=dict(boxstyle='round,pad=0.5', facecolor='lightyellow', edgecolor='black'))

    detail_box.set_text(
        f"Hostname: {nodes[0]['hostname']}\n"
        f"IP: {nodes[0]['ip']}\n"
        f"RTT: {nodes[0]['rtt']} ms\n"
        f"Protocol: {nodes[0]['protocol']}"
    )

    fig.canvas.draw_idle()

    graph_artists = {'nodes': None, 'edges': None, 'labels': None}

    def draw_graph_elements():
        if graph_artists['nodes']:
            graph_artists['nodes'].remove()
        if graph_artists['edges']:
            for artist in graph_artists['edges']:
                artist.remove()
        if graph_artists['labels']:
            for artist in graph_artists['labels'].values():
                artist.remove()

        edge_colors = [protocol_colors.get(G[u][v]['protocol'], 'gray') for u, v in G.edges]
        graph_artists['nodes'] = nx.draw_networkx_nodes(G, pos, ax=ax, node_color='lightblue', node_size=1200)
        graph_artists['edges'] = nx.draw_networkx_edges(G, pos, ax=ax, edge_color=edge_colors, width=2, arrows=True)
        graph_artists['labels'] = nx.draw_networkx_labels(G, pos, labels={i: G.nodes[i]['label'] for i in G.nodes}, font_size=9)
        fig.canvas.draw_idle()

    draw_graph_elements()

    selected_node = {'index': None}

    def on_press(event):
        if event.inaxes != ax or event.button != MouseButton.LEFT:
            return
        for i, (x, y) in pos.items():
            radius = 0.05
            if abs(event.xdata - x) < radius and abs(event.ydata - y) < radius:
                selected_node['index'] = i
                break

    def on_release(event):
        selected_node['index'] = None

    def on_motion(event):
        if selected_node['index'] is None or event.inaxes != ax:
            return
        i = selected_node['index']
        pos[i] = (event.xdata, event.ydata)
        draw_graph_elements()

    def on_click(event):
        if event.inaxes != ax or event.button != MouseButton.LEFT:
            return
        for i, (x, y) in pos.items():
            radius = 0.05
            if abs(event.xdata - x) < radius and abs(event.ydata - y) < radius:
                node = G.nodes[i]
                detail_box.set_text(
                    f"Hostname: {node['hostname']}\n"
                    f"IP: {node['ip']}\n"
                    f"RTT: {node['rtt']} ms\n"
                    f"Protocol: {node['protocol']}"
                )
                fig.canvas.draw_idle()
                break

    fig.canvas.mpl_connect('button_press_event', on_press)
    fig.canvas.mpl_connect('button_release_event', on_release)
    fig.canvas.mpl_connect('motion_notify_event', on_motion)
    fig.canvas.mpl_connect('button_press_event', on_click)
    plt.show()
#run in mainframe 


if __name__ == "__main__":
    if not os.getuid() == 0:
        print(red("Root privileges required!\n"))
        exit(1) #exit 
        #NEED TO USE A VIRTUAL ENVIRONMENT AND PUSH WITH SUDO TO GET ROOT PRIVILEGE 

    #start the parser, get target, protocol, find and hops, 
    parser = OptionParser()
    parser.add_option("-o", "--output", dest="output", help="Output file to save the traceroute results")
    parser.add_option("-t", "--target", dest="target", help="Target address")
    parser.add_option("-p", "--protocol", dest="protocol", default="icmp", help="Protocol (ICMP/UDP/TCP)")
    parser.add_option("-f", "--find", dest="find", default=False, help="Find specific IP address")
    parser.add_option("-n", "--node", dest="node", default=False, help="Number of hops")

    (o, args) = parser.parse_args()

    if not o.target: #resolve target error
        print(red("Target address required!\n"))
        exit(1)

    if o.node:
        if not o.node.isdigit(): #block invalid hop limit
            print(red("Number of hops must be numeric!\n"))
            exit(1)
        if int(o.node) > 255: # obey hop limit
            print(red("Number of hops is too high!\n"))
            exit(1)

    engine = TraceRouteEngine() #instantinate engine 
    output_file = o.output if o.output else "trace_output.txt"
    engine.start_trace(
        o.target,
        o.protocol.lower(),
        o.find,
        int(o.node) if o.node else None,
        output_file) #start process

    #Visulising
    if not os.path.exists("trace_output.txt"):
        print("trace_output.txt not found.")
    else:
        nodes = parse_results("trace_output.txt")
        if nodes:
            draw_graph(nodes)
        else:
            print("No valid data found in trace_output.txt.")
