# Makefile for Custom Traceroute Tool

SCRIPT = ComputerNetworkingProject.py

trace:
	sudo python3 $(SCRIPT) -t $(TARGET) -p $(PROTO) -f $(FORCE_IP) -n $(HOPS)