# zigdump
A lower resolution clone of tcpdump written in Zig.

## Usage
```bash
sudo zigdump --port 80 --interface eno1 
```

--interface: the interface name that you wish to listen to traffic on

**note: port currently doesn't have any impact**

Example output:
```bash
info: Bytes Read: XX
info: Packet: XXXXXXXX
info: IPv4 Packet:
info: Version: 4
info: IHL: 5
info: Type of Service: 0
info: Total Length: 0034
info: Identification: XXXX
info: Flags and Fragment Offset: 4000
info: TTL: 57
info: Protocol: 06
info: Header Checksum: XXXX
info: Source IP: XXX.XXX.XXX.XXX
info: Destination IP: XXX.XXX.XXX.XXX
```
