const std = @import("std");
const cli = @import("cli");

var config = struct {
    port: u16 = undefined,
    interface: []const u8 = undefined,
}{};

// std.log.info("Ethernet Header Dest MAC: {x}", .{buf[0..6]});
// std.log.info("Ethernet Header Source MAC: {x}", .{buf[6..12]});
// std.log.info("Ethernet Header Ethertype: {x}", .{buf[12..14]});
// std.log.info("Ethernet Header Payload: {x}", .{buf[14..]});
const EthernetFrame = extern struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    ethertype: [2]u8,
    payload: [4082]u8,
};

const Ipv4Frame = extern struct {
    version_and_ihl: u8,
    type_of_service: u8,
    total_length: u8,
    identification: [2]u8,
    flags_and_fragment_offset: [2]u8,
    ttl: u8,
    protocol: u8,
    header_checksum: [2]u8,
    src_ip: [4]u8,
    dst_ip: [4]u8,
};

pub fn main(init: std.process.Init) !void {
    var r = cli.AppRunner.init(&init);
    defer r.deinit();

    const app = cli.App{
        .command = cli.Command{
            .name = "zigdump",
            .options = try r.allocOptions(&.{
                .{
                    .long_name = "port",
                    .help = "port to listen to",
                    .required = true,
                    .value_ref = r.mkRef(&config.port),
                },
                .{
                    .long_name = "interface",
                    .help = "interface to listen to",
                    .required = true,
                    .value_ref = r.mkRef(&config.interface),
                },
            }),
            .target = cli.CommandTarget{
                .action = cli.CommandAction{ .exec = run },
            },
        },
    };
    return r.run(&app);
}

fn run() !void {
    std.log.info("listening on :{d}", .{config.port});

    // Get the socket fd
    const socket_result = std.os.linux.socket(std.os.linux.AF.PACKET, std.os.linux.SOCK.RAW, std.mem.nativeToBig(u32, 0x0003));
    const errno = std.posix.errno(socket_result);
    const errno_int = @intFromEnum(errno);
    if (errno_int != 0) {
        std.log.info("errno: {d}", .{errno_int});
    }

    std.log.info("socket_result: {d}", .{socket_result});
    const socket_fd: i32 = @intCast(socket_result);

    // get interface
    var ifr = std.mem.zeroes(std.os.linux.ifreq);
    @memcpy(ifr.ifrn.name[0..config.interface.len], config.interface);

    const interface_res = std.os.linux.ioctl(socket_fd, std.os.linux.SIOCGIFINDEX, @intFromPtr(&ifr));
    if (interface_res < 0) return error.IoctlFailed;

    const if_index = ifr.ifru.ivalue;
    std.log.info("Interface: {d}", .{if_index});

    // populate a sockaddr.ll
    var ll = std.mem.zeroes(std.posix.sockaddr.ll);
    ll.family = std.os.linux.AF.PACKET;
    ll.ifindex = if_index;
    ll.protocol = std.mem.nativeToBig(u16, @intCast(std.os.linux.ETH.P.ALL));

    // bind the socket to that ll
    const bind_res = std.os.linux.bind(socket_fd, @ptrCast(&ll), @sizeOf(std.posix.sockaddr.ll));
    std.log.info("bind result: {d}", .{bind_res});

    var buf: [4096]u8 = undefined;

    while (true) {
        const n = try std.posix.read(socket_fd, &buf);
        std.log.info("Bytes Read: {d}", .{n});
        std.log.info("Packet: {x}", .{buf[0..n]});

        // First should be the Ethernet II frame (14 bytes)
        // var eth_header: [14]u8 = undefined;
        // if (n < @sizeOf(EthernetFrame)) break;

        const e_pkt = @as(EthernetFrame, @bitCast(buf[0..@sizeOf(EthernetFrame)].*));

        // switch on ethertype
        // if 0x0800
        const ethertype = std.mem.readInt(u16, &e_pkt.ethertype, .big);
        if (ethertype == 0x0800) {
            std.log.info("IPv4 Packet:", .{});
            // const version = (e_pkt.payload[0] >> 4 & 0x0F);
            // const ihl = (e_pkt.payload[0] & 0x0F);

            const ip_frame = @as(Ipv4Frame, @bitCast(e_pkt.payload[0..@sizeOf(Ipv4Frame)].*));
            std.log.info("version: {d}", .{ip_frame.version_and_ihl >> 4 & 0x0F});
            std.log.info("ihl: {d}", .{ip_frame.version_and_ihl & 0x0F});
            std.log.info("type of service: {x}", .{ip_frame.type_of_service});
            std.log.info("total length: {x}", .{ip_frame.total_length});
            std.log.info("identification: {x}", .{ip_frame.identification});
            std.log.info("flags and fragment offset: {x}", .{ip_frame.flags_and_fragment_offset});
            std.log.info("ttl: {x}", .{ip_frame.ttl});
            std.log.info("protocol: {x}", .{ip_frame.protocol});
            std.log.info("header checksum: {x}", .{ip_frame.header_checksum});

            const source_ip_int = std.mem.readInt(u32, &ip_frame.src_ip, .big);

            var source_ip_buf: [15]u8 = undefined;
            const src_ip = try bin_to_ip(source_ip_int, &source_ip_buf);

            std.log.info("Source IP: {s}", .{src_ip});

            const destination_ip_int = std.mem.readInt(u32, &ip_frame.dst_ip, .big);

            var destination_ip_buf: [15]u8 = undefined;
            const dst_ip = try bin_to_ip(destination_ip_int, &destination_ip_buf);

            std.log.info("Destination IP: {s}", .{dst_ip});
        }
        std.debug.print("\n", .{});
    }
}

pub fn bin_to_ip(bin_addr: u32, buf: []u8) ![]u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        (bin_addr >> 24) & 0xFF,
        (bin_addr >> 16) & 0xFF,
        (bin_addr >> 8) & 0xFF,
        bin_addr & 0xFF,
    });
}
