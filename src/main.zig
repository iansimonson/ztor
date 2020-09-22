const std = @import("std");
const zben = @import("zben");
const uri = @import("uri");
const c = @cImport({
    @cInclude("http-parser/http_parser.h");
    @cInclude("uv.h");
});

const util = @import("util.zig");

// Pretty log function and set level
// "Magic" root definitions
pub const log = util.log;
pub const log_level = std.log.Level.info;

/// This is a zig stub that is the same size
/// as http_parser which, since it has a bitfield
/// cannot be translated properly.
/// It's also used for accessing the fields
/// directly such as `data`
const http_parser_sized = extern struct {
    bitfield: u32,
    nread: u32,
    content_length: u64,
    http_major: u8,
    http_minor: u8,
    bitfield_2: u32,
    data: *c_void,
};

const Peer = struct {
    ip: [4]u8,
    port: u16,
};

const PeerConnection = struct {
    peer: Peer,
    choked: bool = true,
    interested: bool = false,
    connection: std.fs.File,

    pub fn init(peer: Peer, connection: std.fs.File) @This() {
        return .{
            .peer = peer,
            .choked = true,
            .interested = false,
            .connection = connection,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.connection.close();
    }
};

// TODO - make this so we can download multiple files
//const ActiveTorrent = struct {
//    connections: ConnectionList,
//};

const ConnectionList = std.ArrayList(PeerConnection);

const TRACKER_GET_REQUEST_FORMAT = "GET {}?peer_id={}&" ++ "info_hash={}&" ++
    "port={}&uploaded={}&downloaded={}&" ++
    "compact=1&left={} HTTP/1.1\r\nHost: {}\r\n\r\n";

/// Consists of
/// - Magic: 0x13
/// - "BitTorrent protocol"
/// - 8 bytes of 0s
/// - 20 byte sha1 hash of the info data
/// - 20 byte peer id reported by the tracker
const HANDSHAKE_REQUEST_FORMAT = "\x13BitTorrent protocol" ++ ("\x00" ** 8) ++ "{:20}{:20}";

const HEARTBEAT_FORMAT = "";

// Message Type + Optional payload
const MESSAGE_FORMAT = "{}" ++ "{}";

const MessageType = enum(u8) {
    choke = 0,
    unchoke,
    interested,
    not_interested,
    have,
    bitfield,
    request,
    piece,
    cancel,
};

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = &gpa.allocator;

const TorrentFile = struct {
    announce: []const u8,
    info: Info,
};

const Info = struct {
    name: []const u8,
    piece_length: usize,
    pieces: []const [20]u8,
    files: std.ArrayList(FInfo),
};

const FInfo = struct {
    name: []const u8,
    length: usize,
};

pub fn main() !void {
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len != 3 and args.len != 2) {
        std.log.err("Usage: ztor <torrent> [file/dirname]", .{});
        return error.invalid_arguments;
    }

    const fname = args[1];
    const file = try std.fs.cwd().openFile(fname, .{ .read = true });
    const file_data = try file.readToEndAlloc(alloc, std.math.maxInt(usize));

    var hash_buffer = [_]u8{undefined} ** 20;
    const info = file_data[447 .. file_data.len - 1];
    std.crypto.hash.Sha1.hash(info[0..], hash_buffer[0..], .{});
    std.log.info("First char: {s}", .{util.slice_front(info)});
    std.log.info("Last char: {s}", .{util.slice_back(info)});
    std.log.info("Hash: {s}", .{hash_buffer});
    std.log.info("Hash as hex: {x}", .{hash_buffer});

    var parser = zben.Parser.initWithData(alloc, file_data);
    defer parser.deinit();

    var tree = try parser.parse();
    defer tree.deinit();

    var torrent = try make_torrent(tree);
    defer torrent.info.files.deinit();

    std.log.info("Torrent File: {}", .{torrent});
    std.log.info("Made up of {} {}", .{
        torrent.info.files.items.len,
        if (torrent.info.files.items.len == 1) "file" else "file",
    });
    for (torrent.info.files.items) |item| {
        std.log.info("File:{} - Size: {Bi}", .{ item.name, item.length });
    }

    // Open listening torrent port
    var listener = std.net.StreamServer.init(.{});
    defer listener.deinit();
    try listener.listen(std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 6881));

    var announce = try uri.parse(torrent.announce);

    const host = announce.host.?;
    const port = announce.port orelse 80;

    std.log.info("Announce Host: {}", .{host});
    std.log.info("Announce port: {}", .{port});
    std.log.info("URI Path: {}", .{announce.path.?});

    var rnd_buf = [_]u8{undefined} ** 16;
    try std.crypto.randomBytes(rnd_buf[0..]);
    const peer_id = try std.fmt.allocPrint(alloc, "ZTOR{s}", .{rnd_buf});
    const escaped_hash = try uri.escapeString(alloc, hash_buffer[0..]);
    const escaped_peer_id = try uri.escapeString(alloc, peer_id);

    const formated_request = try std.fmt.allocPrint(alloc, TRACKER_GET_REQUEST_FORMAT, .{
        announce.path.?,
        escaped_peer_id[0..],
        escaped_hash[0..],
        6881,
        0,
        0,
        torrent.info.files.items[0].length,
        host,
    });

    std.log.info("Formatted request: {s}", .{formated_request});

    std.log.info("Connecting to announce server...", .{});

    if (false) {
        var connection = try std.net.tcpConnectToHost(alloc, host, port);
        defer connection.close();
        try connection.writeAll(formated_request[0..]);

        var recv_buffer = [_]u8{undefined} ** 4096;
        const read = try connection.readAll(recv_buffer[0..]);

        std.log.info("Downloaded {} bytes", .{read});
        std.log.info("Data received:\n{}", .{recv_buffer[0..read]});
    }
    var peer_list = std.ArrayList(Peer).init(alloc);

    if (false) {
        var settings: c.http_parser_settings = undefined;
        settings.on_message_begin = ignore_A;
        settings.on_message_complete = ignore_A;
        settings.on_headers_complete = ignore_A;
        settings.on_status = ignore_B;
        settings.on_url = ignore_B;
        settings.on_header_field = ignore_B;
        settings.on_header_value = ignore_B;
        settings.on_body = recv_body;
        settings.on_chunk_header = ignore_A;
        settings.on_chunk_complete = ignore_A;
        var http_parser: *c.http_parser = @ptrCast(*c.http_parser, try alloc.create(http_parser_sized));
        var as_sized = util.cast_from_cptr(*http_parser_sized, http_parser);
        as_sized.data = @ptrCast(*c_void, &peer_list);
        defer alloc.destroy(util.cast_from_cptr(*http_parser_sized, http_parser));
        c.http_parser_init(http_parser, c.enum_http_parser_type.HTTP_RESPONSE);

        // not sure what to do with nparsed
        const nparsed = c.http_parser_execute(http_parser, &settings, recv_buffer[0..read].ptr, read);
        std.log.info("DONE DONE DONE", .{});
    }

    try peer_list.append(Peer{
        .ip = [4]u8{ 127, 0, 0, 1 },
        .port = 9000,
    });

    for (peer_list.items) |peer| {
        std.log.info("Found: Peer{{ .ip = {d}.{d}.{d}.{d}, .port = {}}}", .{ peer.ip[0], peer.ip[1], peer.ip[2], peer.ip[3], peer.port });
    }

    // Connect to each peer
    // Send handshakes
    // Recv handshakes - close connections which fail this
    var connections = ConnectionList.init(alloc);
    defer connections.deinit();

    var poll_fds_list = std.ArrayList(std.os.pollfd).init(alloc);
    defer poll_fds_list.deinit();

    for (peer_list.items) |peer, i| {
        const addr = std.net.Address.initIp4(peer.ip, peer.port);
        var f = tcpConnectToAddress(addr) catch |e| {
            std.log.warn("Could not connect to peer {}.{}.{}.{}:{} - {}", .{
                peer.ip[0], peer.ip[1], peer.ip[2], peer.ip[3], peer.port, e,
            });
            continue;
        };
        errdefer f.close();
        connections.append(PeerConnection.init(peer, f)) catch |e| {
            std.log.err("Error adding peer connection to list: {}", .{e});
            return e;
        };
        poll_fds_list.append(std.os.pollfd{
            .fd = f.handle,
            .events = std.os.POLLOUT | std.os.POLLIN,
            .revents = 0,
        }) catch |e| {
            std.log.err("Error adding peer connection to write list: {}", .{e});
            return e;
        };

        std.log.info("Writing to peer..", .{});
        const buf = try std.fmt.allocPrint(alloc, HANDSHAKE_REQUEST_FORMAT, .{ hash_buffer[0..], peer_id[0..] });
        defer alloc.free(buf);
        var to_write = buf[0..];
        while (true) {
            if (to_write.len == 0) {
                break;
            }
            const ready = std.os.poll(poll_fds_list.items, 0) catch {
                std.log.info("Socket not ready...", .{});
                continue;
            };
            if (ready == 0) {
                continue;
            }
            const len: usize = std.os.write(f.handle, to_write) catch |e| blk: {
                switch (e) {
                    error.WouldBlock => break :blk 0,
                    else => return e,
                }
            };

            to_write.ptr += len;
            to_write.len -= len;
        }
        std.log.info("Wrote to peer..", .{});
        //f.writer().print() catch |e| {
        //    std.log.err("Error writing handshake to peer - {}", .{e});
        //    f.close();
        //    _ = connections.pop();
        //};
        //const r = try f.reader().read();
    }
}

export fn recv_body(p: ?*c.http_parser, data: [*c]const u8, len: usize) callconv(.C) c_int {
    if (p == null) return 1;
    var as_sized = @ptrCast(*http_parser_sized, @alignCast(@alignOf(*http_parser_sized), p.?));
    var peer_list = @ptrCast(*std.ArrayList(Peer), @alignCast(@alignOf(*std.ArrayList(Peer)), as_sized.data));
    var parser = zben.Parser.initWithData(alloc, data[0..len]);
    defer parser.deinit();

    var tree = parser.parse() catch return 1;
    defer tree.deinit();

    // TODO: switch on String or List in case the return is not the compact form
    var peers_blob = (tree.root.Dictionary.get("peers") orelse return 1).String;
    const peer_size = 6; // by definition
    if (@mod(peers_blob.len, peer_size) != 0) return 1;

    const num_peers = @divTrunc(peers_blob.len, peer_size);
    var i: usize = 0;
    while (i < num_peers) : (i += 1) {
        const offset = i * peer_size;
        var peer: Peer = undefined;
        var u16_buf = [2]u8{ undefined, undefined };
        std.mem.copy(u8, peer.ip[0..], data[offset .. offset + 4]);
        std.mem.copy(u8, u16_buf[0..], data[offset + 4 .. offset + 6]);
        peer.port = std.mem.bigToNative(u16, std.mem.bytesAsValue(u16, &u16_buf).*);

        peer_list.append(peer) catch return 1;
    }

    return 0;
}

export fn ignore_A(p: ?*c.http_parser) callconv(.C) c_int {
    return 0;
}

export fn ignore_B(parser: ?*c.http_parser, data: [*c]const u8, len: usize) callconv(.C) c_int {
    return 0;
}

fn make_torrent(tree: zben.BencodeTree) !TorrentFile {
    const top_level = &tree.root.Dictionary;
    var torrent: TorrentFile = undefined;
    torrent.announce = (top_level.get("announce") orelse return error.invalid_dictionary).String;
    const info = (top_level.get("info") orelse return error.invalid_dictionary).Dictionary;
    torrent.info.name = (info.get("name") orelse return error.invalid_dictionary).String;
    torrent.info.piece_length = @intCast(usize, (info.get("piece length") orelse return error.invalid_dictionary).Integer);
    const str = (info.get("pieces") orelse return error.invalid_dictionary).String;
    torrent.info.pieces.ptr = @ptrCast([*]const [20]u8, str.ptr);
    torrent.info.pieces.len = str.len / 20;

    torrent.info.files = std.ArrayList(FInfo).init(alloc);
    errdefer torrent.info.files.deinit();
    if (info.get("length")) |len| {
        try torrent.info.files.append(.{ .name = torrent.info.name, .length = @intCast(usize, len.Integer) });
    } else if (info.get("files")) |files| {
        for (files.List.items) |file| {
            const name = (file.Dictionary.get("path") orelse return error.invalid_dictionary).String;
            const len = @intCast(usize, (file.Dictionary.get("length") orelse return error.invalid_dictionary).Integer);
            try torrent.info.files.append(.{ .name = name, .length = @intCast(usize, len) });
        }
    } else {
        return error.invalid_dictionary;
    }

    return torrent;
}

fn printValue(v: zben.Value) void {
    switch (v) {
        .Empty => std.log.warn("Got an empty value somehow", .{}),
        .Integer => |i| std.log.info("Integer: {}", .{i}),
        .String => |s| std.log.info("String: {}", .{s}),
        .List => |l| {
            std.log.info("LIST:", .{});
            for (l.items) |item| {
                printValue(item);
            }
        },
        .Dictionary => |d| {
            std.log.info("DICT:", .{});
            var iter = d.iterator();
            while (iter.next()) |entry| {
                std.log.info("KEY: {}", .{entry.key});
                printValue(entry.value);
            }
        },
    }
}

/// Override of std.net.tcpConnectToAddress so we can do non-blocking io ourselves
fn tcpConnectToAddress(address: std.net.Address) !std.fs.File {
    const nonblock = std.os.SOCK_NONBLOCK;
    const sock_flags = std.os.SOCK_STREAM | nonblock |
        (if (std.builtin.os.tag == .windows) 0 else std.os.SOCK_CLOEXEC);
    const sockfd = try std.os.socket(address.any.family, sock_flags, std.os.IPPROTO_TCP);
    errdefer std.os.close(sockfd);
    std.os.connect(sockfd, &address.any, address.getOsSockLen()) catch |e| {
        switch (e) {
            error.WouldBlock => {},
            else => {
                return e;
            },
        }
    };

    return std.fs.File{ .handle = sockfd };
}
