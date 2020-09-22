const std = @import("std");
const zben = @import("zben");
const uri = @import("uri");
const c = @cImport({
    @cInclude("http-parser/http_parser.h");
    @cInclude("uv.h");
});

const util = @import("util.zig");
const tor = @import("torrent.zig");
const msg = @import("messages.zig");

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

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = &gpa.allocator;

var peer_id: []const u8 = undefined;

pub fn main() !void {
    defer _ = gpa.deinit();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len != 3 and args.len != 2) {
        std.log.err("Usage: ztor <torrent> [file/dirname]", .{});
        return error.invalid_arguments;
    }

    // Immediately set up peer-id
    peer_id = try tor.make_peer_id(alloc);
    defer alloc.free(peer_id);

    const fname = args[1];
    const file = try std.fs.cwd().openFile(fname, .{ .read = true });
    const file_data = try file.readToEndAlloc(alloc, std.math.maxInt(usize));
    defer alloc.free(file_data);

    var hash_buffer = [_]u8{undefined} ** 20;
    try tor.calculate_info_hash(file_data[0..], hash_buffer[0..]);

    std.log.info("Hash as hex: {x}", .{hash_buffer});

    var parser = zben.Parser.initWithData(alloc, file_data);
    defer parser.deinit();

    var tree = try parser.parse();
    defer tree.deinit();

    var torrent = try tor.make_torrent(alloc, tree);
    // TODO - this needs to be better
    torrent.info_hash = hash_buffer[0..];
    defer torrent.deinit();

    std.log.info("Torrent File: {}", .{torrent});
    std.log.info("Made up of {} {}", .{
        torrent.info.files.items.len,
        if (torrent.info.files.items.len == 1) "file" else "file",
    });
    for (torrent.info.files.items) |item| {
        std.log.info("File:{} - Size: {Bi}", .{ item.name, item.length });
    }

    // Open listening torrent port
    var announce = try uri.parse(torrent.announce);

    const host = announce.host.?;
    const port = announce.port orelse 80;

    std.log.info("Announce Host: {}", .{host});
    std.log.info("Announce port: {}", .{port});
    std.log.info("URI Path: {}", .{announce.path.?});

    const escaped_hash = try uri.escapeString(alloc, hash_buffer[0..]);
    defer alloc.free(escaped_hash);
    const escaped_peer_id = try uri.escapeString(alloc, peer_id);
    defer alloc.free(escaped_peer_id);

    const formated_request = try std.fmt.allocPrint(alloc, msg.TRACKER_GET_REQUEST_FORMAT, .{
        announce.path.?,
        escaped_peer_id[0..],
        escaped_hash[0..],
        6881,
        0,
        0,
        torrent.info.files.items[0].length,
        host,
    });
    defer alloc.free(formated_request);

    std.log.info("Formatted request: {s}", .{formated_request});

    std.log.info("Connecting to announce server...", .{});

    var connection = try std.net.tcpConnectToHost(alloc, host, port);
    defer connection.close();
    try connection.writeAll(formated_request[0..]);

    var recv_buffer = [_]u8{undefined} ** 4096;
    const read = try connection.readAll(recv_buffer[0..]);

    std.log.info("Downloaded {} bytes", .{read});
    std.log.info("Data received:\n{}", .{recv_buffer[0..read]});
    var peer_list = std.ArrayList(tor.Peer).init(alloc);
    defer peer_list.deinit();

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

    // Set up the libuv loop
    const loop = c.uv_default_loop();
    loop.?.*.data = @ptrCast(?*c_void, alloc);

    // Default is max 50 peers so lets go with 100 for now
    var connections = try std.ArrayList(PeerConnection).initCapacity(alloc, 100);
    defer connections.deinit();

    try peer_list.resize(0);
    peer_list.appendAssumeCapacity(tor.Peer{ .ip = [_]u8{ 141, 239, 102, 196 }, .port = 6881 });
    for (peer_list.items) |peer| {
        std.log.info("Found: Peer{{ .ip = {d}.{d}.{d}.{d}, .port = {}}}", .{
            peer.ip[0],
            peer.ip[1],
            peer.ip[2],
            peer.ip[3],
            peer.port,
        });

        connections.appendAssumeCapacity(PeerConnection{
            .peer = peer,
            .connection = undefined,
            .torrent = &torrent,
        });
        var peer_con = &util.slice_back(connections.items)[0];
        _ = c.uv_tcp_init(loop, &peer_con.connection);
        peer_con.connection.data = @ptrCast(?*c_void, peer_con);
        std.log.info("peer_con ptr: {*}", .{peer_con});

        var addr: c.sockaddr_in = undefined;
        const addr_name = try std.fmt.allocPrint0(alloc, "{}.{}.{}.{}", .{
            peer.ip[0],
            peer.ip[1],
            peer.ip[2],
            peer.ip[3],
        });
        defer alloc.free(addr_name);
        _ = c.uv_ip4_addr(addr_name.ptr, peer.port, &addr);

        std.log.info("Connecting to: {}", .{addr_name});
        const connect = try alloc.create(c.uv_connect_t);
        connect.data = @ptrCast(?*c_void, peer_con);
        _ = c.uv_tcp_connect(connect, &peer_con.connection, @ptrCast(?*const c.sockaddr, &addr), on_connect_peer);
    }

    _ = c.uv_run(loop, util.castCEnum(c.uv_run, 1, c.UV_RUN_DEFAULT));
}

export fn recv_body(p: ?*c.http_parser, data: [*c]const u8, len: usize) callconv(.C) c_int {
    if (p == null) return 1;
    var as_sized = @ptrCast(*http_parser_sized, @alignCast(@alignOf(*http_parser_sized), p.?));
    var peer_list = @ptrCast(*std.ArrayList(tor.Peer), @alignCast(@alignOf(*std.ArrayList(tor.Peer)), as_sized.data));
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
        var peer: tor.Peer = undefined;
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

/// Metadata about a particular peer
/// we are connected to for a particular torrent
/// Note: Torrent is NON-OWNING as each
/// peer has a reference to the same torrent
const PeerConnection = struct {
    peer: tor.Peer,
    choked: bool = true,
    interested: bool = false,
    hand_shook: bool = false,
    connection: c.uv_tcp_t,
    torrent: *tor.TorrentFile,
};

/// Start handshaking with peer on successful connection
export fn on_connect_peer(con: ?*c.uv_connect_t, status: i32) void {
    const peer_con = util.cast_from_cptr(*PeerConnection, con.?.handle.?.*.data);
    std.log.info("peer_con ptr: {}", .{con.?.handle.?.*.data});
    if (status < 0) {
        std.log.err("Error connecting to peer: {}.{}.{}.{}:{} - {s}", .{
            peer_con.peer.ip[0],
            peer_con.peer.ip[1],
            peer_con.peer.ip[2],
            peer_con.peer.ip[3],
            peer_con.peer.port,
            c.uv_strerror(status),
        });
        alloc.destroy(con.?);
        return;
    }
    std.log.info("Successfully connected to peer: {}.{}.{}.{}:{}", .{
        peer_con.peer.ip[0],
        peer_con.peer.ip[1],
        peer_con.peer.ip[2],
        peer_con.peer.ip[3],
        peer_con.peer.port,
    });
    var req = alloc.create(WriteReq) catch unreachable;
    var to_send = msg.make_handshake(alloc, peer_id, peer_con.torrent.info_hash) catch unreachable;
    req.buf = c.uv_buf_init(to_send.ptr, @intCast(u32, to_send.len));
    std.log.info("Sent peer - {s}", .{to_send});
    _ = c.uv_write(&req.req, con.?.handle, &req.buf, 1, on_write);
    _ = c.uv_read_start(con.?.handle, alloc_buffer, on_read_handshake);
    alloc.destroy(con.?);
}

/// Allocates a buffer for libuv to use
export fn alloc_buffer(handle: ?*c.uv_handle_t, suggested_size: usize, buf: ?*c.uv_buf_t) void {
    std.debug.assert(buf != null);
    std.debug.assert(handle != null);

    if (buf) |b| {
        var data = alloc.alloc(u8, suggested_size) catch {
            std.log.err("Error allocating buffer on callback", .{});
            b.* = c.uv_buf_init(null, 0);
            return;
        };

        b.* = c.uv_buf_init(data.ptr, @intCast(u32, suggested_size));
    }
}

/// Function to free buffers allocated by alloc_buffer
/// This is a callback after successfully sending bytes down
/// the wire
/// TODO: errors?
export fn on_write(req: ?*c.uv_write_t, status: i32) void {
    const write_req = @fieldParentPtr(WriteReq, "req", req.?);
    alloc.free(write_req.buf.base[0..write_req.buf.len]);
    alloc.destroy(write_req);
}

export fn on_read_handshake(client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    const peer_con = util.cast_from_cptr(*PeerConnection, client.?.data);
    std.log.info("Got response from peer: {}.{}.{}.{}:{}", .{
        peer_con.peer.ip[0],
        peer_con.peer.ip[1],
        peer_con.peer.ip[2],
        peer_con.peer.ip[3],
        peer_con.peer.port,
    });

    if (nread < 0) {
        if (nread == c.UV_EOF) {
            std.log.warn("Peer disconnected. Closing handle...", .{});
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
        }
    } else if (nread > 0) {
        if (nread < 68) {
            std.log.err("Error, handshake not large enough - {} bytes", .{nread});
        }
        std.log.info("Handshake: {}", .{buf.?.base[0..68]});
        std.log.info("Rest in hex: {x}", .{buf.?.base[68..@intCast(usize, nread)]});
    }

    // TODO: actually check the handshake
    // But for now assume we're good to go
    _ = c.uv_read_start(client, alloc_buffer, on_read);
    if (buf.?.base != null) {
        alloc.free(buf.?.base[0..buf.?.len]);
    }
}

/// Read data, client should have already gone through handshake callback
/// This handles the dispatching of messages
export fn on_read(client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    std.debug.assert(client != null);
    std.debug.assert(buf != null);

    if (nread < 0) {
        if (nread == c.UV_EOF) {
            std.log.warn("Peer disconnected. Closing handle...", .{});
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
        }
    } else if (nread > 0) {
        const peer_con = util.cast_from_cptr(*PeerConnection, client.?.data);
        std.log.info("Got message from peer: {}.{}.{}.{}:{}", .{
            peer_con.peer.ip[0],
            peer_con.peer.ip[1],
            peer_con.peer.ip[2],
            peer_con.peer.ip[3],
            peer_con.peer.port,
        });
        std.log.info("Received {} bytes - {}", .{ nread, buf.?.base[0..@intCast(usize, nread)] });
    }
    //} else if (nread > 0) {
    //    const peer_con = util.cast_from_cptr(*PeerConnection, client.?.data);
    //    _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
    //}

    _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
    if (buf.?.base != null) {
        alloc.free(buf.?.base[0..buf.?.len]);
    }
}

const WriteReq = struct {
    req: c.uv_write_t,
    buf: c.uv_buf_t,
};
