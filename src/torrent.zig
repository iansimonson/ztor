const std = @import("std");
const zben = @import("zben");
const uri = @import("uri");

const c = @import("c.zig");
const util = @import("util.zig");
const msg = @import("messages.zig");

const log = std.log.scoped(.torrent);

const Allocator = std.mem.Allocator;
const ConnectionList = std.ArrayList(*PeerConnection);
const WorkQueue = std.fifo.LinearFifo(usize, .Dynamic);

fn getTorrentContext(handle: anytype) *TorrentContext {
    return util.cast_from_cptr(*TorrentContext, handle.?.*.data);
}

export fn onConnectTrackerFwd(connection: ?*c.uv_connect_t, status: i32) void {
    const tc = getTorrentContext(connection.?.handle);
    defer tc.allocator.destroy(connection.?);
    if (status < 0) {
        log.warn("Error connecting to tracker - {}", .{c.uv_strerror(status)});
        return;
    }

    tc.onConnectTracker();
}

export fn onWriteAnnounceFwd(req: ?*c.uv_write_t, status: i32, buf: ?*c.uv_buf_t) void {
    std.debug.assert(buf != null);

    const tc = getTorrentContext(req.?.handle);
    tc.allocator.free(buf.?.base[0..buf.?.len]);
}

export fn onReadAnnounceFwd(handle: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    std.debug.assert(buf != null);
    const tc = getTorrentContext(handle);

    tc.onReadAnnounce(handle, nread, buf);
}

export fn tcAllocBuffer(handle: ?*c.uv_handle_t, suggested_size: usize, buf: ?*c.uv_buf_t) void {
    std.debug.assert(buf != null);
    std.debug.assert(handle != null);

    const tc = getTorrentContext(handle);
    var data = tc.tracker_read_stream.writableWithSize(suggested_size) catch {
        log.err("Error allocating memory for tracker download", .{});
        buf.?.* = c.uv_buf_init(null, 0);
        return;
    };

    buf.?.* = c.uv_buf_init(data.ptr, @intCast(u32, suggested_size));
}

export fn http_ignore(p: ?*c.http_parser) callconv(.C) c_int {
    return 0;
}

export fn http_ignore_data(parser: ?*c.http_parser, data: [*c]const u8, len: usize) callconv(.C) c_int {
    return 0;
}

export fn http_tracker_parse_body(p: ?*c.http_parser, data: [*c]const u8, len: usize) callconv(.C) c_int {
    if (p == null) return 1;
    var as_sized = util.cast_from_cptr(?*c.http_parser_sized, p);
    const tc = getTorrentContext(as_sized);

    var parser = zben.Parser.initWithData(tc.allocator, data[0..len]);
    defer parser.deinit();

    var tree = parser.parse() catch return 1;
    defer tree.deinit();

    var peers_blob = switch (tree.root.Dictionary.get("peers") orelse return 1) {
        .String => |s| s,
        else => {
            log.err("Peers returned in non-compact form. TODO: Implement non-compact form", .{});
            return 1;
        },
    };
    if (@mod(peers_blob.len, msg.COMPACT_PEER_LEN) != 0) return 1;

    var iter = PeerIter{ .data = peers_blob };

    while (iter.next()) |peer| {
        tc.addPeer(peer);
    }

    return 0;
}

const CompletePiece = struct {
    index: usize,
    buffer: []u8,
    read_length: usize,
};

/// Manages an torrent, both uploading and downloading
/// as well as writing out to file. Contains all the context
/// necessary for a given torrent.
/// Note there is no concurrency here so each TorrentContext
/// should be managed by at most one `loop` / thread
pub const TorrentContext = struct {
    allocator: *Allocator,
    peer_id: []const u8,
    loop: *c.uv_loop_t,
    torrent: TorrentFile,
    // Peers we're actively established with
    connected_peers: ConnectionList,
    // Peers which we are not connected to
    inactive_peers: ConnectionList,
    completed_pieces: std.ArrayList(CompletePiece),
    to_write_piece: usize = 0,
    output_file_pipe: c.uv_pipe_t,
    output_filed: c.uv_file,
    work_queue: WorkQueue,
    have_bitfield: PeerConnection.Bitfield,

    tracker_connection: c.uv_tcp_t,
    timer: c.uv_timer_t,
    tracker_read_stream: std.fifo.LinearFifo(u8, .Dynamic),
    inflight_file_pieces: usize = 0,

    pub fn init(alloc: *Allocator, peer_id: []const u8) @This() {
        return .{
            .allocator = alloc,
            .peer_id = peer_id,
            .loop = undefined,
            .torrent = undefined,
            .connected_peers = ConnectionList.init(alloc),
            .inactive_peers = ConnectionList.init(alloc),
            .completed_pieces = std.ArrayList(CompletePiece).init(alloc),
            .output_file_pipe = undefined,
            .output_filed = undefined,
            .work_queue = WorkQueue.init(alloc),
            .have_bitfield = PeerConnection.Bitfield.init(alloc),
            .tracker_connection = undefined,
            .timer = undefined,
            .tracker_read_stream = std.fifo.LinearFifo(u8, .Dynamic).init(alloc),
        };
    }

    pub fn initWithTorrent(allocator: *Allocator, peer_id: []const u8, torrent: TorrentFile) @This() {
        return .{
            .allocator = allocator,
            .peer_id = peer_id,
            .loop = undefined,
            .torrent = torrent,
            .connected_peers = ConnectionList.init(allocator),
            .inactive_peers = ConnectionList.init(allocator),
            .completed_pieces = std.ArrayList(CompletePiece).init(allocator),
            .output_file_pipe = undefined,
            .output_filed = undefined,
            .work_queue = WorkQueue.init(allocator),
            .have_bitfield = PeerConnection.Bitfield.init(allocator),
            .tracker_connection = undefined,
            .timer = undefined,
            .tracker_read_stream = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
        };
    }

    const Progress = struct {
        current: usize,
        total: usize,
    };

    const bitcount_lookup = comptime blk: {
        var count: [256]u8 = std.mem.zeroes([256]u8);
        var i: u8 = 1;
        inline while (true) : (i +%= 1) {
            count[i] = count[@divTrunc(i, 2)] + (i & 1);
            if (i == 0) {
                break;
            }
        }

        break :blk count;
    };

    pub fn progress(self: @This()) Progress {
        var count: usize = 0;
        for (self.have_bitfield.items) |item| {
            count += bitcount_lookup[item];
        }
        return .{
            .current = count,
            .total = self.torrent.info.pieces.len,
        };
    }

    pub fn start(self: *@This(), loop: *c.uv_loop_t) !void {
        const total_pieces = self.torrent.info.pieces.len;
        const bytes_required = @divTrunc(total_pieces, 8) + 1;
        try self.have_bitfield.appendNTimes(0, bytes_required);

        self.loop = loop;
        _ = c.uv_tcp_init(loop, &self.tracker_connection);
        _ = c.uv_tcp_nodelay(&self.tracker_connection, 1);
        self.tracker_connection.data = @ptrCast(?*c_void, self);

        log.info("TorrentContext starting for {}", .{self.torrent.info.name});
        log.info("Torrent File: {}", .{self.torrent});
        log.info("Made up of {} {}", .{
            self.torrent.info.files.items.len,
            if (self.torrent.info.files.items.len == 1) "file" else "file",
        });
        for (self.torrent.info.files.items) |item| {
            log.info("File:{} - Size: {Bi}", .{ item.name, item.length });
        }

        // Open listening torrent port
        var announce = try uri.parse(self.torrent.announce);

        const host = announce.host.?;
        const port = announce.port orelse 80;

        log.info("Connecting to Announce at server {}:{}", .{ host, port });

        // OK so here we're being a bit lazy and resolving in a blocking manner
        const list = try std.net.getAddressList(self.allocator, host, port);
        defer list.deinit();

        const addr = list.addrs[0].in;

        const connect = try self.allocator.create(c.uv_connect_t);
        _ = c.uv_tcp_connect(
            connect,
            &self.tracker_connection,
            @ptrCast(?*const c.sockaddr, &addr.sa),
            onConnectTrackerFwd,
        );
    }

    pub fn onConnectTracker(self: *@This()) void {
        var announce = uri.parse(self.torrent.announce) catch unreachable;
        log.info("Successfully connected to tracker for {}", .{self.torrent.info.name});
        log.info("Sending announce request", .{});
        log.debug("URI Path: {}", .{announce.path.?});

        const escaped_hash = uri.escapeString(self.allocator, self.torrent.info_hash[0..]) catch unreachable;
        defer self.allocator.free(escaped_hash);
        const escaped_peer_id = uri.escapeString(self.allocator, self.peer_id) catch unreachable;
        defer self.allocator.free(escaped_peer_id);

        // TODO - fix uploaded/downloaded/left so we can "resume" a torrent
        const formated_request = std.fmt.allocPrint(self.allocator, msg.TRACKER_GET_REQUEST_FORMAT, .{
            announce.path.?,
            escaped_peer_id[0..],
            escaped_hash[0..],
            6881,
            0,
            0,
            self.torrent.info.files.items[0].length,
            announce.host.?,
        }) catch unreachable;

        msg.write(self.allocator, formated_request, &self.tracker_connection, onWriteAnnounceFwd) catch |e| {
            log.warn("Error connecting to tracker. Shutting down", .{});
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.tracker_connection), null);
            return;
        };
        msg.read_start(&self.tracker_connection, tcAllocBuffer, onReadAnnounceFwd) catch |e| {
            log.warn("Error reading from stream", .{});
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.tracker_connection), null);
        };
    }

    pub fn onReadAnnounce(self: *@This(), handle: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
        if (nread < 0) {
            if (nread == c.UV_EOF) {
                self.parsePeers();
                var i: usize = 0;
                while (i < self.torrent.info.pieces.len) : (i += 1) {
                    self.work_queue.writeItem(i) catch unreachable;
                }
                self.beginDownload();
                log.warn("Tracker disconnected. Closing handle", .{});
                _ = c.uv_close(@ptrCast(?*c.uv_handle_t, handle), null);
            }
        } else if (nread > 0) {
            // we're just going to buffer the tracker info until read is done
            self.tracker_read_stream.update(@intCast(usize, nread));
        }
    }

    fn parsePeers(self: *@This()) void {
        var settings: c.http_parser_settings = undefined;
        settings.on_message_begin = http_ignore;
        settings.on_message_complete = http_ignore;
        settings.on_headers_complete = http_ignore;
        settings.on_status = http_ignore_data;
        settings.on_url = http_ignore_data;
        settings.on_header_field = http_ignore_data;
        settings.on_header_value = http_ignore_data;
        settings.on_body = http_tracker_parse_body;
        settings.on_chunk_header = http_ignore;
        settings.on_chunk_complete = http_ignore;
        var http_parser: *c.http_parser = @ptrCast(*c.http_parser, self.allocator.create(c.http_parser_sized) catch unreachable);
        var as_sized = util.cast_from_cptr(*c.http_parser_sized, http_parser);
        as_sized.data = @ptrCast(*c_void, self);
        defer self.allocator.destroy(util.cast_from_cptr(*c.http_parser_sized, http_parser));
        c.http_parser_init(http_parser, c.enum_http_parser_type.HTTP_RESPONSE);

        const data = self.tracker_read_stream.readableSlice(0);
        // not sure what to do with nparsed
        const nparsed = c.http_parser_execute(http_parser, &settings, data.ptr, data.len);
        self.tracker_read_stream.discard(data.len);
    }

    pub fn deinit(self: *@This()) void {
        for (self.connected_peers.items) |peer| {
            peer.deinit();
            self.allocator.destroy(peer);
        }

        for (self.inactive_peers.items) |peer| {
            peer.deinit();
            self.allocator.destroy(peer);
        }
        self.connected_peers.deinit();
        self.inactive_peers.deinit();
        self.completed_pieces.deinit();
        self.tracker_read_stream.deinit();
        self.work_queue.deinit();
        self.have_bitfield.deinit();
    }

    /// Adds a peer if it has not already been added
    /// It is not a failure to re-add a peer
    /// the duplciate is ignored
    pub fn addPeer(self: *@This(), peer: Peer) void {
        const id = peer.id();
        for (self.connected_peers.items) |p| {
            if (p.peer.id() == id) {
                log.debug("Duplicate peer {} found. Ignoring", .{peer});
                return;
            }
        }

        for (self.inactive_peers.items) |p| {
            if (p.peer.id() == id) {
                log.debug("Duplicate peer {} found. Ignoring", .{peer});
                return;
            }
        }

        const total_pieces = self.torrent.info.pieces.len;
        const bytes_required = @divTrunc(total_pieces, 8) + 1;
        log.info("Bytes length for bitfield is: {}", .{bytes_required});
        var pc = self.allocator.create(PeerConnection) catch unreachable;
        pc.* = .{
            .peer = peer,
            .connection = undefined,
            .timer = undefined,
            .torrent = self,
            .stream_buffer = PeerConnection.Buffer.init(self.allocator),
            .bitfield = PeerConnection.Bitfield.initCapacity(self.allocator, bytes_required) catch unreachable,
            .piece_buffer = PeerConnection.Buffer.init(self.allocator),
        };
        pc.bitfield.appendNTimesAssumeCapacity(0, bytes_required);

        self.inactive_peers.append(pc) catch unreachable;
        log.info("Adding unique peer {}", .{peer});
    }

    /// What we need to do:
    /// 1. connect to a couple new peers
    /// 2. assign all piece work into the work queue
    /// 3. set up idler and timer for everyone
    fn beginDownload(self: *@This()) void {
        log.info("Beginning download for {}", .{self.torrent.info.name});
        _ = c.uv_timer_init(self.loop, &self.timer);
        self.timer.data = self;
        _ = c.uv_timer_start(&self.timer, on_torrent_timer, 100, 100);

        const name = self.allocator.dupeZ(u8, self.torrent.info.files.items[0].name) catch unreachable;
        defer self.allocator.free(name);
        var req: c.uv_fs_t = undefined;
        self.output_filed = c.uv_fs_open(self.loop, &req, name.ptr, c.O_CREAT | c.O_RDWR, 0o644, null);
        _ = c.uv_pipe_init(self.loop, &self.output_file_pipe, 0);
        self.output_file_pipe.data = self;
        _ = c.uv_pipe_open(&self.output_file_pipe, self.output_filed);

        for (self.inactive_peers.items) |peer| {
            _ = c.uv_tcp_init(self.loop, &peer.connection);
            _ = c.uv_tcp_nodelay(&peer.connection, 1);
            peer.connection.data = @ptrCast(?*c_void, peer);

            var addr: c.sockaddr_in = undefined;
            const addr_name = std.fmt.allocPrint0(self.allocator, "{}.{}.{}.{}", .{
                peer.peer.ip[0],
                peer.peer.ip[1],
                peer.peer.ip[2],
                peer.peer.ip[3],
            }) catch unreachable;
            defer self.allocator.free(addr_name);
            _ = c.uv_ip4_addr(addr_name.ptr, peer.peer.port, &addr);

            log.info("Connecting to peer - {}", .{peer.peer});
            const connect = self.allocator.create(c.uv_connect_t) catch unreachable;
            connect.data = @ptrCast(?*c_void, peer);
            _ = c.uv_tcp_connect(connect, &peer.connection, @ptrCast(?*const c.sockaddr, &addr), on_connect_peer);
            self.connected_peers.append(peer) catch unreachable;
        }

        self.inactive_peers.resize(0) catch unreachable;
    }

    pub fn checkFinished(self: *@This()) void {
        const work_done = self.work_queue.readableLength() == 0 and self.completed_pieces.items.len == 0 and self.inflight_file_pieces == 0;

        if (!work_done) {
            return;
        }

        for (self.connected_peers.items) |peer| {
            if (peer.current_work) |cw| {
                return;
            }
        }

        for (self.connected_peers.items) |peer| {
            peer.close();
        }
        _ = self.connected_peers.resize(0) catch unreachable;

        if (self.to_write_piece >= self.torrent.info.pieces.len) {
            _ = c.uv_timer_stop(&self.timer);
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.output_file_pipe), null);
        }
    }

    pub fn dispatchWork(self: *@This()) void {
        for (self.connected_peers.items) |item| {
            item.nextPiece();
        }
    }

    fn sort_by_index(ctx: *const @This(), lhs: CompletePiece, rhs: CompletePiece) bool {
        return lhs.index < rhs.index;
    }

    pub fn writePieces(self: *@This()) void {
        std.sort.sort(CompletePiece, self.completed_pieces.items, self, sort_by_index);

        for (self.completed_pieces.items) |item| {
            const idx = item.index;
            const byte_idx = @divTrunc(idx, 8);
            const bit_idx = (7 - @mod(idx, 8));
            self.have_bitfield.items[byte_idx] |= (std.math.shl(u8, 1, bit_idx));
        }

        while (self.completed_pieces.items.len > 0 and self.completed_pieces.items[0].index <= self.to_write_piece) {
            const item = &self.completed_pieces.items[0];
            if (item.index < self.to_write_piece) {
                _ = self.completed_pieces.orderedRemove(0);
                continue;
            }

            log.info("Writing piece {{index = {}, size = {Bi}}}", .{ item.index, item.read_length });
            const data = self.allocator.alloc(u8, item.read_length) catch unreachable;
            std.mem.copy(u8, data[0..], item.buffer[0..item.read_length]);
            msg.write(self.allocator, data, &self.output_file_pipe, on_file_write) catch |e| {
                log.warn("Error writing piece to file - {}", .{e});
                self.allocator.free(data);
                return;
            };

            self.allocator.free(item.buffer);
            _ = self.completed_pieces.orderedRemove(0);
            log.info("Wrote piece {}/{}", .{ self.to_write_piece, self.torrent.info.pieces.len - 1 });
            self.to_write_piece += 1;
            self.inflight_file_pieces += 1;
        }
    }
};

export fn on_file_write(req: ?*c.uv_write_t, status: i32, buf: ?*c.uv_buf_t) void {
    const tc = getTorrentContext(req.?.handle);
    tc.allocator.free(buf.?.base[0..buf.?.len]);
    tc.inflight_file_pieces -= 1;
}

export fn on_torrent_timer(timer: ?*c.uv_timer_t) void {
    const torrent = getTorrentContext(timer);
    torrent.writePieces();
    torrent.dispatchWork();
    torrent.checkFinished();

    const progress = torrent.progress();
    const stdout = std.io.getStdOut();
    stdout.writer().print("\rDownloaded {}/{} pieces", .{ progress.current, progress.total }) catch unreachable;
}

fn get_peer_connection(handle: anytype) *PeerConnection {
    std.debug.assert(handle != null);
    return util.cast_from_cptr(*PeerConnection, handle.?.*.data);
}

/// Metadata about a particular peer
/// we are connected to for a particular torrent
/// Note: Torrent is NON-OWNING as each
/// peer has a reference to the same torrent
const PeerConnection = struct {
    peer: Peer,
    choked: bool = true,
    interested: bool = false,
    hand_shook: bool = false,
    connection: c.uv_tcp_t,
    timer: c.uv_timer_t,
    torrent: *TorrentContext,
    // this is read-stream, do we need a write stream?
    stream_buffer: Buffer,
    bitfield: Bitfield,
    piece_buffer: Buffer,
    current_work: ?WorkData = null,

    const WorkData = struct {
        idx: usize,
        current_offset: usize,
        awaiting: u8,
    };

    pub const Buffer = std.fifo.LinearFifo(u8, .Dynamic);
    pub const Bitfield = std.ArrayList(u8);

    const keep_alive_timeout: usize = 45_000; // 45 seconds
    const piece_size: u32 = std.math.shl(u32, 1, 14);

    pub fn init(allocator: *Allocator) @This() {}

    pub fn deinit(self: *@This()) void {
        self.stream_buffer.deinit();
        self.bitfield.deinit();
        self.piece_buffer.deinit();
    }

    pub fn keepAlive(self: *@This()) void {
        // only send keepalive if we're active
        if (c.uv_is_active(@ptrCast(?*c.uv_handle_t, &self.connection)) == 0) {
            return;
        }

        const c_keep_alive = @intToPtr([*c]u8, @ptrToInt(msg.KEEP_ALIVE[0..]))[0..msg.KEEP_ALIVE.len];
        msg.write(self.torrent.allocator, c_keep_alive, &self.connection, null) catch |e| {
            log.warn("Could not write keep-alive to peer {}", .{self.peer});
        };
    }

    pub fn onConnect(self: *@This(), connection: ?*c.uv_connect_t, status: i32) void {
        const alloc = self.torrent.allocator;
        defer alloc.destroy(connection.?);
        if (status < 0) {
            log.warn("Error connecting to peer: {} - {s}", .{
                self.peer,
                c.uv_strerror(status),
            });
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.connection), on_close);
            return;
        }
        log.info("Successfully connected to peer: {}", .{self.peer});

        var handshake = msg.make_handshake(
            alloc,
            self.torrent.peer_id,
            self.torrent.torrent.info_hash,
        ) catch |e| {
            log.warn("Error allocating handshake for peer {}", .{self.peer});
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.connection), on_close);
            return;
        };

        msg.write(alloc, handshake, &self.connection, on_write) catch |e| {
            log.warn("Error sending handshake to peer {}", .{self.peer});
            alloc.free(handshake);
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.connection), on_close);
            return;
        };

        msg.read_start(&self.connection, alloc_buffer, on_read_handshake) catch |e| {
            log.warn("Error reading from stream for peer {}: {}", .{ self.peer, e });
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.connection), on_close);
        };
    }

    pub fn allocBuffer(self: *@This(), handle: ?*c.uv_handle_t, suggested_size: usize, buf: ?*c.uv_buf_t) void {
        var data = self.stream_buffer.writableWithSize(suggested_size) catch {
            log.err("Error allocating buffer on callback", .{});
            buf.?.* = c.uv_buf_init(null, 0);
            return;
        };

        buf.?.* = c.uv_buf_init(data.ptr, @intCast(u32, suggested_size));
    }

    pub fn onWrite(self: *@This(), handle: ?*c.uv_write_t, status: i32, buf: ?*c.uv_buf_t) void {
        self.torrent.allocator.free(buf.?.base[0..buf.?.len]);
    }

    pub fn close(self: *@This()) void {
        log.warn("Peer is closing...", .{});
        _ = c.uv_timer_stop(&self.timer);
        if (c.uv_is_active(@ptrCast(?*c.uv_handle_t, &self.connection)) != 0) {
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.connection), on_close);
        }
    }

    pub fn onClose(self: *@This(), handle: ?*c.uv_handle_t) void {
        log.info("Successfully closed connection to peer {}", .{self.peer});
        _ = c.uv_timer_stop(&self.timer);
        if (self.current_work) |cw| {
            self.torrent.work_queue.writeItem(cw.idx) catch unreachable;
        }

        self.current_work = null;
        self.choked = true;
        self.interested = false;
    }

    pub fn onHandshake(self: *@This(), client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
        log.info("Got response from peer: {}", .{self.peer});

        if (nread < 0) {
            if (nread == c.UV_EOF) {
                log.warn("Peer {} disconnected. Closing handle...", .{self.peer});
                _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), on_close);
            }
        } else if (nread > 0) {
            self.stream_buffer.update(@intCast(usize, nread));
            const data = self.stream_buffer.readableSlice(0);
            const handshake = msg.consume_handshake(data, self.torrent.torrent.info_hash) catch {
                // TODO be better
                log.err(
                    "Error validating handshake. Got: {x}",
                    .{data},
                );
                _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), on_close);
                return;
            };
            self.stream_buffer.discard(msg.HANDSHAKE_LENGTH);

            self.sendUnchoke() catch |e| {
                log.warn("Error sending unchoke to peer {}", .{self.peer});
                _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), on_close);
                return;
            };
            self.sendInterested() catch |e| {
                log.warn("Error sending interested to peer {}", .{self.peer});
                _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), on_close);
                return;
            };

            self.handleMessages();

            msg.read_start(client, alloc_buffer, on_read) catch |e| {
                log.warn("Error swapping read stream from handshake for peer {}: {}", .{ self.peer, e });
                _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), on_close);
                return;
            };

            // setup keepalive timer
            _ = c.uv_timer_init(self.torrent.loop, &self.timer);
            self.timer.data = @ptrCast(?*c_void, self);
            _ = c.uv_timer_start(&self.timer, keep_alive, keep_alive_timeout, keep_alive_timeout);
        }
    }

    pub fn onRead(self: *@This(), client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
        if (nread < 0) {
            if (nread == c.UV_EOF) {
                log.warn("Peer {} disconnected. Closing handle...", .{self.peer});
                _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), on_close);
                if (self.current_work) |cw| {
                    if (!piece_complete(cw, self.torrent.torrent.info.piece_length)) {
                        self.return_piece();
                    }
                }
            }
        } else if (nread > 0) {
            self.stream_buffer.update(@intCast(usize, nread));
            log.debug("Received {} more bytes from peer: {}", .{ nread, self.peer });
        }

        self.handleMessages();
    }

    fn sendUnchoke(self: *@This()) !void {
        var unchoke = msg.make_unchoke(self.torrent.allocator) catch unreachable;
        errdefer self.torrent.allocator.free(unchoke);
        try msg.write(self.torrent.allocator, unchoke, &self.connection, on_write);
    }

    fn sendInterested(self: *@This()) !void {
        var interested = msg.make_interested(self.torrent.allocator) catch unreachable;
        errdefer self.torrent.allocator.free(interested);
        try msg.write(self.torrent.allocator, interested, &self.connection, on_write);
    }

    fn handleMessages(self: *@This()) void {
        var data = self.stream_buffer.readableSlice(0);
        log.debug("Total stream to process {} bytes", .{data.len});
        //log.debug("Data: {x}", .{data});

        var consumed_bytes: usize = 0;
        const total_bytes = data.len;

        defer self.stream_buffer.discard(consumed_bytes);

        while (msg.consume_message(data) catch |e| {
            log.warn("Error - invalid message received from peer {}", .{self.peer});
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &self.connection), on_close);
            return;
        }) |message| {
            consumed_bytes += message.total_size;
            data = data[message.total_size..];

            log.debug("Processing msg - {}", .{message.message_type});

            switch (message.message_type) {
                .keep_alive => {},
                .choke => {
                    self.choked = true;
                    self.return_piece();
                },
                .unchoke => {
                    self.choked = false;
                },
                .interested => {},
                .not_interested => {},
                .have => {
                    const idx = message.number(u32, 0);
                    self.setIdx(idx);
                },
                .bitfield => { // basically a big "have" message
                    std.debug.assert(message.data.len <= self.bitfield.items.len);

                    for (message.data) |byte, i| {
                        self.bitfield.items[i] = byte;
                    }
                },
                .request => { // TODO actually implement uploading
                },
                .cancel => { // we're not uploading so whatever
                },
                .piece => { // Actually save the file
                    const idx = message.number(u32, 0);
                    const offset = message.number(u32, @sizeOf(u32));
                    var rest = message.data[@sizeOf(u32) + @sizeOf(u32) ..];
                    if (self.current_work) |*cw| {
                        if (cw.idx != idx) {
                            log.warn(
                                "Got a piece message for wrong piece - got {{idx = {}, offset = {}}} expected {}",
                                .{ idx, offset, cw.idx },
                            );
                            continue;
                        }
                        if (rest.len != piece_size) {
                            log.warn(
                                "Got a piece message with incorrect piece size - {b} vs {b}",
                                .{ rest.len, piece_size },
                            );
                        }
                        var write_to = self.piece_buffer.writableWithSize(rest.len) catch unreachable;
                        std.mem.copy(u8, write_to, rest);
                        self.piece_buffer.update(rest.len);

                        log.info("Peer {} Wrote Piece {{idx = {}, offset = {}}}", .{ self.peer, idx, offset });

                        cw.awaiting -= 1;

                        if (piece_complete(cw.*, self.torrent.torrent.info.piece_length)) {
                            log.info("Peer {} fully downloaded piece {}", .{ self.peer, cw.idx });
                            self.send_finished_piece();
                        }
                        self.nextPiece();
                    } else {
                        log.warn(
                            "Got a piece message with no current work for {{idx = {}, offset = {}}}",
                            .{ idx, offset },
                        );
                    }
                },
            }
        }
    }

    const max_pipelined_pieces: u8 = 5;

    fn piece_complete(work: WorkData, length: usize) bool {
        return work.awaiting == 0 and work.current_offset >= length;
    }

    fn send_finished_piece(self: *@This()) void {
        self.piece_buffer.realign();
        self.torrent.completed_pieces.append(.{
            .index = self.current_work.?.idx,
            .buffer = self.piece_buffer.buf,
            .read_length = self.piece_buffer.readableLength(),
        }) catch unreachable;
        self.current_work = null;
        self.piece_buffer = Buffer.init(self.torrent.allocator);
    }

    fn return_piece(self: *@This()) void {
        if (self.current_work) |cw| {
            log.debug("Peer {} returning piece {}", .{ self.peer, cw.idx });
            self.torrent.work_queue.writeItem(cw.idx) catch unreachable;
        }
        self.current_work = null;
        self.piece_buffer.discard(self.piece_buffer.readableLength());
    }

    fn nextPiece(self: *@This()) void {
        if (self.choked) {
            return;
        }

        if (self.current_work) |*cw| {
            // If we're already downloading do nothing
            log.debug("Peer {} working on piece {}", .{ self.peer, cw.* });
            // send 5 at a time, not just 5 then 1 after the other
            if (cw.awaiting > 0) {
                return;
            }

            while (cw.awaiting < max_pipelined_pieces and cw.current_offset < self.torrent.torrent.info.piece_length) {
                const amnt = std.math.min(piece_size, self.torrent.torrent.info.piece_length - cw.current_offset);
                var request = msg.make_request(self.torrent.allocator, cw.idx, cw.current_offset, amnt) catch unreachable;
                log.debug("Requesting next offset ({})", .{cw.current_offset});
                msg.write(self.torrent.allocator, request, &self.connection, on_write) catch |e| {
                    log.warn(
                        "Error requesting {{idx = {}, offset = {}}} from peer {}. Returning piece to queue - {}",
                        .{ cw.idx, cw.current_offset, self.peer, e },
                    );
                    self.torrent.work_queue.writeItem(cw.idx) catch unreachable;
                    self.current_work = null;
                    self.piece_buffer.deinit();
                    self.piece_buffer = Buffer.init(self.torrent.allocator);
                    return;
                };

                cw.awaiting += 1;
                cw.current_offset += piece_size;
            }
        } else {
            const idx = self.torrent.work_queue.readItem();

            if (idx) |i| {
                log.info("Grabbing a new piece - index: {}", .{i});
                if (!self.hasPiece(i)) {
                    self.torrent.work_queue.writeItem(i) catch unreachable;
                    return;
                }
                self.current_work = .{
                    .idx = i,
                    .current_offset = 0,
                    .awaiting = 0,
                };
                log.info("Successfully grabbed piece - sending request", .{});
                self.nextPiece();
            }
        }
    }

    fn setIdx(self: *@This(), idx: usize) void {
        const byte_idx = @divTrunc(idx, 8);
        const bit_idx = (7 - @mod(idx, 8));
        self.bitfield.items[byte_idx] |= (std.math.shl(u8, 1, bit_idx));
    }

    fn hasPiece(self: @This(), idx: usize) bool {
        const byte_idx = @divTrunc(idx, 8);
        const bit_idx = (7 - @mod(idx, 8));
        return (self.bitfield.items[byte_idx] & (std.math.shl(u8, 1, bit_idx))) != 0;
    }
};

pub const TorrentFile = struct {
    announce: []const u8,
    info: Info,
    info_hash: []const u8,

    pub fn deinit(self: *@This()) void {
        self.info.files.deinit();
    }
};

pub const Info = struct {
    name: []const u8,
    piece_length: usize,
    pieces: []const [20]u8,
    files: std.ArrayList(FInfo),
};

pub const FInfo = struct {
    name: []const u8,
    length: usize,
};

/// Generates a peer id for the ZTOR BitTorrent client
/// composed of ZTOR followed by 16 random characters
/// The string must be freed by the caller
pub fn make_peer_id(alloc: *std.mem.Allocator) ![]const u8 {
    var rnd_buf = [_]u8{undefined} ** 16;
    try std.crypto.randomBytes(rnd_buf[0..]);
    return std.fmt.allocPrint(alloc, "ZTOR{s}", .{rnd_buf});
}

pub fn make_torrent(alloc: *std.mem.Allocator, tree: zben.BencodeTree) !TorrentFile {
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

pub fn calculate_info_hash(data: []const u8, memory: []u8) !void {
    std.debug.assert(memory.len == 20);
    var l = zben.Lexer.initWithData(data);
    var offset: usize = 0;
    var begin_offset: usize = 0;
    var end_offset: usize = 0;
    var nested: usize = 0;
    var start_found: bool = false;
    while (l.next()) |token| {
        switch (token.token_type) {
            .string => {
                if (!start_found and std.mem.eql(u8, "info", token.data)) {
                    begin_offset = offset + token.data.len;
                    start_found = true;
                }
            },
            .end => {
                if (start_found) {
                    nested -= 1;
                    if (nested == 0) {
                        end_offset = offset + token.data.len;
                        break;
                    }
                }
            },
            .list_begin, .integer_begin, .dictionary_begin => {
                if (start_found) {
                    nested += 1;
                }
            },
            else => {},
        }

        offset += token.data.len;
    }

    if (!start_found or end_offset <= begin_offset) {
        return error.info_not_found;
    }

    const info_full = data[begin_offset..end_offset];
    log.debug("Full Dump:\n{}", .{info_full[0..]});
    log.debug("First char: {s}", .{util.slice_front(info_full)});
    log.debug("Last char: {s}", .{util.slice_back(info_full)});
    std.crypto.hash.Sha1.hash(info_full[0..], memory[0..], .{});
}

pub fn printValue(v: zben.Value) void {
    switch (v) {
        .Empty => log.warn("Got an empty value somehow", .{}),
        .Integer => |i| log.info("Integer: {}", .{i}),
        .String => |s| log.info("String: {}", .{s}),
        .List => |l| {
            log.info("LIST:", .{});
            for (l.items) |item| {
                printValue(item);
            }
        },
        .Dictionary => |d| {
            log.info("DICT:", .{});
            var iter = d.iterator();
            while (iter.next()) |entry| {
                log.info("KEY: {}", .{entry.key});
                printValue(entry.value);
            }
        },
    }
}

pub const PeerIter = struct {
    data: []const u8,

    const ip_len = 4;
    const port_len = 2;

    pub fn next(self: *@This()) ?Peer {
        if (self.data.len < msg.COMPACT_PEER_LEN) {
            return null;
        }

        var p = Peer{ .ip = undefined, .port = undefined };
        std.mem.copy(u8, p.ip[0..], self.data[0..ip_len]);
        p.port = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, self.data[ip_len .. ip_len + port_len]));
        self.data = self.data[msg.COMPACT_PEER_LEN..];
        return p;
    }
};

/// ipv4 peers only for now
/// TODO: ipv6?
pub const Peer = struct {
    ip: [4]u8,
    port: u16,
    empty: u16 = 0, // padding out to u64

    /// For fast compare we treat the peer as a u64
    pub fn id(self: @This()) u64 {
        return std.mem.bytesToValue(u64, std.mem.asBytes(&self));
    }

    pub fn format(peer: Peer, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("{}.{}.{}.{}:{}", .{
            peer.ip[0],
            peer.ip[1],
            peer.ip[2],
            peer.ip[3],
            peer.port,
        });
    }
};

export fn keep_alive(handle: ?*c.uv_timer_t) void {
    std.debug.assert(handle != null);

    const peer_con = get_peer_connection(handle);
    peer_con.keepAlive();
}

///// Start handshaking with peer on successful connection
export fn on_connect_peer(con: ?*c.uv_connect_t, status: i32) void {
    std.debug.assert(con != null);

    const peer_con = get_peer_connection(con.?.handle);
    peer_con.onConnect(con, status);
}

///// Allocates a buffer for libuv to use
export fn alloc_buffer(handle: ?*c.uv_handle_t, suggested_size: usize, buf: ?*c.uv_buf_t) void {
    std.debug.assert(buf != null);
    std.debug.assert(handle != null);

    const peer_con = get_peer_connection(handle);
    peer_con.allocBuffer(handle, suggested_size, buf);
}

///// This is a callback after successfully sending bytes down
///// the wire
export fn on_write(req: ?*c.uv_write_t, status: i32, buf: ?*c.uv_buf_t) void {
    std.debug.assert(req != null);

    const peer_con = get_peer_connection(req.?.handle);
    peer_con.onWrite(req, status, buf);
}

export fn on_close(client: ?*c.uv_handle_t) void {
    std.debug.assert(client != null);

    const peer_con = get_peer_connection(client);
    peer_con.onClose(client);
}

export fn on_read_handshake(client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    std.debug.assert(buf != null);

    const peer_con = get_peer_connection(client);
    peer_con.onHandshake(client, nread, buf);
}

/// Read data, client should have already gone through handshake callback
/// This handles the dispatching of messages
export fn on_read(client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    std.debug.assert(client != null);
    std.debug.assert(buf != null);

    const peer_con = get_peer_connection(client);
    peer_con.onRead(client, nread, buf);
}
