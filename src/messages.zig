const std = @import("std");

const c = @import("c.zig");
const util = @import("util.zig");

const log = std.log.scoped(.messages);

pub const WriteCallback = fn (handle: ?*c.uv_write_t, status: i32, buffer: ?*c.uv_buf_t) callconv(.C) void;
pub const AllocCallback = fn (handle: ?*c.uv_handle_t, size: usize, buf: ?*c.uv_buf_t) callconv(.C) void;
pub const ReadCallback = fn (handle: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) callconv(.C) void;

const WriteReq = struct {
    req: c.uv_write_t,
    buf: c.uv_buf_t,
    alloc: *std.mem.Allocator,
    callback: ?WriteCallback,
};

/// Write data to a given stream
/// Does _not_ take ownership of the data slice
/// The data slice must be freed in the callback
pub fn write(
    allocator: *std.mem.Allocator,
    data: []u8,
    stream: anytype,
    callback: ?WriteCallback,
) !void {
    comptime {
        if (!util.is_pointer(@TypeOf(stream))) {
            @compileLog(@TypeOf(stream));
            @compileError("Stream must be a pointer type");
        }
    }

    var req = try allocator.create(WriteReq);
    errdefer allocator.destroy(req);

    req.buf = c.uv_buf_init(data.ptr, @intCast(u32, data.len));
    req.alloc = allocator;
    req.callback = callback;
    const result = c.uv_write(
        &req.req,
        @ptrCast(?*c.uv_stream_t, stream),
        &req.buf,
        1,
        write_finish,
    );

    if (result < 0) {
        return error.write_error;
    }
}

/// A wrapper function to free the `WriteReq` and make it unnecessary
/// to leak that data structure
export fn write_finish(req: ?*c.uv_write_t, status: i32) void {
    const write_req = @fieldParentPtr(WriteReq, "req", req.?);
    if (write_req.callback) |callback| {
        callback(req, status, &write_req.buf);
    }
    write_req.alloc.destroy(write_req);
}

pub fn read_start(stream: anytype, alloc_cb: AllocCallback, read_cb: ReadCallback) !void {
    comptime {
        if (!util.is_pointer(@TypeOf(stream))) {
            @compileLog(@TypeOf(stream));
            @compileError("Stream must be a pointer type");
        }
    }

    const result = c.uv_read_start(@ptrCast(?*c.uv_stream_t, stream), alloc_cb, read_cb);
    if (result < 0) {
        return error.stream_read_error;
    }
}

pub const COMPACT_PEER_LEN: usize = 6;

pub const KEEP_ALIVE = "\x00\x00\x00\x00";

const MSG_LEN = "{:4}";

const UNCHOKE = MSG_LEN ++ "\x01";
const INTERESTED = MSG_LEN ++ "\x02";
const REQUEST = MSG_LEN ++ "\x06{:4}{:4}{:4}";

pub const TRACKER_GET_REQUEST_FORMAT = "GET {}?peer_id={}&" ++ "info_hash={}&" ++
    "port={}&uploaded={}&downloaded={}&" ++
    "compact=1&left={} HTTP/1.1\r\nHost: {}\r\n\r\n";

/// Consists of
/// - Magic: 0x13
/// - "BitTorrent protocol"
/// - 8 bytes of 0s
/// - 20 byte sha1 hash of the info data
/// - 20 byte peer id reported by the tracker
const HANDSHAKE_REQUEST_FORMAT = "\x13BitTorrent protocol" ++ ("\x00" ** 8) ++ "{:20}{:20}";

pub const HANDSHAKE_LENGTH = 68;

pub const HEARTBEAT_FORMAT = "";

// Message Type + Optional payload
pub const MESSAGE_FORMAT = "{}" ++ "{}";

pub const MessageType = enum(u8) {
    choke,
    unchoke,
    interested,
    not_interested,
    have,
    bitfield,
    request,
    piece,
    cancel,
    keep_alive,
};

/// Create the handshake message for a particular torrent
/// User must free the memory at some point
/// Use this rather than trying to format directly to not get
/// the ordering wrong of peer_id and info_hash
pub fn make_handshake(alloc: *std.mem.Allocator, peer_id: []const u8, info_hash: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, HANDSHAKE_REQUEST_FORMAT, .{ info_hash, peer_id });
}

pub fn make_unchoke(alloc: *std.mem.Allocator) ![]u8 {
    const msg_len = std.mem.nativeToBig(u32, 1);
    return std.fmt.allocPrint(alloc, UNCHOKE, .{std.mem.asBytes(&msg_len)});
}

pub fn make_interested(alloc: *std.mem.Allocator) ![]u8 {
    const msg_len = std.mem.nativeToBig(u32, 1);
    return std.fmt.allocPrint(alloc, INTERESTED, .{std.mem.asBytes(&msg_len)});
}

pub fn make_request(alloc: *std.mem.Allocator, index: usize, offset: usize, length: usize) ![]u8 {
    const msg_len = (1 + @sizeOf(u32) * 3);
    const msg_len_big = std.mem.nativeToBig(u32, msg_len);
    const idx_big = std.mem.nativeToBig(u32, @intCast(u32, index));
    const offset_big = std.mem.nativeToBig(u32, @intCast(u32, offset));
    const length_big = std.mem.nativeToBig(u32, @intCast(u32, length));
    return std.fmt.allocPrint(alloc, REQUEST, .{
        std.mem.asBytes(&msg_len_big),
        std.mem.asBytes(&idx_big),
        std.mem.asBytes(&offset_big),
        std.mem.asBytes(&length_big),
    });
}

fn validate_handshake(msg: []const u8, info_hash: []const u8) bool {
    return msg.len >= HANDSHAKE_LENGTH;
}

pub fn consume_handshake(msg: []const u8, info_hash: []const u8) ![]const u8 {
    if (!validate_handshake(msg, info_hash)) {
        return error.invalid_handshake;
    }

    return msg[0..HANDSHAKE_LENGTH];
}

pub const Message = struct {
    total_size: u32,
    message_type: MessageType,
    data: []const u8,

    pub fn number(self: Message, comptime T: type, offset: usize) T {
        var num = [_]u8{undefined} ** @sizeOf(T);
        std.mem.copy(u8, num[0..], self.data[offset .. offset + @sizeOf(T)]);
        return std.mem.bigToNative(T, std.mem.bytesToValue(T, num[0..]));
    }
};

/// Consume a message
/// throws away the size field if
/// a complete message exists
/// Errors on invalid data
pub fn consume_message(data: []const u8) !?Message {
    var d = data[0..];
    if (d.len < 4) {
        return null;
    }

    const size = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, d[0..4]));
    d = d[4..];

    // Keep alive message - only consume size
    if (size == 0) {
        return Message{
            .total_size = 4,
            .message_type = .keep_alive,
            .data = d[0..size],
        };
    }

    // we don't have enough from the stream
    if (d.len < size) {
        return null;
    }

    const msg_type = message_type(d[0]);
    if (msg_type) |t| {
        return Message{
            .total_size = size + 4,
            .message_type = t,
            .data = d[1..size],
        };
    } else {
        return error.unknown_msg_type;
    }
}

pub fn message_type(char: u8) ?MessageType {
    if (char > std.meta.fields(MessageType).len - 1) {
        return null;
    }

    return @intToEnum(MessageType, char);
}
