const std = @import("std");
const c = @import("c.zig");

pub const WriteReq = struct {
    req: c.uv_write_t,
    buf: c.uv_buf_t,
};

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

/// Consume a message
/// throws away the size field if
/// a complete message exists
pub fn consume_message(data: []const u8) ?[]const u8 {
    if (data.len < 4) {
        return null;
    }

    const size = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, data[0..4]));
    if (data[4..].len < size) {
        return null;
    }

    return data[4 .. 4 + size];
}

pub fn message_type(char: u8) ?MessageType {
    if (char > std.meta.fields(MessageType).len) {
        return null;
    }

    return @intToEnum(MessageType, char);
}
