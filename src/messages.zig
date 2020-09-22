const std = @import("std");

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

pub const HEARTBEAT_FORMAT = "";

// Message Type + Optional payload
pub const MESSAGE_FORMAT = "{}" ++ "{}";

pub const MessageType = enum(u8) {
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

/// Create the handshake message for a particular torrent
/// User must free the memory at some point
/// Use this rather than trying to format directly to not get
/// the ordering wrong of peer_id and info_hash
pub fn make_handshake(alloc: *std.mem.Allocator, peer_id: []const u8, info_hash: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, HANDSHAKE_REQUEST_FORMAT, .{ info_hash, peer_id });
}