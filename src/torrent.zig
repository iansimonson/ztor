const std = @import("std");
const zben = @import("zben");

const util = @import("util.zig");

const log = std.log.scoped(.torrent);

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

pub const Peer = struct {
    ip: [4]u8,
    port: u16,
};
