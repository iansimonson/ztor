const std = @import("std");
const zben = @import("zben");

const c = @import("c.zig");
const util = @import("util.zig");
const tor = @import("torrent.zig");
const msg = @import("messages.zig");

// Pretty log function and set level
// "Magic" root definitions
pub const log = util.log;
pub const log_level = std.log.Level.debug;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = &gpa.allocator;
//const alloc = std.heap.c_allocator;

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

    var tc = tor.TorrentContext.initWithTorrent(alloc, peer_id, torrent);
    defer tc.deinit();

    // Set up the libuv loop
    const loop = c.uv_default_loop();
    loop.?.*.data = @ptrCast(?*c_void, alloc);

    try tc.start(loop);

    _ = c.uv_run(loop, util.castCEnum(c.uv_run, 1, c.UV_RUN_DEFAULT));
    _ = c.uv_run(loop, util.castCEnum(c.uv_run, 1, c.UV_RUN_DEFAULT)); // to finish closing things
}
