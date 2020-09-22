const std = @import("std");
pub const c = @import("uv_c.zig").c;

pub var alloc: *std.mem.Allocator = undefined;
var initialized: bool = false;

pub const WriteReq = struct {
    req: c.uv_write_t,
    buf: c.uv_buf_t,
};

pub fn init(allocator: *std.mem.Allocator) void {
    alloc = allocator;
    initialized = true;
}

/// Allocates a buffer for libuv to use
pub export fn alloc_buffer(handle: ?*c.uv_handle_t, suggested_size: usize, buf: ?*c.uv_buf_t) void {
    std.debug.assert(buf != null);
    std.debug.assert(handle != null);
    std.debug.assert(initialized);

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
pub export fn on_write(req: ?*c.uv_write_t, status: i32) void {
    std.debug.assert(initialized);
    const write_req = @fieldParentPtr(WriteReq, "req", req.?);
    alloc.free(write_req.buf.base[0..write_req.buf.len]);
    alloc.destroy(write_req);
}
