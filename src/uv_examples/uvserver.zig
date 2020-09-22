const std = @import("std");
const util = @import("util.zig");
const uv_util = @import("uv_util.zig");
const c = @import("uv_c.zig").c;
pub const log = util.log;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = &gpa.allocator;

const DEFAULT_PORT = 3000;
const DEFAULT_BACKLOG = 128;

pub fn main() !void {
    uv_util.init(alloc);
    defer _ = gpa.deinit();

    const loop = c.uv_default_loop();
    var addr: c.sockaddr_in = undefined;

    var server: c.uv_tcp_t = undefined;
    _ = c.uv_tcp_init(loop, &server);

    server.data = @ptrCast(?*c_void, loop);

    _ = c.uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &addr);

    _ = c.uv_tcp_bind(&server, @ptrCast(?*const c.sockaddr, &addr), 0);
    const r = c.uv_listen(@ptrCast(?*c.uv_stream_t, &server), DEFAULT_BACKLOG, on_new_connection);
    if (r != 0) {
        std.log.err("Listen error {}", .{c.uv_strerror(r)});
        return error.listen_error;
    }
    _ = c.uv_run(loop, util.castCEnum(c.uv_run, 1, c.UV_RUN_DEFAULT));

    std.log.info("Closing...", .{});
}

export fn on_new_connection(server: ?*c.uv_stream_t, status: i32) void {
    if (status < 0) {
        std.log.err("New connection error {}", .{c.uv_strerror(status)});
        return;
    }

    var client = alloc.create(c.uv_tcp_t) catch {
        std.log.err("Error allocating client", .{});
        return;
    };
    errdefer alloc.destroy(client);

    const loop = util.cast_from_cptr(*c.uv_loop_t, server.?.data);
    _ = c.uv_tcp_init(loop, client);
    if (c.uv_accept(server, @ptrCast(?*c.uv_stream_t, client)) == 0) {
        _ = c.uv_read_start(@ptrCast(?*c.uv_stream_t, client), uv_util.alloc_buffer, echo_read);
    } else {
        _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
    }
}

export fn echo_read(client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    std.debug.assert(client != null);
    std.debug.assert(buf != null);

    if (nread < 0) {
        if (nread == c.UV_EOF) {
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
        }
    } else if (nread > 0) {
        var req = alloc.create(uv_util.WriteReq) catch unreachable;
        const buf_data = alloc.dupe(u8, buf.?.base[0..@intCast(usize, nread)]) catch unreachable;
        std.log.info("< {s}", .{buf_data});
        req.buf = c.uv_buf_init(buf_data.ptr, @intCast(u32, buf_data.len));
        _ = c.uv_write(&req.req, client, &req.buf, 1, uv_util.on_write);
    }

    if (buf.?.base != null) {
        alloc.free(buf.?.base[0..buf.?.len]);
    }
}
