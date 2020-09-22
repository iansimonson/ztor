const std = @import("std");
const util = @import("util.zig");
const uv_util = @import("uv_util.zig");
const c = uv_util.c;

pub const log = util.log;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = &gpa.allocator;

const DEFAULT_PORT = 3000;

const data = "HELLO FROM CLIENT!";

pub fn main() !void {
    uv_util.init(alloc);
    defer _ = gpa.deinit();

    const loop = c.uv_default_loop();
    var addr: c.sockaddr_in = undefined;

    var client: c.uv_tcp_t = undefined;
    _ = c.uv_tcp_init(loop, &client);
    client.data = @ptrCast(?*c_void, loop);

    _ = c.uv_ip4_addr("127.0.0.1", DEFAULT_PORT, &addr);

    const connect = try alloc.create(c.uv_connect_t);

    _ = c.uv_tcp_connect(connect, &client, @ptrCast(?*const c.sockaddr, &addr), on_connect);

    //_ = c.uv_tcp_bind(&server, @ptrCast(?*const c.sockaddr, &addr), 0);
    //const r = c.uv_listen(@ptrCast(?*c.uv_stream_t, &server), DEFAULT_BACKLOG, on_new_connection);
    //if (r != 0) {
    //    std.log.err("Listen error {}", .{c.uv_strerror(r)});
    //    return error.listen_error;
    //}
    _ = c.uv_run(loop, util.castCEnum(c.uv_run, 1, c.UV_RUN_DEFAULT));

    std.log.info("Closing...", .{});
}

export fn on_connect(con: ?*c.uv_connect_t, status: i32) void {
    var req = alloc.create(uv_util.WriteReq) catch unreachable;
    std.log.info("> {s}", .{data});
    const to_send = alloc.dupe(u8, data) catch unreachable;
    req.buf = c.uv_buf_init(to_send.ptr, @intCast(u32, to_send.len));
    _ = c.uv_write(&req.req, con.?.handle, &req.buf, 1, uv_util.on_write);
    _ = c.uv_read_start(con.?.handle, uv_util.alloc_buffer, on_read);
    alloc.destroy(con.?);
}

export fn on_read(client: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    std.debug.assert(client != null);
    std.debug.assert(buf != null);

    if (nread < 0) {
        if (nread == c.UV_EOF) {
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
        }
    } else if (nread > 0) {
        std.log.info("< {s}", .{buf.?.base[0..buf.?.len]});
        _ = c.uv_close(@ptrCast(?*c.uv_handle_t, client), null);
    }

    if (buf.?.base != null) {
        alloc.free(buf.?.base[0..buf.?.len]);
    }
}
