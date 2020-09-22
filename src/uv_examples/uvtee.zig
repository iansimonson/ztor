const std = @import("std");
const c = @cImport({
    @cInclude("uv.h");
});

const util = @import("util.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = &gpa.allocator;

var stdin_pipe: c.uv_pipe_t = undefined;
var stdout_pipe: c.uv_pipe_t = undefined;
var file_pipe: c.uv_pipe_t = undefined;

// Read parts
export fn alloc_buffer(handle: ?*c.uv_handle_t, suggested_size: usize, buf: ?*c.uv_buf_t) void {
    std.debug.assert(buf != null);
    buf.?.* = c.uv_buf_init((alloc.alloc(u8, suggested_size) catch unreachable).ptr, @intCast(u32, suggested_size));
}

export fn read_stdin(stream: ?*c.uv_stream_t, nread: isize, buf: ?*const c.uv_buf_t) void {
    std.debug.assert(stream != null);
    std.debug.assert(buf != null);

    if (nread < 0) {
        if (nread == c.UV_EOF) {
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &stdin_pipe), null);
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &stdout_pipe), null);
            _ = c.uv_close(@ptrCast(?*c.uv_handle_t, &file_pipe), null);
        }
    } else if (nread > 0) {
        write_data(@ptrCast(?*c.uv_stream_t, &stdout_pipe), @intCast(u32, nread), buf.?.*, on_stdout_write);
        write_data(@ptrCast(?*c.uv_stream_t, &file_pipe), @intCast(u32, nread), buf.?.*, on_file_write);
    }

    if (buf.?.base != null) {
        alloc.free(buf.?.base[0..buf.?.len]);
    }
}

// Write parts
const WriteReq = extern struct {
    req: c.uv_write_t,
    buf: c.uv_buf_t,
};

fn free_write_req(req: *c.uv_write_t) void {
    const write_req = @fieldParentPtr(WriteReq, "req", req);
    alloc.free(write_req.buf.base[0..write_req.buf.len]);
    alloc.destroy(write_req);
}

export fn on_stdout_write(req: ?*c.uv_write_t, status: i32) void {
    if (req) |r| {
        free_write_req(r);
    }
}

const on_file_write = on_stdout_write;

export fn write_data(dest: ?*c.uv_stream_t, size: u32, buf: c.uv_buf_t, cb: c.uv_write_cb) void {
    std.debug.assert(size > 0);
    var req = alloc.create(WriteReq) catch unreachable;
    req.buf = c.uv_buf_init((alloc.alloc(u8, @intCast(usize, size)) catch unreachable).ptr, size);
    std.mem.copy(u8, req.buf.base[0..size], buf.base[0..size]);
    _ = c.uv_write(&req.req, @ptrCast(?*c.uv_stream_t, dest), &req.buf, 1, cb);
}

pub fn main() !void {
    defer _ = gpa.deinit();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len != 2) {
        std.log.warn("Usage: uv_test <outfile>", .{});
        return error.missing_args;
    }

    const fname = try alloc.dupeZ(u8, args[1]);
    defer alloc.free(fname);

    const loop = c.uv_default_loop();

    _ = c.uv_pipe_init(loop, &stdin_pipe, 0);
    defer _ = c.uv_loop_close(c.uv_default_loop());

    _ = c.uv_pipe_open(&stdin_pipe, 0);

    _ = c.uv_pipe_init(loop, &stdout_pipe, 0);
    _ = c.uv_pipe_open(&stdout_pipe, 1);

    var file_req: c.uv_fs_t = undefined;
    var fd = c.uv_fs_open(loop, &file_req, fname.ptr, c.O_CREAT | c.O_RDWR, 0o644, null);
    std.log.info("Opened fd: {d}", .{fd});
    _ = c.uv_pipe_init(loop, &file_pipe, 0);
    _ = c.uv_pipe_open(&file_pipe, fd);

    _ = c.uv_read_start(@ptrCast(*c.uv_stream_t, &stdin_pipe), alloc_buffer, read_stdin);

    _ = c.uv_run(loop, util.castCEnum(c.uv_run, 1, c.UV_RUN_DEFAULT));
}
