const std = @import("std");

/// This is taken from std.log's example of what
/// a logging function might look like
pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    //const scope_prefix = "(" ++ switch (scope) {
    //    .default => @tagName(scope),
    //    else => return,
    //} ++ "): ";
    const scope_prefix = "(" ++ @tagName(scope) ++ "): ";

    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    const held = std.debug.getStderrMutex().acquire();
    defer held.release();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}

pub fn argType(comptime func: anytype, comptime index: usize) type {
    return @typeInfo(@TypeOf(func)).Fn.args[index].arg_type.?;
}

pub fn castCEnum(comptime c_func: anytype, comptime arg_pos: usize, enum_value: c_int) argType(c_func, arg_pos) {
    return @intToEnum(argType(c_func, arg_pos), enum_value);
}

/// Casts a C pointer to a zig pointer including
/// align casting properly. Should only be used
/// when it's known that the types are abi compatible
pub fn cast_from_cptr(comptime T: type, ptr: anytype) T {
    return @ptrCast(T, @alignCast(@alignOf(T), ptr));
}
