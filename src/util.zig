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

/// Given a function and an index returns the type
/// of the argument at position index
/// e.g. given fn foo(handle: Handle, value: Value) void
/// argType(foo, 0) -> Handle
/// argType(foo, 1) -> Value
pub fn argType(comptime func: anytype, comptime index: usize) type {
    return @typeInfo(@TypeOf(func)).Fn.args[index].arg_type.?;
}

/// Useful for translated-c enums where a function
/// is expecting `.cimport:x:y.enum.unnamed_enum_Z
/// but the values have been translated as e.g. i32s
/// to operate on other c functions
pub fn castCEnum(comptime c_func: anytype, comptime arg_pos: usize, enum_value: c_int) argType(c_func, arg_pos) {
    return @intToEnum(argType(c_func, arg_pos), enum_value);
}

/// Casts a C pointer to a zig pointer including
/// align casting properly. Should only be used
/// when it's known that the types are abi compatible
pub fn cast_from_cptr(comptime T: type, ptr: anytype) T {
    return @ptrCast(T, @alignCast(@alignOf(T), ptr));
}

/// Returns the last item in a slice as a slice of length 1
pub fn slice_back(data: []const u8) []const u8 {
    return data[data.len - 1 .. data.len];
}

/// Returns the first item in a slice as a slice of length 1
pub fn slice_front(data: []const u8) []const u8 {
    return data[0..1];
}
