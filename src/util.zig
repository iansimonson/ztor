const std = @import("std");

var log_file: ?std.fs.File = null;

/// This is taken from std.log's example of what
/// a logging function might look like
pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (log_file == null) {
        log_file = std.fs.cwd().createFile("ztor.log", .{}) catch unreachable;
    }
    //const scope_prefix = "(" ++ switch (scope) {
    //    .default => @tagName(scope),
    //    else => return,
    //} ++ "): ";
    const scope_prefix = "(" ++ @tagName(scope) ++ "): ";
    const end_color = "\x1b[0m";
    const color = switch (level) {
        .warn => "\x1b[93m",
        .err => "\x1b[91m",
        else => end_color,
    };

    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    log_file.?.writer().print(color ++ prefix ++ format ++ "\n" ++ end_color, args) catch return;
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
pub fn slice_back(data: anytype) @TypeOf(data) {
    return data[data.len - 1 .. data.len];
}

/// Returns the first item in a slice as a slice of length 1
pub fn slice_front(data: anytype) @TypeOf(data) {
    return data[0..1];
}

fn is_(comptime T: type, comptime type_enum: @Type(.EnumLiteral)) bool {
    return switch (@typeInfo(T)) {
        type_enum => true,
        .Optional => |o| {
            return is_(o.child, type_enum);
        },
        else => false,
    };
}

pub fn is_pointer(comptime T: type) bool {
    return is_(T, .Pointer);
}
