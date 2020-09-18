const std = @import("std");
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
    const scope_prefix = "(" ++ @tagName(scope) ++ "):";

    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;

    const held = std.debug.getStderrMutex().acquire();
    defer held.release();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}
