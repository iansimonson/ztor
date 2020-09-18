const std = @import("std");
const Builder = @import("std").build.Builder;
//var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var buffer = [_]u8{0} ** 4194304;
var fba = std.heap.FixedBufferAllocator.init(buffer[0..]);
const alloc = &fba.allocator;

pub fn build(b: *Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const ensure_lib_dir_exists = b.addSystemCommand(
        &[_][]const u8{
            "mkdir",
            "-p",
            "./zig-cache/lib",
        },
    );
    const ensure_include_dir_exists = b.addSystemCommand(
        &[_][]const u8{
            "mkdir",
            "-p",
            "./zig-cache/include/http-parser",
        },
    );
    const build_http_parser_c = b.addSystemCommand(
        &[_][]const u8{
            "make",
            "-C",
            "./deps/http-parser",
            "package",
        },
    );
    build_http_parser_c.step.dependOn(&ensure_include_dir_exists.step);
    build_http_parser_c.step.dependOn(&ensure_lib_dir_exists.step);
    const install_http_parser_lib = b.addSystemCommand(
        &[_][]const u8{
            "cp",
            "./deps/http-parser/libhttp_parser.a",
            "./zig-cache/lib/libhttp_parser.a",
        },
    );
    install_http_parser_lib.step.dependOn(&build_http_parser_c.step);
    const install_http_parser_headers = b.addSystemCommand(
        &[_][]const u8{
            "cp",
            "./deps/http-parser/http_parser.h",
            "./zig-cache/include/http-parser/http_parser.h",
        },
    );
    install_http_parser_headers.step.dependOn(&build_http_parser_c.step);

    const exe = b.addExecutable("ztor", "src/main.zig");
    exe.addPackagePath("zben", "./deps/zben/src/main.zig");
    //exe.addPackagePath("url", "./deps/url/src/url.zig");
    exe.addPackagePath("uri", "./deps/zig-uri/uri.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addLibPath("./zig-cache/lib/");
    exe.addIncludeDir("./zig-cache/include");
    exe.linkSystemLibraryName("http_parser");
    exe.linkLibC();
    exe.install();
    exe.step.dependOn(&install_http_parser_lib.step);
    exe.step.dependOn(&install_http_parser_headers.step);

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
