const std = @import("std");
const Builder = @import("std").build.Builder;
//var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var buffer = [_]u8{0} ** 4194304;
var fba = std.heap.FixedBufferAllocator.init(buffer[0..]);
const alloc = &fba.allocator;

fn build_http_parser(b: *Builder) *std.build.RunStep {
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
    install_http_parser_headers.step.dependOn(&install_http_parser_lib.step);
    return install_http_parser_headers;
}

pub fn build(b: *Builder) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const http_parser = build_http_parser(b);

    const exe = b.addExecutable("ztor", "src/main.zig");
    exe.addPackagePath("zben", "./deps/zben/src/main.zig");
    exe.addPackagePath("uri", "./deps/zig-uri/uri.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addLibPath("./zig-cache/lib/");
    exe.addIncludeDir("./zig-cache/include");
    exe.linkSystemLibraryName("http_parser");
    exe.linkLibC();
    exe.install();
    exe.step.dependOn(&http_parser.step);

    const uvtee = b.addExecutable("uvtee", "src/uv_examples/uvtee.zig");
    uvtee.setTarget(target);
    uvtee.setBuildMode(mode);
    uvtee.linkSystemLibrary("uv");
    uvtee.linkLibC();
    uvtee.install();

    const uvserver = b.addExecutable("uvserver", "src/uv_examples/uvserver.zig");
    uvserver.setTarget(target);
    uvserver.setBuildMode(mode);
    uvserver.linkSystemLibrary("uv");
    uvserver.linkLibC();
    uvserver.install();

    const uvclient = b.addExecutable("uvclient", "src/uv_examples/uvclient.zig");
    uvclient.setTarget(target);
    uvclient.setBuildMode(mode);
    uvclient.linkSystemLibrary("uv");
    uvclient.linkLibC();
    uvclient.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const uvtee_cmd = uvtee.run();
    uvtee_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const uvtee_step = b.step("uv_test", "Run uv test");
    uvtee_step.dependOn(&uvtee_cmd.step);
}
