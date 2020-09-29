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

fn build_libuv(b: *Builder) *std.build.RunStep {
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
            "./zig-cache/include/libuv",
        },
    );
    const make_build_dir = b.addSystemCommand(
        &[_][]const u8{
            "mkdir",
            "-p",
            "./deps/libuv/build",
        },
    );

    make_build_dir.step.dependOn(&ensure_include_dir_exists.step);
    make_build_dir.step.dependOn(&ensure_include_dir_exists.step);

    const run_cmake = b.addSystemCommand(
        &[_][]const u8{
            "cmake",
            "-DCMAKE_INSTALL_PREFIX=./zig-cache",
            "-S",
            "./deps/libuv/",
            "-B",
            "./deps/libuv/build/",
        },
    );

    run_cmake.step.dependOn(&make_build_dir.step);

    const build_libuv_step = b.addSystemCommand(
        &[_][]const u8{
            "cmake",
            "--build",
            "./deps/libuv/build",
        },
    );

    build_libuv_step.step.dependOn(&run_cmake.step);

    const install_libuv_step = b.addSystemCommand(
        &[_][]const u8{
            "cmake",
            "--install",
            "./deps/libuv/build",
        },
    );
    install_libuv_step.step.dependOn(&build_libuv_step.step);
    return install_libuv_step;
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
    const libuv = build_libuv(b);

    const exe = b.addExecutable("ztor", "src/main.zig");
    exe.addPackagePath("zben", "./deps/zben/src/main.zig");
    exe.addPackagePath("uri", "./deps/zig-uri/uri.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addLibPath("./zig-cache/lib/");
    exe.addIncludeDir("./zig-cache/include");
    exe.linkSystemLibraryName("http_parser");
    exe.linkSystemLibrary("uv");
    exe.linkLibC();
    exe.install();
    exe.step.dependOn(&http_parser.step);
    exe.step.dependOn(&libuv.step);

    const uvtee = b.addExecutable("uvtee", "src/uv_examples/uvtee.zig");
    uvtee.setTarget(target);
    uvtee.setBuildMode(mode);
    uvtee.addIncludeDir("./zig-cache/include");
    uvtee.addLibPath("./zig-cache/lib/");
    uvtee.linkSystemLibrary("uv");
    uvtee.linkLibC();
    uvtee.install();

    const uvserver = b.addExecutable("uvserver", "src/uv_examples/uvserver.zig");
    uvserver.setTarget(target);
    uvserver.setBuildMode(mode);
    uvserver.linkSystemLibrary("uv");
    uvserver.addIncludeDir("./zig-cache/include");
    uvserver.addLibPath("./zig-cache/lib/");
    uvserver.linkLibC();
    uvserver.install();

    const uvclient = b.addExecutable("uvclient", "src/uv_examples/uvclient.zig");
    uvclient.setTarget(target);
    uvclient.setBuildMode(mode);
    uvclient.linkSystemLibrary("uv");
    uvclient.addIncludeDir("./zig-cache/include");
    uvclient.addLibPath("./zig-cache/lib/");
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
