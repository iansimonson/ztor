usingnamespace @cImport({
    @cInclude("http-parser/http_parser.h");
    @cInclude("uv.h");
});

/// This is a zig stub that is the same size
/// as http_parser which, since it has a bitfield
/// cannot be translated properly.
/// It's also used for accessing the fields
/// directly such as `data`
pub const http_parser_sized = extern struct {
    bitfield: u32,
    nread: u32,
    content_length: u64,
    http_major: u8,
    http_minor: u8,
    bitfield_2: u32,
    data: *c_void,
};
