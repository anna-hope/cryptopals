const std = @import("std");
const testing = std.testing;

const c = @cImport({
    @cInclude("openssl/aes.h");
});

test "ecb" {
    // std.debug.print("{d}\n", .{c.AES_ecb_encrypt(in: [*c]const u8, out: [*c]u8, key: [*c]const AES_KEY, enc: c_int)});
}
