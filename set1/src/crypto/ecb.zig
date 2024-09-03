const std = @import("std");
const testing = std.testing;

const openssl_crypto = @cImport({
    @cInclude("openssl/crypto.h");
});

test "ecb" {
    std.debug.print("{d}\n", .{openssl_crypto.OpenSSL_version_num()});
}
