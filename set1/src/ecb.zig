const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const helpers = @import("helpers.zig");
const string_utils = @import("string_utils.zig");

const c = @cImport({
    @cInclude("openssl/aes.h");
});

test "ecb" {
    const allocator = testing.allocator;

    const key = "YELLOW SUBMARINE";

    const dir = std.fs.cwd();
    const raw_data = try dir.readFileAlloc(allocator, "data/not_random_data.txt", 1024);
    defer allocator.free(raw_data);

    var b64_lines = try helpers.readLines(allocator, dir, "data/not_random_data_encrypted.txt", 1024);
    defer b64_lines.deinit();

    const b64_data = try mem.join(allocator, "", b64_lines.data);
    const b64 = string_utils.Base64String.initFromBase64(b64_data);
    const encrypted_data = try b64.decode(allocator);
    defer allocator.free(encrypted_data);

    defer allocator.free(encrypted_data);

    const out = try allocator.alloc(u8, raw_data.len);
    defer allocator.free(out);

    c.AES_decrypt(&encrypted_data, &out, key);

    testing.expectEqualStrings(raw_data, out);
}
