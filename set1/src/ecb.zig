const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const Allocator = mem.Allocator;

const helpers = @import("helpers.zig");
const string_utils = @import("string_utils.zig");

const c = @cImport({
    @cInclude("openssl/aes.h");
});

pub fn aesEcbDecrypt(allocator: Allocator) ![]u8 {
    // const key_len = 60;

    const user_key = "YELLOW SUBMARINE";
    // var key_arr = mem.zeroes([key_len]u8);
    // mem.copyBackwards(u8, &key_arr, user_key);
    // const key_vec: @Vector(key_len, u8) = key_arr;

    var aes_key: c.AES_KEY = undefined;
    const aes_result = c.AES_set_decrypt_key(user_key, 128, &aes_key);
    std.debug.assert(aes_result == 0);

    const dir = std.fs.cwd();

    var b64_lines = try helpers.readLines(allocator, dir, "data/7.txt", 1024);
    defer b64_lines.deinit();

    const b64_data = try mem.join(allocator, "", b64_lines.data);
    defer allocator.free(b64_data);

    const b64 = string_utils.Base64String.initFromBase64(b64_data);
    const encrypted_data = try b64.decode(allocator);
    defer allocator.free(encrypted_data);

    const out = try allocator.alloc(u8, encrypted_data.len);
    var windows = mem.window(u8, encrypted_data, 16, 16);
    var current_offset: usize = 0;

    while (windows.next()) |window| : (current_offset += window.len) {
        const new_offset = current_offset + window.len;
        c.AES_ecb_encrypt(window.ptr, out[current_offset..new_offset].ptr, &aes_key, 0);
    }

    return out;
}
