const std = @import("std");
const base64 = std.base64;
const Allocator = std.mem.Allocator;

const encoder = base64.Base64Encoder.init(base64.standard.alphabet_chars, base64.standard.pad_char);

pub const CryptoError = error {
    UnequalLengthBuffers,
};

pub fn hexToBase64(source_hex: []u8, allocator: Allocator) ![]const u8 {
    const out_bytes = try allocator.alloc(u8, source_hex.len);
    defer allocator.free(out_bytes);
    const out_bytes_decoded = try std.fmt.hexToBytes(out_bytes, source_hex);

    const dest = try allocator.alloc(u8, encoder.calcSize(out_bytes_decoded.len));
    const out = encoder.encode(dest, out_bytes_decoded);
    return out;
}

pub fn fixedXor(buf1_hex: []const u8, buf2_hex: []const u8, allocator: Allocator) ![]u8 {
    if (buf1_hex.len != buf2_hex.len) {
        return CryptoError.UnequalLengthBuffers;
    }

    const buf1 = try allocator.alloc(u8, buf1_hex.len);
    defer allocator.free(buf1);
    const buf1_slice = try std.fmt.hexToBytes(buf1, buf1_hex);

    const buf2 = try allocator.alloc(u8, buf2_hex.len);
    defer allocator.free(buf2);
    const buf2_slice = try std.fmt.hexToBytes(buf2, buf2_hex);

    const out_bytes = try allocator.alloc(u8, buf1_slice.len);
    defer allocator.free(out_bytes);

    for (0..out_bytes.len) |index| {
        const byte1 = buf1_slice[index];
        const byte2 = buf2_slice[index];

        out_bytes[index] = byte1 ^ byte2;

    }

    const out = try allocator.alloc(u8, out_bytes.len * 2);
    for (out_bytes, 0..out_bytes.len) |byte, index| {
        const hex_seq: [2]u8 = std.fmt.hex(byte);
        out[index * 2] = hex_seq[0];
        out[index * 2 + 1] = hex_seq[1];
    }

    return out;
}