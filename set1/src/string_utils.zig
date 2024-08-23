const std = @import("std");
const base64 = std.base64;
const fmt = std.fmt;

const Allocator = std.mem.Allocator;

const alphabet_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const char_frequency_map = std.AutoHashMap(u8, f32);
const encoder = base64.Base64Encoder.init(base64.standard.alphabet_chars, base64.standard.pad_char);

pub const HexString = struct {
    const Self = @This();
    allocator: ?Allocator = null,
    buf: []const u8,

    pub fn init(allocator: Allocator, raw_bytes: []const u8) !Self {
        const hex_bytes = try allocator.alloc(u8, raw_bytes.len * 2);
        for (raw_bytes, 0..raw_bytes.len) |byte, index| {
            const hex_seq: [2]u8 = fmt.hex(byte);
            hex_bytes[index * 2] = hex_seq[0];
            hex_bytes[index * 2 + 1] = hex_seq[1];
        }
        return Self{ .allocator = allocator, .buf = hex_bytes };
    }

    /// The input has to be a valid hex-encoded byte buffer, or the behavior will be unexpected.
    pub fn initFromHex(already_hex: []const u8) Self {
        return Self{ .buf = already_hex };
    }

    pub fn deinit(self: *Self) void {
        if (self.allocator) |allocator| {
            allocator.free(self.buf);
        }
    }

    pub fn decode(self: Self, allocator: Allocator) ![]u8 {
        const out_bytes = try allocator.alloc(u8, self.buf.len / 2);
        _ = try std.fmt.hexToBytes(out_bytes, self.buf);
        return out_bytes;
    }
};

pub fn hexToBase64(allocator: Allocator, source: HexString) ![]const u8 {
    const out_bytes = try allocator.alloc(u8, source.buf.len);
    defer allocator.free(out_bytes);
    const out_bytes_decoded = try fmt.hexToBytes(out_bytes, source.buf);

    const dest = try allocator.alloc(u8, encoder.calcSize(out_bytes_decoded.len));
    const out = encoder.encode(dest, out_bytes_decoded);
    return out;
}

pub fn getCharFrequencies(allocator: Allocator, words: [][]u8) !char_frequency_map {
    var char_counts = std.AutoHashMap(u8, u64).init(allocator);
    defer char_counts.deinit();

    var total_chars: u32 = 0;
    for (words) |word| {
        for (word) |char| {
            const result = try char_counts.getOrPutValue(char, 0);
            result.value_ptr.* += 1;
            total_chars += 1;
        }
    }

    const total: f32 = @floatFromInt(total_chars);

    var char_frequencies = std.AutoHashMap(u8, f32).init(allocator);
    var char_counts_iterator = char_counts.iterator();
    while (char_counts_iterator.next()) |entry| {
        const freq: f32 = @floatFromInt(entry.value_ptr.*);
        try char_frequencies.put(entry.key_ptr.*, freq / total);
    }

    return char_frequencies;
}

fn scoreString(string: []const u8, char_frequencies: char_frequency_map) f32 {
    var score: f32 = 0.0;
    for (string) |char| {
        if (char_frequencies.get(char)) |char_freq| {
            score += char_freq;
        }
    }
    return score / @as(f32, @floatFromInt(string.len));
}

test "fast hex to base64" {
    const allocator = std.testing.allocator;
    const input = HexString.initFromHex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");

    var hex_len: usize = 0;
    while (hex_len < input.buf.len) {
        var current_char_is_hex = false;
        for (std.fmt.hex_charset) |char| {
            if (input.buf[hex_len] == char) {
                current_char_is_hex = true;
            }
        }

        if (!current_char_is_hex) {
            break;
        }

        hex_len += 1;
    }

    const output = try hexToBase64(allocator, input);
    defer allocator.free(output);

    const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    try std.testing.expectStringStartsWith(output, expected);
}
