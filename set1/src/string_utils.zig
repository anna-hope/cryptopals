const std = @import("std");
const base64 = std.base64;
const fmt = std.fmt;
const mem = std.mem;
const testing = std.testing;

const Allocator = std.mem.Allocator;

pub const alphabet_chars = base64.standard_alphabet_chars;
pub const char_frequency_map = std.AutoHashMap(u8, f32);

// TODO: Make into tagged union to deal with managed (newly allocated) vs unmanaged case
// TODO: So that we don't always need to take an allocator in decode
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
        const decoded = try std.fmt.hexToBytes(out_bytes, self.buf);
        std.debug.assert(decoded.len == out_bytes.len);
        return out_bytes;
    }
};

pub const Base64String = struct {
    const Self = @This();
    allocator: ?Allocator = null,
    buf: []const u8,

    pub fn init(allocator: Allocator, raw_bytes: []const u8) !Self {
        const encoder = base64.Base64Encoder.init(base64.standard.alphabet_chars, base64.standard.pad_char);
        const buf = try allocator.alloc(u8, encoder.calcSize(raw_bytes.len));
        const out = encoder.encode(buf, raw_bytes);
        std.debug.assert(out.len == buf.len);

        return Self{ .allocator = allocator, .buf = buf };
    }

    pub fn initFromBase64(buf: []const u8) Self {
        return Self{ .buf = buf };
    }

    pub fn deinit(self: *Self) void {
        if (self.allocator) |allocator| {
            allocator.free(self.buf);
        }
    }
};

pub fn hexToBase64(allocator: Allocator, source: HexString) !Base64String {
    const source_raw = try source.decode(allocator);
    defer allocator.free(source_raw);
    return try Base64String.init(allocator, source_raw);
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

pub fn scoreString(string: []const u8, char_frequencies: char_frequency_map) f32 {
    var score: f32 = 0.0;
    for (string) |char| {
        if (char_frequencies.get(char)) |char_freq| {
            score += char_freq;
        }
    }
    return score / @as(f32, @floatFromInt(string.len));
}

fn sortBytes(buf: []u8) void {
    const compare = std.sort.asc(u8);
    std.sort.heap(u8, buf, {}, compare);
}

fn u8toBitArray(byte: u8) [8]u2 {
    var out = [_]u2{0} ** 8;
    var remains = byte;
    var index: u8 = 7;
    while (remains > 0) {
        const remainder = remains % 2;
        remains /= 2;
        out[index] = @intCast(remainder);
        index -= 1;
    }

    return out;
}

pub fn computeHammingDistance(buf1: []const u8, buf2: []const u8) usize {
    // var longer: []const u8 = undefined;
    // var shorter: []const u8 = undefined;
    //
    // if (buf1.len > buf2.len) {
    //     longer = buf1;
    //     shorter = buf2;
    // } else {
    //     longer = buf2;
    //     shorter = buf1;
    // }

    var distance: usize = 0;

    for (buf1, buf2) |byte1, byte2| {
        const difference = u8toBitArray(byte1 ^ byte2);
        for (difference) |bit| {
            distance += @intCast(bit);
        }
    }
    return distance;
}

test "fast hex to base64" {
    const allocator = std.testing.allocator;
    const input = HexString.initFromHex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");

    var output = try hexToBase64(allocator, input);
    defer output.deinit();

    const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    try std.testing.expectEqualStrings(expected, output.buf);
}

// test "sort bytes" {
//     const string = "Zig";
//     const allocator = testing.allocator;
//
//     sortBytes(string);
//     try testing.expectEqualStrings("Zgi", string);
// }

test "u8 to bit array" {
    const input: u8 = 5;
    const bits = u8toBitArray(input);
    const expected = [_]u2{ 0, 0, 0, 0, 0, 1, 0, 1 };
    try testing.expectEqual(expected, bits);
}

test "fast hamming distance" {
    const input1 = "this is a test";
    const input2 = "wokka wokka!!!";
    try testing.expectEqual(37, computeHammingDistance(input1, input2));
}
