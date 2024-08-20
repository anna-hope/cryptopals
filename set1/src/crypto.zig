const std = @import("std");
const base64 = std.base64;
const fs = std.fs;
const hash = std.hash;
const mem = std.mem;
const testing = std.testing;

const Allocator = std.mem.Allocator;

const encoder = base64.Base64Encoder.init(base64.standard.alphabet_chars, base64.standard.pad_char);

const char_frequency_map = std.AutoHashMap(u8, f32);

pub const CryptoError = error{
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

fn readLines(allocator: Allocator, file_path: []const u8) ![][]u8 {
    const file = try fs.openFileAbsolute(file_path, .{});
    defer file.close();

    const file_reader = file.reader();
    var words = std.ArrayList([]u8).init(allocator);
    while (try file_reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 50)) |word| {
        try words.append(word[0..word.len]);
    }

    return try words.toOwnedSlice();
}

fn getCharFrequencies(allocator: Allocator, words: [][]u8) !char_frequency_map {
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

// pub fn decryptXordHex(allocator: Allocator, input: []const u8, words: [][]u8) ![]u8 {
//
// }

test "hex to base64" {
    const allocator = std.testing.allocator;
    const source = try allocator.alloc(u8, 100);
    defer allocator.free(source);

    std.mem.copyForwards(u8, source, "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");

    var hex_len: usize = 0;
    while (hex_len < source.len) {
        var current_char_is_hex = false;
        for (std.fmt.hex_charset) |char| {
            if (source[hex_len] == char) {
                current_char_is_hex = true;
            }
        }

        if (!current_char_is_hex) {
            break;
        }

        hex_len += 1;
    }

    const output = try hexToBase64(source[0..hex_len], allocator);
    defer allocator.free(output);

    const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    try std.testing.expectStringStartsWith(output, expected);
}

test "fixed xor" {
    const buf1 = "1c0111001f010100061a024b53535009181c";
    const buf2 = "686974207468652062756c6c277320657965";

    const allocator = std.testing.allocator;
    const out = try fixedXor(buf1, buf2, allocator);
    defer allocator.free(out);

    const expected = "746865206b696420646f6e277420706c6179";
    try std.testing.expectStringStartsWith(out, expected);
}

// test "read file" {
//     const dict_path = "/usr/share/dict/words";
//     const allocator = testing.allocator;
//
//     const words = try readLines(allocator, dict_path);
//     defer allocator.free(words);
//
//     try testing.expect(words.len > 0);
//     try testing.expectEqualStrings("A", words[0]);
//     try testing.expectEqualStrings("Zyzzogeton", words[words.len - 1]);
//
//     for (words) |word| {
//         defer allocator.free(word);
//     }
// }

test "get character frequencies" {
    const allocator = std.testing.allocator;
    var words = std.ArrayList([]u8).init(allocator);
    for (0..3) |_| {
        const buf = try allocator.alloc(u8, 5);
        mem.copyForwards(u8, buf, "hello");
        try words.append(buf);
    }

    const words_slice = try words.toOwnedSlice();
    defer allocator.free(words_slice);

    var char_frequencies = try getCharFrequencies(allocator, words_slice);
    defer char_frequencies.deinit();

    try testing.expect(char_frequencies.count() > 0);

    var char_freqs_iter = char_frequencies.iterator();
    while (char_freqs_iter.next()) |entry| {
        try testing.expect(entry.value_ptr.* > 0.0);
    }

    for (words_slice) |word| {
        defer allocator.free(word);
    }
}
