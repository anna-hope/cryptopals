const std = @import("std");
const base64 = std.base64;
const fmt = std.fmt;
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

fn bytesToHex(allocator: Allocator, buf_bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, buf_bytes.len * 2);
    for (buf_bytes, 0..buf_bytes.len) |byte, index| {
        const hex_seq: [2]u8 = std.fmt.hex(byte);
        out[index * 2] = hex_seq[0];
        out[index * 2 + 1] = hex_seq[1];
    }
    return out;
}

fn fixedXorBytes(allocator: Allocator, buf1: []const u8, buf2: []const u8) ![]u8 {
    if (buf1.len != buf2.len) {
        return CryptoError.UnequalLengthBuffers;
    }

    const out = try allocator.alloc(u8, buf1.len);

    for (0..out.len) |index| {
        const byte1 = buf1[index];
        const byte2 = buf2[index];

        out[index] = byte1 ^ byte2;
    }

    return out;
}

pub fn fixedXorHex(allocator: Allocator, buf1_hex: []const u8, buf2_hex: []const u8) ![]u8 {
    if (buf1_hex.len != buf2_hex.len) {
        return CryptoError.UnequalLengthBuffers;
    }

    const buf1 = try allocator.alloc(u8, buf1_hex.len);
    defer allocator.free(buf1);
    const buf1_slice = try std.fmt.hexToBytes(buf1, buf1_hex);

    const buf2 = try allocator.alloc(u8, buf2_hex.len);
    defer allocator.free(buf2);
    const buf2_slice = try std.fmt.hexToBytes(buf2, buf2_hex);

    const out_bytes = try fixedXorBytes(allocator, buf1_slice, buf2_slice);
    defer allocator.free(out_bytes);

    return try bytesToHex(allocator, out_bytes);
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

fn scoreString(string: []const u8, char_frequencies: char_frequency_map) f32 {
    var score: f32 = 0.0;
    for (string) |char| {
        if (char_frequencies.get(char)) |char_freq| {
            score += char_freq;
        }
    }
    return score / @as(f32, @floatFromInt(string.len));
}

pub fn decryptXordHex(allocator: Allocator, input: []const u8, words: [][]u8) ![]u8 {
    var char_frequencies = try getCharFrequencies(allocator, words);
    defer char_frequencies.deinit();

    // Get the alphabet to have a list of all the possible characters that could act as the key.
    // (Assuming alphabetic ascii.)
    var alphabet = std.ArrayList(u8).init(allocator);
    defer alphabet.deinit();

    var char_freqs_keys_iter = char_frequencies.keyIterator();
    while (char_freqs_keys_iter.next()) |char| {
        try alphabet.append(char.*);
    }

    const input_bytes = try allocator.alloc(u8, input.len);
    defer allocator.free(input_bytes);
    const input_bytes_slice = try fmt.hexToBytes(input_bytes, input);

    const best_candidate: []u8 = try allocator.alloc(u8, input.len);
    var best_score: f32 = 0.0;

    for (alphabet.items) |char| {
        var key_candidate = try std.BoundedArray(u8, 1024).init(0);
        key_candidate.appendNTimesAssumeCapacity(char, input_bytes_slice.len);
        const key_candidate_slice = key_candidate.slice();

        const decrypted_candidate = try fixedXorBytes(allocator, input_bytes_slice, key_candidate_slice);
        defer allocator.free(decrypted_candidate);

        const score = scoreString(decrypted_candidate, char_frequencies);

        if (score > best_score) {
            mem.copyForwards(u8, best_candidate, decrypted_candidate);
            best_score = score;
        }
    }

    return best_candidate;
}

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
    const out = try fixedXorHex(allocator, buf1, buf2);
    defer allocator.free(out);

    const expected = "746865206b696420646f6e277420706c6179";
    try std.testing.expectStringStartsWith(out, expected);
}

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
