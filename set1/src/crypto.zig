const std = @import("std");
const string_utils = @import("string_utils.zig");

const base64 = std.base64;
const fmt = std.fmt;
const fs = std.fs;
const hash = std.hash;
const math = std.math;
const mem = std.mem;
const testing = std.testing;

const Allocator = std.mem.Allocator;

const HexString = string_utils.HexString;
const Base64String = string_utils.Base64String;

pub const CryptoError = error{
    UnequalLengthBuffers,
    BufferTooShort,
};

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

pub fn fixedXorHex(allocator: Allocator, hex1: HexString, hex2: HexString) !HexString {
    if (hex1.buf.len != hex2.buf.len) {
        return CryptoError.UnequalLengthBuffers;
    }

    const buf1 = try hex1.decode(allocator);
    defer allocator.free(buf1);

    const buf2 = try hex2.decode(allocator);
    defer allocator.free(buf2);

    const out_bytes = try fixedXorBytes(allocator, buf1, buf2);
    defer allocator.free(out_bytes);

    return try HexString.init(allocator, out_bytes);
}

pub const DecryptedOutput = struct {
    output: []u8,
    key: u8,
    score: f32,
};

pub fn decryptXordHex(allocator: Allocator, input: HexString, char_frequencies: string_utils.char_frequency_map) !DecryptedOutput {
    // Get the alphabet to have a list of all the possible characters that could act as the key.
    // (Assuming alphabetic ascii.)
    var alphabet = std.ArrayList(u8).init(allocator);
    defer alphabet.deinit();

    for (string_utils.alphabet_chars) |char| {
        try alphabet.append(char);
    }

    const input_bytes = try input.decode(allocator);
    defer allocator.free(input_bytes);

    const best_candidate: []u8 = try allocator.alloc(u8, input_bytes.len);
    var best_score: f32 = 0.0;
    var key: ?u8 = null;

    for (alphabet.items) |char| {
        var key_candidate = try std.BoundedArray(u8, 1024).init(0);
        key_candidate.appendNTimesAssumeCapacity(char, input_bytes.len);
        const key_candidate_slice = key_candidate.slice();

        const decrypted_candidate = try fixedXorBytes(allocator, input_bytes, key_candidate_slice);
        defer allocator.free(decrypted_candidate);

        const score = string_utils.scoreString(decrypted_candidate, char_frequencies);

        if (score > best_score) {
            mem.copyForwards(u8, best_candidate, decrypted_candidate);
            best_score = score;
            key = char;
        }
    }

    return DecryptedOutput{ .output = best_candidate, .key = key.?, .score = best_score };
}

pub fn encryptRepeatingKeyXor(allocator: Allocator, input: []const u8, key: []const u8) !HexString {
    const raw_output = try allocator.alloc(u8, input.len);
    defer allocator.free(raw_output);

    for (input, 0..input.len) |input_byte, index| {
        const key_byte = key[index % key.len];
        const encrypted_input_byte = try fixedXorBytes(allocator, &[_]u8{input_byte}, &[_]u8{key_byte});
        defer allocator.free(encrypted_input_byte);

        // Copy the byte so we can free the encrypted_input_byte array
        mem.copyForwards(
            u8,
            raw_output[index .. index + 1],
            encrypted_input_byte,
        );
    }

    return try HexString.init(allocator, raw_output);
}

fn getNormalizedChunkEditDistance(input: []const u8, chunk_len: usize) !f32 {
    if (chunk_len * 2 > input.len) {
        return CryptoError.BufferTooShort;
    }

    const first_chunk = input[0..chunk_len];
    const second_chunk = input[chunk_len .. chunk_len * 2];
    const distance = try string_utils.computeHammingDistance(first_chunk, second_chunk);
    return @as(f32, @floatFromInt(distance)) / @as(f32, @floatFromInt(chunk_len));
}

const KeySize = struct {
    len: usize,
    distance: f32,

    fn getSmallerDistance(_: void, a: KeySize, b: KeySize) math.Order {
        return math.order(a.distance, b.distance);
    }
};

pub fn breakRepeatingKeyXor(allocator: Allocator, input: []const u8, min_key_len: usize, max_key_len: usize) ![]u8 {
    const out = try allocator.alloc(u8, input.len);

    var queue = std.PriorityDequeue(KeySize, void, KeySize.getSmallerDistance).init(allocator, {});
    defer queue.deinit();

    for (min_key_len..max_key_len + 1) |key_size| {
        const distance = try getNormalizedChunkEditDistance(input, key_size);
        try queue.add(KeySize{ .distance = distance, .len = key_size });
    }

    const num_key_sizes: usize = 3;
    var smallest_distance_keys = try std.BoundedArray(KeySize, num_key_sizes).init(0);
    for (0..num_key_sizes) |_| {
        smallest_distance_keys.append(queue.removeMin()) catch unreachable;
    }
    std.debug.print("{any}\n", .{smallest_distance_keys});

    return out;
}

test "fast fixed xor" {
    const buf1 = HexString.initFromHex("1c0111001f010100061a024b53535009181c");
    const buf2 = HexString.initFromHex("686974207468652062756c6c277320657965");

    const allocator = std.testing.allocator;
    var out = try fixedXorHex(allocator, buf1, buf2);
    defer out.deinit();

    const expected = "746865206b696420646f6e277420706c6179";
    try std.testing.expectStringStartsWith(out.buf, expected);
}

test "decrypt XOR'd hex" {
    const allocator = testing.allocator;
    const dict_path = "/usr/share/dict/words";
    const helpers = @import("helpers.zig");

    const input = HexString.initFromHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

    const root = try std.fs.openDirAbsolute("/", .{});
    const words = try helpers.readLines(allocator, root, dict_path);
    defer allocator.free(words);
    var char_frequencies = try string_utils.getCharFrequencies(allocator, words);
    defer char_frequencies.deinit();

    const decrypted_output = try decryptXordHex(allocator, input, char_frequencies);
    defer allocator.free(decrypted_output.output);

    try testing.expectEqualStrings("Cooking MC's like a pound of bacon", decrypted_output.output);
    try testing.expectEqual('X', decrypted_output.key);

    for (words) |word| {
        defer allocator.free(word);
    }
}

test "fast repeating-key XOR" {
    const allocator = testing.allocator;
    const input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    const expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    const key = "ICE";
    var output = try encryptRepeatingKeyXor(allocator, input, key);
    defer output.deinit();

    try testing.expectEqualStrings(expected, output.buf);
}

test "fast get character frequencies" {
    const allocator = std.testing.allocator;
    var words = std.ArrayList([]u8).init(allocator);
    for (0..3) |_| {
        const buf = try allocator.alloc(u8, 5);
        mem.copyForwards(u8, buf, "hello");
        try words.append(buf);
    }

    const words_slice = try words.toOwnedSlice();
    defer allocator.free(words_slice);

    var char_frequencies = try string_utils.getCharFrequencies(allocator, words_slice);
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

test "fast get normalized edit distance for chunks" {
    const input1 = "aaaaaa";
    const normalized_distance1 = try getNormalizedChunkEditDistance(input1, 3);
    try testing.expectApproxEqAbs(0.0, normalized_distance1, 1e-5);

    const input2 = "aaabbb";
    const normalized_distance2 = try getNormalizedChunkEditDistance(input2, 3);
    try testing.expectApproxEqAbs(2.0, normalized_distance2, 1e-5);
}

test "break repeating-key XOR" {
    const allocator = testing.allocator;
    const test_filename = "data/pride_prejudice_jane.txt";

    const cwd = fs.cwd();
    const input = try cwd.readFileAlloc(allocator, test_filename, 1024 * 10);
    defer allocator.free(input);

    const decrypted = try breakRepeatingKeyXor(allocator, input, 2, 10);
    defer allocator.free(decrypted);
}
