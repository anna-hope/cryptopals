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

const Base64String = string_utils.Base64String;
const HexString = string_utils.HexString;
const char_frequency_map = string_utils.char_frequency_map;

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

fn decryptXordSingleByteKey(allocator: Allocator, input: []const u8, key_byte: u8) ![]u8 {
    var key_candidate = try std.BoundedArray(u8, 1024).init(0);
    key_candidate.appendNTimesAssumeCapacity(key_byte, input.len);
    const key_candidate_slice = key_candidate.slice();

    const decrypted_candidate = try fixedXorBytes(allocator, input, key_candidate_slice);
    return decrypted_candidate;
}

pub const DecryptedOutput = struct {
    output: []u8,
    key: u8,
    score: f32,
};

fn decryptXordBytes(allocator: Allocator, input: []const u8, char_frequencies: string_utils.char_frequency_map) !DecryptedOutput {
    // Get the alphabet to have a list of all the possible characters that could act as the key.
    // (Assuming alphabetic ascii.)
    var alphabet = std.ArrayList(u8).init(allocator);
    defer alphabet.deinit();

    for (string_utils.alphabet_chars) |char| {
        try alphabet.append(char);
    }

    const best_candidate: []u8 = try allocator.alloc(u8, input.len);
    var best_score: f32 = 0.0;
    var key: ?u8 = null;

    for (alphabet.items) |char| {
        const decrypted_candidate = try decryptXordSingleByteKey(allocator, input, char);
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

pub fn decryptXordHex(allocator: Allocator, input: HexString, char_frequencies: string_utils.char_frequency_map) !DecryptedOutput {
    const input_bytes = try input.decode(allocator);
    defer allocator.free(input_bytes);
    return decryptXordBytes(allocator, input_bytes, char_frequencies);
}

pub fn xorWithRepeatingKey(allocator: Allocator, input: []const u8, key: []const u8) ![]u8 {
    const raw_output = try allocator.alloc(u8, input.len);

    for (input, 0..input.len) |input_byte, index| {
        const key_byte = key[index % key.len];
        const encrypted_byte = input_byte ^ key_byte;
        raw_output[index] = encrypted_byte;
    }

    return raw_output;
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
    size: usize,
    distance: f32,

    fn compareDistance(_: void, a: KeySize, b: KeySize) math.Order {
        return math.order(a.distance, b.distance);
    }
};

const SpecialBlockPlace = enum {
    Start,
    End,
};

const InputBlocks = struct {
    const Self = @This();
    allocator: Allocator,
    num_blocks: usize,
    block_size: usize,
    special_block_size: usize,
    data: []u8,

    fn init(allocator: Allocator, input_len: usize, block_size: usize, special_block_place: ?SpecialBlockPlace) !Self {
        var num_blocks = input_len / block_size;

        // In case we can't cleanly divide input_size by block_size,
        // and need a "special" differently-sized block at start or end
        const leftover_bytes: usize = input_len - num_blocks * block_size;
        var special_block_size: usize = 0;
        if (leftover_bytes > 0) {
            switch (special_block_place.?) {
                SpecialBlockPlace.Start => {
                    special_block_size = block_size + leftover_bytes;
                },
                SpecialBlockPlace.End => {
                    special_block_size = leftover_bytes;
                    num_blocks += 1;
                },
            }
        }

        const data = try allocator.alloc(u8, input_len);
        return Self{ .allocator = allocator, .num_blocks = num_blocks, .block_size = block_size, .special_block_size = special_block_size, .data = data };
    }

    fn initWithData(allocator: Allocator, input: []const u8, block_size: usize) !Self {
        var self = try Self.init(allocator, input.len, block_size, SpecialBlockPlace.End);
        self.makeBlocks(input);
        return self;
    }

    fn makeBlocks(self: *Self, input: []const u8) void {
        for (0..self.num_blocks) |block_index| {
            const block_range = self.getBlockStartEnd(block_index);
            mem.copyBackwards(u8, self.data[block_range.start..block_range.end], input[block_range.start..block_range.end]);
        }
    }

    fn deinit(self: *Self) void {
        self.allocator.free(self.data);
    }

    fn getSpecialBlockIndex(self: Self) ?usize {
        if (self.special_block_size > self.block_size) {
            // If the special block is larger than regular ones, it's at the beginning.
            return 0;
        } else if (self.special_block_size > 0 and self.special_block_size < self.block_size) {
            // Otherwise, it's at the end (because it's shorter than regular blocks)
            return self.num_blocks - 1;
        }

        // Or we don't have a special block at all
        return null;
    }

    fn getBlockStartEnd(self: Self, block_index: usize) struct { start: usize, end: usize } {
        const block_size = if (self.special_block_size > 0 and block_index == self.getSpecialBlockIndex().?) blk: {
            break :blk self.special_block_size;
        } else blk: {
            break :blk self.block_size;
        };

        var block_start = block_index * self.block_size;
        if (block_size < self.special_block_size) {
            // We have a special block at the beginning (and we are not inside it),
            // (because the size of the current block is shorter than the size of the special block)
            // so we need to offset the current block_start by the size of the special block.
            block_start += self.special_block_size - block_size;
        }

        const block_end = block_start + block_size;
        return .{ .start = block_start, .end = block_end };
    }

    fn getBlock(self: Self, block_index: usize) []const u8 {
        const block_range = self.getBlockStartEnd(block_index);
        return self.data[block_range.start..block_range.end];
    }

    fn setByteAtIndex(self: *Self, block_index: usize, byte_index: usize, byte: u8) void {
        const block_start = self.getBlockStartEnd(block_index).start;
        self.data[block_start + byte_index] = byte;
    }

    fn setBlock(self: *Self, block_index: usize, data: []const u8) void {
        const block_range = self.getBlockStartEnd(block_index);
        std.debug.assert(data.len == block_range.end - block_range.start);
        std.mem.copyBackwards(u8, self.data[block_range.start..block_range.end], data);
    }

    fn transpose(self: Self) !Self {
        var new_special_block_place: ?SpecialBlockPlace = null;
        var new_block_size = self.num_blocks;
        if (self.getSpecialBlockIndex()) |special_block_index| {
            if (special_block_index + 1 == self.num_blocks) {
                // If it's currently at the end, the transposed blocks should have it at the start.
                new_special_block_place = SpecialBlockPlace.Start;
            } else {
                // ... and vice versa
                new_special_block_place = SpecialBlockPlace.End;
            }
            // Don't count the special block for new block size
            new_block_size -= 1;
        }

        var transposed = try Self.init(self.allocator, self.data.len, new_block_size, new_special_block_place);

        for (0..self.num_blocks) |block_index| {
            const block = self.getBlock(block_index);
            for (block, 0..block.len) |byte, byte_index| {
                transposed.setByteAtIndex(byte_index, block_index, byte);
            }
        }

        return transposed;
    }

    fn iter(self: Self) BlockIterator {
        return BlockIterator.init(self);
    }
};

const BlockIterator = struct {
    const Self = @This();
    current_index: usize = 0,
    blocks: InputBlocks,

    fn init(blocks: InputBlocks) Self {
        return Self{ .blocks = blocks };
    }

    fn next(self: *Self) ?[]const u8 {
        if (self.current_index >= self.blocks.num_blocks) {
            return null;
        }

        const block = self.blocks.getBlock(self.current_index);
        self.current_index += 1;
        return block;
    }
};

pub const DecryptedRepeatingKeyOutput = struct {
    const Self = @This();
    allocator: Allocator,
    key: []const u8,
    output: []const u8,
    total_score: f32,

    pub fn init(allocator: Allocator, key: []const u8, output: []const u8, total_score: f32) Self {
        return Self{ .allocator = allocator, .key = key, .output = output, .total_score = total_score };
    }

    pub fn deinit(self: *Self) void {
        defer self.allocator.free(self.key);
        defer self.allocator.free(self.output);
    }

    pub fn getKeyMeanScore(self: Self) f32 {
        return self.total_score / @as(f32, @floatFromInt(self.key.len));
    }

    pub fn compareMeanScore(_: void, self: Self, other: Self) math.Order {
        const this_mean_score = self.getKeyMeanScore();
        const other_mean_score = other.getKeyMeanScore();
        return math.order(this_mean_score, other_mean_score);
    }
};

fn breakRepeatingKeyFixedLen(allocator: Allocator, input: []const u8, key_len: usize, char_frequencies: char_frequency_map) !DecryptedRepeatingKeyOutput {
    var input_blocks = try InputBlocks.initWithData(allocator, input, key_len);
    defer input_blocks.deinit();

    var transposed_blocks = try input_blocks.transpose();
    defer transposed_blocks.deinit();

    var key_candidates = try std.ArrayList(u8).initCapacity(allocator, transposed_blocks.num_blocks);
    defer key_candidates.deinit();

    var transposed_blocks_iter = transposed_blocks.iter();

    // Solve each block as if it was single-character XOR
    while (transposed_blocks_iter.next()) |block| {
        const decrypted = try decryptXordBytes(allocator, block, char_frequencies);
        defer allocator.free(decrypted.output);
        try key_candidates.append(decrypted.key);
    }

    var key_bytes = std.ArrayList(u8).init(allocator);
    var total_key_score: f32 = 0.0;

    // Now get the histograms for every key for every block
    // The best scoring keys are likely to be the key for that block
    var block_index: usize = 0;
    var transposed_blocks_iter2 = transposed_blocks.iter();
    while (transposed_blocks_iter2.next()) |block| {
        var best_key: ?u8 = null;
        var best_score: f32 = 0.0;

        const best_decryption_block = try allocator.alloc(u8, block.len);
        defer allocator.free(best_decryption_block);

        for (key_candidates.items) |key| {
            const decrypted = try decryptXordSingleByteKey(allocator, block, key);
            defer allocator.free(decrypted);

            const score = string_utils.scoreString(decrypted, char_frequencies);
            if (score > best_score) {
                best_score = score;
                best_key = key;
                mem.copyBackwards(u8, best_decryption_block, decrypted);
            }
        }

        try key_bytes.append(best_key.?);
        total_key_score += best_score;
        transposed_blocks.setBlock(block_index, best_decryption_block);
        block_index += 1;
    }

    // Now that each transposed block is set to its decrypted value, we can get back the original input
    const original_blocks_decrypted = try transposed_blocks.transpose();
    const key = try key_bytes.toOwnedSlice();
    return DecryptedRepeatingKeyOutput.init(allocator, key, original_blocks_decrypted.data, total_key_score);
}

pub fn breakRepeatingKeyXor(allocator: Allocator, input: Base64String, min_key_len: usize, max_key_len: usize, vocab: [][]u8) !DecryptedRepeatingKeyOutput {
    var queue = std.PriorityDequeue(KeySize, void, KeySize.compareDistance).init(allocator, {});
    defer queue.deinit();

    const input_raw = try input.decode(allocator);
    defer allocator.free(input_raw);

    for (min_key_len..max_key_len + 1) |key_size| {
        const distance = try getNormalizedChunkEditDistance(input_raw, key_size);
        try queue.add(KeySize{ .distance = distance, .size = key_size });
    }

    const max_num_key_sizes = 3;
    const num_key_sizes: usize = @min(queue.len, max_num_key_sizes);
    var smallest_distance_keys = try std.BoundedArray(KeySize, max_num_key_sizes).init(0);
    for (0..num_key_sizes) |_| {
        // We know the array is large enough and the queue has enough elements
        smallest_distance_keys.append(queue.removeMin()) catch unreachable;
    }

    var char_frequencies = try string_utils.getCharFrequencies(allocator, vocab);
    defer char_frequencies.deinit();

    var decrypted_candidates = std.PriorityQueue(DecryptedRepeatingKeyOutput, void, DecryptedRepeatingKeyOutput.compareMeanScore).init(allocator, {});
    defer decrypted_candidates.deinit();

    for (smallest_distance_keys.slice()) |key_size| {
        const decrypted = try breakRepeatingKeyFixedLen(allocator, input_raw, key_size.size, char_frequencies);
        try decrypted_candidates.add(decrypted);
    }

    // Find the best decrypted candidate based on mean key score
    const best_candidate = decrypted_candidates.remove();

    while (decrypted_candidates.count() > 0) {
        var candidate = decrypted_candidates.removeIndex(0);
        defer candidate.deinit();
    }
    return best_candidate;
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
    const output = try xorWithRepeatingKey(allocator, input, key);
    defer allocator.free(output);
    var hex_output = try HexString.init(allocator, output);
    defer hex_output.deinit();

    try testing.expectEqualStrings(expected, hex_output.buf);
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

test "fast make and transpose blocks" {
    const allocator = testing.allocator;

    const test_input = "AAAABBBBCCCCDDDD";
    const block_size: usize = 3;

    var blocks = try InputBlocks.initWithData(allocator, test_input, block_size);
    defer blocks.deinit();
    var transposed_blocks = try blocks.transpose();
    defer transposed_blocks.deinit();

    var block_iterator = transposed_blocks.iter();

    const expected_blocks: [3]*const [6]u8 = .{ "AABCDD", "ABBCD\x00", "ABCCD\x00" };

    var block_index: usize = 0;
    while (block_iterator.next()) |block| {
        try testing.expectStringStartsWith(block, expected_blocks[block_index][0..block.len]);
        block_index += 1;
    }
}

test "break repeating-key XOR" {
    const allocator = testing.allocator;
    const test_filename = "data/pride_prejudice_encrypted_jane.txt";

    const cwd = fs.cwd();
    const input = try cwd.readFileAlloc(allocator, test_filename, 1024 * 10);
    defer allocator.free(input);
    const b64input = Base64String.initFromBase64(input);

    const root_dir = try fs.openDirAbsolute("/", .{});
    const dict_path = "/usr/share/dict/words";
    const helpers = @import("helpers.zig");
    var words = try helpers.readLines(allocator, root_dir, dict_path);
    defer words.deinit();

    const decrypted = try breakRepeatingKeyXor(allocator, b64input, 2, 10, words.data);
    defer allocator.free(decrypted.output);
    defer allocator.free(decrypted.key);

    try testing.expectEqualStrings("jane", decrypted.key);
    try testing.expectEqualStrings(input, decrypted.output);
}
