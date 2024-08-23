const std = @import("std");
const crypto = @import("crypto.zig");
const helpers = @import("helpers.zig");

pub fn main() !void {
    var general_purpuse_allocator = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    const gpa = general_purpuse_allocator.allocator();
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    const allocator = arena_allocator.allocator();
    defer arena_allocator.deinit();

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    try stdout.print("Running...\n", .{});

    try bw.flush(); // don't forget to flush!

    const data_path = "/Users/annahope/projects/rc/cryptopals/set1/data/4.txt";
    const inputs = try helpers.readLines(allocator, data_path);

    const dict_path = "/usr/share/dict/words";
    const words = try helpers.readLines(allocator, dict_path);

    const char_freqs = try crypto.getCharFrequencies(allocator, words);
    var final_output: ?crypto.DecryptedOutput = null;
    var best_index: usize = 0;

    for (inputs, 0..inputs.len) |input, index| {
        const input_hex = crypto.HexString.initFromHex(input);
        const output = try crypto.decryptXordHex(allocator, input_hex, char_freqs);
        if (final_output) |fo| {
            if (output.score > fo.score) {
                final_output = output;
                best_index = index;
            }
        } else {
            final_output = output;
        }

        try bw.flush();
    }

    try stdout.print("best index: {d}, message: {s}, key: {c}\n", .{ best_index, final_output.?.output, final_output.?.key });

    try bw.flush();
}
