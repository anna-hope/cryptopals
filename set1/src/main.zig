const std = @import("std");
const crypto = @import("crypto.zig");
const helpers = @import("helpers.zig");

pub fn main() !void {
    var general_purpuse_allocator = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    const gpa = general_purpuse_allocator.allocator();
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    const allocator = arena_allocator.allocator();
    defer arena_allocator.deinit();

    const input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    std.debug.print("{s}\n", .{input});
    const dict_path = "/usr/share/dict/words";

    const words = try helpers.readLines(allocator, dict_path);
    const decrypted_output = try crypto.decryptXordHex(allocator, input, words);

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("message: {s}, key: {c}\n", .{ decrypted_output.output, decrypted_output.key });

    try bw.flush(); // don't forget to flush!
}
