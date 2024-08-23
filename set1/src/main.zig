const std = @import("std");
const fs = std.fs;
const process = std.process;

const crypto = @import("crypto.zig");
const helpers = @import("helpers.zig");

const ProgramError = error{
    NotEnoughArguments,
};

pub fn main() !void {
    std.debug.print("Running...\n", .{});

    var general_purpuse_allocator = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    const gpa = general_purpuse_allocator.allocator();
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    const allocator = arena_allocator.allocator();
    defer arena_allocator.deinit();

    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var args_iterator = try process.argsWithAllocator(allocator);
    const program_name = args_iterator.next().?;
    const maybe_input_path = args_iterator.next();
    const maybe_key = args_iterator.next();

    var input_path: []const u8 = undefined;
    var key: []const u8 = undefined;

    var have_enough_args = false;

    if (maybe_input_path) |some_input_path| {
        input_path = some_input_path;
        if (maybe_key) |some_key| {
            key = some_key;
            have_enough_args = true;
        }
    }

    if (!have_enough_args) {
        try stdout.print("Usage: {s} <relative_input_path> <encryption_key>\n", .{program_name});
        try bw.flush();
        return error.NotEnoughArguments;
    }

    const cwd = fs.cwd();
    // Limit to 10 megabytes
    const input = try cwd.readFileAlloc(allocator, input_path, 1024 * 1024 * 10);

    const encrypted = try crypto.encryptRepeatingKeyXor(allocator, input, key);

    try stdout.print("{s}\n", .{encrypted.buf});

    try bw.flush();
}
