const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const process = std.process;

const Allocator = mem.Allocator;

const crypto = @import("crypto/xor.zig");
const helpers = @import("helpers.zig");
const string_utils = @import("string_utils.zig");

const Base64String = string_utils.Base64String;

const ProgramError = error{
    UnsupportedMode,
    NotEnoughArguments,
};

fn encrypt(allocator: Allocator, args: *process.ArgIterator) !Base64String {
    var have_enough_args = false;
    var input_path: []const u8 = undefined;
    var key: []const u8 = undefined;

    const maybe_input_path = args.next();
    const maybe_key = args.next();

    if (maybe_input_path) |some_input_path| {
        input_path = some_input_path;
        if (maybe_key) |some_key| {
            key = some_key;
            have_enough_args = true;
        }
    }

    if (!have_enough_args) {
        return error.NotEnoughArguments;
    }

    const cwd = fs.cwd();
    // Limit to 10 megabytes
    const input = try cwd.readFileAlloc(allocator, input_path, 1024 * 1024 * 10);
    defer allocator.free(input);

    const encrypted = try crypto.xorWithRepeatingKey(allocator, input, key);
    defer allocator.free(encrypted);

    const encoded = try string_utils.Base64String.init(allocator, encrypted);
    return encoded;
}

fn decrypt(allocator: Allocator, args: *process.ArgIterator) !crypto.DecryptedRepeatingKeyOutput {
    var input_path: []const u8 = undefined;
    const maybe_input_path = args.next();

    if (maybe_input_path) |some_input_path| {
        input_path = some_input_path;
    } else {
        return ProgramError.NotEnoughArguments;
    }

    const min_key_len = 2;
    const max_key_len = 40;

    const cwd = fs.cwd();
    var input_lines = try helpers.readLines(allocator, cwd, input_path, null);
    defer input_lines.deinit();

    const input = try mem.concat(allocator, u8, input_lines.data);
    defer allocator.free(input);

    const b64input = Base64String.initFromBase64(input);

    const root_dir = try fs.openDirAbsolute("/", .{});
    const dict_path = "/usr/share/dict/words";
    var words = try helpers.readLines(allocator, root_dir, dict_path, null);
    defer words.deinit();

    const decrypted = try crypto.breakRepeatingKeyXor(allocator, b64input, min_key_len, max_key_len, words.data);
    return decrypted;
}

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
    const maybe_mode = args_iterator.next();

    var output: []const u8 = undefined;

    if (maybe_mode) |some_mode| {
        if (mem.eql(u8, some_mode, "encrypt")) {
            if (encrypt(allocator, &args_iterator)) |encrypted| {
                output = encrypted.buf;
            } else |err| switch (err) {
                error.NotEnoughArguments => {
                    try stdout.print("usage: {s} encrypt <input_path> <encryption_key>\n", .{program_name});
                    try bw.flush();
                    return err;
                },
                else => return err,
            }
        } else if (mem.eql(u8, some_mode, "decrypt")) {
            if (decrypt(allocator, &args_iterator)) |decrypted| {
                try stdout.print("brute forced encryption key: '{s}'\n", .{decrypted.key});
                output = decrypted.output;
                try stdout.print("BEGIN DECRYPTED TEXT:\n-----\n", .{});
            } else |err| {
                switch (err) {
                    error.NotEnoughArguments => {
                        try stdout.print("usage: {s} decrypt <input_path>\n", .{program_name});
                        try bw.flush();
                    },
                    else => return err,
                }
            }
        } else {
            return ProgramError.UnsupportedMode;
        }
    }

    try stdout.print("{s}\n", .{output});
    try bw.flush();
}
