const std = @import("std");
const fs = std.fs;
const testing = std.testing;

const Allocator = std.mem.Allocator;

pub fn readLines(allocator: Allocator, file_path: []const u8) ![][]u8 {
    const file = try fs.openFileAbsolute(file_path, .{});
    defer file.close();

    const file_reader = file.reader();
    var words = std.ArrayList([]u8).init(allocator);
    while (try file_reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 1024)) |word| {
        try words.append(word[0..word.len]);
    }

    return try words.toOwnedSlice();
}

test "read file" {
    const path = "/Users/annahope/projects/rc/cryptopals/set1/data/4.txt";
    const allocator = testing.allocator;

    const lines = try readLines(allocator, path);
    defer allocator.free(lines);

    try testing.expect(lines.len > 0);

    for (lines) |line| {
        defer allocator.free(line);
    }
}
