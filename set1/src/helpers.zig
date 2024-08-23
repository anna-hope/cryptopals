const std = @import("std");
const fs = std.fs;
const testing = std.testing;

const Allocator = std.mem.Allocator;

pub fn readLines(allocator: Allocator, dir: fs.Dir, relative_path: []const u8) ![][]u8 {
    const file = try dir.openFile(relative_path, .{});
    defer file.close();

    const file_reader = file.reader();
    var words = std.ArrayList([]u8).init(allocator);
    while (try file_reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 1024)) |word| {
        try words.append(word[0..word.len]);
    }

    return try words.toOwnedSlice();
}

test "fast read file lines" {
    const path = "data/4.txt";
    const allocator = testing.allocator;

    const lines = try readLines(allocator, fs.cwd(), path);
    defer allocator.free(lines);

    try testing.expect(lines.len > 0);

    for (lines) |line| {
        defer allocator.free(line);
    }
}
