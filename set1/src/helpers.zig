const std = @import("std");
const fs = std.fs;
const testing = std.testing;

const Allocator = std.mem.Allocator;

pub fn readLines(allocator: Allocator, file_path: []const u8) ![][]u8 {
    const file = try fs.openFileAbsolute(file_path, .{});
    defer file.close();

    const file_reader = file.reader();
    var words = std.ArrayList([]u8).init(allocator);
    while (try file_reader.readUntilDelimiterOrEofAlloc(allocator, '\n', 50)) |word| {
        try words.append(word[0..word.len]);
    }

    return try words.toOwnedSlice();
}

test "read file" {
    const dict_path = "/usr/share/dict/words";
    const allocator = testing.allocator;

    const words = try readLines(allocator, dict_path);
    defer allocator.free(words);

    try testing.expect(words.len > 0);
    try testing.expectEqualStrings("A", words[0]);
    try testing.expectEqualStrings("Zyzzogeton", words[words.len - 1]);

    for (words) |word| {
        defer allocator.free(word);
    }
}
