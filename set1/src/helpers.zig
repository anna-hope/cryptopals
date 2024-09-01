const std = @import("std");
const fs = std.fs;
const testing = std.testing;

const Allocator = std.mem.Allocator;

const default_max_line_len: usize = 2048;

pub const Lines = struct {
    const Self = @This();
    allocator: Allocator,
    data: [][]u8,
    len: usize,

    /// Lines will own the passed data.
    pub fn init(allocator: Allocator, data: [][]u8) Self {
        return Self{ .allocator = allocator, .data = data, .len = data.len };
    }

    pub fn deinit(self: *Self) void {
        for (self.data) |line| {
            defer self.allocator.free(line);
        }

        self.allocator.free(self.data);
    }

    pub fn iter(self: Self) LinesIterator {
        return LinesIterator{ .lines = self };
    }
};

pub const LinesIterator = struct {
    const Self = @This();
    index: usize = 0,
    lines: Lines,

    pub fn next(self: *Self) ?[]u8 {
        if (self.index >= self.lines.len) {
            return null;
        }

        const current_line = self.lines.data[self.index];
        self.index += 1;
        return current_line;
    }
};

pub fn readLines(allocator: Allocator, dir: fs.Dir, relative_path: []const u8, max_line_len: ?usize) !Lines {
    const file = try dir.openFile(relative_path, .{});
    defer file.close();

    const max_size = if (max_line_len) |given_line_len| blk: {
        break :blk given_line_len;
    } else blk: {
        break :blk default_max_line_len;
    };

    const file_reader = file.reader();
    var words = std.ArrayList([]u8).init(allocator);
    while (try file_reader.readUntilDelimiterOrEofAlloc(allocator, '\n', max_size)) |word| {
        try words.append(word[0..word.len]);
    }

    return Lines.init(allocator, try words.toOwnedSlice());
}

test "fast read file lines" {
    const path = "data/4.txt";
    const allocator = testing.allocator;

    var lines = try readLines(allocator, fs.cwd(), path, null);
    defer lines.deinit();

    try testing.expect(lines.len > 0);
}
