const std = @import("std");
const crypto = @import("crypto.zig");

pub fn main() !void {
    const input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    std.debug.print("{s}\n", .{input});

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    // const stdout_file = std.io.getStdOut().writer();
    // var bw = std.io.bufferedWriter(stdout_file);
    // const stdout = bw.writer();
    //
    // try stdout.print("Run `zig build test` to run the tests.\n", .{});
    //
    // try bw.flush(); // don't forget to flush!
}
