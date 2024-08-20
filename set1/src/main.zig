const std = @import("std");
const crypto = @import("crypto.zig");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});


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

test "hex to base64" {
    const allocator = std.testing.allocator;
    const source = try allocator.alloc(u8, 100);
    defer allocator.free(source);

    std.mem.copyForwards(u8, source, "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");

    var hex_len: usize = 0;
    while (hex_len < source.len) {
        var current_char_is_hex = false;
        for (std.fmt.hex_charset) |char| {
            if (source[hex_len] == char) {
                current_char_is_hex = true;
            }
        }

        if (!current_char_is_hex) {
            break;
        }

        hex_len += 1;
    }

    const output = try crypto.hexToBase64(source[0..hex_len], allocator);
    defer allocator.free(output);

    const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    try std.testing.expectStringStartsWith(output, expected);
}

test "fixed xor" {
    const buf1 = "1c0111001f010100061a024b53535009181c";
    const buf2 = "686974207468652062756c6c277320657965";

    const allocator = std.testing.allocator;
    const out = try crypto.fixedXor(buf1, buf2, allocator);
    defer allocator.free(out);

    const expected = "746865206b696420646f6e277420706c6179";
    try std.testing.expectStringStartsWith(out, expected);
}