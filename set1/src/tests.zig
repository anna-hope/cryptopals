// Need this for `zig build test` to run tests in all files.
// https://stackoverflow.com/a/75762773/2472220
// comptime forces Zig to import the files even if they aren't used
comptime {
    _ = @import("crypto.zig");
    _ = @import("helpers.zig");
    _ = @import("string_utils.zig");
}
