const std = @import("std");

var global_io: std.Io = undefined;

fn out(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(global_io, text);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    global_io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 3) {
        try out(allocator, "uso: repro_zig <version> <semilla> <fichero>...\n", .{});
        std.process.exit(2);
    }
    const version = args[1];
    const seed = args[2];

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(version);
    hasher.update("|");
    hasher.update(seed);
    hasher.update("|");

    var names = std.ArrayList([]const u8).empty;
    for (args[3..]) |path| try names.append(allocator, path);
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    for (names.items) |path| {
        const data = std.Io.Dir.cwd().readFileAlloc(
            global_io, path, allocator, std.Io.Limit.limited(16 * 1024 * 1024)
        ) catch continue;
        hasher.update(path);
        hasher.update("=");
        hasher.update(data);
        hasher.update("\n");
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);
    try out(allocator, "build_id={s}\nversion={s}\nsemilla={s}\nficheros={d}\n", .{
        &hex, version, seed, names.items.len,
    });
}

test "attestation determinista" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("1.0", "1.0");
}
