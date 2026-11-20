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
    if (args.len < 2) {
        try out(allocator, "uso: footprint_zig <eventos.json>\n", .{});
        std.process.exit(2);
    }

    const data = try std.Io.Dir.cwd().readFileAlloc(
        global_io, args[1], allocator, std.Io.Limit.limited(16 * 1024 * 1024)
    );
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    var pairs = std.ArrayList([]const u8).empty;
    for (parsed.value.array.items) |item| {
        const obj = item.object;
        const et = obj.get("event_type") orelse continue;
        const tech = obj.get("technique") orelse continue;
        const pair = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ et.string, tech.string });
        try pairs.append(allocator, pair);
    }
    std.mem.sort([]const u8, pairs.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (pairs.items) |pair| {
        hasher.update(pair);
        hasher.update("\n");
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);
    try out(allocator, "{s}\n", .{&hex});
}

test "footprint es estable" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSlice(std.json.Value, a,
        "[{\"event_type\":\"process_create\",\"technique\":\"T1059\"}]", .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
}
