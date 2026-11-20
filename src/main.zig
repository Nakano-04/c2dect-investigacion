const std = @import("std");

var global_io: std.Io = undefined;

fn out(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(global_io, text);
}

fn sha256Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);
    return allocator.dupe(u8, &hex);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    global_io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    const manifest_path = if (args.len > 1) args[1] else "artifacts.sha256";

    const manifest = std.Io.Dir.cwd().readFileAlloc(global_io, manifest_path, allocator, std.Io.Limit.limited(16 * 1024 * 1024)) catch |err| {
        try out(allocator, "no se pudo leer {s}: {s}\n", .{ manifest_path, @errorName(err) });
        std.process.exit(2);
    };
    defer allocator.free(manifest);

    var checked: usize = 0;
    var bad: usize = 0;
    var lines = std.mem.splitScalar(u8, manifest, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const expected = fields.next() orelse continue;
        const rel = fields.next() orelse continue;

        const data = std.Io.Dir.cwd().readFileAlloc(global_io, rel, allocator, std.Io.Limit.limited(64 * 1024 * 1024)) catch {
            try out(allocator, "FALTA: {s}\n", .{rel});
            bad += 1;
            continue;
        };
        defer allocator.free(data);

        const actual = try sha256Hex(allocator, data);
        defer allocator.free(actual);
        checked += 1;
        if (!std.mem.eql(u8, expected, actual)) {
            try out(allocator, "CAMBIO: {s} ({s} -> {s})\n", .{ rel, expected, actual });
            bad += 1;
        }
    }

    try out(allocator, "comprobados: {d} | problemas: {d} | resultado: {s}\n", .{
        checked,
        bad,
        if (bad == 0) "OK" else "FAIL",
    });
    if (bad != 0) std.process.exit(1);
}

test "sha256Hex es determinista" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const a = try sha256Hex(gpa.allocator(), "contenido");
    defer gpa.allocator().free(a);
    const b = try sha256Hex(gpa.allocator(), "contenido");
    defer gpa.allocator().free(b);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqual(@as(usize, 64), a.len);
}
