const std = @import("std");

var global_io: std.Io = undefined;

fn out(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(global_io, text);
}

const Counts = struct { seen: usize = 0, unseen: usize = 0 };

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    global_io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) {
        try out(allocator, "uso: bypass_audit_zig <registro.json>\n", .{});
        std.process.exit(2);
    }

    const data = try std.Io.Dir.cwd().readFileAlloc(
        global_io, args[1], allocator, std.Io.Limit.limited(16 * 1024 * 1024)
    );
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const sensor = obj.get("sensor") orelse {
        try out(allocator, "sensor declarado obligatorio (G8)\n", .{});
        std.process.exit(2);
    };
    const reps = obj.get("repeticiones") orelse {
        try out(allocator, "faltan repeticiones\n", .{});
        std.process.exit(2);
    };

    var map = std.StringHashMap(Counts).init(allocator);
    for (reps.array.items) |item| {
        const io = item.object;
        const tech = io.get("tecnica") orelse continue;
        const seen_val = io.get("visto") orelse continue;
        const seen = seen_val == .bool and seen_val.bool;
        const entry = try map.getOrPut(tech.string);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        if (seen) entry.value_ptr.seen += 1 else entry.value_ptr.unseen += 1;
    }

    try out(allocator, "sensor={s} | tecnicas={d}\n", .{ sensor.string, map.count() });
    try out(allocator, "| Tecnica | Visto | No visto | Bypass observado |\n|---|---:|---:|---:|\n", .{});
    var it = map.iterator();
    while (it.next()) |entry| {
        const total = entry.value_ptr.seen + entry.value_ptr.unseen;
        const bypass = @as(f64, @floatFromInt(entry.value_ptr.unseen)) / @as(f64, @floatFromInt(total));
        try out(allocator, "| {s} | {d} | {d} | {d:.4} |\n", .{
            entry.key_ptr.*, entry.value_ptr.seen, entry.value_ptr.unseen, bypass,
        });
    }
}

test "estructura Counts" {
    var c = Counts{};
    c.seen += 2;
    c.unseen += 1;
    try std.testing.expectEqual(@as(usize, 3), c.seen + c.unseen);
}
