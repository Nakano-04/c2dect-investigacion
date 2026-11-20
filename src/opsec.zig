const std = @import("std");

var global_io: std.Io = undefined;

fn out(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(global_io, text);
}

fn observabilidad(signals: std.json.Value, sensors: std.json.Value) f64 {
    if (sensors != .array or sensors.array.items.len == 0) return 0;
    var total: i64 = 0;
    for (sensors.array.items) |sensor| {
        const s = sensor.string;
        if (signals == .object) {
            if (signals.object.get(s)) |v| {
                const raw: i64 = if (v == .integer) v.integer else if (v == .float) @intFromFloat(v.float) else 0;
                total += @min(3, @max(0, raw));
            }
        }
    }
    const max: f64 = @as(f64, @floatFromInt(3 * sensors.array.items.len));
    return @round((@as(f64, @floatFromInt(total)) / max) * 10000) / 10000;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    global_io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) {
        try out(allocator, "uso: opsec_zig <tecnicas.json>\n", .{});
        std.process.exit(2);
    }

    const data = try std.Io.Dir.cwd().readFileAlloc(
        global_io, args[1], allocator, std.Io.Limit.limited(16 * 1024 * 1024)
    );
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    try out(allocator, "| Tecnica | Observabilidad |\n|---|---:|\n", .{});
    for (parsed.value.array.items) |item| {
        const obj = item.object;
        const id = obj.get("id") orelse continue;
        const signals = obj.get("signals") orelse .null;
        const sensors = obj.get("sensors_assumed") orelse .null;
        const score = observabilidad(signals, sensors);
        try out(allocator, "| {s} | {d:.4} |\n", .{ id.string, score });
    }
}

test "observabilidad con pesos" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parsed = try std.json.parseFromSlice(std.json.Value, a,
        "{\"signals\":{\"process\":2,\"network\":3},\"sensors_assumed\":[\"process\",\"network\"]}", .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectApproxEqAbs(@as(f64, 0.8333),
        observabilidad(obj.get("signals").?, obj.get("sensors_assumed").?), 0.0001);
}
