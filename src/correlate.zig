const std = @import("std");

var global_io: std.Io = undefined;

fn out(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(text);
    try std.Io.File.stdout().writeStreamingAll(global_io, text);
}

const Event = struct {
    host: []const u8,
    pid: i64,
    event_type: []const u8,
    t: f64,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    global_io = init.io;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 3) {
        try out(allocator, "uso: correlate_zig <eventos.json> <ventana_segundos>\n", .{});
        std.process.exit(2);
    }
    const window = std.fmt.parseFloat(f64, args[2]) catch 60.0;

    const data = try std.Io.Dir.cwd().readFileAlloc(
        global_io, args[1], allocator, std.Io.Limit.limited(16 * 1024 * 1024)
    );
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, data, .{});
    defer parsed.deinit();

    var events = std.ArrayList(Event).empty;
    for (parsed.value.array.items) |item| {
        const o = item.object;
        const host = o.get("host") orelse continue;
        const pid_v = o.get("pid") orelse continue;
        const et = o.get("event_type") orelse continue;
        const t_v = o.get("t") orelse continue;
        const pid: i64 = if (pid_v == .integer) pid_v.integer else 0;
        const t: f64 = if (t_v == .float) t_v.float else if (t_v == .integer) @floatFromInt(t_v.integer) else 0;
        try events.append(allocator, .{
            .host = host.string, .pid = pid, .event_type = et.string, .t = t,
        });
    }

    var caught: usize = 0;
    var landed: usize = 0;
    for (events.items, 0..) |seed, i| {
        if (!std.mem.eql(u8, seed.event_type, "param_poison")) continue;

        var have_rx = false;
        var have_hijack = false;
        for (events.items, 0..) |other, j| {
            if (j == i) continue;
            if (!std.mem.eql(u8, other.host, seed.host) or other.pid != seed.pid) continue;
            if (other.t < seed.t or other.t - seed.t > window) continue;
            if (std.mem.eql(u8, other.event_type, "peb_rx")) have_rx = true;
            if (std.mem.eql(u8, other.event_type, "thread_hijack")) have_hijack = true;
        }
        if (have_rx and have_hijack) caught += 1 else landed += 1;
    }

    try out(allocator,
        "cadena P3: param_poison -> peb_rx -> thread_hijack | ventana={d}s\n" ++
        "caught={d} | landed={d}\n",
        .{ window, caught, landed },
    );
}

test "Event struct" {
    const e = Event{ .host = "h", .pid = 1, .event_type = "peb_rx", .t = 1.0 };
    try std.testing.expectEqualStrings("peb_rx", e.event_type);
}
