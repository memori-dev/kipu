const std = @import("std");
const builtin = @import("builtin");
const Format = @import("format.zig").Format;

// TODO update to >= 0.15.0 and remove this (unable to just yet as std.fs.File.metadata was removed)
const group = switch (builtin.os.tag) {
    .linux, .freebsd, .openbsd, .dragonfly, .netbsd, .macos => extern struct {
        name: ?[*:0]const u8,
        passwd: ?[*:0]const u8,
        gid: std.c.gid_t,
        mem: [*:null]?[*:0]const u8,
    },
    else => void,
};
extern "c" fn getgrgid(gid: std.c.gid_t) ?*group;
// TODO remove up to here

fn hashFile(f: std.fs.File) !u160 {
	// ensure the offset is 0
	try f.seekTo(0);

	var sha = std.crypto.hash.Sha1.init(.{});
	const rdr = f.reader();
	var buf: [4096]u8 = undefined;
	var n = try rdr.read(&buf);
	while (n != 0): (n = try rdr.read(&buf)) {
		_ = sha.update(buf[0..n]);
	}

	return std.mem.readInt(u160, &(sha.finalResult()), .big);
}

pub const Metadata = struct {
	const Self = @This();

	const fieldCount = std.meta.fields(Self).len;
	// TODO temporary, switch to msgpack
	const delimiter = '|';

	path: []const u8,
	fmt:  Format,
	size: u64,
	hash: u160,

	perms: u9,
	user:  []const u8,
	group: []const u8,

	created:  u32,
	accessed: u32,
	modified: u32,
	changed:  u32,

	pub fn new(allocator: std.mem.Allocator, path: []const u8) !Self {
		const f = try std.fs.openFileAbsolute(path, .{});

		const stat = try f.stat();
		const size = stat.size;

		const meta = try f.metadata();
		const statx = meta.inner.statx;

		const pwu = std.c.getpwuid(statx.uid) orelse return error.UnknownUserForUid;
		const uName = pwu.*.name orelse return error.UnknownUserName;

		// TODO update to >= 0.15.0 and change getgrgid to std.c.getgrgid (unable to just yet as std.fs.File.metadata was removed)
		const gwu = getgrgid(statx.gid) orelse return error.UnknownGroupForGid;
		const gName = gwu.*.name orelse return error.UnknownGroupName;

		return .{
			.path = try allocator.dupe(u8, path),
			.fmt  = try Format.parse(f, size),
			.size = size,
			.hash = if (size == 0) 0 else try hashFile(f),

			.user  = try allocator.dupe(u8, std.mem.span(uName)),
			.group = try allocator.dupe(u8, std.mem.span(gName)),
			.perms = @intCast(stat.mode & 0o777),

			.created  = @intCast(statx.btime.sec),
			.accessed = @intCast(statx.atime.sec),
			.modified = @intCast(statx.mtime.sec),
			.changed  = @intCast(statx.ctime.sec),
		};
	}

	pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
		try writer.print("{s}{c}{s}{c}{d}{c}{d}{c}{o}{c}{s}{c}{s}{c}{d}{c}{d}{c}{d}{c}{d}", .{
			self.path,          Self.delimiter,
			@tagName(self.fmt), Self.delimiter,
			self.size,          Self.delimiter,
			self.hash,          Self.delimiter,
			self.perms,         Self.delimiter,
			self.user,          Self.delimiter,
			self.group,         Self.delimiter,
			self.created,       Self.delimiter,
			self.accessed,      Self.delimiter,
			self.modified,      Self.delimiter,
			self.changed,
		});
   }

   // TODO use std.meta.fields
   pub fn decode(allocator: std.mem.Allocator, line: []const u8) !Self {
		var it = std.mem.splitScalar(u8, line, Self.delimiter);

		var split: [Self.fieldCount][]const u8 = undefined;
		var i: usize = 0;
		while (it.next()) |v| {
			split[i] = v;
			i += 1;
		}
		if (i != Self.fieldCount) return error.invalidInputCount;

		return .{
			.path = try allocator.dupe(u8, split[0]),
			.fmt  = std.meta.stringToEnum(Format, split[1]).?,
			.size = try std.fmt.parseInt(u64, split[2], 10),
			.hash = try std.fmt.parseInt(u64, split[3], 10),

			.perms = try std.fmt.parseInt(u9, split[4], 8),
			.user  = try allocator.dupe(u8, split[5]),
			.group = try allocator.dupe(u8, split[6]),

			.created  = try std.fmt.parseInt(u32, split[7],  10),
			.accessed = try std.fmt.parseInt(u32, split[8],  10),
			.modified = try std.fmt.parseInt(u32, split[9],  10),
			.changed  = try std.fmt.parseInt(u32, split[10], 10),
		};
   }
};
