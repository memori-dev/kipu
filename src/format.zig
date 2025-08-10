const std = @import("std");
const assert = std.debug.assert;

pub const Format = enum {
	empty,

	mkv,
	mpeg,
	flv,
	wmv,
	gif,
	itc,
	jpg,
	jp2,
	png,
	bmp,
	psd,
	svg,
	webp,
	tiff,
	aac,
	au,
	amr,
	aiff,
	ogg,
	wav,
	avi,
	mp3,
	id3,
	flac,
	midi,
	zip,
	zip_empty,
	zip_spanned,
	lzw,
	pak,
	rar,
	se7enz,
	gzip,
	xz,
};

const Signature = struct {
	const Self = @This();
	const maxLen: usize = 64;

	format: Format,

	// sig must have ignored bits as 0
	// ignore has all ignored bits as 0 and useful bits as a 1
	// both must divisible by two, the same length, and <= twice the len of maxLen
	sig:    [Self.maxLen]u8,
	ignore: [Self.maxLen]u8,
	len:    usize,

	fn init(f: Format, hex: []const u8, ignoreHex: ?[]const u8) Self {
		assert(hex.len % 2 == 0);
		assert(hex.len <= Self.maxLen*2);
		if (ignoreHex) |v| assert(v.len == hex.len);

		var sig: [Signature.maxLen]u8 = undefined;
		_ = std.fmt.hexToBytes(&sig, hex) catch unreachable;

		var ignore: [Signature.maxLen]u8 = @splat(255);
		if (ignoreHex) |v| _ = std.fmt.hexToBytes(&ignore, v) catch unreachable;

		return .{
			.format = f,
			.sig    = sig,
			.ignore = ignore,
			.len    = hex.len/2,
		};
	}
};

const fileOffsetsSigs = [_]Signature{
	Signature.init(Format.mkv,         "1a45dfa3",                         null), // also webm, mka, mks, mk3d
	Signature.init(Format.mpeg,        "000001bA",                         null), // mpg, mp2, vob
	Signature.init(Format.mpeg,        "000001b3",                         null), // mpg
	Signature.init(Format.flv,         "464c5601",                         null),
	Signature.init(Format.wmv,         "3026b2758e66cf11a6d900aa0062ce6c", null), // asf, wma

	Signature.init(Format.gif,         "474946383961",                     null),
	Signature.init(Format.gif,         "474946383761",                     null),
	Signature.init(Format.itc,         "0000011c697463680000000200000002", null),
	// TODO test all jpg versions
	Signature.init(Format.jpg,         "ffd8ffdb",                 null),
	Signature.init(Format.jpg,         "ffd8ffe0",                 null),
	Signature.init(Format.jpg,         "ffd8ffee",                 null),
	Signature.init(Format.jpg,         "ffd8ffe1",                 null),
	Signature.init(Format.jpg,         "ffd8ffe2",                 null),
	Signature.init(Format.jp2,         "0000000C6a5020200D0a870a", null),
	Signature.init(Format.jp2,         "ff4fff51",                 null),
	Signature.init(Format.png,         "89504e470d0a1a0a",         null),
	Signature.init(Format.bmp,         "424d",                     null),
	Signature.init(Format.psd,         "38425053",                 null),
	Signature.init(Format.svg,         "3C737667",                 null), // <svg
	Signature.init(Format.webp,        "524946460000000057454250", "ffffffff00000000ffffffff"),

	Signature.init(Format.tiff,        "492049",   null),
	Signature.init(Format.tiff,        "4d4d002a", null),
	Signature.init(Format.tiff,        "49492a00", null),
	Signature.init(Format.tiff,        "49492b00", null),

	Signature.init(Format.aac,         "fff1",                                         null),
	Signature.init(Format.aac,         "fff9",                                         null),
	Signature.init(Format.au,          "2e736e64",                                     null), // snd
	Signature.init(Format.amr,         "2321414d52",                                   null),
	Signature.init(Format.aiff,        "464f524d0000000041494646", "ffffffff00000000ffffffff"),
	Signature.init(Format.ogg,         "4f676753",                                     null), // OggS
	Signature.init(Format.wav,         "524946460000000057415645", "ffffffff00000000ffffffff"),
	Signature.init(Format.avi,         "524946460000000041564920", "ffffffff00000000ffffffff"),
	Signature.init(Format.mp3,         "fffb",                                         null),
	Signature.init(Format.mp3,         "fff3",                                         null),
	Signature.init(Format.mp3,         "fff2",                                         null),
	Signature.init(Format.id3,         "494433",                                       null),
	Signature.init(Format.flac,        "664c6143",                                     null),
	Signature.init(Format.midi,        "4d546864",                                     null),

	// zip OR aar, apk, docx, epub, ipa, jar, kmz, maff, msix, odp, ods, odt, pk3, pk4, pptx, usdz, vsdx, xlsx, xpi 
	Signature.init(Format.zip,         "504b0304",         null),
	Signature.init(Format.zip_empty,   "504b0506",         null),
	Signature.init(Format.zip_spanned, "504b0708",         null),
	Signature.init(Format.lzw,         "1f9d",             null),
	Signature.init(Format.pak,         "0500000001000000", null),
	Signature.init(Format.rar,         "526172211a0700",   null),
	Signature.init(Format.rar,         "526172211a070100", null),
	Signature.init(Format.se7enz,      "377abcaf271c",     null),
	Signature.init(Format.gzip,        "1f8b08",           null),
	Signature.init(Format.xz,          "fd377a585a00",     null),
};
