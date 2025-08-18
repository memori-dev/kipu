const std = @import("std");
const assert = std.debug.assert;

// references
//// https://github.com/Sembiance/dexvert/
//// https://github.com/jsummers/deark
//// https://www.garykessler.net/library/file_sigs.html
//// https://en.wikipedia.org/wiki/List_of_file_signatures
//// https://www.swiftforensics.com/

// TODO full header parsing to get "all" of the metadata from a file and fix magic collisions
// TODO struct to hold the relevant metadata

pub const Format = enum {
	const Self = @This();

	unknown,
	empty,

	pgp_public,
	pgp_private,
	crt,
	bash,
	pwsh,
   perl,
	dos_mz, dos_zm,
	dot_,
	a,
	py_compiled, // TODO https://github.com/python/cpython/blob/5b8664433829ea967c150363cf49a5c4c1380fe8/Lib/importlib/_bootstrap_external.py#L242
	luac,
	typelib,
	elf, // so
	ealf,
	macho,
	tbd,
	rpm,
	selinux,
	xml, // svg
	class,
	mo,
	crx,
	sqlite, sqlite_wal, sqlite_shm,
	icns,
	ico,
	txt,
	ds_store,
	plist,
	mkv,
	mpeg,
	gif,
	jpg,
	jp2,
	png,
	svg,
	bmp,
	pdf, // ai
	itc,
	psd,
	ogg, // opus
	wav,
	avi,
	mp3,
	id3, // TODO can be mp3 / flac / aac / ...
	m4a,
	aac,
	flac,
	midi,
	lzw,
	zip, zip_empty,zip_spanned, // jar, xpi
	pak,
	se7enz,
	gzip,
	nes,
	heic,
	nib,
	mp4,
	tar,
	iso9660,
	cdi,
	dmg,
	mxf,
	aiff,
	amr,
	au,
	deskmate,
	rtf,
	flv,
	html,
	mov,
	otf,
	ttc,
	ra,
	rar,
	swf,
	xz,
	tiff,
	ttf,
	vcf,
	voc,
	webp,
	wmv,
	woff,
	ciso,
	wad,
	itl,
	ics,
	dcp,

	osxChromeServiceWorkerCacheIndex,
	osxChromeServiceWorkerCacheTheRealIndex,
	osxChromeServiceWorkerCacheScript,

	firefoxCacheMorgueFinal,
	firefoxJsonLZ4,

	pub fn parse(f: std.fs.File, size: u64) !Self {
		if (size == 0) return Self.empty;

		var matchedFormat: Self = .unknown;
		var buf: [Signature.maxLen]u8 = undefined;

		for (fileOffsetsSigs) |fos| {
			if (size < fos.offsetBytes) continue;

			const offset: u64 = if (fos.offsetIsFromEnd) size - fos.offsetBytes else fos.offsetBytes;
			try f.seekTo(offset);
			const n = try f.reader().read(&buf);

			for (fos.sigs) |sig| {
				if (n < sig.len) continue;

				// ignore has all useful bits as a 1 and ignored bits as 0
				// sig must also have ignored bits as 0
				var i: usize = 0;
				while (i < sig.len and buf[i] & sig.ignore[i] == sig.sig[i]) : (i += 1) {}

				// check every u8 matched
				if (i != sig.len) continue;

				// match found
				// assert multiple matches should not happen
			   // `or matchedSignature == sig.Format` is used to handle iso9660 since all of the offsets match
				assert(matchedFormat == .unknown or matchedFormat == sig.format);
				matchedFormat = sig.format;
			}
		}

		return matchedFormat;
	}
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
		@setEvalBranchQuota(3800);
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

const fileOffsetsSigs = [_]struct{
	offsetBytes: u64,
	offsetIsFromEnd: bool,
	sigs: []const Signature
}{
	.{
		.offsetBytes = 0,
		.offsetIsFromEnd = false,
		.sigs = &[_]Signature{
			// https://www.swiftforensics.com/2018/11/the-dot-underscore-file-format.html
			Signature.init(Format.dot_,        "00051607",           null),
			Signature.init(Format.ds_store,    "000000014275643100", null),
			Signature.init(Format.plist,       "62706c697374",       null), // bplist
			Signature.init(Format.icns,        "69636e73",           null),
			Signature.init(Format.itl,         "6864666d0000009000", null),

			Signature.init(Format.a,           "213c617263683e0a",             null), // !<arch>.
			Signature.init(Format.elf,         "7f454c46",                     null), // .ELF | TODO elf not matching .so?
			Signature.init(Format.ealf,        "45414c46",                     null), // EALF
			Signature.init(Format.macho,       "feedface",                     null), // 32 bit
			Signature.init(Format.macho,       "feedfacf",                     null), // 64 bit
			Signature.init(Format.macho,       "cefaedfe",                     null), // 32 bit reverse
			Signature.init(Format.macho,       "cffaedfe",                     null), // 64 bit reverse
			Signature.init(Format.typelib,     "474f424a0a4d45544144415441",   null), // GOBJ.METADATA
			Signature.init(Format.html,        "3c21444f43545950452068746d6c", null), // <!DOCTYPE html
			Signature.init(Format.html,        "3c21646f63747970652068746d6c", null), // <!doctype html
			Signature.init(Format.html,        "3c68746d6c",                   null), // <html
			Signature.init(Format.tbd,         "2d2d2d2021746170692d746264",   null), // --- !tapi-tbd

			Signature.init(Format.luac,        "1b4c75615400",                   null), // .LuaT
			// TODO matching for all pyc/pyo versions
			Signature.init(Format.py_compiled, "03f30d0a",                       null), // 2.7
			Signature.init(Format.py_compiled, "420d0d0a",                       null), // 3.7
			Signature.init(Format.py_compiled, "cb0d0d0a",                       null), // 3.12

			Signature.init(Format.nib, "4E494241726368697665", null), // NIBArchive

			// TODO -----BEGIN RSA PRIVATE KEY-----
			Signature.init(Format.pgp_private, "2D2D2D2D2D424547494E205047502050524956415445204B455920424C4F434B2D2D2D2D2D", null), // -----BEGIN PGP PRIVATE KEY BLOCK-----
			Signature.init(Format.pgp_public,  "2D2D2D2D2D424547494E20504750205055424C4943204B455920424C4F434B2D2D2D2D2D",   null), // -----BEGIN PGP PUBLIC KEY BLOCK-----
			Signature.init(Format.crt,         "2D2D2D2D2D424547494E2043455254494649434154452D2D2D2D2D",                     null), // -----BEGIN CERTIFICATE-----

			Signature.init(Format.dos_mz,      "4d5a",     null), // MZ
			Signature.init(Format.dos_zm,      "5a4d",     null), // ZM
			Signature.init(Format.ico,         "00000100", null),

			Signature.init(Format.swf,         "435753", null), // CWS
			Signature.init(Format.swf,         "465753", null), // FWS
			Signature.init(Format.swf,         "5a5753", null), // ZWS

			// TODO matching for all bash types
			Signature.init(Format.bash, "23212F62696E2F7368",                     null), // #!/bin/sh
			Signature.init(Format.bash, "23212F62696E2F62617368",                 null), // #!/bin/bash
			Signature.init(Format.bash, "2321202F62696E2F7368",                   null), // #! /bin/sh
			Signature.init(Format.bash, "2321202F62696E2F62617368",               null), // #! /bin/bash
			Signature.init(Format.bash, "23212F7573722F62696E2F7368",             null), // #!/usr/bin/sh
			Signature.init(Format.bash, "23212F7573722F62696E2F62617368",         null), // #!/usr/bin/bash
			Signature.init(Format.bash, "23212F7573722F62696E2F656E762062617368", null), // #!/usr/bin/env bash
			Signature.init(Format.pwsh, "23212F7573722F62696E2F656E762070777368", null), // #!/usr/bin/env pwsh
			Signature.init(Format.perl, "23212F7573722F62696E2F7065726C",         null), // #!/usr/bin/perl

			Signature.init(Format.class,       "cafebabe",             null), // java class / macho fat
			Signature.init(Format.crx,         "43723234",             null),
			Signature.init(Format.mo,          "de120495",             null),
			Signature.init(Format.rpm,         "edabeedb",             null),
			Signature.init(Format.selinux,     "425a6835314159265359", null), // BZh51AY&SY
			Signature.init(Format.xml,         "3c3f786d6c20",         null),

			Signature.init(Format.sqlite,      "53514c69746520666f726d6174203300", null),
			Signature.init(Format.sqlite_wal,  "377f0682",                         null),
			Signature.init(Format.sqlite_wal,  "377f0683",                         null),
			Signature.init(Format.sqlite_shm,  "18e22d0000000000",                 null),

			Signature.init(Format.otf,         "4f54544f00", null),
			Signature.init(Format.ttc,         "74746366",   null),
			Signature.init(Format.ttf,         "7472756500", null),
			Signature.init(Format.ttf,         "0001000000", null),
			Signature.init(Format.woff,        "774f4646",   null),
			Signature.init(Format.woff,        "774f4632",   null),

			Signature.init(Format.mkv,         "1a45dfa3",                         null), // also webm, mka, mks, mk3d
			Signature.init(Format.mpeg,        "000001bA",                         null), // mpg, mp2, vob
			Signature.init(Format.mpeg,        "000001b3",                         null), // mpg
			Signature.init(Format.mxf,         "060e2b34020501010d0102010102",     null),
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

			Signature.init(Format.dcp, "4949524308000000", null), // IIRC....

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
			Signature.init(Format.ra,          "2e524d460000001200",                           null),
			Signature.init(Format.ra,          "2e7261fd00",                                   null),
			Signature.init(Format.voc,         "437265617469766520566f6963652046696c651a1a00", null),

			Signature.init(Format.deskmate,    "0d444f43",     null),
			Signature.init(Format.pdf,         "255044462d",   null),
			Signature.init(Format.rtf,         "7b5c72746631", null), // {\rtf1

			Signature.init(Format.ics, "424547494E3A5643414C454E444152", null), // BEGIN:VCALENDAR
			Signature.init(Format.vcf, "424547494E3A5643415244",         null), // BEGIN:VCARD

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

			Signature.init(Format.ciso,        "4349534f", null),

			Signature.init(Format.nes,         "4e4553",   null),   // NES
			Signature.init(Format.wad,         "49574144", null), // IWAD

			// osx chrome custom handling
			// ~/Library/Application Support/Google/Chrome/Default/Service Worker/CacheStorage/
			// ~/Library/Caches/Google/Chrome/
			Signature.init(Format.osxChromeServiceWorkerCacheIndex,        "305c72a71b6dfbfc09",               null),
			Signature.init(Format.osxChromeServiceWorkerCacheTheRealIndex, "00000000000000006f79207265746e65", "0000000000000000ffffffffffffffff"),

			// ~/Library/Application Support/Google/Chrome/Default/Service Worker/CacheStorage/uuid/uuid
			// ~/Library/Caches/Google/Chrome/*/Code Cache/wasm/uuid
			// ~/Library/Caches/Google/Chrome/*/Code Cache/js/uuid
			Signature.init(Format.osxChromeServiceWorkerCacheScript, "305c72a71b6dfbfc05000000", null), // 0\r..m......

			Signature.init(Format.firefoxCacheMorgueFinal, "ff060000734e61507059", null),
			Signature.init(Format.firefoxJsonLZ4,          "6d6f7a4c7a343000",     null), // mozLz40.
		}
	},
	.{
		.offsetBytes = 4,
		.offsetIsFromEnd = false,
		.sigs = &[_]Signature{
			Signature.init(Format.heic, "6674797068656963", null), // ftypheic
			Signature.init(Format.heic, "667479706d",       null), // ftypm

			Signature.init(Format.mp4,  "6674797069736f6d", null),
			Signature.init(Format.mp4,  "667479704d534e56", null),
			Signature.init(Format.m4a,  "667479704d344120", null),

			Signature.init(Format.flv,  "667479704d345620", null), // m4v
			Signature.init(Format.mov,  "6674797071742020", null),
		}
	},
	.{
		.offsetBytes = 257,
		.offsetIsFromEnd = false,
		.sigs = &[_]Signature{
			Signature.init(Format.tar, "7573746172003030", null),
			Signature.init(Format.tar, "7573746172202000", null),
		},
	},
	.{
		.offsetBytes = 32769,
		.offsetIsFromEnd = false,
		.sigs = &[_]Signature{
			Signature.init(Format.iso9660, "4344303031", null),
		}
	},
	.{
		.offsetBytes = 34817,
		.offsetIsFromEnd = false,
		.sigs = &[_]Signature{
			Signature.init(Format.iso9660, "4344303031", null),
		}
	},
	.{
		.offsetBytes = 36865,
		.offsetIsFromEnd = false,
		.sigs = &[_]Signature{
			Signature.init(Format.iso9660, "4344303031", null),
		}
	},
	.{
		.offsetBytes = 387785,
		.offsetIsFromEnd = false,
		.sigs = &[_]Signature{
			Signature.init(Format.cdi, "4344303031", null),
		}
	},
	.{
		.offsetBytes = 512,
		.offsetIsFromEnd = true,
		.sigs = &[_]Signature{
			Signature.init(Format.dmg, "6b6f6c79", null),
		}
	},
};
