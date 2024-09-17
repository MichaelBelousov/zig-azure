const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const proc = std.process;

const t = std.testing;

const c = @cImport({
    @cInclude("time.h");
});

pub const Account = struct {
    name: []const u8,
    key: []const u8,
};

/// NOTE: this is the only supported API version
/// https://learn.microsoft.com/en-us/rest/api/storageservices/service-sas-examples#blob-examples
pub const version: []const u8 = "2015-02-21";

fn findHeader(haystack: []const std.http.Header, needle: []const u8) ?[]const u8 {
    for (haystack) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, needle)) {
            return header.value;
        }
    }
    return null;
}

pub const SharedKey = struct {
    const CanonicalizedHeaderString = struct {
        requestOptions: std.http.Client.FetchOptions,

        // FIXME: duplicates have not been removed!
        pub fn format(
            self: @This(),
            comptime fmt_str: []const u8,
            fmt_opts: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = fmt_str;
            _ = fmt_opts;

            // NOTE: any amount of x-ms-meta-NAME headers can be used...
            const MAX_HEADERS = 32;
            const Header = std.http.Header;

            //const headers_buff: [@sizeOf(Header) * MAX_HEADERS]u8 align(@alignOf(Header)) = undefined;
            var headers_buff: [MAX_HEADERS]Header = undefined;

            const x_ms_prefixed_headers_count = blk: {
                var result: usize = 0;
                for (self.requestOptions.extra_headers) |header| {
                    if (std.ascii.startsWithIgnoreCase(header.name, "x-ms-")) {
                        result += 1;
                    }
                }
                break :blk result;
            };

            std.debug.assert(x_ms_prefixed_headers_count <= MAX_HEADERS);

            const x_ms_prefixed_headers: []Header = headers_buff[0..x_ms_prefixed_headers_count];

            {
                var i: usize = 0;
                for (self.requestOptions.extra_headers) |header| {
                    if (std.ascii.startsWithIgnoreCase(header.name, "x-ms-")) {
                        x_ms_prefixed_headers[i] = header;
                        i += 1;
                    }
                }
            }

            const HeaderNameLessThan = struct {
                fn impl(_: void, a: Header, b: Header) bool {
                    return std.ascii.lessThanIgnoreCase(a.name, b.name);
                }
            };

            std.sort.pdq(Header, x_ms_prefixed_headers, {}, HeaderNameLessThan.impl);

            for (x_ms_prefixed_headers, 0..) |header, i| {
                var lowercase_buf: [128]u8 = undefined;
                const lowered_name = std.ascii.lowerString(&lowercase_buf, header.name);
                _ = try writer.write(lowered_name);
                _ = try writer.write(":");
                _ = try writer.write(header.value);
                if (i != x_ms_prefixed_headers.len - 1) {
                    _ = try writer.write("\n");
                }
            }
        }

        test "format CanonicalizedHeaderString" {
            const formatted = std.fmt.comptimePrint("{}", .{CanonicalizedHeaderString{
                .requestOptions = .{
                    .method = .GET,
                    .location = .{ .url = "http://test" },
                    .extra_headers = &.{
                        // out of alphabetical order and random casing
                        .{ .name = "x-MS-version", .value = version },
                        .{ .name = "X-MS-DATE", .value = "DATE" },
                    },
                },
            }});
            try t.expectEqualStrings(
                \\x-ms-date:DATE
                \\x-ms-version:2015-02-21
            , formatted);
        }
    };

    const CanonicalizedResourceString = struct {
        requestOptions: std.http.Client.FetchOptions,
        account: Account,

        pub fn format(
            self: @This(),
            comptime fmt_str: []const u8,
            fmt_opts: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = fmt_str;
            _ = fmt_opts;

            std.debug.assert(self.requestOptions.location == .uri);

            const uri = self.requestOptions.location.uri;

            const path = if (uri.path.percent_encoded.len == 0) "/" else uri.path.percent_encoded;
            _ = try writer.print("/{s}{s}", .{ self.account.name, path });

            const query = if (uri.query) |q| q.percent_encoded else "";

            const MAX_PARAMS = 64;
            const Param = struct { name: []const u8, value: []const u8 };
            var params_buff: [MAX_PARAMS]Param = undefined;

            // TODO: use a real query parser
            const params = blk: {
                var query_param_iter = std.mem.splitScalar(u8, query, '&');
                var i: usize = 0;
                while (query_param_iter.next()) |param| {
                    const name = std.mem.sliceTo(param, '=');
                    const val: ?[]const u8 = if (name.len != param.len) param[name.len + 1 ..] else null;
                    if (val == null)
                        continue;
                    // TODO: use non-debug asserts
                    std.debug.assert(i < params_buff.len);
                    params_buff[i] = .{ .name = name, .value = val.? };
                    i += 1;
                }
                break :blk params_buff[0..i];
            };

            const ParamNameLessThan = struct {
                fn impl(_: void, a: Param, b: Param) bool {
                    return std.ascii.lessThanIgnoreCase(a.name, b.name);
                }
            };

            std.sort.pdq(Param, params, {}, ParamNameLessThan.impl);

            for (params) |param| {
                _ = try writer.write("\n");
                var lowercase_buf: [128]u8 = undefined;
                const lowered_name = std.ascii.lowerString(&lowercase_buf, param.name);
                _ = try writer.write(lowered_name);
                _ = try writer.write(":");
                // FIXME: uridecode the value
                _ = try writer.write(param.value);
            }
        }

        test "format CanonicalizedResourceString" {
            const uri = std.Uri{
                .host = .{ .percent_encoded = "example.com" },
                .query = .{ .percent_encoded = "a=2&BOB=alice&JOHN&tame=&manny=Calvera" },
                .path = .{ .percent_encoded = "/api/thing" },
                .scheme = "https",
            };

            const formatted = std.fmt.comptimePrint("{}", .{CanonicalizedResourceString{
                .requestOptions = .{
                    .method = .GET,
                    .location = .{ .uri = uri },
                    .extra_headers = &.{
                        // out of alphabetical order and random casing
                        .{ .name = "x-MS-version", .value = version },
                        .{ .name = "X-MS-DATE", .value = "DATE" },
                    },
                },
                .account = .{
                    .name = "ACCOUNT_NAME",
                    .key = "ACCOUNT_KEY",
                },
            }});

            try t.expectEqualStrings(
                \\/ACCOUNT_NAME/api/thing
                \\a:2
                \\bob:alice
                \\manny:Calvera
                \\tame:
            , formatted);
        }
    };

    pub fn getUtcTime(a: std.mem.Allocator) []const u8 {
        const date_buff = a.alloc(u8, 128) catch unreachable;
        defer a.free(date_buff);

        const timer = c.time(null);
        const tm_info = c.gmtime(&timer);
        _ = c.strftime(date_buff.ptr, date_buff.len, "%a, %d %b %Y %T GMT", tm_info);

        const date = a.dupe(u8, std.mem.sliceTo(date_buff, 0)) catch unreachable;

        return date;
    }

    pub fn authorize(reqOpts: std.http.Client.FetchOptions, opts: struct {
        allocator: std.mem.Allocator,
        date: []const u8,
        account: Account,
    }) []const u8 {
        const Base64Decoder = std.base64.standard.Decoder;
        // TODO: error handling
        const decoded_key = opts.allocator.alloc(u8, Base64Decoder.calcSizeForSlice(opts.account.key) catch unreachable) catch unreachable;
        defer opts.allocator.free(decoded_key);

        Base64Decoder.decode(decoded_key, opts.account.key) catch unreachable;

        var input_buff: [1024]u8 = undefined;

        const content_len = if (reqOpts.payload) |p| p.len else 0;
        // FIXME: calculate max required space
        var len_buff: [24]u8 = undefined;
        const content_len_str = if (content_len > 0) std.fmt.bufPrint(&len_buff, "{}", .{content_len}) catch unreachable else "";

        //https://github.com/Azure/azure-sdk-for-js/blob/main/sdk/storage/storage-blob/src/policies/StorageSharedKeyCredentialPolicy.ts#L43
        const signature_input = std.fmt.bufPrint(
            &input_buff,
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{}
            \\{}
        ,
            .{
                @tagName(reqOpts.method.?),
                findHeader(reqOpts.extra_headers, "Content-Language") orelse "",
                findHeader(reqOpts.extra_headers, "Content-Encoding") orelse "",
                content_len_str,
                findHeader(reqOpts.extra_headers, "Content-Md5") orelse "",
                switch (reqOpts.headers.content_type) {
                    .override => |v| v,
                    else => "",
                },
                findHeader(reqOpts.extra_headers, "Date") orelse "",
                findHeader(reqOpts.extra_headers, "if-modified-since") orelse "",
                findHeader(reqOpts.extra_headers, "if-match") orelse "",
                findHeader(reqOpts.extra_headers, "if-none-match") orelse "",
                findHeader(reqOpts.extra_headers, "if-unmodified-since") orelse "",
                findHeader(reqOpts.extra_headers, "Range") orelse "",
                CanonicalizedHeaderString{ .requestOptions = reqOpts },
                CanonicalizedResourceString{ .requestOptions = reqOpts, .account = opts.account },
            },
        ) catch unreachable;

        const debug = std.posix.getenv("DEBUG") != null;

        if (debug) std.debug.print("SIGNATURE INPUT:\n{s}\nEND SIGNATURE INPUT\n", .{signature_input});

        const signature_input_urldecoded = std.Uri.percentDecodeInPlace(signature_input);

        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var hash_buff: [HmacSha256.mac_length]u8 = undefined;

        HmacSha256.create(&hash_buff, signature_input_urldecoded, decoded_key);

        const Base64Encoder = std.base64.standard.Encoder;
        const encoded_sig = opts.allocator.alloc(u8, Base64Encoder.calcSize(hash_buff.len)) catch unreachable;
        defer opts.allocator.free(encoded_sig);

        _ = Base64Encoder.encode(encoded_sig, &hash_buff);

        if (debug) std.debug.print("BASE64 SIGNATURE:\n{s}\n", .{encoded_sig});

        const authorization = std.fmt.allocPrint(
            opts.allocator,
            "SharedKey {s}:{s}",
            .{ opts.account.name, encoded_sig },
        ) catch unreachable;

        if (debug) std.debug.print("AUTH:\n{s}\n", .{authorization});

        return authorization;
    }
};

/// caller must dealloc
pub fn get8601UtcTime(a: std.mem.Allocator, opts: struct { offset_sec: c_int = 0 }) []const u8 {
    // FIXME: why not use a stack buffer
    const date_buff = a.alloc(u8, 128) catch unreachable;
    defer a.free(date_buff);

    var timer = c.time(null);

    var tm_info: c.tm = undefined;
    _ = c.localtime_r(&timer, &tm_info);

    // TODO: why does it seem when checking that timezone is an hour off?
    // (gnu's tm.tm_gmtoff is 14400 but timezone is 18000)
    c.tzset();
    tm_info.tm_sec += opts.offset_sec + @as(c_int, @intCast(c.timezone));
    // normalizes the time struct
    _ = c.mktime(&tm_info);

    _ = c.strftime(date_buff.ptr, date_buff.len, "%Y-%m-%dT%H:%M:%SZ", &tm_info);

    const date = a.dupe(u8, std.mem.sliceTo(date_buff, 0)) catch unreachable;

    return date;
}

fn isNotBase64Char(_c: u8) bool {
    const isBase64Char = switch (_c) {
        '+', '/' => true,
        else => false,
    };
    return !isBase64Char;
}

fn isNotColon(_c: u8) bool {
    return _c != ':';
}

/// https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas
pub const ServiceSas = struct {

    // NOTE: non-blobstorage fields are ignored, blob-storage only fields area considered
    pub const Fields = struct {
        /// year/month/day
        version: []const u8 = "2015-04-05",
        // subset of "bqtf"
        services: []const u8 = "",
        // subset of "bcd" with addons "vs"
        resource: []const u8 = "",
        /// year/month/day
        start: ?[]const u8 = null,
        /// year/month/day
        expiry: []const u8 = "",
        /// ordered subset of "racwdxltmeop"
        permissions: []const u8 = "",
        identifier: ?[]const u8 = null,
        ip: ?[]const u8 = null,
        protocol: ?[]const u8 = null,
        // some of these are only for later versions that this doesn't yet support
        directoryDepth: ?u64 = null,
        encryptionScope: ?[]const u8 = null,
        response: ?struct {
            contentDisposition: ?[]const u8 = null,
            contentEncoding: ?[]const u8 = null,
            contentLanguage: ?[]const u8 = null,
            contentType: ?[]const u8 = null,
            cacheControl: ?[]const u8 = null,
        } = null,

        const ResourceType = enum(u16) {
            blob = parse("b"),
            blobSnapshot = parse("bs"),
            blobVersion = parse("bv"),
            container = parse("c"),
            directory = parse("d"),

            // copying std.http.Method hack
            pub fn parse(src: []const u8) ?u16 {
                if (std.mem.eql(u8, src, "b")) {
                    return @as(*u16, @ptrCast("b\x00".ptr)).*;
                } else if (std.mem.eql(u8, src, "bv")) {
                    return @as(*u16, @ptrCast("bv".ptr)).*;
                } else if (std.mem.eql(u8, src, "bs")) {
                    return @as(*u16, @ptrCast("bs".ptr)).*;
                } else if (std.mem.eql(u8, src, "c")) {
                    return @as(*u16, @ptrCast("c\x00".ptr)).*;
                } else if (std.mem.eql(u8, src, "d")) {
                    return @as(*u16, @ptrCast("d\x00".ptr)).*;
                } else {
                    return null;
                }
            }

            pub fn string(self: @This()) []const u8 {
                switch (self) {
                    .blob => "b",
                    .blobSnapshot => "bs",
                    .blobVersion => "bv",
                    .container => "c",
                    .directory => "d",
                }
            }
        };
    };

    fields: Fields,
    signature: []const u8,

    const CanonicalizedResourceString = struct {
        serviceType: []const u8 = "blob",
        account_name: []const u8,
        // NOTE: includes the leading '/'
        path: []const u8,

        pub fn format(
            self: @This(),
            comptime fmt_str: []const u8,
            fmt_opts: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = fmt_str;
            _ = fmt_opts;

            _ = try writer.print("/{s}/{s}{s}", .{ self.serviceType, self.account_name, self.path });
        }

        test "format ServiceSas blob CanonicalizedResourceString" {
            // URL = https://myaccount.blob.core.windows.net/music/intro.mp3
            const formatted = std.fmt.comptimePrint("{}", .{ServiceSas.CanonicalizedResourceString{
                .path = "music/intro.mp3",
            }});

            try t.expectEqualStrings("/blob/myaccount/music/intro.mp3", formatted);
        }
    };

    /// path must contain the leading '/'
    /// if in azurite, make sure "NOT" to contain the root part of the path that is the account name
    pub fn sign(a: std.mem.Allocator, fields: Fields, path: []const u8, account: Account) ServiceSas {
        const Base64Decoder = std.base64.standard.Decoder;
        // TODO: error handling

        // TODO: we know key size, use an exact size buffer
        var key_buff: [128]u8 = undefined;
        const decoded_key = key_buff[0 .. Base64Decoder.calcSizeForSlice(account.key) catch unreachable];

        Base64Decoder.decode(decoded_key, account.key) catch unreachable;

        // FIXME: paths that are too long will crash
        var input_buff: [2048]u8 = undefined;

        const signature_input = std.fmt.bufPrint(
            &input_buff,
            \\{s}
            \\{s}
            \\{s}
            \\{}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
        ,
            .{
                fields.permissions,
                fields.start orelse "",
                fields.expiry,
                ServiceSas.CanonicalizedResourceString{ .path = path, .account_name = account.name },
                fields.identifier orelse "",
                fields.ip orelse "",
                fields.protocol orelse "",
                fields.version,
                (if (fields.response) |r| r.cacheControl else null) orelse "",
                (if (fields.response) |r| r.contentDisposition else null) orelse "",
                (if (fields.response) |r| r.contentEncoding else null) orelse "",
                (if (fields.response) |r| r.contentLanguage else null) orelse "",
                (if (fields.response) |r| r.contentType else null) orelse "",
            },
        ) catch unreachable;

        // TODO: only in debug mode
        std.debug.print("SIGNATURE INPUT:\n", .{});
        std.json.stringify(signature_input, .{}, std.io.getStdErr().writer()) catch unreachable;
        std.debug.print("\n", .{});

        const signature_input_urldecoded = std.Uri.percentDecodeInPlace(signature_input);

        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var hash_buff: [HmacSha256.mac_length]u8 = undefined;

        HmacSha256.create(&hash_buff, signature_input_urldecoded, decoded_key);

        const Base64Encoder = std.base64.standard.Encoder;
        const encoded_sig = a.alloc(u8, Base64Encoder.calcSize(hash_buff.len)) catch unreachable;

        _ = Base64Encoder.encode(encoded_sig, &hash_buff);

        std.debug.print("BASE64 SIGNATURE:\n{s}\n", .{encoded_sig});

        return .{
            .fields = fields,
            .signature = encoded_sig,
        };
    }

    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.signature);
    }

    pub fn uri(self: @This()) AsUri {
        return AsUri{ .sas = self };
    }

    const blob = Fields{
        .version = "2015-04-05",
        .resource = "b",
    };

    pub const AsUri = struct {
        sas: ServiceSas,

        // TODO: format
        pub fn format(
            self: @This(),
            comptime fmt_str: []const u8,
            fmt_opts: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            // TODO: print everything through a wrapping percent encoding writer
            _ = fmt_str;
            _ = fmt_opts;
            _ = try writer.print("sp={s}", .{self.sas.fields.permissions});

            if (self.sas.fields.start) |st| {
                // _ = try writer.print("&st={s}", .{st});
                _ = try writer.print("&st=", .{});
                try std.Uri.Component.percentEncode(writer, st, isNotColon);
            }

            //_ = try writer.print("&se={s}", .{self.sas.fields.expiry});
            _ = try writer.print("&se=", .{});
            try std.Uri.Component.percentEncode(writer, self.sas.fields.expiry, isNotColon);

            if (self.sas.fields.identifier) |si|
                _ = try writer.print("&si={s}", .{si});
            if (self.sas.fields.ip) |sip|
                _ = try writer.print("&sip={s}", .{sip});
            if (self.sas.fields.protocol) |spr|
                _ = try writer.print("&spr={s}", .{spr});
            if (self.sas.fields.directoryDepth) |sdd|
                _ = try writer.print("&sdd={}", .{sdd});
            if (self.sas.fields.encryptionScope) |ses|
                _ = try writer.print("&ses={s}", .{ses});
            if (self.sas.fields.response != null and self.sas.fields.response.?.cacheControl != null)
                _ = try writer.print("&rscc={s}", .{self.sas.fields.response.?.cacheControl.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentDisposition != null)
                _ = try writer.print("&rscd={s}", .{self.sas.fields.response.?.contentDisposition.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentEncoding != null)
                _ = try writer.print("&rsce={s}", .{self.sas.fields.response.?.contentEncoding.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentLanguage != null)
                _ = try writer.print("&rscl={s}", .{self.sas.fields.response.?.contentLanguage.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentType != null)
                _ = try writer.print("&rsct={s}", .{self.sas.fields.response.?.contentType.?});
            _ = try writer.print("&sv={s}", .{self.sas.fields.version});
            _ = try writer.print("&sr={s}", .{self.sas.fields.resource});
            _ = try writer.print("&sig=", .{});
            try std.Uri.Component.percentEncode(writer, self.sas.signature, isNotBase64Char);
        }
    };
};

/// https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas
pub const AccountSas = struct {
    pub const Fields = ServiceSas.Fields;

    fields: Fields,
    signature: []const u8,

    const CanonicalizedResourceString = ServiceSas.CanonicalizedResourceString;

    pub fn sign(a: std.mem.Allocator, fields: Fields, account: Account) ServiceSas {
        const Base64Decoder = std.base64.standard.Decoder;
        // TODO: error handling

        // TODO: we know key size, use an exact size buffer
        var key_buff: [128]u8 = undefined;
        const decoded_key = key_buff[0 .. Base64Decoder.calcSizeForSlice(account.key) catch unreachable];

        Base64Decoder.decode(decoded_key, account.key) catch unreachable;

        var input_buff: [1024]u8 = undefined;

        const signature_input = std.fmt.bufPrint(
            &input_buff,
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\{s}
            \\
        ,
            .{
                account.name,
                fields.permissions,
                fields.services,
                fields.resource,
                fields.start orelse "",
                fields.expiry,
                fields.ip orelse "",
                fields.protocol orelse "",
                fields.version,
            },
        ) catch unreachable;

        const signature_input_urldecoded = std.Uri.percentDecodeInPlace(signature_input);

        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var hash_buff: [HmacSha256.mac_length]u8 = undefined;

        HmacSha256.create(&hash_buff, signature_input_urldecoded, decoded_key);

        const Base64Encoder = std.base64.standard.Encoder;
        const encoded_sig = a.alloc(u8, Base64Encoder.calcSize(hash_buff.len)) catch unreachable;

        _ = Base64Encoder.encode(encoded_sig, &hash_buff);

        return .{
            .fields = fields,
            .signature = encoded_sig,
        };
    }

    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.signature);
    }

    pub fn uri(self: @This()) AsUri {
        return AsUri{ .sas = self };
    }

    const blob = Fields{
        .version = "2015-04-05",
        .resource = "b",
    };

    pub const AsUri = struct {
        sas: ServiceSas,

        // TODO: format
        pub fn format(
            self: @This(),
            comptime fmt_str: []const u8,
            fmt_opts: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = fmt_str;
            _ = fmt_opts;
            _ = try writer.print("sv={s}", .{self.sas.fields.version});
            _ = try writer.print("&sig=", .{});
            try std.Uri.Component.percentEncode(writer, self.sas.signature, isNotBase64Char);
            _ = try writer.print("&ss={s}", .{self.sas.fields.services});
            _ = try writer.print("&srt={s}", .{self.sas.fields.resource});
            _ = try writer.print("&sp={s}", .{self.sas.fields.permissions});
            _ = try writer.print("&se={s}", .{self.sas.fields.expiry});
            if (self.sas.fields.identifier) |si|
                _ = try writer.print("&si={s}", .{si});
            if (self.sas.fields.directoryDepth) |sdd|
                _ = try writer.print("&sdd={}", .{sdd});
            if (self.sas.fields.start) |st|
                _ = try writer.print("&st={s}", .{st});
            if (self.sas.fields.ip) |sip|
                _ = try writer.print("&sip={s}", .{sip});
            if (self.sas.fields.protocol) |spr|
                _ = try writer.print("&spr={s}", .{spr});
            if (self.sas.fields.encryptionScope) |ses|
                _ = try writer.print("&ses={s}", .{ses});
            if (self.sas.fields.response != null and self.sas.fields.response.?.cacheControl != null)
                _ = try writer.print("&rscc={s}", .{self.sas.fields.response.?.cacheControl.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentDisposition != null)
                _ = try writer.print("&rscd={s}", .{self.sas.fields.response.?.contentDisposition.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentEncoding != null)
                _ = try writer.print("&rsce={s}", .{self.sas.fields.response.?.contentEncoding.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentLanguage != null)
                _ = try writer.print("&rscl={s}", .{self.sas.fields.response.?.contentLanguage.?});
            if (self.sas.fields.response != null and self.sas.fields.response.?.contentType != null)
                _ = try writer.print("&rsct={s}", .{self.sas.fields.response.?.contentType.?});
        }
    };
};

pub const Azurite = struct {
    azurite_process: ?proc.Child = null,

    pub fn init(opts: struct {
        allocator: std.mem.Allocator,
        in_memory: bool = false,
        auto_start: bool = true,
    }) @This() {
        var azurite_process: ?proc.Child = null;

        if (opts.auto_start) {
            const base_proc_args = [_][]const u8{
                "pnpm",    "exec",
                "azurite", "--silent",
                "--debug", ".azurite-debug.log",
            };
            const proc_args_in_memory = base_proc_args ++ .{"--inMemoryPersistence"};
            const proc_args_on_disk = base_proc_args ++ .{ "--location", ".azurite" };
            const proc_args: []const []const u8 = if (opts.in_memory) &proc_args_in_memory else &proc_args_on_disk;

            azurite_process = proc.Child.init(proc_args, opts.allocator);
            azurite_process.?.stderr_behavior = .Inherit;
            azurite_process.?.stdout_behavior = .Inherit;
            azurite_process.?.spawn() catch unreachable;
        }

        // FIXME: race, read stdout to for azurite to announce it started serving
        std.time.sleep(std.time.ns_per_s * 1);

        return Azurite{
            .azurite_process = azurite_process,
        };
    }

    pub fn deinit(self: *@This()) void {
        if (self.azurite_process) |*azuriteProc| {
            const kill_result = azuriteProc.kill() catch |e| blk: {
                std.log.warn("failed to kill process: {}\n", .{e});
                break :blk proc.Child.Term{ .Unknown = 42 };
            };

            switch (kill_result) {
                .Exited => |code| if (code == 0) return,
                .Signal => |id| if (id == std.posix.SIG.TERM) return,
                inline else => |v| std.log.warn("non-zero exit after kill: {s}, {}", .{ @tagName(kill_result), v }),
            }
        }
    }
};

pub const BlobStorage = struct {
    scheme: []const u8 = "https",
    host_name: []const u8,
    path_prefix: []const u8 = "/",
    port: u16 = 443, // default https
    account: Account,
    client: std.http.Client,

    pub fn init(
        a: std.mem.Allocator,
        opts: struct {
            scheme: []const u8 = "https",
            host_name: ?[]const u8 = null,
            path_prefix: []const u8 = "/",
            port: u16 = 443, // default https
            account: Account,
            client: ?std.http.Client = null,
        },
    ) @This() {
        const host_name = opts.host_name orelse std.fmt.allocPrint(a, "{s}.blob.core.windows.net", .{opts.account.name}) catch unreachable;

        return BlobStorage{
            .scheme = opts.scheme,
            .host_name = host_name,
            .path_prefix = opts.path_prefix,
            .port = opts.port,
            .account = opts.account,
            .client = opts.client orelse .{
                .allocator = a,
            },
        };
    }

    pub fn deinit(self: *@This()) void {
        self.client.deinit();
    }

    // TODO: return a struct with a free function
    pub fn listFiles(self: *@This(), a: std.mem.Allocator) ![]const []const u8 {
        var storage = std.ArrayList(u8).init(a);
        defer storage.clearAndFree();

        var query_buff: [512]u8 = undefined;
        const query = std.fmt.bufPrint(&query_buff, "restype=container&comp=list", .{}) catch unreachable;

        const uri = std.Uri{
            .port = self.port,
            .host = .{ .percent_encoded = self.host_name },
            .scheme = self.scheme,
            .query = .{ .percent_encoded = query },
            .path = .{ .percent_encoded = self.path_prefix },
        };

        const date = SharedKey.getUtcTime(a);
        defer a.free(date);

        var fetch_opts: std.http.Client.FetchOptions = .{
            .method = .GET,
            .location = .{ .uri = uri },
            .response_storage = .{ .dynamic = &storage },
            .max_append_size = 256 * 1024 * 1024,
            .extra_headers = &.{
                .{ .name = "x-ms-date", .value = date },
                .{ .name = "x-ms-version", .value = version },
            },
        };

        const authorization = SharedKey.authorize(fetch_opts, .{
            .allocator = a,
            .date = date,
            .account = self.account,
        });
        defer a.free(authorization);

        fetch_opts.headers = .{
            .authorization = .{ .override = authorization },
        };

        const resp = self.client.fetch(fetch_opts) catch |e| {
            std.log.warn("Error '{}' making azure blob storage list containers request to '{}'", .{ e, uri });
            // FIXME: propagate error
            return e;
        };

        if (resp.status != .ok) {
            std.log.warn("Unexpected status '{}' making azure blob storage list containers request to '{}'", .{ resp.status, uri });
            return error.AzureReqFail;
        }

        const result_size = std.mem.count(u8, storage.items, "\n") + 1;
        const result = a.alloc([]const u8, result_size) catch unreachable;
        var line_iter = std.mem.splitScalar(u8, storage.items, '\n');

        // TODO: xml parse the body for returned containers
        {
            var i: usize = 0;
            while (line_iter.next()) |line| {
                result[i] = a.dupe(u8, line) catch unreachable;
                i += 1;
            }
        }

        return result;
    }

    /// path is the uri path and query parameters
    /// SEE: https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob?tabs=microsoft-entra-id
    pub fn readObject(self: *@This(), a: std.mem.Allocator, name: []const u8) ![]u8 {
        var path_buff: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buff, "{s}{s}", .{ self.path_prefix, name }) catch unreachable;

        const uri = std.Uri{
            .port = self.port,
            .host = .{ .percent_encoded = self.host_name },
            .scheme = self.scheme,
            .path = .{ .percent_encoded = path },
        };

        // TODO: use std_opts.log_level instead of this
        const debug = std.posix.getenv("DEBUG") != null;

        if (debug) std.debug.print("readObject({})\n", .{uri});

        const date = SharedKey.getUtcTime(a);
        defer a.free(date);

        var storage = std.ArrayList(u8).init(a);
        defer storage.deinit();

        var fetch_opts: std.http.Client.FetchOptions = .{
            .method = .GET,
            .location = .{ .uri = uri },
            .extra_headers = &.{
                .{ .name = "x-ms-date", .value = date },
                .{ .name = "x-ms-version", .value = version },
            },
            .response_storage = .{ .dynamic = &storage },
            .max_append_size = 256 * 1024 * 1024,
        };

        const authorization = SharedKey.authorize(fetch_opts, .{
            .allocator = a,
            .date = date,
            .account = self.account,
        });
        defer a.free(authorization);

        fetch_opts.headers = .{
            .authorization = .{ .override = authorization },
        };

        const resp = self.client.fetch(fetch_opts) catch |e| {
            std.log.warn("Error '{}' making azure blob storage list containers request to '{}'", .{ e, uri });
            // FIXME: propagate error
            return e;
        };

        if (resp.status != .ok) {
            std.log.warn("Unexpected status '{}' making azure blob storage read blob request to '{}'", .{ resp.status, uri });
            return error.AzureReqFail;
        }

        return storage.toOwnedSlice() catch unreachable;
    }

    /// path is the uri path and query parameters
    /// SEE: https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob?tabs=microsoft-entra-id
    pub fn writeObject(self: *@This(), a: std.mem.Allocator, name: []const u8, data: []const u8) !void {
        var path_buff: [512]u8 = undefined;
        // FIXME: this probably contains a double '/'
        const path = std.fmt.bufPrint(&path_buff, "{s}{s}", .{ self.path_prefix, name }) catch unreachable;

        const uri = std.Uri{
            .port = self.port,
            .host = .{ .percent_encoded = self.host_name },
            .scheme = self.scheme,
            .path = .{ .percent_encoded = path },
        };

        std.log.debug("writeObject({})\n", .{uri});

        const date = SharedKey.getUtcTime(a);
        defer a.free(date);

        var fetch_opts: std.http.Client.FetchOptions = .{
            .method = .PUT,
            .location = .{ .uri = uri },
            .extra_headers = &.{
                //.{ .name = "x-ms-blob-content-disposition", .value = "attachment; filename=\"test.txt\"" },
                .{ .name = "x-ms-blob-type", .value = "BlockBlob" },
                .{ .name = "x-ms-date", .value = date },
                .{ .name = "x-ms-version", .value = version },
            },
            .payload = data,
        };

        const authorization = SharedKey.authorize(fetch_opts, .{
            .allocator = a,
            .date = date,
            .account = self.account,
        });
        defer a.free(authorization);

        fetch_opts.headers = .{
            .authorization = .{ .override = authorization },
        };

        const resp = self.client.fetch(fetch_opts) catch |e| {
            std.log.warn("Error '{}' making azure blob storage list containers request to '{}'", .{ e, uri });
            // FIXME: propagate error
            return e;
        };

        if (resp.status != .created) {
            std.log.warn("Unexpected status '{}' making azure blob storage write blob request to '{}'", .{ resp.status, uri });
            return error.AzureReqFail;
        }
    }

    pub fn createContainer(self: *@This(), a: std.mem.Allocator, name: []const u8) !void {
        var path_buff: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buff, "{s}{s}", .{ self.path_prefix, name }) catch unreachable;

        const uri = std.Uri{
            .port = self.port,
            .host = .{ .percent_encoded = self.host_name },
            .scheme = self.scheme,
            .query = .{ .percent_encoded = "restype=container" },
            .path = .{ .percent_encoded = path },
        };

        const debug = std.posix.getenv("DEBUG") != null;

        if (debug) std.debug.print("createContainer({})\n", .{uri});

        const date = SharedKey.getUtcTime(a);
        defer a.free(date);

        var fetch_opts: std.http.Client.FetchOptions = .{
            .method = .PUT,
            .location = .{ .uri = uri },
            .extra_headers = &.{
                .{ .name = "x-ms-date", .value = date },
                .{ .name = "x-ms-version", .value = version },
            },
        };

        const authorization = SharedKey.authorize(fetch_opts, .{
            .allocator = a,
            .date = date,
            .account = self.account,
        });
        defer a.free(authorization);

        fetch_opts.headers = .{
            .authorization = .{ .override = authorization },
        };

        const resp = self.client.fetch(fetch_opts) catch |e| {
            std.log.warn("Error '{}' making azure blob storage list containers request to '{}'", .{ e, uri });
            // FIXME: propagate error
            return e;
        };

        if (resp.status == .conflict) return error.Conflict;

        if (resp.status != .created) {
            std.log.warn("Unexpected status '{}' making azure blob storage list containers request to '{}'", .{ resp.status, uri });
            return error.AzureReqFail;
        }
    }
};

test "azurite listFiles" {
    var azurite = Azurite.init(.{
        .allocator = t.allocator,
        .in_memory = true,
    });
    defer azurite.deinit();

    var blob_storage = BlobStorage.init(t.allocator, .{
        .scheme = "http",
        .host_name = "127.0.0.1",
        .port = 10000,
        .account = .{
            .name = "devstoreaccount1",
            .key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
        },
        .path_prefix = "/devstoreaccount1/",
    });
    defer blob_storage.deinit();

    blob_storage.createContainer(t.allocator, "root") catch |e| switch (e) {
        error.Conflict => {},
        else => return e,
    };

    try blob_storage.writeObject(t.allocator, "test.txt", "hello!");
    const obj1_data = try blob_storage.readObject(t.allocator, "test.txt");
    try t.expectEqualStrings(obj1_data, "hello!");

    const files = try blob_storage.listFiles(t.allocator);
    defer {
        for (files) |file| t.allocator.free(file);
        t.allocator.free(files);
    }

    try t.expectEqual(1, files.len);
    try t.expectEqualStrings("test", files[0]);

    for (files) |file| {
        std.debug.print("file: {s}\n", .{file});
    }
}
