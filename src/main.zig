const std = @import("std");
const assert = std.debug.assert;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const CanonicalGraph = struct {
    pub const Vertex = enum(u32) { _ };
    /// Must be lexicographically sorted.
    pub const Edge = struct {
        pub const Index = enum(u32) { _ };

        a: Vertex,
        b: Vertex,

        pub fn order(x: Edge, y: Edge) std.math.Order {
            return switch (std.math.order(@intFromEnum(x.a), @intFromEnum(y.a))) {
                inline .lt, .gt => |tag| tag,
                .eq => std.math.order(@intFromEnum(x.b), @intFromEnum(y.b)),
            };
        }
    };

    vertex_count: u32,
    /// Must be lexicographically sorted.
    edges: []const Edge,

    pub const ValidationResult = enum { valid, vertex_out_of_bounds, edges_not_sorted };
    pub fn validate(canonical_graph: CanonicalGraph) ValidationResult {
        var last_edge: ?Edge = null;
        for (canonical_graph.edges) |edge| {
            defer last_edge = edge;

            if (@intFromEnum(edge.a) >= canonical_graph.vertex_count or
                @intFromEnum(edge.b) >= canonical_graph.vertex_count)
            {
                return .vertex_out_of_bounds;
            }

            if ((last_edge orelse continue).order(edge) != .lt) {
                return .edges_not_sorted;
            }
        }

        return .valid;
    }
};

pub const Color = enum(u8) {
    red,
    green,
    blue,

    pub const Mapping = enum {
        red_green_blue,
        red_blue_green,
        blue_red_green,
        blue_green_red,
        green_blue_red,
        green_red_blue,

        pub fn generate() Mapping {
            return std.crypto.random.enumValue(Mapping);
        }

        const mapping_array = [6][3]Color{
            .{ .red, .green, .blue },
            .{ .red, .blue, .green },
            .{ .blue, .red, .green },
            .{ .blue, .green, .red },
            .{ .green, .blue, .red },
            .{ .green, .red, .blue },
        };

        pub fn map(mapping: Mapping, in: Color) Color {
            return mapping_array[@intFromEnum(mapping)][@intFromEnum(in)];
        }
    };
};

pub const GraphColoring = struct {
    pub const Key = [HmacSha256.key_length]u8;

    colors: []const Color,
    keys: []const Key,

    pub fn generateKey() Key {
        var key: Key = undefined;
        std.crypto.random.bytes(&key);
        return key;
    }

    pub const ValidationResult = enum { valid, invalid };
    pub fn validate(coloring: GraphColoring, canonical_graph: CanonicalGraph) ValidationResult {
        for (canonical_graph.edges) |edge| {
            if (coloring.colors[@intFromEnum(edge.a)] == coloring.colors[@intFromEnum(edge.b)]) {
                return .invalid;
            }
        }

        return .valid;
    }

    pub fn commitmentLength(coloring: GraphColoring) usize {
        return coloring.colors.len * HmacSha256.key_length;
    }

    pub fn createCommitment(coloring: GraphColoring, canonical_graph: CanonicalGraph, out: []u8) void {
        assert(coloring.colors.len == canonical_graph.vertex_count);
        assert(coloring.keys.len == canonical_graph.vertex_count);
        assert(out.len == coloring.commitmentLength());
        assert(canonical_graph.validate() == .valid);
        assert(coloring.validate(canonical_graph) == .valid);

        for (
            coloring.colors[0..canonical_graph.vertex_count],
            coloring.keys[0..canonical_graph.vertex_count],
            0..canonical_graph.vertex_count,
        ) |color, key, index| {
            HmacSha256.create(
                out[index * HmacSha256.mac_length ..][0..HmacSha256.mac_length],
                &.{@intFromEnum(color)},
                &key,
            );
        }
    }

    pub const RevealEdge = extern struct {
        edge: CanonicalGraph.Edge.Index align(1),
        color_a: Color align(1),
        color_b: Color align(1),
        key_a: Key align(1),
        key_b: Key align(1),

        pub const ValidationResult = enum { valid, edge_out_of_bounds, coloring_incorrect };
        pub fn validate(
            reveal_edge: RevealEdge,
            canonical_graph: CanonicalGraph,
        ) RevealEdge.ValidationResult {
            if (reveal_edge.edge >= canonical_graph.edges.len) {
                return .edge_out_of_bounds;
            }

            if (reveal_edge.color_a == reveal_edge.color_b) {
                return .coloring_incorrect;
            }
        }
    };

    pub fn revealEdge(
        coloring: GraphColoring,
        canonical_graph: CanonicalGraph,
        edge_index: CanonicalGraph.Edge.Index,
    ) RevealEdge {
        assert(@intFromEnum(edge_index) < canonical_graph.edges.len);
        const edge = canonical_graph.edges[@intFromEnum(edge_index)];
        return .{
            .edge = edge_index,
            .color_a = coloring.colors[edge.a],
            .color_b = coloring.colors[edge.b],
            .key_a = coloring.colors[edge.a],
            .key_b = coloring.colors[edge.b],
        };
    }
};

pub const GraphColorings = struct {
    colors: []const Color,
    keys: []const GraphColoring.Key,

    pub fn init(
        canonical_graph: CanonicalGraph,
        original_colors: []const Color,
        final_colors: []Color,
        final_keys: []GraphColoring.Key,
    ) GraphColorings {
        assert(original_colors.len == canonical_graph.vertex_count);
        const rounds = @divExact(final_colors.len, original_colors.len);

        for (0..rounds) |round| {
            var mapping = Color.Mapping.generate();
            for (
                original_colors,
                final_colors[round * original_colors.len ..][0..original_colors.len],
                final_keys[round * original_colors.len ..][0..original_colors.len],
            ) |original_color, *final_color, *final_key| {
                final_color.* = mapping.map(original_color);
                final_key.* = GraphColoring.generateKey();
            }
        }

        return .{ .colors = final_colors, .keys = final_keys };
    }

    pub fn coloringForRound(
        colorings: GraphColorings,
        canonical_graph: CanonicalGraph,
        round: usize,
    ) GraphColoring {
        return .{
            .colors = colorings.colors[round * canonical_graph.vertex_count ..][0..canonical_graph.vertex_count],
            .keys = colorings.keys[round * canonical_graph.vertex_count ..][0..canonical_graph.vertex_count],
        };
    }

    pub fn commitmentLength(colorings: GraphColorings) usize {
        return colorings.colors.len * HmacSha256.key_length;
    }

    pub fn createCommitment(colorings: GraphColorings, canonical_graph: CanonicalGraph, out: []u8) void {
        assert(colorings.colors.len % canonical_graph.vertex_count == 0);
        assert(colorings.keys.len % canonical_graph.vertex_count == 0);
        assert(colorings.colors.len == colorings.keys.len);

        assert(out.len == colorings.commitmentLength());

        const rounds = @divExact(colorings.colors.len, canonical_graph.vertex_count);

        for (0..rounds) |round| {
            const coloring = colorings.coloringForRound(canonical_graph, round);
            coloring.createCommitment(
                canonical_graph,
                out[round * coloring.commitmentLength() ..][0..coloring.commitmentLength()],
            );
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const canonical_graph = CanonicalGraph{
        .vertex_count = 6,
        .edges = &.{
            .{ .a = @enumFromInt(0), .b = @enumFromInt(1) },
            .{ .a = @enumFromInt(0), .b = @enumFromInt(2) },
            .{ .a = @enumFromInt(1), .b = @enumFromInt(2) },
            .{ .a = @enumFromInt(2), .b = @enumFromInt(3) },
            .{ .a = @enumFromInt(2), .b = @enumFromInt(4) },
            .{ .a = @enumFromInt(3), .b = @enumFromInt(5) },
            .{ .a = @enumFromInt(4), .b = @enumFromInt(5) },
        },
    };
    assert(canonical_graph.validate() == .valid);

    const rounds = 128;

    var list = std.MultiArrayList(struct { color: Color, key: GraphColoring.Key }){};
    try list.resize(allocator, rounds * canonical_graph.vertex_count);
    defer list.deinit(allocator);

    var colorings = GraphColorings.init(
        canonical_graph,
        &.{
            .red,
            .blue,
            .green,
            .red,
            .blue,
            .green,
        },
        list.items(.color),
        list.items(.key),
    );

    var out: [rounds * canonical_graph.vertex_count * @sizeOf(GraphColoring.Key)]u8 = undefined;
    colorings.createCommitment(canonical_graph, &out);
    // colorings.coloringForRound(canonical_graph, 0).createCommitment(canonical_graph, &out);

    std.log.info("{}", .{std.fmt.fmtSliceHexLower(&out)});
}
