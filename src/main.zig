const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
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
        // assert(coloring.validate(canonical_graph) == .valid);

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
        edge_index: CanonicalGraph.Edge.Index align(1),
        color_a: Color align(1),
        color_b: Color align(1),
        key_a: Key align(1),
        key_b: Key align(1),

        pub const ValidationResult = enum { valid, edge_out_of_bounds, coloring_incorrect };
        pub fn validate(
            reveal_edge: RevealEdge,
            canonical_graph: CanonicalGraph,
        ) RevealEdge.ValidationResult {
            if (reveal_edge.edge_index >= canonical_graph.edges.len) {
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
            .edge_index = edge_index,
            .color_a = coloring.colors[@intFromEnum(edge.a)],
            .color_b = coloring.colors[@intFromEnum(edge.b)],
            .key_a = coloring.keys[@intFromEnum(edge.a)],
            .key_b = coloring.keys[@intFromEnum(edge.b)],
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

pub const NonInteractiveProver = struct {
    pub fn revealRandomEdgeForRound(
        csprng: std.Random,
        colorings: GraphColorings,
        canonical_graph: CanonicalGraph,
        round: usize,
    ) GraphColoring.RevealEdge {
        const coloring = colorings.coloringForRound(canonical_graph, round);
        return coloring.revealEdge(
            canonical_graph,
            @enumFromInt(csprng.intRangeLessThan(u32, 0, @intCast(canonical_graph.edges.len))),
        );
    }

    pub fn revealRandomEdges(
        csprng: std.Random,
        colorings: GraphColorings,
        canonical_graph: CanonicalGraph,
        rounds: usize,
        out: []u8,
    ) void {
        assert(out.len == rounds * @sizeOf(GraphColoring.RevealEdge));
        for (0..rounds) |round| {
            @memcpy(
                out[round * @sizeOf(GraphColoring.RevealEdge) ..][0..@sizeOf(GraphColoring.RevealEdge)],
                &std.mem.toBytes(revealRandomEdgeForRound(csprng, colorings, canonical_graph, round)),
            );
        }
    }
};

pub const NonInteractiveValidator = struct {
    pub fn validate(
        canonical_graph: CanonicalGraph,
        commitment: []const u8,
        proof: []const u8,
    ) bool {
        var commitment_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(commitment, &commitment_hash, .{});
        var default_csprng = std.Random.DefaultCsprng.init(commitment_hash);
        const csprng = default_csprng.random();
        // TODO: assertions

        const per_round_commitment_len = canonical_graph.vertex_count * HmacSha256.key_length;

        for (0..proof.len / @sizeOf(GraphColoring.RevealEdge)) |round| {
            const round_commitment = commitment[round * per_round_commitment_len ..][0..per_round_commitment_len];
            const revealed_edge: GraphColoring.RevealEdge =
                @bitCast(proof[round * @sizeOf(GraphColoring.RevealEdge) ..][0..@sizeOf(GraphColoring.RevealEdge)].*);

            if (@intFromEnum(revealed_edge.edge_index) != csprng.intRangeLessThan(u32, 0, @intCast(canonical_graph.edges.len))) {
                return false;
            }

            const edge = canonical_graph.edges[@intFromEnum(revealed_edge.edge_index)];

            var out: [HmacSha256.mac_length]u8 = undefined;

            HmacSha256.create(&out, &.{@intFromEnum(revealed_edge.color_a)}, &revealed_edge.key_a);
            const edge_a_commitment = round_commitment[@intFromEnum(edge.a) * HmacSha256.key_length ..][0..HmacSha256.key_length];
            if (!std.mem.eql(u8, &out, edge_a_commitment)) {
                return false;
            }

            HmacSha256.create(&out, &.{@intFromEnum(revealed_edge.color_b)}, &revealed_edge.key_b);
            const edge_b_commitment = round_commitment[@intFromEnum(edge.b) * HmacSha256.key_length ..][0..HmacSha256.key_length];
            if (!std.mem.eql(u8, &out, edge_b_commitment)) {
                return false;
            }

            if (revealed_edge.color_a == revealed_edge.color_b) {
                return false;
            }
        }

        return true;
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
            // .red,
            .green,
        },
        list.items(.color),
        list.items(.key),
    );

    var commitment: [rounds * canonical_graph.vertex_count * @sizeOf(GraphColoring.Key)]u8 = undefined;
    colorings.createCommitment(canonical_graph, &commitment);

    var commitment_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&commitment, &commitment_hash, .{});
    var default_csprng = std.Random.DefaultCsprng.init(commitment_hash);
    const csprng = default_csprng.random();

    var proof: [rounds * @sizeOf(GraphColoring.RevealEdge)]u8 = undefined;
    NonInteractiveProver.revealRandomEdges(csprng, colorings, canonical_graph, rounds, &proof);

    std.log.info("{any}", .{NonInteractiveValidator.validate(canonical_graph, &commitment, &proof)});
    // std.log.info("{}", .{std.fmt.fmtSliceHexLower(&proof)});
}
