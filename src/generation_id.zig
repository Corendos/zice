const std = @import("std");

/// Generational ID to be used as handle.
pub fn GenerationId(comptime StorageType: type, comptime index_bit_count: u16) type {
    const storage_type_info = @typeInfo(StorageType);
    if (storage_type_info != .Int) @compileError("Expected Integer type for GenerationId, got " ++ @tagName(@typeInfo(StorageType)));
    if (storage_type_info.Int.signedness != .unsigned) @compileError("Expected Unsigned Integer type for GenerationId");
    if (index_bit_count >= storage_type_info.Int.bits) @compileError("Index bit count needs to be less than storage bit size");

    const IndexType = std.meta.Int(.unsigned, index_bit_count);
    const DetailsType = std.meta.Int(.unsigned, storage_type_info.Int.bits - index_bit_count);

    return extern union {
        raw: StorageType,
        parts: packed struct { index: IndexType, details: DetailsType },
    };
}

test "Basic usage" {
    const generation_id = GenerationId(u16, 6){ .parts = .{ .index = 5, .details = 5 } };

    try std.testing.expectEqual(@sizeOf(u16), @sizeOf(@TypeOf(generation_id)));
    try std.testing.expectEqual(@as(u16, 325), generation_id.raw);
}
