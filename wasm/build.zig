const std = @import("std");
const wasm = std.Target.wasm;

// https://nullprogram.com/blog/2025/04/04/
// https://webassembly.github.io/spec/core/syntax/modules.html
// https://developer.mozilla.org/en-US/docs/WebAssembly/Guides/Using_the_JavaScript_API
// https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/JavaScript_interface
pub fn build(b: *std.Build) void {
    const lib = b.addExecutable(.{
        .name = "wasmstr",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .wasm32,
                .os_tag = .freestanding,
                .cpu_features_add = wasm.featureSet(&.{
                    .atomics,
                    .bulk_memory,
                }),
            }),
            .optimize = .ReleaseSmall,
            .strip = true,
            .sanitize_c = .full,
        }),
        .linkage = .static,
        // llvm backend with lld give smaller binaries (1.3K)
        // compared to selfhosted (4.8K)
        .use_lld = true,
        .use_llvm = true,
    });
    lib.entry = .disabled;
    // TODO: understand what each option does
    // lib.import_memory = true;
    // lib.import_table = true;
    // lib.import_symbols = true;
    // lib.export_memory = true;
    // lib.export_table = true; MUST BE REMOVED can't be enabled with import tables
    // lib.shared_memory = true;
    // lib.max_memory = 67108864;
    lib.bundle_compiler_rt = false;
    lib.bundle_ubsan_rt = false;
    lib.root_module.export_symbol_names = &.{ "alloc", "free", "add", "sub", "zlog" };

    b.installArtifact(lib);
}
