const std = @import("std");
const elf = std.elf;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xFFF1;
pub const SHT_SYMTAB: u32 = 2;

pub const UndefinedSymbol = struct {
    name: []const u8,
    file_offset: usize,
};

pub const ElfModifier = struct {
    buffer: []u8,
    is_64bit: bool,
    shoff: u64,
    shentsize: u16,
    shnum: u16,

    const Self = @This();

    pub fn init(buffer: []u8) !Self {
        if (buffer.len < @sizeOf(elf.Elf64_Ehdr)) {
            return error.BufferTooSmall;
        }

        // Check ELF magic
        const magic = "\x7fELF";
        if (!std.mem.eql(u8, buffer[0..4], magic)) {
            return error.InvalidElfMagic;
        }

        const e_ident = buffer[0..16];
        const is_64bit = e_ident[elf.EI_CLASS] == elf.ELFCLASS64;

        if (!is_64bit) {
            return error.Only64BitSupported;
        }

        // Read header fields directly
        const hdr = std.mem.bytesToValue(elf.Elf64_Ehdr, buffer[0..@sizeOf(elf.Elf64_Ehdr)]);

        return Self{
            .buffer = buffer,
            .is_64bit = is_64bit,
            .shoff = hdr.e_shoff,
            .shentsize = hdr.e_shentsize,
            .shnum = hdr.e_shnum,
        };
    }

    pub fn findUndefinedSymbols(self: *const Self, allocator: std.mem.Allocator) !std.ArrayListUnmanaged(UndefinedSymbol) {
        var result = std.ArrayListUnmanaged(UndefinedSymbol){};
        errdefer result.deinit(allocator);

        // Find .symtab section
        var symtab_offset: u64 = 0;
        var symtab_size: u64 = 0;
        var symtab_entsize: u64 = 0;
        var strtab_offset: u64 = 0;

        var i: u16 = 0;
        while (i < self.shnum) : (i += 1) {
            const sh_offset = self.shoff + @as(u64, i) * self.shentsize;
            if (sh_offset + @sizeOf(elf.Elf64_Shdr) > self.buffer.len) {
                continue;
            }

            const shdr = std.mem.bytesToValue(
                elf.Elf64_Shdr,
                self.buffer[sh_offset..][0..@sizeOf(elf.Elf64_Shdr)],
            );

            if (shdr.sh_type == SHT_SYMTAB) {
                symtab_offset = shdr.sh_offset;
                symtab_size = shdr.sh_size;
                symtab_entsize = shdr.sh_entsize;

                // Get associated strtab
                const strtab_sh_offset = self.shoff + @as(u64, shdr.sh_link) * self.shentsize;
                if (strtab_sh_offset + @sizeOf(elf.Elf64_Shdr) <= self.buffer.len) {
                    const strtab_shdr = std.mem.bytesToValue(
                        elf.Elf64_Shdr,
                        self.buffer[strtab_sh_offset..][0..@sizeOf(elf.Elf64_Shdr)],
                    );
                    strtab_offset = strtab_shdr.sh_offset;
                }
                break;
            }
        }

        if (symtab_offset == 0 or symtab_entsize == 0) {
            return result;
        }

        // Iterate through symbols
        const num_syms = symtab_size / symtab_entsize;
        var sym_idx: u64 = 1; // Skip index 0 (null symbol)
        while (sym_idx < num_syms) : (sym_idx += 1) {
            const sym_offset = symtab_offset + sym_idx * symtab_entsize;
            if (sym_offset + @sizeOf(elf.Elf64_Sym) > self.buffer.len) {
                continue;
            }

            const sym = std.mem.bytesToValue(
                elf.Elf64_Sym,
                self.buffer[sym_offset..][0..@sizeOf(elf.Elf64_Sym)],
            );

            // Check if undefined symbol (SHN_UNDEF)
            if (sym.st_shndx == SHN_UNDEF) {
                // Get symbol name
                const name_start = strtab_offset + sym.st_name;
                if (name_start >= self.buffer.len) {
                    continue;
                }

                var name_end = name_start;
                while (name_end < self.buffer.len and self.buffer[name_end] != 0) {
                    name_end += 1;
                }

                if (name_end > name_start) {
                    try result.append(allocator, .{
                        .name = self.buffer[name_start..name_end],
                        .file_offset = sym_offset,
                    });
                }
            }
        }

        return result;
    }

    pub fn modifySymbol(self: *Self, file_offset: usize, new_value: u64) void {
        if (file_offset + @sizeOf(elf.Elf64_Sym) > self.buffer.len) {
            return;
        }

        // Elf64_Sym layout:
        // offset 0:  st_name  (4 bytes)
        // offset 4:  st_info  (1 byte)
        // offset 5:  st_other (1 byte)
        // offset 6:  st_shndx (2 bytes) <- modify to SHN_ABS
        // offset 8:  st_value (8 bytes) <- modify to kernel address
        // offset 16: st_size  (8 bytes)

        // Write st_shndx = SHN_ABS
        const shndx_offset = file_offset + 6;
        std.mem.writeInt(u16, self.buffer[shndx_offset..][0..2], SHN_ABS, .little);

        // Write st_value = kernel address
        const value_offset = file_offset + 8;
        std.mem.writeInt(u64, self.buffer[value_offset..][0..8], new_value, .little);
    }
};
