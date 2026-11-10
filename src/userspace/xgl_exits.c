/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * xgl_exits — userspace side of named tail-call exits: reading the
 * ".xgl.exits" declarations and patching the exit magic immediates
 * into bound slot numbers.
 *
 * The patcher does raw ELF64 little-endian surgery on a copy of the
 * object (the kernel never sees the magic).  Only sections libbpf
 * treats as programs are scanned (non-'.' prefixed, PROGBITS, size a
 * multiple of the 8-byte instruction width); the distinctive magic
 * mask makes false positives on data effectively impossible.
 */

#define _DEFAULT_SOURCE

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

#include <xgl/xgl_exits.h>
#include <xgl/xgl_graph.h>

/* internal, implemented here (prototyped in xgl_graph.c) */
int xgl_patch_exit_immediates(const char *in_path, const char *out_path,
                              const uint32_t *ids, const uint32_t *slots,
                              size_t n);

/*
 * xgl_read_exit_decls - Read the ".xgl.exits" declarations of a BPF
 * object.  Caller frees.  Returns -ENOENT when the object declares
 * no exits.
 */
int
xgl_read_exit_decls(const char *obj_path,
                    struct xgl_exit_meta **out, size_t *n)
{
    Elf *elf = NULL;
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data;
    struct xgl_exit_meta *entries;
    size_t shstrndx;
    int fd = -1;
    int ret = 0;

    if (!obj_path || !out || !n)
        return -EINVAL;

    *out = NULL;
    *n = 0;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return -ELIBBAD;

    fd = open(obj_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        ret = -ELIBBAD;
        goto out;
    }

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            continue;
        if (elf_getshdrstrndx(elf, &shstrndx) != 0)
            continue;
        const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (name && strcmp(name, ".xgl.exits") == 0)
            break;
    }
    if (!scn) {
        ret = -ENOENT;
        goto out;
    }

    data = elf_getdata(scn, NULL);
    if (!data || data->d_size == 0 ||
        data->d_size % sizeof(*entries) != 0) {
        ret = -EINVAL;
        goto out;
    }

    entries = malloc(data->d_size);
    if (!entries) {
        ret = -ENOMEM;
        goto out;
    }
    memcpy(entries, data->d_buf, data->d_size);

    *out = entries;
    *n = data->d_size / sizeof(*entries);

out:
    if (elf)
        elf_end(elf);
    if (fd >= 0)
        close(fd);
    return ret;
}

/* BPF instruction encoding (uapi/linux/bpf.h). */
struct xgl_bpf_insn {
    uint8_t  code;
    uint8_t  dst_src;   /* dst:4 | src:4 */
    uint16_t off;
    int32_t  imm;
};

#define BPF_MOV32_IMM 0xb4
#define BPF_LD_IMM64  0x18

static int slot_for_id(const uint32_t *ids, const uint32_t *slots,
                       size_t n, uint32_t id)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (ids[i] == id)
            return (int)slots[i];
    return -1;
}

/*
 * Patch one section of instructions in the in-memory image.
 * Returns the number of patched immediates, or -1 on an unbound id.
 */
static int
patch_section(uint8_t *buf, size_t size,
              const uint32_t *ids, const uint32_t *slots, size_t n)
{
    struct xgl_bpf_insn *insns = (struct xgl_bpf_insn *)buf;
    size_t count = size / sizeof(*insns);
    size_t i;
    int patched = 0;

    for (i = 0; i < count; i++) {
        struct xgl_bpf_insn *ins = &insns[i];
        int slot;

        if (ins->code == BPF_MOV32_IMM &&
            ((uint32_t)ins->imm & XGL_EXIT_MAGIC_MASK) ==
                XGL_EXIT_MAGIC_BASE) {
            uint32_t id = (uint32_t)ins->imm & ~XGL_EXIT_MAGIC_MASK;
            slot = slot_for_id(ids, slots, n, id);
            if (slot < 0)
                return -1;
            ins->imm = slot;
            patched++;
        } else if (ins->code == BPF_LD_IMM64 && (i + 1) < count) {
            /* 64-bit immediate: magic sits in the second half. */
            struct xgl_bpf_insn *lo = &insns[i + 1];
            if (((uint32_t)lo->imm & XGL_EXIT_MAGIC_MASK) ==
                XGL_EXIT_MAGIC_BASE) {
                uint32_t id = (uint32_t)lo->imm & ~XGL_EXIT_MAGIC_MASK;
                slot = slot_for_id(ids, slots, n, id);
                if (slot < 0)
                    return -1;
                lo->imm = slot;
                patched++;
            }
            i++; /* skip the second half */
        }
    }
    return patched;
}

/*
 * xgl_patch_exit_immediates - Copy a BPF object, rewriting the exit
 * magic immediates to their bound slots.  Only program sections
 * (libbpf convention: name not starting with '.', PROGBITS, size a
 * multiple of 8) are scanned.
 *
 * Returns 0 on success (even if nothing was patched — objects
 * without XGL_EXIT calls pass through), -ENOENT if an immediate
 * references an id with no binding.
 */
int
xgl_patch_exit_immediates(const char *in_path, const char *out_path,
                          const uint32_t *ids, const uint32_t *slots,
                          size_t n)
{
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;
    const char *shstrtab;
    uint8_t *image;
    size_t size;
    int fd = -1;
    int ret = 0;
    int out = -1;
    uint16_t i;

    if (!in_path || !out_path)
        return -EINVAL;

    fd = open(in_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    {
        off_t end = lseek(fd, 0, SEEK_END);

        if (end < (off_t)sizeof(*ehdr)) {
            ret = -EINVAL;
            goto out;
        }
        size = (size_t)end;
        lseek(fd, 0, SEEK_SET);
    }

    image = malloc(size);
    if (!image) {
        ret = -ENOMEM;
        goto out;
    }
    if (read(fd, image, size) != (ssize_t)size) {
        ret = -EIO;
        free(image);
        goto out;
    }
    close(fd);
    fd = -1;

    ehdr = (Elf64_Ehdr *)image;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        ret = -EINVAL;
        goto out_free;
    }

    shdrs = (Elf64_Shdr *)(image + ehdr->e_shoff);
    if (ehdr->e_shstrndx >= ehdr->e_shnum ||
        shdrs[ehdr->e_shstrndx].sh_offset + shdrs[ehdr->e_shstrndx].sh_size > size) {
        ret = -EINVAL;
        goto out_free;
    }
    shstrtab = (const char *)(image + shdrs[ehdr->e_shstrndx].sh_offset);

    for (i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &shdrs[i];
        const char *name;

        if (sh->sh_type != SHT_PROGBITS || sh->sh_size == 0 ||
            sh->sh_size % 8 != 0 || sh->sh_name >=
            shdrs[ehdr->e_shstrndx].sh_size)
            continue;

        name = shstrtab + sh->sh_name;
        if (name[0] == '.')
            continue;   /* not a program section */

        if (sh->sh_offset + sh->sh_size > size) {
            ret = -EINVAL;
            goto out_free;
        }

        if (patch_section(image + sh->sh_offset, sh->sh_size,
                          ids, slots, n) < 0) {
            ret = -ENOENT;  /* unbound exit id */
            goto out_free;
        }
    }

    out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        ret = -errno;
        goto out_free;
    }
    if (write(out, image, size) != (ssize_t)size) {
        ret = -EIO;
        close(out);
        out = -1;
        goto out_free;
    }

out_free:
    free(image);
out:
    if (fd >= 0)
        close(fd);
    if (out >= 0)
        close(out);
    return ret;
}
