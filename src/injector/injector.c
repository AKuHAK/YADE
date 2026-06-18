#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "pgc.h"

typedef struct {
    uint32_t VM_CMD_PARSER_SWITCH_ADDR;
    uint32_t VM_ADDR;
    uint32_t VOB_BUFFER_ADDR;
    uint32_t JUMP_POINTER;
    uint32_t CMD_DATA_ADDR;
    uint32_t IFO_BUFFER;
} RegionConfig;

void copy_file(const char *src, const char *dst) {
    FILE *fs = fopen(src, "rb");
    if (!fs) return;
    FILE *fd = fopen(dst, "wb");
    if (!fd) { fclose(fs); return; }
    char buffer[16384];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), fs)) > 0) fwrite(buffer, 1, n, fd);
    fclose(fs);
    fclose(fd);
}

extern void pgc_build(pgc_t *pgc, uint8_t **buf, uint32_t *len);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: injector <version>\n");
        return 1;
    }

    FILE *fp_jump = fopen("./build/jump.bin", "rb");
    if (!fp_jump) { perror("jump.bin not found"); return 1; }
    uint8_t payload[512] = {0};
    size_t payload_len = fread(payload, 1, 444, fp_jump);
    fclose(fp_jump);

    if (strncmp(argv[1], "3.00", 4) == 0) {
        RegionConfig regions[] = {
            {0x00909208, 0x01558e40, 0x0155cec0, 0x0090ec20, 0x01551da8, 0x01555600}, // 3.00E
            {0x00909108, 0x01383840, 0x013878c0, 0x0090eb18, 0x0137c7a8, 0x01380000}, // 3.00U
            {0x00684988, 0x010ff040, 0x011030c0, 0x0068a318, 0x010f7fa8, 0x010fb800}  // 3.00J
        };

        for (int i = 0; i < 3; i++) {
            char vob[64], ifo[64], bup[64];
            sprintf(vob, "./build/fs/VIDEO_TS/VTS_%02d_1.VOB", i + 1);
            sprintf(ifo, "./build/fs/VIDEO_TS/VTS_%02d_0.IFO", i + 1);
            sprintf(bup, "./build/fs/VIDEO_TS/VTS_%02d_0.BUP", i + 1);

            copy_file("./fs/VIDEO_TS/VTS_01_1.VOB", vob); //
            copy_file("./fs/VIDEO_TS/VTS_01_0.BUP", ifo);
            copy_file("./fs/VIDEO_TS/VTS_01_0.BUP", bup);

            uint32_t sw_idx = (regions[i].JUMP_POINTER - regions[i].VM_CMD_PARSER_SWITCH_ADDR) >> 2;
            uint8_t vm_cmd[24] = {0};
            memcpy(&vm_cmd[4], &regions[i].CMD_DATA_ADDR, 4);
            vm_cmd[8] = 0x01;
            memcpy(&vm_cmd[10], &sw_idx, 2);
            vm_cmd[20] = 0x03;

            FILE *f = fopen(vob, "rb+");
            if (f) {
                fseek(f, 0x629, SEEK_SET); fwrite(vm_cmd, 1, 24, f);
                fseek(f, 0x644, SEEK_SET); fwrite(payload, 1, payload_len, f);
                fclose(f);
            }
        }
    }
    
    printf("Injection complete.\n");
    return 0;
}