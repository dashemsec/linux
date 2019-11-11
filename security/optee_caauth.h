#include <linux/binfmts.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include <linux/cred.h>
#include <linux/tee_drv.h>
#include <linux/file.h>

#define AUTH_SEC_NAME ".caauth_sec"
#define TA_CAAUTH_UUID \
	{0x42116460, 0xb389, 0x4013, \
        { 0xa2, 0x20, 0xb4, 0x3e, 0x92, 0x33, 0x8a, 0x3d} }


int optee_find_and_validate_casignature(struct linux_binprm *bprm);
int optee_check_dev_permission(uint16_t caauth_flag);

#define CAVERIFY_FLAG_AUTH_SUCCESS	(1 << 0)
#define CAVERIFY_FLAG_AUTH_FAILED	(2 << 0)
#define CAVERIFY_FLAG_CAAUTH_FOUND	(1 << 4)
#define CAVERIFY_FLAG_CAAUTH_NOT_FOUND	(2 << 4)
#define CAVERIFY_FLAG_VALIDATION_DONE	(1 << 8)

typedef struct  {
        uint32_t timeLow;
        uint16_t timeMid;
        uint16_t timeHiAndVersion;
        uint8_t clockSeqAndNode[8];
}TEEC_UUID;

