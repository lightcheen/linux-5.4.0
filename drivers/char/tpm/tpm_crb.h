#ifndef TPM_CRB_H
#define TPM_CRB_H

#include <linux/types.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/acpi.h>
#include <linux/module.h>

struct crb_priv {
	u32 sm;
	const char *hid;
	void __iomem *iobase;
	struct crb_regs_head __iomem *regs_h;
	struct crb_regs_tail __iomem *regs_t;
	u8 __iomem *cmd;
	u8 __iomem *rsp;
	u32 cmd_size;
	u32 smc_func_id;
};

enum crb_ctrl_sts {
	CRB_CTRL_STS_ERROR	= BIT(0),
	CRB_CTRL_STS_TPM_IDLE	= BIT(1),
};

struct crb_regs_tail {
	u32 ctrl_req;
	u32 ctrl_sts;
	u32 ctrl_cancel;
	u32 ctrl_start;
	u32 ctrl_int_enable;
	u32 ctrl_int_sts;
	u32 ctrl_cmd_size;
	u32 ctrl_cmd_pa_low;
	u32 ctrl_cmd_pa_high;
	u32 ctrl_rsp_size;
	u64 ctrl_rsp_pa;
} __packed;

// 函数声明
u8 crb_status(struct tpm_chip *chip);
void crb_cancel(struct tpm_chip *chip);
bool crb_req_canceled(struct tpm_chip *chip, u8 status);
int crb_go_idle(struct tpm_chip *chip);
int crb_cmd_ready(struct tpm_chip *chip);
int crb_request_locality(struct tpm_chip *chip, int loc);
int crb_relinquish_locality(struct tpm_chip *chip, int loc);

#endif /* TPM_CRB_H */
