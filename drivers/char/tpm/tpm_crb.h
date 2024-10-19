#ifndef TPM_CRB_H
#define TPM_CRB_H

#include <linux/types.h>
#include <linux/io.h>
#include <linux/device.h>
#include <linux/acpi.h>
#include <linux/module.h>

// 函数声明
u8 crb_status(struct tpm_chip *chip);
void crb_cancel(struct tpm_chip *chip);
bool crb_req_canceled(struct tpm_chip *chip, u8 status);
int crb_go_idle(struct tpm_chip *chip);
int crb_cmd_ready(struct tpm_chip *chip);
int crb_request_locality(struct tpm_chip *chip, int loc);
int crb_relinquish_locality(struct tpm_chip *chip, int loc);

#endif /* TPM_CRB_H */
