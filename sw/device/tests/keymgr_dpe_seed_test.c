// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <stdbool.h>
#include <stdint.h>

#include "hw/top/dt/kmac.h"
#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/dif/dif_keymgr_dpe.h"
#include "sw/device/lib/dif/dif_kmac.h"
#include "sw/device/lib/dif/dif_otp_ctrl.h"
#include "sw/device/lib/dif/dif_rstmgr.h"
#include "sw/device/lib/runtime/hart.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/runtime/print.h"
#include "sw/device/lib/testing/keymgr_dpe_testutils.h"
#include "sw/device/lib/testing/otp_ctrl_testutils.h"
#include "sw/device/lib/testing/rstmgr_testutils.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/dif/dif_rom_ctrl.h"
#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"
#include "hw/top/keymgr_dpe_regs.h"  // Generated.
#include "hw/top/kmac_regs.h"    // Generated.
#include "hw/top/otp_ctrl_regs.h" // Generated.

OTTF_DEFINE_TEST_CONFIG();

static dif_kmac_t kmac;
static dif_keymgr_dpe_t keymgr_dpe;
static dif_rom_ctrl_t rom_ctrl;
static dif_otp_ctrl_t otp;

enum {
  // Size of the SW key which is read in 32-bit words.
  kSizeSwKeyWords = sizeof(((dif_keymgr_dpe_output_t){0}).value[0]) / sizeof(uint32_t)
};

static const dif_keymgr_dpe_generate_params_t kGenParamSwTest = {
    .key_dest = kDifKeymgrDpeKeyDestNone,
    .sideload_key = false,
    .salt =
        {
            0x01,
            0x23,
            0x45,
            0x67,
            0x89,
            0xa0,
            0xbc,
            0xde
        },
    .version = 0x0,
    .slot_src_sel = kCreatorRootKeyParams.slot_dst_sel
};

static void dump_as_hex_bytestream(const char *name, const uint32_t *word_data, size_t word_len) {
  base_printf("%s:\r\n", name);
  
  while (word_len--) {
    base_printf("%02X%02X%02X%02X",
        *word_data & 0xFF,
        (*word_data >> 8) & 0xFF,
        (*word_data >> 16) & 0xFF,
        (*word_data >> 24) & 0xFF
    );
    word_data++;
  }
  base_printf("\r\n");
}

static void dump_rom_digests(dif_rom_ctrl_t *rom_ctrl) {
  dif_rom_ctrl_digest_t computed_digest;
  dif_rom_ctrl_digest_t expected_digest;

  // Get digests
  CHECK_DIF_OK(dif_rom_ctrl_get_digest(rom_ctrl, &computed_digest));
  CHECK_DIF_OK(dif_rom_ctrl_get_expected_digest(rom_ctrl, &expected_digest));

  // See if they are the same
  for (size_t i = 0; i < ROM_CTRL_DIGEST_MULTIREG_COUNT; ++i) {
    if (computed_digest.digest[i] != expected_digest.digest[i]) {
      LOG_INFO("Expected digest not the same as actual!");    
      break;
    }
  }
  dump_as_hex_bytestream("Expected_ROM_Digest", expected_digest.digest, ROM_CTRL_DIGEST_MULTIREG_COUNT);
  dump_as_hex_bytestream("Actual_ROM_Digest", computed_digest.digest, ROM_CTRL_DIGEST_MULTIREG_COUNT);  
}

static void dump_device_id(dif_otp_ctrl_t *otp) {
  uint32_t device_id[OTP_CTRL_PARAM_DEVICE_ID_SIZE >> 2];
  
  for (size_t i = 0; i < OTP_CTRL_PARAM_DEVICE_ID_SIZE; i += 4) {

    CHECK_STATUS_OK(otp_ctrl_testutils_dai_read32(otp, kDifOtpCtrlPartitionHwCfg0,
            OTP_CTRL_PARAM_DEVICE_ID_OFFSET - OTP_CTRL_PARAM_HW_CFG0_OFFSET + i,
                                      &device_id[i >> 2]));
  }

  // Dump the key as a bytestream
  dump_as_hex_bytestream("Device_Id", device_id, ARRAYSIZE(device_id));
}

static void get_key(dif_keymgr_dpe_t *keymgr, uint32_t *key_out) {
  LOG_INFO("Obtaining previously generated SW key...");
  dif_keymgr_dpe_output_t output_key_shares = {0};
  CHECK_DIF_OK(dif_keymgr_dpe_read_output(keymgr, &output_key_shares));
  
  for (size_t i = 0; i < kSizeSwKeyWords; ++i) {
    key_out[i] = output_key_shares.value[0][i] ^ output_key_shares.value[1][i]; // Key is share0 ^ share1
    LOG_INFO("[%d] key=0x%08X : share0=0x%08X share1=0x%08X", 
      i, key_out[i], output_key_shares.value[0][i], output_key_shares.value[1][i]);
  }
}

bool test_main(void) {
  uint32_t key_at_crk[kSizeSwKeyWords] = {0};
  LOG_INFO("Test begins...");
 
  // Init ROM Ctrl and OTP
  CHECK_DIF_OK(dif_rom_ctrl_init(
    mmio_region_from_addr(TOP_EARLGREY_ROM_CTRL_REGS_BASE_ADDR), &rom_ctrl
  ));

  // Init OTP and dump dev ID 
  CHECK_DIF_OK(dif_otp_ctrl_init(
    mmio_region_from_addr(TOP_EARLGREY_OTP_CTRL_CORE_BASE_ADDR), &otp
  ));

  dump_rom_digests(&rom_ctrl);
  dump_device_id(&otp);
     
  // Start keymgr_dpe, generating CreatorRootKey into the slot defined by
  // kCreatorRootKeyParams(/sw/device/lib/testing/keymgr_dpe_testutils.h)
  CHECK_STATUS_OK(keymgr_dpe_testutils_startup(&keymgr_dpe, &kmac));
  CHECK_STATUS_OK(keymgr_dpe_testutils_check_state(
      &keymgr_dpe, kDifKeymgrDpeStateAvailable));
  
  LOG_INFO("KeymgrDpe derived CreatorRootKey and removed the UDS");

  // Generate SW key and read it.
  CHECK_STATUS_OK(
      keymgr_dpe_testutils_generate_key(&keymgr_dpe, &kGenParamSwTest));
  LOG_INFO("Keymgr generated SW output for key at CreatorRootKey State");
  get_key(&keymgr_dpe, key_at_crk);
  dump_as_hex_bytestream("Key@CreatorRootKey State", key_at_crk, ARRAYSIZE(key_at_crk));
  return true;
}
