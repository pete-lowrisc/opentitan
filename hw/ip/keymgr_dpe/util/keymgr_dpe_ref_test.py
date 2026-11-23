# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# An independent reference implementation of the key manager state transition to createrrootkey state
# and SW key generation. Output key value can then be compared with the test 'keymger_dpe_seed_test.c'.

# HW seeds are derived from the RTL and hard-coded here. OTP values match those built into a bespoke
# OTP RMA Image in 'keymgr_dpe_seed_test.c'.
# ROM Digest is supplied on the command line as it depends on the ROM image contents - it is output from
# the 'keymgr_dpe_seed_test.c' test.

# Improvement would be to automatically pick up values from the RTL in this script.

import argparse
import sys
import logging
import struct

from Crypto.Hash import KMAC256
from typing import List

# These values match the keymgr_dpe_seed_test.c test case
# The creator root key shares are combined to produce the UDS seed. They are written to
# the SECRET2 OTP partition.
# The device ID is writen to the HW_CFG0 OTP partition.
OTP_VALUES = {
    'creator_root_key_share_0':
    bytes.fromhex("94b49efff8af5fe4431bd38e115d84b33401e0c3caf9d2313fb98d11e2f08a64"),
    'creator_root_key_share_1':
    bytes.fromhex("2cb7fca838cc85199c3c61b5a9e5f49c0f7ab0d205c2951fc50e7c59e91ced62"),
    'device_id':
    bytes.fromhex("526b016f2499f77d23f2338d445987ae45d02a00bde464b3f6b732cca3b43fef")
}

# SW Values used
SW_VALUES = {
    # SW binding value used to advance to the creator root key. This is supplied
    # from SW in the call to advance - below value is copied from keymgr_testutils.h.
    'creator_swbind': [
        0xdc96c23d, 0xaf36e268, 0xcb68ff71, 0xe92f76e2,
        0xb8a8379d, 0x426dc745, 0x19f5cff7, 0x4ec9c6d6
    ],

    # Salt as used in the 'keymgr_dpe_seed_test.c' test case to generate the SW key.
    'salt': [
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xa0,
        0xbc,
        0xde
    ],

    # Version as used in the 'keymgr_dpe_seed_test.c' test case to generate the SW key.
    'version': 0x0
}

# These values are hardcoded in the RTL, generated at topgen time into
# hw/top_earlgrey/rtl/autogen/top_earlgrey_rnd_cnst_pkg.sv.
HW_VALUES = {
    # RndCnstKeymgrRevisionSeed - used to move to CreatorRootKey state.
    'revision_seed': bytes.fromhex("a6eafbba5acd035dd7700fcf1d48ebd0513af0c164b52e884f90f2e62d13a596"),
    # RndCnstLcCtrlLcKeymgrDivRma - from LC and used to move to CreatorRootKey state.
    'lc_seed': bytes.fromhex("0717c91cfceca84287601dd59ea67b4d"),
    # RndCnstKeymgrSoftOutputSeed - used to generate the SW key.  This is the SW export constant.
    'sw_const': bytes.fromhex("8de632180ff3215b26235f17e73371b938ccc209b5126629c48e1ab45ad46b27"),
    # RndCnstKeymgrNoneSeed - used to generate the SW key, "none" indicates no HW destination.
    'keyid': bytes.fromhex("cc4761ba188dd84c87100d52e6ce500195f4031a37c1770073400f05c664f969")
}


# Simple mixin to get logging output
class LoggingMixin:
    """ Mixin for logger. """

    def __init__(self, name=None):
        if name is None:
            name = self.__class__.__name__

        self._log = logging.getLogger(name)


class KeyManagerDpeRef(LoggingMixin):
    """ Generate keys for key manager. """

    def __init__(self, parser_args):
        self._args = parser_args
        self._le_data = not parser_args.inputs_be

        self._curr_key = self.unmask_key(
            self.endianness_swap_bytes(self._args.creator_root_share0)
            if self._args.creator_root_share0
            else OTP_VALUES.get('creator_root_key_share_0'),

            self.endianness_swap_bytes(self._args.creator_root_share1)
            if self._args.creator_root_share1
            else OTP_VALUES.get('creator_root_key_share_1')
        )
        super().__init__()

    def endianness_swap_bytes(self, arr: bytes) -> bytes:
        """ Reverse order of bytearray if required. """
        return arr[::-1] if self._le_data else arr

    def le_bytes_from_uint_array(self, uint_arr: List[int]) -> bytearray:
        return bytearray(struct.pack(f'>{len(uint_arr)}I', *(uint_arr[::-1])))

    def unmask_key(self, s1: bytes, s2: bytes, reverse_shares: bool = True):
        """ By default shares need reversing. """
        if reverse_shares:
            s1 = s1[::-1]
            s2 = s2[::-1]

        return bytearray([x ^ y for x, y in zip(s1, s2)])

    @staticmethod
    def keymgr_kmac(key: bytes, data_list: List[bytes], *, required_output_bits = 256) -> bytes:
        """ Calculate a keymgr key as output from KMAC.

            Keymgr constructs large array of all the values in order provided.
            But it then chunks these and sends it backwards to the kmac due to endianness.

            Therefore here we reverse each entry and iterate the array backwards.
            NOTE: Due to KMAC app i/f, 64 bits must be sent.  But a mask is used to specify
            how much is valid.  Therefore we need no pad here.

            Due to a potential issue, the output length requested (which is encoded & appended
            to the message for the hash) is fixed at 512 bits irrespective of the number of bits
            actually required.
        """
        mac = KMAC256.new(key=key, mac_len=64)  # Always specify output length as 512 bits

        for i in range(1, len(data_list) + 1):
            mac.update(data_list[-i][::-1])

        return mac.digest()[:required_output_bits // 8]

    def adv_creator_root_key(self):
        """ Advance to creator root key state.

            Order for CreatorRootKey is:
            sw_binding,
            device_id,
            lc_keymgr_state (from OTP)
            rom_digest_i.data,
            revision_seed
        """
        self._log.info(
            f'Caculating CreatorRootKey using unmasked value: {self._curr_key.hex()}...')

        # ROM Digest supplied on command line as it depends on ROM contents
        rom_digest = self.endianness_swap_bytes(self._args.rom_digest)

        device_id = self.endianness_swap_bytes(
            self._args.device_id) if self._args.device_id else OTP_VALUES.get('device_id')

        lc_seed = self.endianness_swap_bytes(
            self._args.lc_seed) if self._args.lc_seed else HW_VALUES.get('lc_seed')
        revision_seed = self.endianness_swap_bytes(
            self._args.revision_seed) if self._args.revision_seed else HW_VALUES.get('revision_seed')

        sw_binding = self.le_bytes_from_uint_array(SW_VALUES.get('creator_swbind'))

        self._log.debug(f'SW Binding: {sw_binding.hex()}')
        self._log.debug(f'Device Id: {device_id.hex()}')
        self._log.debug(f'ROM Digest: {rom_digest.hex()}')
        self._log.debug(f'LC Seed: {lc_seed.hex()}')
        self._log.debug(f'Revision Seed: {revision_seed.hex()}')

        creator_key = self.keymgr_kmac(
            self._curr_key, [sw_binding, device_id, lc_seed, rom_digest, revision_seed])

        self._log.info(f'Creator Root key (as LE) = {creator_key[::-1].hex()}')

        self._curr_key = creator_key

    def generate_sw_key(self) -> bytes:
        """ Generate a SW Key at current KeyMgrDpe State.

            Order for a generated SW key is:
            Version
            Salt
            KeyId
            SWExportConstant

            Returns key as bytes.
        """
        # Version in LE order as bytes
        version = struct.pack('>I', SW_VALUES.get('version'))

        salt = self.le_bytes_from_uint_array(SW_VALUES.get('salt'))
        keyid = self.endianness_swap_bytes(
            self._args.sw_key_id) if self._args.sw_key_id else HW_VALUES.get('keyid')
        sw_export_constant = self.endianness_swap_bytes(
            self._args.sw_const) if self._args.sw_const else HW_VALUES.get('sw_const')

        self._log.debug(f"Version: {version.hex()}")
        self._log.debug(f"Salt: {salt.hex()}")
        self._log.debug(f"SW Key ID: {keyid.hex()}")
        self._log.debug(f"SW Export Constant: {sw_export_constant.hex()}")

        # SW keys are output as 384 bits
        gen_sw_key = self.keymgr_kmac(
            self._curr_key, [version, salt, keyid, sw_export_constant], required_output_bits = 384)

        self._log.info(f'Generated SW key (as LE)= {gen_sw_key[::-1].hex()}')

        return gen_sw_key


def run_test(args: argparse.Namespace, log: logging.Logger) -> bool:
    log.info('Running Key Manager Reference Test...')

    kmdperef = KeyManagerDpeRef(args)

    log.info('Advance to CreatorRoot Key...')
    kmdperef.adv_creator_root_key()

    log.info('Generate a SW key from CreatorRootState...')
    sw_key_crk = kmdperef.generate_sw_key()

    log.critical(f"Output SW Key @ CreatorRootState: {sw_key_crk.hex()}")
    log.info('Done')


def valid_bytes(hexstr: str, desired_len: int = 32) -> bytes:
    """ Read input bytes of given length. """
    try:
        bytarr = bytes.fromhex(hexstr)
        if len(bytarr) == desired_len:
            return bytarr
    except ValueError:
        pass

    raise argparse.ArgumentTypeError(f"Input must be hex byte string of {desired_len} bytes")


def create_command_line_parser():
    parser = argparse.ArgumentParser(description='keymgr-dpe-ref-test',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--rom_digest', help='Hash of the ROM image (required)',
                        type=lambda x: valid_bytes(x, 32), required=True)

    parser.add_argument('--creator_root_share0',
                        help='Creator Root from OTP share0 (optional)',
                        type=lambda x: valid_bytes(x, 32))
    
    parser.add_argument('--creator_root_share1',
                        help='Creator Root from OTP share1 (optional)',
                        type=lambda x: valid_bytes(x, 32))

    parser.add_argument('--device_id', help='Device ID (optional)))',
                        type=lambda x: valid_bytes(x, 32))

    parser.add_argument(
        '--lc_seed', help='LC Seed for current LC state (e.g RMA) (optional)',
        type=lambda x: valid_bytes(x, 16))

    parser.add_argument('--revision_seed', help='Revision seed from RTL (optional)',
                        type=lambda x: valid_bytes(x, 32))

    parser.add_argument(
        '--sw_const', help='SW Constant from RTL (optional)', type=lambda x: valid_bytes(x, 32))
    parser.add_argument(
        '--sw_key_id', help='SW KeyId from RTL (optional)', type=lambda x: valid_bytes(x, 32))

    parser.add_argument(
        '--inputs_be', help='Whether input bytestreams are big-endian or not (default is LE)',
        action='store_true')

    parser.add_argument('-v', '--verbose', dest='verbose_log',
                        action='store_true', help='Enable verbose logging (optional)')

    return parser


def run_with_command_line_arguments(parser: argparse.ArgumentParser) -> bool:
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose_log else logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    log = logging.getLogger(__name__)
    log.info(f'{sys.argv[0]} running')

    # Catch unhandled exceptions here
    try:
        exitcode = run_test(args, log)
        if exitcode:
            log.critical('Command succeeded!')
    except Exception as e:
        log.debug(f'Unhandled exception {e} occurred!', exc_info=True)
        log.error(f'Unhandled error {e}')
        exitcode = False

    return exitcode


if __name__ == '__main__':
    exitcode = False
    try:
        parser = create_command_line_parser()
        exitcode = run_with_command_line_arguments(parser)

    except IOError as e:
        parser.error(str(e))

    except SystemExit:
        pass

    sys.exit(0 if exitcode else -1)
