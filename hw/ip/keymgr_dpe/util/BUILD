# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_python//python:defs.bzl", "py_binary")
load("@ot_python_deps//:requirements.bzl", "requirement")

package(default_visibility = ["//visibility:public"])


py_binary(
    name = "keymgr_dpe_ref_test",
    srcs = ["keymgr_dpe_ref_test.py"],
    main = "keymgr_dpe_ref_test.py",
    deps = [
             requirement("pycryptodome")
    ],
)
