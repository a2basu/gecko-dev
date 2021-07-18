/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef RLBOX_OPUS_H
#define RLBOX_OPUS_H

#define RLBOX_SINGLE_THREADED_INVOCATIONS

#include "mozilla/rlbox/rlbox_types.hpp"
#include "mozilla/rlbox/rlbox_config.h"

#ifdef MOZ_WASM_SANDBOXING_OPUS
#  include "mozilla/rlbox/rlbox_lucet_sandbox.hpp"
namespace rlbox {
    class rlbox_lucet_sandbox;
}
using rlbox_opus_sandbox_type = rlbox::rlbox_lucet_sandbox;
#else
#  define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol
#  include "mozilla/rlbox/rlbox_noop_sandbox.hpp"
using rlbox_opus_sandbox_type = rlbox::rlbox_noop_sandbox;
#endif

#include "mozilla/rlbox/rlbox.hpp"

using rlbox_sandbox_opus = rlbox::rlbox_sandbox<rlbox_opus_sandbox_type>;

#endif
