#ifndef OPUS_FUNCTIONS_FOR_RLBOX_H
#define OPUS_FUNCTIONS_FOR_RLBOX_H

#include "opus_multistream.h"

OPUS_EXPORT int opus_multistream_decoder_ctl_phase_inversion_set(OpusMSDecoder *st, int flag);

OPUS_EXPORT int opus_multistream_decoder_ctl_reset(OpusMSDecoder *st, int request);

#endif
