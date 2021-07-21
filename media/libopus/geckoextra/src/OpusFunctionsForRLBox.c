#include "opus/OpusFunctionsForRLBox.h"

int opus_multistream_decoder_ctl_phase_inversion_set(OpusMSDecoder *st, int flag) {
    return opus_multistream_decoder_ctl(st, OPUS_SET_PHASE_INVERSION_DISABLED(flag));
}

int opus_multistream_decoder_ctl_reset(OpusMSDecoder *st, int request) {
    return opus_multistream_decoder_ctl(st, request);
}

