/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//#include <iostream>
//#include <unistd.h>
//using namespace std;

#include "OpusDecoder.h"
#ifdef MOZ_WASM_SANDBOXING_OPUS
# include "mozilla/ipc/LibrarySandboxPreload.h"
#endif

#include <inttypes.h>  // For PRId64

#include "OpusParser.h"
#include "TimeUnits.h"
#include "VideoUtils.h"
#include "VorbisDecoder.h"  // For VorbisLayout
#include "VorbisUtils.h"
#include "mozilla/EndianUtils.h"
#include "mozilla/PodOperations.h"
#include "mozilla/SyncRunnable.h"
#include "opus/opus.h"
extern "C" {
#include "opus/opus_multistream.h"
}

#define OPUS_DEBUG(arg, ...)                                           \
  DDMOZ_LOG(sPDMLog, mozilla::LogLevel::Debug, "::%s: " arg, __func__, \
            ##__VA_ARGS__)

namespace mozilla {

OpusDataDecoder::OpusDataDecoder(const CreateDecoderParams& aParams)
    : mSandbox(CreateSandbox()),
      mInfo(aParams.AudioConfig()),
      mOpusDecoder(nullptr),
      mSkip(0),
      mDecodedHeader(false),
      mPaddingDiscarded(false),
      mFrames(0),
      mChannelMap(AudioConfig::ChannelLayout::UNKNOWN_MAP),
      mDefaultPlaybackDeviceMono(aParams.mOptions.contains(
          CreateDecoderParams::Option::DefaultPlaybackDeviceMono)) {}

OpusDataDecoder::~OpusDataDecoder() {
  if (mOpusDecoder) {
    mSandbox->invoke_sandbox_function(opus_multistream_decoder_destroy, mOpusDecoder);
    mOpusDecoder = nullptr;
  }
}

RefPtr<ShutdownPromise> OpusDataDecoder::Shutdown() {
  // mThread may not be set if Init hasn't been called first.
  MOZ_ASSERT(!mThread || mThread->IsOnCurrentThread());
  return ShutdownPromise::CreateAndResolve(true, __func__);
}

void OpusDataDecoder::AppendCodecDelay(MediaByteBuffer* config,
                                       uint64_t codecDelayUS) {
  uint8_t buffer[sizeof(uint64_t)];
  BigEndian::writeUint64(buffer, codecDelayUS);
  config->AppendElements(buffer, sizeof(uint64_t));
}

RefPtr<MediaDataDecoder::InitPromise> OpusDataDecoder::Init() {
  mThread = GetCurrentSerialEventTarget();
  size_t length = mInfo.mCodecSpecificConfig->Length();
  uint8_t* p = mInfo.mCodecSpecificConfig->Elements();
  if (length < sizeof(uint64_t)) {
    OPUS_DEBUG("CodecSpecificConfig too short to read codecDelay!");
    return InitPromise::CreateAndReject(
        MediaResult(
            NS_ERROR_DOM_MEDIA_FATAL_ERR,
            RESULT_DETAIL("CodecSpecificConfig too short to read codecDelay!")),
        __func__);
  }
  int64_t codecDelay = BigEndian::readUint64(p);
  length -= sizeof(uint64_t);
  p += sizeof(uint64_t);
  if (NS_FAILED(DecodeHeader(p, length))) {
    OPUS_DEBUG("Error decoding header!");
    return InitPromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_FATAL_ERR,
                    RESULT_DETAIL("Error decoding header!")),
        __func__);
  }

  MOZ_ASSERT(mMappingTable.Length() >= uint32_t(mOpusParser->mChannels));
  auto t_r = mSandbox->malloc_in_sandbox<int>(1);
  auto sandboxedMappingTable = mSandbox->malloc_in_sandbox<uint8_t>(mMappingTable.Length());
  rlbox::memcpy(*mSandbox, sandboxedMappingTable, mMappingTable.Elements(), mMappingTable.Length());

  mOpusDecoder = mSandbox->invoke_sandbox_function(opus_multistream_decoder_create, 
      mOpusParser->mRate, mOpusParser->mChannels, mOpusParser->mStreams, 
      mOpusParser->mCoupledStreams, sandboxedMappingTable, t_r);

  if (!mOpusDecoder) {
    OPUS_DEBUG("Error creating decoder!");
    return InitPromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_FATAL_ERR,
                    RESULT_DETAIL("Error creating decoder!")),
        __func__);
  }

  // Opus has a special feature for stereo coding where it represent wide
  // stereo channels by 180-degree out of phase. This improves quality, but
  // needs to be disabled when the output is downmixed to mono. Playback number
  // of channels are set in AudioSink, using the same method
  // `DecideAudioPlaybackChannels()`, and triggers downmix if needed.
  if (mDefaultPlaybackDeviceMono || DecideAudioPlaybackChannels(mInfo) == 1) {
    mSandbox->invoke_sandbox_function(opus_multistream_decoder_ctl_phase_inversion_set, mOpusDecoder, 1);
  }

  mSkip = mOpusParser->mPreSkip;
  mPaddingDiscarded = false;

  if (codecDelay !=
      FramesToUsecs(mOpusParser->mPreSkip, mOpusParser->mRate).value()) {
    NS_WARNING("Invalid Opus header: CodecDelay and pre-skip do not match!");
    return InitPromise::CreateAndReject(NS_ERROR_DOM_MEDIA_FATAL_ERR, __func__);
  }

  if (mInfo.mRate != (uint32_t)mOpusParser->mRate) {
    NS_WARNING("Invalid Opus header: container and codec rate do not match!");
  }
  if (mInfo.mChannels != (uint32_t)mOpusParser->mChannels) {
    NS_WARNING(
        "Invalid Opus header: container and codec channels do not match!");
  }

  std::unique_ptr<int> r = t_r.copy_and_verify([](std::unique_ptr<int> r) { return r; });
  //free t_r and sandboxedMappingTable
  mSandbox->free_in_sandbox(t_r);
  mSandbox->free_in_sandbox(sandboxedMappingTable);
  t_r = nullptr;
  sandboxedMappingTable = nullptr;
  return *r == OPUS_OK
             ? InitPromise::CreateAndResolve(TrackInfo::kAudioTrack, __func__)
             : InitPromise::CreateAndReject(
                   MediaResult(
                       NS_ERROR_DOM_MEDIA_FATAL_ERR,
                       RESULT_DETAIL(
                           "could not create opus multistream decoder!")),
                   __func__);
}

nsresult OpusDataDecoder::DecodeHeader(const unsigned char* aData,
                                       size_t aLength) {
  MOZ_ASSERT(!mOpusParser);
  MOZ_ASSERT(!mOpusDecoder);
  MOZ_ASSERT(!mDecodedHeader);
  mDecodedHeader = true;

  mOpusParser = MakeUnique<OpusParser>();
  if (!mOpusParser->DecodeHeader(const_cast<unsigned char*>(aData), aLength)) {
    return NS_ERROR_FAILURE;
  }
  int channels = mOpusParser->mChannels;

  mMappingTable.SetLength(channels);
  AudioConfig::ChannelLayout vorbisLayout(
      channels, VorbisDataDecoder::VorbisLayout(channels));
  if (vorbisLayout.IsValid()) {
    mChannelMap = vorbisLayout.Map();

    AudioConfig::ChannelLayout smpteLayout(
        AudioConfig::ChannelLayout::SMPTEDefault(vorbisLayout));

    AutoTArray<uint8_t, 8> map;
    map.SetLength(channels);
    if (mOpusParser->mChannelMapping == 1 &&
        vorbisLayout.MappingTable(smpteLayout, &map)) {
      for (int i = 0; i < channels; i++) {
        mMappingTable[i] = mOpusParser->mMappingTable[map[i]];
      }
    } else {
      // Use Opus set channel mapping and return channels as-is.
      PodCopy(mMappingTable.Elements(), mOpusParser->mMappingTable, channels);
    }
  } else {
    // Create a dummy mapping table so that channel ordering stay the same
    // during decoding.
    for (int i = 0; i < channels; i++) {
      mMappingTable[i] = i;
    }
  }

  return NS_OK;
}

RefPtr<MediaDataDecoder::DecodePromise> OpusDataDecoder::Decode(
    MediaRawData* aSample) {
  MOZ_ASSERT(mThread->IsOnCurrentThread());
  uint32_t channels = mOpusParser->mChannels;

  if (mPaddingDiscarded) {
    // Discard padding should be used only on the final packet, so
    // decoding after a padding discard is invalid.
    OPUS_DEBUG("Opus error, discard padding on interstitial packet");
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_FATAL_ERR,
                    RESULT_DETAIL("Discard padding on interstitial packet")),
        __func__);
  }

  if (!mLastFrameTime ||
      mLastFrameTime.ref() != aSample->mTime.ToMicroseconds()) {
    // We are starting a new block.
    mFrames = 0;
    mLastFrameTime = Some(aSample->mTime.ToMicroseconds());
  }
  auto t_aSampleData = mSandbox->malloc_in_sandbox<uint8_t>(aSample->Size());
  rlbox::memcpy(*mSandbox, t_aSampleData, aSample->Data(), aSample->Size());
  // Maximum value is 63*2880, so there's no chance of overflow.
  int frames_number = mSandbox->invoke_sandbox_function(
      opus_packet_get_nb_frames, t_aSampleData, aSample->Size()).copy_and_verify([](int frames_number) {
		if (frames_number > 0 && frames_number <= (63*2880))
			return frames_number;
		else if (frames_number == OPUS_BAD_ARG || frames_number == OPUS_INVALID_PACKET)
			return frames_number;
		else
			return OPUS_INVALID_PACKET; });

  if (frames_number <= 0) {
    OPUS_DEBUG("Invalid packet header: r=%d length=%zu", frames_number,
               aSample->Size());
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_DECODE_ERR,
                    RESULT_DETAIL("Invalid packet header: r=%d length=%u",
                                  frames_number, uint32_t(aSample->Size()))),
        __func__);
  }

  int samples = mSandbox->invoke_sandbox_function(opus_packet_get_samples_per_frame,
      t_aSampleData, opus_int32(mOpusParser->mRate)).copy_and_verify([](int samples) {
		if (samples >= 0 || samples == OPUS_INVALID_PACKET)
			return samples;
		else
			return OPUS_INVALID_PACKET; });

  // A valid Opus packet must be between 2.5 and 120 ms long (48kHz).
  CheckedInt32 totalFrames =
      CheckedInt32(frames_number) * CheckedInt32(samples);
  if (!totalFrames.isValid()) {
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_DECODE_ERR,
                    RESULT_DETAIL("Frames count overflow")),
        __func__);
  }

  int frames = totalFrames.value();
  if (frames < 120 || frames > 5760) {
    OPUS_DEBUG("Invalid packet frames: %d", frames);
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_DECODE_ERR,
                    RESULT_DETAIL("Invalid packet frames:%d", frames)),
        __func__);
  }

  // Decode to the appropriate sample type.
#ifdef MOZ_SAMPLE_TYPE_FLOAT32
  /* tainted<void*, rlbox_noop_sandbox> tainted_p = tainted<void*, rlbox_noop_sandbox>::UNSAFE_accept_pointer(some_void_ptr); */
  auto t_buffer = mSandbox->malloc_in_sandbox<float>(frames * channels);
  auto t_ret = mSandbox->invoke_sandbox_function(opus_multistream_decode_float, mOpusDecoder, t_aSampleData,
		  aSample->Size(), t_buffer, frames,
                                          false);
#else
  auto t_buffer = mSandbox->malloc_in_sandbox<uint16_t>(frames * channels);
  auto t_ret = mSandbox->invoke_sandbox_function(
      opus_multistream_decode, mOpusDecoder, t_aSampleData, aSample->Size(),
                              t_buffer, frames, false);
#endif

  int ret = t_ret.copy_and_verify([](int ret) { return ret; });

  AlignedAudioBuffer buffer(t_buffer.unverified_safe_pointer_because(frames*channels, "trying out sandboxing"), frames * channels);
  if (!buffer) {
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_OUT_OF_MEMORY, __func__), __func__);
  }
  if (ret < 0) {
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_DECODE_ERR,
                    RESULT_DETAIL("Opus decoding error:%d", ret)),
        __func__);
  }
  mSandbox->free_in_sandbox(t_buffer);
  mSandbox->free_in_sandbox(t_aSampleData);
  t_buffer = nullptr;
  t_aSampleData = nullptr;
  NS_ASSERTION(ret == frames, "Opus decoded too few audio samples");
  auto startTime = aSample->mTime;

  // Trim the initial frames while the decoder is settling.
  if (mSkip > 0) {
    int32_t skipFrames = std::min<int32_t>(mSkip, frames);
    int32_t keepFrames = frames - skipFrames;
    OPUS_DEBUG("Opus decoder skipping %d of %d frames", skipFrames, frames);
    PodMove(buffer.get(), buffer.get() + skipFrames * channels,
            keepFrames * channels);
    startTime = startTime + FramesToTimeUnit(skipFrames, mOpusParser->mRate);
    frames = keepFrames;
    mSkip -= skipFrames;
  }

  if (aSample->mDiscardPadding > 0) {
    OPUS_DEBUG("Opus decoder discarding %u of %d frames",
               aSample->mDiscardPadding, frames);
    // Padding discard is only supposed to happen on the final packet.
    // Record the discard so we can return an error if another packet is
    // decoded.
    if (aSample->mDiscardPadding > uint32_t(frames)) {
      // Discarding more than the entire packet is invalid.
      OPUS_DEBUG("Opus error, discard padding larger than packet");
      return DecodePromise::CreateAndReject(
          MediaResult(NS_ERROR_DOM_MEDIA_FATAL_ERR,
                      RESULT_DETAIL("Discard padding larger than packet")),
          __func__);
    }

    mPaddingDiscarded = true;
    frames = frames - aSample->mDiscardPadding;
  }

  // Apply the header gain if one was specified.
#ifdef MOZ_SAMPLE_TYPE_FLOAT32
  if (mOpusParser->mGain != 1.0f) {
    float gain = mOpusParser->mGain;
    uint32_t samples = frames * channels;
    for (uint32_t i = 0; i < samples; i++) {
      buffer[i] *= gain;
    }
  }
#else
  if (mOpusParser->mGain_Q16 != 65536) {
    int64_t gain_Q16 = mOpusParser->mGain_Q16;
    uint32_t samples = frames * channels;
    for (uint32_t i = 0; i < samples; i++) {
      int32_t val = static_cast<int32_t>((gain_Q16 * buffer[i] + 32768) >> 16);
      buffer[i] = static_cast<AudioDataValue>(MOZ_CLIP_TO_15(val));
    }
  }
#endif

  auto duration = FramesToTimeUnit(frames, mOpusParser->mRate);
  if (!duration.IsValid()) {
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_OVERFLOW_ERR,
                    RESULT_DETAIL("Overflow converting WebM audio duration")),
        __func__);
  }
  auto time = startTime -
              FramesToTimeUnit(mOpusParser->mPreSkip, mOpusParser->mRate) +
              FramesToTimeUnit(mFrames, mOpusParser->mRate);
  if (!time.IsValid()) {
    return DecodePromise::CreateAndReject(
        MediaResult(NS_ERROR_DOM_MEDIA_OVERFLOW_ERR,
                    RESULT_DETAIL("Overflow shifting tstamp by codec delay")),
        __func__);
  };

  mFrames += frames;

  if (!frames) {
    return DecodePromise::CreateAndResolve(DecodedData(), __func__);
  }

  // Trim extra allocated frames.
  buffer.SetLength(frames * channels);

  return DecodePromise::CreateAndResolve(
      DecodedData{new AudioData(aSample->mOffset, time, std::move(buffer),
                                mOpusParser->mChannels, mOpusParser->mRate,
                                mChannelMap)},
      __func__);
}

RefPtr<MediaDataDecoder::DecodePromise> OpusDataDecoder::Drain() {
  MOZ_ASSERT(mThread->IsOnCurrentThread());
  return DecodePromise::CreateAndResolve(DecodedData(), __func__);
}

RefPtr<MediaDataDecoder::FlushPromise> OpusDataDecoder::Flush() {
  MOZ_ASSERT(mThread->IsOnCurrentThread());
  if (!mOpusDecoder) {
    return FlushPromise::CreateAndResolve(true, __func__);
  }

  MOZ_ASSERT(mOpusDecoder);
  // Reset the decoder.
  mSandbox->invoke_sandbox_function(opus_multistream_decoder_ctl_reset, mOpusDecoder, OPUS_RESET_STATE);
  mSkip = mOpusParser->mPreSkip;
  mPaddingDiscarded = false;
  mLastFrameTime.reset();
  return FlushPromise::CreateAndResolve(true, __func__);
}

/* static */
bool OpusDataDecoder::IsOpus(const nsACString& aMimeType) {
  return aMimeType.EqualsLiteral("audio/opus");
}

rlbox_sandbox_opus* OpusDataDecoder::CreateSandbox() {
  rlbox_sandbox_opus* sandbox = new rlbox_sandbox_opus();
#ifdef MOZ_WASM_SANDBOXING_OPUS
// Firefox preloads the library externally to ensure we won't be stopped
// by the content sandbox
  const bool external_loads_exist = true;
  // See Bug 1606981: In some environments allowing stdio in the wasm sandbox
  // fails as the I/O redirection involves querying meta-data of file
  // descriptors. This querying fails in some environments.
  const bool allow_stdio = false;
  sandbox->create_sandbox(mozilla::ipc::GetSandboxedOpusPath().get(),
      external_loads_exist, allow_stdio);
  //cerr << "PID: " << getpid();
  //cerr << "Create WASM Sandbox" << endl;
#else
  sandbox->create_sandbox();
  //cerr << "PID: " << getpid();
  //cerr << "Create Noop Sandbox" << endl;
#endif
  return sandbox;
}

void OpusDataDecoder::SandboxDestroy::operator()(rlbox_sandbox_opus* sandbox) {
  //auto& transition_times = sandbox->process_and_get_transition_times();
  //cerr << "No. of transitions: " << transition_times.size() << endl;
  //cerr << "Time: " << sandbox->get_total_ns_time_in_sandbox_and_transitions() << endl;
  sandbox->destroy_sandbox();
  delete sandbox;
}
}  // namespace mozilla
#undef OPUS_DEBUG
