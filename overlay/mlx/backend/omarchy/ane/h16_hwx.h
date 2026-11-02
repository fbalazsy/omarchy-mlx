// SPDX-License-Identifier: GPL-2.0-only
// C++ port of aurora tools/testing/selftests/drivers/ane/h16-sections.py
// (GPL-2.0-only, aurora-silicon/linux 3aa52f4f, sha256 479806b8...). This file
// and h16_hwx.cpp carry that licence; they must be relicensed by the script's
// author or rewritten from the format facts before this lane is published
// under the repository's MIT licence.
#pragma once

// H16 (ABI version 3) program sections, built on the host from the HWX.
//
// DRM_IOCTL_ANE_H16_LOAD takes the original HWX plus four host-built
// sections (generic, operation, procedure, text properties). This header
// parses an H16G or H17 HWX and builds those sections exactly as the
// kernel tree's reference client h16-sections.py does: same parse, same
// task-stream walk, same buffer ID assignment, same byte layouts and the
// same named refusals. Nothing here touches a device; the bundle validator
// and the lane-3 device both use it.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "mlx/api.h"

namespace mlx::core::omarchy::ane {

// Mach-O CPU subtypes of the HWX header (offset 8).
constexpr uint32_t kAneHwxSubtypeH16G = 7;
constexpr uint32_t kAneHwxSubtypeH17 = 9;
// DRM_ANE_H16_SECTIONS, the kind order H16_LOAD takes them in.
constexpr size_t kAneH16SectionCount = 4;
constexpr std::array<const char*, kAneH16SectionCount> kAneH16SectionNames{
    "generic.bin", "operation.bin", "procedure.bin", "text-properties.bin"};

// A named refusal. The message after the prefix is the reference script's
// HwxError text.
struct AneH16HwxError : std::runtime_error {
  explicit AneH16HwxError(const std::string& reason)
      : std::runtime_error("[omarchy-ane] h16 hwx: " + reason + "."),
        reason(reason) {}
  std::string reason;
};

// One __FVMLIB surface in HWX segment order (the order H16_LOAD reports
// and H16_EXEC takes).
struct AneH16Surface {
  uint64_t vm{0};
  uint64_t allocation{0}; // the __FVMLIB segment vmsize
  uint32_t direction{0};  // 1 input, 2 output (the segment protection)
  std::optional<std::string> name;
  uint64_t span{0};       // tensor descriptor n * batch
  uint32_t id{0};         // generic-section buffer ID
};

struct AneH16Region {
  uint64_t vm{0};
  uint64_t size{0};
  uint32_t offset{0};
};

struct AneH16Parsed {
  uint32_t subtype{0};
  std::vector<AneH16Surface> surfaces;
  AneH16Region text;
  std::optional<AneH16Region> kernel;
  std::optional<AneH16Region> scratch; // offset unused
  size_t descriptor{0};                // file offset of the program descriptor
};

struct AneH16Sections {
  // generic, operation, procedure, text properties: H16_LOAD kind order.
  std::array<std::vector<uint8_t>, kAneH16SectionCount> sections;
  std::vector<AneH16Surface> surfaces;            // segment order, IDs set
  std::optional<uint32_t> scratch_id;
  uint64_t scratch_bytes{0};                      // __DATA,__bss size or 0
  std::vector<std::pair<uint32_t, uint32_t>> refs; // (BAR slot, tag)
  uint32_t tasks{0};
  uint32_t subtype{0};
};

// The reference parse(): surfaces, text and kernel sections, scratch and the
// program descriptor. Throws AneH16HwxError.
MLX_API AneH16Parsed h16_parse_hwx(const uint8_t* hwx, size_t size);

// The reference walk(): number of tasks and the BAR slots their records
// reference, for a task stream that must open with `prologue`.
MLX_API std::pair<uint32_t, std::vector<uint32_t>> h16_walk_tasks(
    const uint8_t* stream,
    size_t size,
    uint32_t prologue);

// The reference build(): the four H16_LOAD sections for one HWX.
MLX_API AneH16Sections h16_build_sections(const uint8_t* hwx, size_t size);

// A read-only private mapping of one file (a sealed /proc/self/fd/N image
// or a plain path). The HWX of a whole model is hundreds of megabytes; the
// validator and the device map it instead of copying it.
class MLX_API AneMappedFile {
 public:
  explicit AneMappedFile(const std::string& path);
  ~AneMappedFile();
  AneMappedFile(const AneMappedFile&) = delete;
  AneMappedFile& operator=(const AneMappedFile&) = delete;
  const uint8_t* data() const {
    return data_;
  }
  size_t size() const {
    return size_;
  }

 private:
  const uint8_t* data_{nullptr};
  size_t size_{0};
};

} // namespace mlx::core::omarchy::ane
