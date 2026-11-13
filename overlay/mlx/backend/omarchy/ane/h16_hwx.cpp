// SPDX-License-Identifier: GPL-2.0-only
// C++ port of aurora tools/testing/selftests/drivers/ane/h16-sections.py
// (GPL-2.0-only, aurora-silicon/linux 3aa52f4f, sha256 479806b8...). See
// h16_hwx.h for the licence note.
//
// Port rules. Every check, every byte layout and every refusal text follows
// the script. Where the script would stop with an unnamed Python error (a
// struct.unpack past the end of the file, StopIteration from an exhausted
// buffer ID range), this port refuses with a named AneH16HwxError instead;
// the refusal is the same, only the message differs. The same holds for a
// load-command name that is not UTF-8 (the script's decode() raises). Python slicing that
// silently shortens (a task stream that runs past the end of the file) is
// reproduced as shortening, so such a stream fails the same later check.

#include "mlx/backend/omarchy/ane/h16_hwx.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

namespace mlx::core::omarchy::ane {
namespace {

constexpr uint32_t kHwxMagic = 0xbeefface;
constexpr uint32_t kGenericMagic = 1;
constexpr uint32_t kGenericVersion = 0x10;
constexpr size_t kGenericHeader = 0x208;
constexpr size_t kGenericEntry = 0x30;
constexpr size_t kOperationRecord = 0x40c;
constexpr size_t kOperationRefsMax = (kOperationRecord - 0x0c) / 8;
constexpr uint32_t kResourceKernel = 1007;
constexpr uint32_t kFirstOutputId = 4;
constexpr uint32_t kInputIdEnd = 0x3d; // range(FIRST_OUTPUT_ID + 1, 0x3d)

constexpr std::pair<uint32_t, uint32_t> kRegisters[] = {
    {0x0000, 0x005c}, {0x4100, 0x41a4}, {0x44d0, 0x44d4},
    {0x4500, 0x453c}, {0x4900, 0x4930}, {0x4d00, 0x4e44},
    {0x5100, 0x5154}, {0x5500, 0x5620}, {0x5900, 0x5930}};

// Mach-O CPU subtype to the u32 that opens the task stream.
std::optional<uint32_t> prologue_of(uint32_t subtype) {
  if (subtype == kAneHwxSubtypeH16G) return 1;
  if (subtype == kAneHwxSubtypeH17) return 0;
  return std::nullopt;
}

[[noreturn]] void refuse(const std::string& reason) {
  throw AneH16HwxError(reason);
}

// struct.unpack_from("<I"/"<Q") with the bounds check Python performs by
// raising struct.error.
uint32_t u32(const uint8_t* b, size_t size, size_t o, const char* what) {
  if (o > size || size - o < 4) refuse(what);
  return uint32_t(b[o]) | (uint32_t(b[o + 1]) << 8) |
      (uint32_t(b[o + 2]) << 16) | (uint32_t(b[o + 3]) << 24);
}

uint64_t u64(const uint8_t* b, size_t size, size_t o, const char* what) {
  return uint64_t(u32(b, size, o, what)) |
      (uint64_t(u32(b, size, o + 4, what)) << 32);
}

// Python's strict UTF-8 decoder: no overlong forms, no surrogates, nothing
// above U+10FFFF.
bool valid_utf8(const uint8_t* p, size_t n) {
  size_t i = 0;
  while (i < n) {
    const uint8_t c = p[i];
    size_t extra = 0;
    uint32_t min = 0;
    uint32_t value = 0;
    if (c < 0x80) {
      ++i;
      continue;
    } else if (c >= 0xc2 && c <= 0xdf) {
      extra = 1, min = 0x80, value = c & 0x1f;
    } else if (c >= 0xe0 && c <= 0xef) {
      extra = 2, min = 0x800, value = c & 0x0f;
    } else if (c >= 0xf0 && c <= 0xf4) {
      extra = 3, min = 0x10000, value = c & 0x07;
    } else {
      return false;
    }
    if (n - i - 1 < extra) return false;
    for (size_t k = 1; k <= extra; ++k) {
      if ((p[i + k] & 0xc0) != 0x80) return false;
      value = (value << 6) | (p[i + k] & 0x3f);
    }
    if (value < min || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
      return false;
    }
    i += extra + 1;
  }
  return true;
}

// cstr(b[start:end]): bytes up to the first NUL of a Python slice, which
// clamps both ends to the buffer, decoded as strict UTF-8 (the script's
// bytes.decode() raises on anything else).
std::string cstr(const uint8_t* b, size_t size, size_t start, size_t end) {
  start = std::min(start, size);
  end = std::min(std::max(end, start), size);
  const auto* first = b + start;
  const auto* last = b + end;
  const auto* nul = std::find(first, last, uint8_t{0});
  if (!valid_utf8(first, static_cast<size_t>(nul - first))) {
    throw AneH16HwxError("HWX name is not valid UTF-8");
  }
  return std::string(reinterpret_cast<const char*>(first), nul - first);
}

void put32(std::vector<uint8_t>& out, size_t o, uint32_t v) {
  for (int i = 0; i < 4; ++i) out[o + i] = uint8_t(v >> (8 * i));
}

void put64(std::vector<uint8_t>& out, size_t o, uint64_t v) {
  for (int i = 0; i < 8; ++i) out[o + i] = uint8_t(v >> (8 * i));
}

bool register_valid(uint32_t word) {
  const uint64_t byte = uint64_t(word) * 4;
  return std::any_of(
      std::begin(kRegisters), std::end(kRegisters), [&](const auto& range) {
        return range.first <= byte && byte < range.second;
      });
}

bool any_nonzero(const uint8_t* b, size_t size, size_t start, size_t end) {
  start = std::min(start, size);
  end = std::min(end, size);
  return std::any_of(b + start, b + std::max(start, end), [](uint8_t v) {
    return v != 0;
  });
}

constexpr const char* kTruncated = "truncated load command";

} // namespace

AneH16Parsed h16_parse_hwx(const uint8_t* hwx, size_t size) {
  if (size < 32 || u32(hwx, size, 0, kTruncated) != kHwxMagic ||
      !prologue_of(u32(hwx, size, 8, kTruncated))) {
    refuse("not an H16G or H17 HWX");
  }
  AneH16Parsed parsed;
  parsed.subtype = u32(hwx, size, 8, kTruncated);
  std::optional<AneH16Region> text;
  std::optional<size_t> descriptor;
  // tensors[name] = (direction, n * batch); Python ints do not overflow.
  std::map<std::string, std::pair<uint32_t, unsigned __int128>> tensors;
  std::vector<unsigned __int128> spans;

  size_t pos = 32;
  const uint32_t commands = u32(hwx, size, 16, kTruncated);
  for (uint32_t command = 0; command < commands; ++command) {
    const uint32_t cmd = u32(hwx, size, pos, kTruncated);
    const uint32_t length = u32(hwx, size, pos + 4, kTruncated);
    if (length < 8 || pos + length > size) {
      refuse(kTruncated);
    }
    if (cmd == 0x19) {
      const std::string segment = cstr(hwx, size, pos + 8, pos + 24);
      const uint64_t vmsize = u64(hwx, size, pos + 32, kTruncated);
      const uint32_t prot = u32(hwx, size, pos + 60, kTruncated);
      const uint32_t sections = u32(hwx, size, pos + 64, kTruncated);
      for (uint32_t i = 0; i < sections; ++i) {
        const size_t at = pos + 72 + size_t(80) * i;
        const std::string name = cstr(hwx, size, at, at + 16);
        const uint64_t svm = u64(hwx, size, at + 32, kTruncated);
        const uint64_t ssize = u64(hwx, size, at + 40, kTruncated);
        const uint32_t soff = u32(hwx, size, at + 48, kTruncated);
        if (segment == "__FVMLIB") {
          if (prot != 1 && prot != 2) {
            refuse("surface segment is neither input nor output");
          }
          AneH16Surface surface;
          surface.vm = svm;
          surface.allocation = vmsize;
          surface.direction = prot;
          parsed.surfaces.push_back(surface);
        } else if (segment == "__TEXT" && name == "__text") {
          text = AneH16Region{svm, ssize, soff};
        } else if (segment == "__TEXT" && name == "__const") {
          parsed.constants = svm;
        } else if (
            segment == "__KERN_" + std::to_string(parsed.kernels.size()) &&
            name == "__kern_" + std::to_string(parsed.kernels.size())) {
          parsed.kernels.push_back(AneH16Region{svm, ssize, soff});
        } else if (segment == "__DATA" && name == "__bss") {
          if (prot != 3) {
            refuse("scratch segment is not read/write");
          }
          parsed.scratch = AneH16Region{svm, ssize, 0};
        }
      }
    } else if (cmd == 4 && u32(hwx, size, pos + 8, kTruncated) == 4) {
      descriptor = pos;
    } else if (cmd == 4 && u32(hwx, size, pos + 8, kTruncated) == 3) {
      const uint32_t shortoff = u32(hwx, size, pos + 0x7c, kTruncated);
      const uint32_t n = u32(hwx, size, pos + 0x28, kTruncated);
      const uint64_t batch = u64(hwx, size, pos + 0x50, kTruncated);
      const uint32_t direction = u32(hwx, size, pos + 0x14, kTruncated);
      tensors[cstr(hwx, size, pos + shortoff, pos + length)] = {
          direction, static_cast<unsigned __int128>(n) * batch};
    } else if (cmd == 0x40) {
      const uint64_t vm = u64(hwx, size, pos + 16, kTruncated);
      const std::string name = cstr(hwx, size, pos + 24, pos + length);
      for (auto& surface : parsed.surfaces) {
        if (surface.vm == vm) {
          surface.name = name;
        }
      }
    }
    pos += length;
  }
  if (!text || !descriptor || parsed.surfaces.size() < 2) {
    refuse("HWX lacks a task stream, program descriptor or surfaces");
  }
  parsed.text = *text;
  parsed.descriptor = *descriptor;
  for (auto& surface : parsed.surfaces) {
    auto found = surface.name ? tensors.find(*surface.name) : tensors.end();
    if (found == tensors.end() || found->second.first != surface.direction ||
        found->second.second == 0 || found->second.second > surface.allocation) {
      refuse(
          "surface " + (surface.name ? *surface.name : std::string("None")) +
          " has no matching tensor");
    }
    surface.span = static_cast<uint64_t>(found->second.second);
  }
  if (std::count_if(
          parsed.surfaces.begin(), parsed.surfaces.end(),
          [](const AneH16Surface& s) { return s.direction == 2; }) != 1) {
    refuse("an H16 program has exactly one output");
  }
  return parsed;
}

std::pair<uint32_t, std::vector<uint32_t>> h16_walk_tasks(
    const uint8_t* stream,
    size_t size,
    uint32_t prologue) {
  constexpr const char* kPrologue = "task stream lacks the prologue of its target";
  constexpr const char* kOverrun = "task overruns the stream";
  if (size < 16 || size % 4 != 0 || u32(stream, size, 0, kPrologue) != prologue ||
      any_nonzero(stream, size, 4, 16)) {
    refuse(kPrologue);
  }
  size_t pos = 16;
  uint32_t tasks = 0;
  std::set<uint32_t> slots;
  while (pos < size) {
    const uint32_t words = (u32(stream, size, pos, kOverrun) >> 16) & 0x7ff;
    if (words == 0) {
      if (any_nonzero(stream, size, pos, pos + 16)) {
        refuse("nonzero padding in the task stream");
      }
      pos += 16;
      continue;
    }
    const size_t end = pos + size_t(4) * words;
    const size_t header =
        (u32(stream, size, pos + 32, kOverrun) & 3) == 3 ? 10 : 9;
    if (words < header || end > size) {
      refuse(kOverrun);
    }
    size_t rec = pos + 4 * header;
    while (rec < end) {
      const uint32_t h = u32(stream, size, rec, kOverrun);
      rec += 4;
      size_t count = 0;
      if (h & (1u << 31)) {
        count = 1 + __builtin_popcount((h >> 15) & 0xffff);
      } else {
        count = ((h >> 15) & 0x3f) + 1;
        if (h & (1u << 29)) {
          slots.insert((h >> 23) & 0x3f);
        }
      }
      if (!register_valid(h & 0x7fff) || rec + 4 * count > end) {
        refuse("task record outside the register image");
      }
      rec += 4 * count;
    }
    pos = (end + 15) & ~size_t(15);
    tasks += 1;
  }
  if (tasks == 0) {
    refuse("task stream has no task");
  }
  return {tasks, std::vector<uint32_t>(slots.begin(), slots.end())};
}

AneH16Sections h16_build_sections(const uint8_t* hwx, size_t size) {
  AneH16Parsed parsed = h16_parse_hwx(hwx, size);
  // stream = hwx[text_off:text_off + text_size]: a slice clamps to the file.
  const size_t start = std::min<size_t>(parsed.text.offset, size);
  const size_t length = static_cast<size_t>(
      std::min<uint64_t>(parsed.text.size, size - start));
  const auto [tasks, slots] =
      h16_walk_tasks(hwx + start, length, *prologue_of(parsed.subtype));

  AneH16Sections out;
  out.subtype = parsed.subtype;
  out.tasks = tasks;
  uint32_t next_input = kFirstOutputId + 1;
  auto take_input = [&]() {
    if (next_input >= kInputIdEnd) {
      refuse("HWX has more surfaces than the generic buffer ID range");
    }
    return next_input++;
  };
  for (auto& surface : parsed.surfaces) {
    surface.id = surface.direction == 2 ? kFirstOutputId : take_input();
  }
  struct Entry {
    uint32_t id;
    uint32_t direction;
    uint64_t size;
  };
  std::vector<Entry> entries;
  for (const auto& surface : parsed.surfaces) {
    entries.push_back({surface.id, surface.direction, surface.allocation});
  }
  // One LOAD slot is one BAR base: several kernel sections, or a kernel
  // section next to the constants, travel as EXECUTE buffers.
  std::map<uint32_t, uint64_t> bases;
  for (uint32_t slot : slots) {
    bases[slot] = u64(
        hwx, size, parsed.descriptor + size_t(0x10) * (slot + 1),
        "program descriptor ends before a referenced BAR slot");
  }
  const bool constants_used = parsed.constants &&
      std::any_of(bases.begin(), bases.end(), [&](const auto& b) {
        return b.second == *parsed.constants;
      });
  const bool kernel_buffers = parsed.kernels.size() > 1 ||
      (!parsed.kernels.empty() && constants_used);
  if (parsed.scratch) {
    out.scratch_id = take_input();
    out.scratch_bytes = parsed.scratch->size;
    entries.push_back({*out.scratch_id, 1, parsed.scratch->size});
  }
  if (kernel_buffers) {
    for (const auto& kernel : parsed.kernels) {
      out.kernel_ids.push_back(take_input());
      entries.push_back({out.kernel_ids.back(), 1, kernel.size});
    }
  }

  auto& generic = out.sections[0];
  generic.assign(kGenericHeader + kGenericEntry * entries.size(), 0);
  put32(generic, 0, kGenericMagic);
  put32(generic, 4, kGenericVersion);
  put32(generic, 0x204, static_cast<uint32_t>(entries.size()));
  for (size_t k = 0; k < entries.size(); ++k) {
    const size_t e = kGenericHeader + kGenericEntry * k;
    put32(generic, e, 1);
    put32(generic, e + 4, entries[k].id);
    put32(generic, e + 8, entries[k].direction - 1);
    put32(generic, e + 0x10, entries[k].direction);
    put64(generic, e + 0x20, entries[k].size);
    put32(generic, e + 0x28, 0xffff);
  }

  for (uint32_t slot : slots) {
    const uint64_t base = bases[slot];
    if (base == 0) {
      continue;
    }
    auto hit = std::find_if(
        parsed.surfaces.begin(), parsed.surfaces.end(),
        [&](const AneH16Surface& s) { return s.vm == base; });
    if (hit != parsed.surfaces.end()) {
      out.refs.emplace_back(slot, hit->id);
    } else if (parsed.scratch && base == parsed.scratch->vm) {
      out.refs.emplace_back(slot, *out.scratch_id);
    } else if (auto kernel = std::find_if(
                   parsed.kernels.begin(), parsed.kernels.end(),
                   [&](const AneH16Region& k) { return k.vm == base; });
               kernel != parsed.kernels.end()) {
      out.refs.emplace_back(
          slot,
          kernel_buffers ? out.kernel_ids[kernel - parsed.kernels.begin()]
                         : kResourceKernel);
    } else if (
        parsed.constants && base == *parsed.constants && slot == 1 &&
        (kernel_buffers || parsed.kernels.empty())) {
      // Slot 1 carries the constants.
      out.refs.emplace_back(slot, kResourceKernel);
    } else {
      char hexbase[32];
      std::snprintf(
          hexbase, sizeof(hexbase), "%#llx",
          static_cast<unsigned long long>(base));
      refuse(
          "BAR slot " + std::to_string(slot) + " base " + hexbase +
          " names no surface, scratch, kernel or constants");
    }
  }
  if (out.refs.empty() || out.refs.size() > kOperationRefsMax) {
    refuse("program binds no buffer through a BAR slot");
  }
  auto& operation = out.sections[1];
  operation.assign(4 + kOperationRecord, 0);
  put32(operation, 0, 1);
  put32(operation, 4 + 0x08, static_cast<uint32_t>(out.refs.size()));
  for (size_t j = 0; j < out.refs.size(); ++j) {
    put32(operation, 4 + 0x0c + 8 * j, out.refs[j].first);
    put32(operation, 4 + 0x0c + 8 * j + 4, out.refs[j].second);
  }

  auto& procedure = out.sections[2];
  procedure.assign(0x38, 0);
  put32(procedure, 0, 1);
  put32(procedure, 4, 0);
  put64(procedure, 8, 0x18);
  put64(procedure, 0x10, 0x20);
  const uint32_t words[8] = {1, 3, 0, 0, 1, 0, 0xffffffffu, 4};
  for (size_t i = 0; i < 8; ++i) {
    put32(procedure, 0x18 + 4 * i, words[i]);
  }

  auto& properties = out.sections[3];
  properties.assign(0x28, 0);
  put32(properties, 0, 1);
  put32(properties, 4, 0);
  put32(properties, 8, 0);
  put32(properties, 12, tasks);
  put64(properties, 0x10, 0);
  put64(properties, 0x18, 0);
  put64(properties, 0x20, parsed.text.size);

  out.surfaces = std::move(parsed.surfaces);
  return out;
}

AneMappedFile::AneMappedFile(const std::string& path) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    throw std::runtime_error(
        "[omarchy-ane] cannot open HWX " + path + ": " + std::strerror(errno));
  }
  struct stat status {};
  if (::fstat(fd, &status) != 0 || !S_ISREG(status.st_mode)) {
    const int error = errno;
    ::close(fd);
    throw std::runtime_error(
        "[omarchy-ane] HWX " + path + " is not a regular file" +
        (error ? std::string(": ") + std::strerror(error) : std::string()));
  }
  size_ = static_cast<size_t>(status.st_size);
  if (size_ > 0) {
    void* mapping = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) {
      const int error = errno;
      ::close(fd);
      throw std::runtime_error(
          "[omarchy-ane] cannot map HWX " + path + ": " + std::strerror(error));
    }
    data_ = static_cast<const uint8_t*>(mapping);
  }
  ::close(fd);
}

AneMappedFile::~AneMappedFile() {
  if (data_) {
    ::munmap(const_cast<uint8_t*>(data_), size_);
  }
}

} // namespace mlx::core::omarchy::ane
