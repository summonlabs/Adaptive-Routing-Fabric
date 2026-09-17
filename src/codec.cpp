// Canonical little-endian byte codec.
#include "adaptive_routing/codec.hpp"

namespace adaptive_routing {
namespace {

void append_u64(std::string& buffer, std::uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    buffer.push_back(static_cast<char>(static_cast<unsigned char>((value >> (8 * index)) & 0xFFU)));
  }
}

}  // namespace

void ByteWriter::put_u8(std::uint8_t value) { buffer_.push_back(static_cast<char>(value)); }

void ByteWriter::put_u16(std::uint16_t value) {
  put_u8(static_cast<std::uint8_t>(value & 0xFFU));
  put_u8(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
}

void ByteWriter::put_u32(std::uint32_t value) {
  for (int index = 0; index < 4; ++index) {
    put_u8(static_cast<std::uint8_t>((value >> (8 * index)) & 0xFFU));
  }
}

void ByteWriter::put_u64(std::uint64_t value) { append_u64(buffer_, value); }

void ByteWriter::put_i64(std::int64_t value) {
  put_u64(static_cast<std::uint64_t>(value));
}

void ByteWriter::put_bool(bool value) { put_u8(value ? 1U : 0U); }

void ByteWriter::put_bytes(std::string_view bytes) {
  put_u64(static_cast<std::uint64_t>(bytes.size()));
  buffer_.append(bytes.data(), bytes.size());
}

void ByteWriter::put_string(std::string_view text) { put_bytes(text); }

bool ByteReader::take(std::size_t count, std::string_view& out) noexcept {
  if (count > remaining()) {
    return false;
  }
  out = bytes_.substr(offset_, count);
  offset_ += count;
  return true;
}

std::optional<std::uint8_t> ByteReader::get_u8() noexcept {
  std::string_view slice;
  if (!take(1, slice)) {
    return std::nullopt;
  }
  return static_cast<std::uint8_t>(static_cast<unsigned char>(slice[0]));
}

std::optional<std::uint16_t> ByteReader::get_u16() noexcept {
  std::string_view slice;
  if (!take(2, slice)) {
    return std::nullopt;
  }
  std::uint16_t value = 0;
  for (int index = 0; index < 2; ++index) {
    value |= static_cast<std::uint16_t>(static_cast<unsigned char>(slice[static_cast<std::size_t>(index)]))
             << (8 * index);
  }
  return value;
}

std::optional<std::uint32_t> ByteReader::get_u32() noexcept {
  std::string_view slice;
  if (!take(4, slice)) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  for (int index = 0; index < 4; ++index) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(slice[static_cast<std::size_t>(index)]))
             << (8 * index);
  }
  return value;
}

std::optional<std::uint64_t> ByteReader::get_u64() noexcept {
  std::string_view slice;
  if (!take(8, slice)) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (int index = 0; index < 8; ++index) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(slice[static_cast<std::size_t>(index)]))
             << (8 * index);
  }
  return value;
}

std::optional<std::int64_t> ByteReader::get_i64() noexcept {
  const auto raw = get_u64();
  if (!raw.has_value()) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(*raw);
}

std::optional<bool> ByteReader::get_bool() noexcept {
  const auto raw = get_u8();
  if (!raw.has_value() || *raw > 1U) {
    return std::nullopt;
  }
  return *raw == 1U;
}

std::optional<std::string> ByteReader::get_bytes(std::uint64_t limit) noexcept {
  const auto length = get_u64();
  if (!length.has_value()) {
    return std::nullopt;
  }
  // The declared length is bounded BEFORE any allocation or consumption, so an
  // absurd length costs nothing to reject.
  if (*length > limit) {
    return std::nullopt;
  }
  std::string_view slice;
  if (!take(static_cast<std::size_t>(*length), slice)) {
    return std::nullopt;
  }
  return std::string(slice);
}

std::optional<std::string> ByteReader::get_string(std::uint64_t limit) noexcept {
  return get_bytes(limit);
}

}  // namespace adaptive_routing
