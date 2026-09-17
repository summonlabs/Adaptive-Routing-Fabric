// Canonical byte codec.
//
// Every byte that leaves this runtime -- on the wire or on disk -- is written
// through ByteWriter and read through ByteReader. The encoding is explicitly
// little-endian and never a raw C++ memory layout, so a struct change cannot
// silently change the format and a padded layout cannot leak into a digest.
//
// The reader is deliberately hostile: every length is bounded, every enum is
// validated, every integer is range checked by the caller, and a decode that
// does not consume the whole buffer is a trailing-byte rejection rather than a
// silent success.
#ifndef ADAPTIVE_ROUTING_CODEC_HPP
#define ADAPTIVE_ROUTING_CODEC_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace adaptive_routing {

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

class ByteWriter {
 public:
  ByteWriter() = default;

  void put_u8(std::uint8_t value);
  void put_u16(std::uint16_t value);
  void put_u32(std::uint32_t value);
  void put_u64(std::uint64_t value);
  void put_i64(std::int64_t value);
  void put_bool(bool value);
  // Length-prefixed byte string, bounded by the caller's own limit.
  void put_bytes(std::string_view bytes);
  void put_string(std::string_view text);

  [[nodiscard]] const std::string& buffer() const noexcept { return buffer_; }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  [[nodiscard]] std::string take() noexcept { return std::move(buffer_); }

 private:
  std::string buffer_;
};

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

class ByteReader {
 public:
  explicit ByteReader(std::string_view bytes) noexcept : bytes_(bytes) {}

  [[nodiscard]] std::optional<std::uint8_t> get_u8() noexcept;
  [[nodiscard]] std::optional<std::uint16_t> get_u16() noexcept;
  [[nodiscard]] std::optional<std::uint32_t> get_u32() noexcept;
  [[nodiscard]] std::optional<std::uint64_t> get_u64() noexcept;
  [[nodiscard]] std::optional<std::int64_t> get_i64() noexcept;
  [[nodiscard]] std::optional<bool> get_bool() noexcept;
  // Length-prefixed byte string. \p limit is the maximum accepted length; a
  // longer declared length is rejected before any bytes are consumed.
  [[nodiscard]] std::optional<std::string> get_bytes(std::uint64_t limit) noexcept;
  [[nodiscard]] std::optional<std::string> get_string(std::uint64_t limit) noexcept;

  [[nodiscard]] std::size_t remaining() const noexcept { return bytes_.size() - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
  // True when every byte has been consumed. Decoders must check this and reject
  // trailing bytes.
  [[nodiscard]] bool finished() const noexcept { return offset_ == bytes_.size(); }

 private:
  [[nodiscard]] bool take(std::size_t count, std::string_view& out) noexcept;

  std::string_view bytes_;
  std::size_t offset_ = 0;
};

}  // namespace adaptive_routing

#endif  // ADAPTIVE_ROUTING_CODEC_HPP
