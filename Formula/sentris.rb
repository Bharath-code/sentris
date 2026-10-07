class Sentris < Formula
  desc "High-performance secret scanner with autonomous dual-key remediation"
  homepage "https://sentris.dev"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sentris-security/sentris/releases/download/v0.1.0/sentris-v0.1.0-aarch64-apple-darwin.tar.gz"
      # sha256 "REPLACE_WITH_ACTUAL_RELEASE_SHA256"
    else
      url "https://github.com/sentris-security/sentris/releases/download/v0.1.0/sentris-v0.1.0-x86_64-apple-darwin.tar.gz"
      # sha256 "REPLACE_WITH_ACTUAL_RELEASE_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/sentris-security/sentris/releases/download/v0.1.0/sentris-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      # sha256 "REPLACE_WITH_ACTUAL_RELEASE_SHA256"
    else
      url "https://github.com/sentris-security/sentris/releases/download/v0.1.0/sentris-v0.1.0-x86_64-unknown-linux-musl.tar.gz"
      # sha256 "REPLACE_WITH_ACTUAL_RELEASE_SHA256"
    end
  end

  def install
    bin.install "sentris"
  end

  test do
    assert_match "Sentris", shell_output("#{bin}/sentris --version")
    system "#{bin}/sentris", "scan", "--help"
  end
end
