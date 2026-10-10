#!/usr/bin/env bash
# neqo (mozilla QUIC/HTTP3) ファジング環境セットアップ
#
# 検証済み環境: Ubuntu 24.04 / root / クラウドコンテナ（egress 制限あり）
#   rustc stable 1.97 + nightly 1.101 / cargo-fuzz 0.13.2 / clang-18 / ninja 1.11
#   NSS NSS_3_131_RTM(gitミラー) + NSPR 4.35(apt source) を --static でソースビルド
#
# 重要な前提（この順序でないと詰まる、実際にハマった点）:
#   1. neqo は nss-rs(>=3.126) を要求。Ubuntu の libnss3-dev は 3.98 で足りない。
#   2. nss-rs のソース取得は hg.mozilla.org だが egress でブロック(403)される。
#      → NSS は github.com/nss-dev/nss (git は通る) から取得して自前ビルドする。
#   3. cargo-fuzz は CARGO_CFG_FUZZING を立て、nss-rs は fuzzing 時に NSS を「静的リンク」する。
#      → NSS は --static で、NSPR も静的(.a)が要る。--system-nspr は .so のみで不可。
#      → NSPR ソースを apt-get source で取得し nss/../nspr に置いて NSS に同梱ビルドさせる。
#   4. リリースビルド(LTO)だと __sancov_gen_ 未定義でリンク失敗 → `cargo fuzz build --dev` で回避。
#
# 使い方:
#   WORK=/path/to/workdir ./setup-neqo-fuzz.sh        # 構築
#   source ./neqo-fuzz.env && cd $NEQO && \
#     cargo +nightly fuzz run --dev frame -- -max_total_time=60   # 実行
set -euo pipefail

WORK="${WORK:-$PWD/neqo-fuzz-work}"
mkdir -p "$WORK"; cd "$WORK"
echo ">>> WORK=$WORK"

# --- 0. OS パッケージ -------------------------------------------------------
apt-get update -qq
apt-get install -y libnss3-dev libnspr4-dev pkg-config ninja-build clang llvm \
                   git python3 python3-pip mercurial
# gyp-next (NSS のビルドシステム)
command -v gyp >/dev/null 2>&1 || pip3 install --break-system-packages gyp-next || pip3 install gyp-next

# --- 1. Rust toolchain ------------------------------------------------------
rustup toolchain install nightly --profile minimal --component rust-src
cargo install cargo-fuzz --locked || true   # 既に入っていれば続行

# --- 2. NSPR ソース (apt の deb-src から) -----------------------------------
# Ubuntu 24.04 deb822 形式の sources に deb-src を追加
sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources || true
apt-get update -qq
[ -d nspr-4.35 ] || apt-get source libnspr4      # → nspr-4.35/nspr/configure

# --- 3. NSS 本体 (github ミラーを git で。hg.mozilla.org は egress ブロック) --
NSS_TAG="${NSS_TAG:-NSS_3_131_RTM}"
[ -d nss ] || GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "$NSS_TAG" \
                https://github.com/nss-dev/nss.git nss
# NSS が期待する ../nspr にソースを配置（NSS が NSPR を静的同梱ビルドする）
ln -sfn nspr-4.35/nspr nspr

# --- 4. NSS + NSPR を静的ビルド ---------------------------------------------
# --static が静的 .a を生成（certdb, nspr4, plc4, plds4, ... 全部）
( cd nss && ./build.sh --opt --static --disable-tests )
test -f dist/Release/lib/libcertdb.a
test -f dist/Release/lib/libnspr4.a
echo ">>> NSS static libs OK"

# --- 5. neqo 取得 -----------------------------------------------------------
[ -d neqo ] || git clone --depth 1 https://github.com/mozilla/neqo.git neqo

# --- 6. 環境変数を書き出す --------------------------------------------------
cat > "$WORK/../neqo-fuzz.env" <<EOF
# source this before building/running neqo fuzzers
export NEQO="$WORK/neqo"
export NSS_DIR="$WORK/nss"          # nss-rs: $NSS_DIR/../dist を使う
export NSS_PREBUILT=1               # 既にビルド済み（再ビルドさせない）
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
export LD_LIBRARY_PATH="$WORK/dist/Release/lib"
EOF
echo ">>> wrote neqo-fuzz.env"

# --- 7. 代表ターゲットをビルドして疎通確認 ----------------------------------
# shellcheck disable=SC1091
source "$WORK/../neqo-fuzz.env"
cd "$NEQO"
cargo +nightly fuzz build --dev frame      # --dev で __sancov_gen_ リンク問題を回避
echo ">>> build OK. 試走:  cargo +nightly fuzz run --dev frame -- -max_total_time=30"
