#!/usr/bin/env bash
# ============================================================================
#  build_apk.sh —— 不依赖 Gradle 的手工 APK 构建
#
#  为什么不用 Gradle：这台机器上没装 Gradle（也没有 Kotlin 编译器），
#  但 Android SDK 的 build-tools 和 JDK 都在。用 aapt2 + javac + d8 +
#  zipalign + apksigner 完全能编出一个可安装的签名 APK，而且每一步都看得见。
#
#  产物：android/dist/FragDPI-android-<version>.apk
#
#  用法：bash android/build_apk.sh
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
APP="$HERE/app"
DIST="$HERE/dist"
BUILD="$HERE/build"

# Windows 上 build-tools 里是 aapt2.exe / d8.bat / apksigner.bat；
# Linux（CI 的 ubuntu runner）上是无后缀的可执行文件。这里统一一下。
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe"; BAT=".bat" ;;
  *)                    EXE="";    BAT=""    ;;
esac
PYBIN="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"

# SDK 位置：环境变量优先，其次各平台常见路径
if [ -z "${ANDROID_SDK_ROOT:-}" ] && [ -z "${ANDROID_HOME:-}" ]; then
  for c in "$HOME/AppData/Local/Android/Sdk" "$HOME/Android/Sdk" "/usr/lib/android-sdk"; do
    [ -d "$c" ] && export ANDROID_SDK_ROOT="$c" && break
  done
fi
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"

BT="$(ls -d "$SDK"/build-tools/*/ 2>/dev/null | sort -V | tail -1)"
PLATFORM_JAR="$(ls -d "$SDK"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"

[ -n "$SDK" ] && [ -d "$SDK" ] || { echo "✗ 找不到 Android SDK，请设置 ANDROID_SDK_ROOT"; exit 1; }
[ -n "$BT" ] || { echo "✗ 找不到 build-tools，请用 sdkmanager 安装"; exit 1; }
[ -n "$PLATFORM_JAR" ] || { echo "✗ 找不到 android.jar（platforms/android-*）"; exit 1; }
[ -n "$PYBIN" ] || { echo "✗ 找不到 python3/python"; exit 1; }

VERSION="$(tr -d '\r\n' < "$REPO/VERSION" 2>/dev/null || echo 0.0.0)"
# APK 用独立的版本号：安卓版还没到桌面版的功能完整度，别跟着桌面版号跑
APK_VERSION="0.1.0"

echo "======================================================================"
echo "  FragDPI Android 构建"
echo "======================================================================"
echo "  SDK          : $SDK"
echo "  build-tools  : $BT"
echo "  android.jar  : $PLATFORM_JAR"
echo "  桌面版版本   : $VERSION   /   APK 版本: $APK_VERSION"
echo

rm -rf "$BUILD" "$DIST"
mkdir -p "$BUILD/compiled" "$BUILD/gen" "$BUILD/classes" "$BUILD/dex" "$DIST"

# ---------------------------------------------------------------- 1 资源
echo "[1/6] aapt2 compile 资源"
"$BT/aapt2$EXE" compile --dir "$APP/res" -o "$BUILD/compiled/res.zip"

echo "[2/6] aapt2 link 生成资源表 + R.java"
"$BT/aapt2$EXE" link \
  -o "$BUILD/base.ap_" \
  -I "$PLATFORM_JAR" \
  --manifest "$APP/AndroidManifest.xml" \
  --java "$BUILD/gen" \
  --min-sdk-version 24 \
  --target-sdk-version 34 \
  --version-code 1 \
  --version-name "$APK_VERSION" \
  "$BUILD/compiled/res.zip"

# ---------------------------------------------------------------- 2 编译
echo "[3/6] javac 编译 Java 源码"
# 只编 App 源码，**排除 *Test.java**（那些是纯 JVM 单测，不该进 APK）
SOURCES=()
while IFS= read -r f; do SOURCES+=("$f"); done < <(find "$APP/src" -name '*.java' ! -name '*Test.java')
while IFS= read -r f; do SOURCES+=("$f"); done < <(find "$BUILD/gen" -name '*.java')

echo "      源文件 ${#SOURCES[@]} 个"
# -source/-target 8 + bootclasspath：Android 的运行时是 Java 8 语言级别的子集，
# 用 android.jar 当引导类库，避免把 JDK 的类误打进 APK。
# ⚠️ 这里**不能**把 javac 的输出直接 pipe 掉：一旦漏掉真正的编译错误，
#    后面 d8 只会报个莫名其妙的 "NoSuchFileException: R.class"，很难查。
set +e
javac -encoding UTF-8 -source 8 -target 8 -nowarn \
  -bootclasspath "$PLATFORM_JAR" -classpath "$PLATFORM_JAR" \
  -d "$BUILD/classes" "${SOURCES[@]}" > "$BUILD/javac.log" 2>&1
JAVAC_RC=$?
set -e
grep -v "bootstrap class path" "$BUILD/javac.log" || true
if [ "$JAVAC_RC" -ne 0 ]; then
  echo "✗ javac 编译失败（退出码 $JAVAC_RC），完整日志：$BUILD/javac.log"
  exit "$JAVAC_RC"
fi

# ---------------------------------------------------------------- 3 dex
echo "[4/6] d8 转 dex"
# ⚠️ d8 是 Java 工具，**不会**对文件内容里的路径做 POSIX→Windows 转换。
#    所以这里 cd 进 $BUILD、用相对路径列 class 文件；
#    直接写 find 出来的 /c/... 绝对路径会让 d8 找不到文件。
( cd "$BUILD" && find classes -name '*.class' | sort > classlist.txt )
echo "      class 文件 $(wc -l < "$BUILD/classlist.txt") 个"
( cd "$BUILD" && "$BT/d8$BAT" --lib "$PLATFORM_JAR" --min-api 24 --release \
    --output dex @classlist.txt )

# ---------------------------------------------------------------- 4 打包
echo "[5/6] 打包 + zipalign"
"$PYBIN" - "$BUILD/base.ap_" "$BUILD/dex/classes.dex" "$BUILD/unsigned.apk" <<'PY'
import sys, shutil, zipfile
base, dex, out = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.copyfile(base, out)
with zipfile.ZipFile(out, "a", zipfile.ZIP_DEFLATED) as z:
    z.write(dex, "classes.dex")
print("      已写入 classes.dex")
PY

"$BT/zipalign$EXE" -p -f 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"

# ---------------------------------------------------------------- 5 签名
echo "[6/6] apksigner 签名"
KS="$HERE/debug.keystore"
if [ ! -f "$KS" ]; then
  # ⚠️ keytool 常常**不在 PATH 上**（本机只有 java/javac 通过 javapath 暴露出来）。
  #    直接用 "keytool" 会以 127（command not found）失败，而且还藏在 set -e 后面，
  #    报错看着像签名失败，其实是生成密钥库那一步就崩了。所以这里按三级回退找它。
  KEYTOOL="$(command -v keytool 2>/dev/null || true)"
  if [ -z "$KEYTOOL" ] && [ -n "${JAVA_HOME:-}" ]; then
    [ -x "$JAVA_HOME/bin/keytool" ] && KEYTOOL="$JAVA_HOME/bin/keytool"
    [ -x "$JAVA_HOME/bin/keytool.exe" ] && KEYTOOL="$JAVA_HOME/bin/keytool.exe"
  fi
  if [ -z "$KEYTOOL" ]; then
    JAVAC_BIN="$(command -v javac 2>/dev/null || true)"
    [ -n "$JAVAC_BIN" ] && [ -x "$(dirname "$JAVAC_BIN")/keytool" ] && \
      KEYTOOL="$(dirname "$JAVAC_BIN")/keytool"
  fi
  [ -n "$KEYTOOL" ] || {
    echo "✗ 找不到 keytool（JDK 的 keytool）。请把 JDK 的 bin 加进 PATH 或设置 JAVA_HOME。"
    exit 1
  }
  echo "      生成调试用密钥库（仅用于本地安装，不要用于正式发布）"
  echo "      keytool = $KEYTOOL"
  rm -f "$KS"
  "$KEYTOOL" -genkeypair -keystore "$KS" -alias fragdpi -keyalg RSA -keysize 2048 \
    -validity 10000 -storepass android -keypass android \
    -dname "CN=FragDPI Debug,O=FragDPI,C=CN" >/dev/null 2>&1 || {
      echo "✗ 生成密钥库失败"; exit 1; }
  [ -f "$KS" ] || { echo "✗ 密钥库没有生成出来"; exit 1; }
fi
APK="$DIST/FragDPI-android-$APK_VERSION.apk"
"$BT/apksigner$BAT" sign \
  --ks "$KS" --ks-key-alias fragdpi \
  --ks-pass pass:android --key-pass pass:android \
  --out "$APK" "$BUILD/aligned.apk"

echo
echo "======================================================================"
echo "  构建完成"
echo "======================================================================"
"$BT/apksigner$BAT" verify --print-certs "$APK" | head -5
ls -la "$APK"
echo
echo "安装： adb install -r \"$APK\""
echo "（或把 APK 拷到手机点开安装；需允许「安装未知来源应用」）"
