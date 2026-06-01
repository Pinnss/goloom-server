#!/usr/bin/env bash
# Сборка Android .aar из mobile/ этого репозитория через gomobile.
#
# Перед запуском:
#   export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125
#   go install golang.org/x/mobile/cmd/gomobile@latest
#   gomobile init
#
# Результат:
#   build/android/goloom.aar  — бросить в app/libs/ Android-проекта
#
# Цели по умолчанию: armeabi-v7a, arm64-v8a, x86, x86_64.

set -euo pipefail

# Пройти к корню репозитория независимо от того, откуда запустили скрипт.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT}"

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ERROR: ANDROID_NDK_HOME не задан. Установи путь к NDK, например:"
    echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/26.1.10909125"
    exit 1
fi

if ! command -v gomobile >/dev/null 2>&1; then
    echo "ERROR: gomobile не найден в PATH. Поставь:"
    echo "  go install golang.org/x/mobile/cmd/gomobile@latest"
    echo "  gomobile init"
    exit 1
fi

# Go 1.25 ужесточил проверку //go:linkname. Транзитивно-зависимый
# wlynxg/anet (через pion/transport) использует linkname к net.zoneCache,
# что ломает линковку. Отключаем проверку, пока anet не выпустит фикс.
# Переменная аддитивная — уважаем существующий GOFLAGS пользователя.
if [[ "${GOFLAGS:-}" != *"checklinkname=0"* ]]; then
    export GOFLAGS="${GOFLAGS:+$GOFLAGS }-ldflags=-checklinkname=0"
fi

OUT_DIR="${ROOT}/build/android"
OUT_AAR="${OUT_DIR}/goloom.aar"

mkdir -p "${OUT_DIR}"

echo "==> Building goloom.aar"
echo "    NDK:    ${ANDROID_NDK_HOME}"
echo "    Output: ${OUT_AAR}"

# androidapi 26 = minSdk 26 (Android 8.0). Совпадает с manifest minSdk
# в goloom-android. Меняй здесь и там одновременно.
# Цели по умолчанию (gomobile собирает под все 4): armeabi-v7a, arm64-v8a, x86, x86_64.
# Можно сузить через GOLOOM_TARGETS env, например, "android/arm64,android/arm" —
# полезно при отладке несовместимостей runtime-зависимостей с x86-сборкой.
TARGETS="${GOLOOM_TARGETS:-android}"

gomobile bind \
    -target="${TARGETS}" \
    -androidapi=26 \
    -javapkg=app.goloom.bridge \
    -o "${OUT_AAR}" \
    ./mobile

SIZE=$(du -h "${OUT_AAR}" | cut -f1)
echo "==> OK: ${OUT_AAR} (${SIZE})"
echo
echo "Скопировать в Android-проект:"
echo "  cp ${OUT_AAR} \$HOME/IdeaProjects/goloom-android/app/libs/goloom.aar"
