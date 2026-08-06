#!/usr/bin/env bash
# 打包 ScanBMC 为 macOS .app（在项目根目录运行；依赖 .venv 里的 pyinstaller）
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/pyinstaller ]; then
    echo "错误：未找到 .venv/bin/pyinstaller，请先执行："
    echo "  python3 -m venv .venv && .venv/bin/pip install PySide6 pyinstaller"
    exit 1
fi

# 本机沙箱/权限可能禁止写 ~/Library/Application Support，把缓存重定向到项目内
export PYINSTALLER_CONFIG_DIR="$(pwd)/.pyinstaller_cache"

.venv/bin/pyinstaller --noconfirm --clean --windowed \
    --name ScanBMC \
    --osx-bundle-identifier com.scanbmc.app \
    scanbmc_gui.py

echo
echo "产物: dist/ScanBMC.app"
echo "首次在别的 Mac 上分发时若被 Gatekeeper 拦截：右键 → 打开。"
