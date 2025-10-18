#!/bin/bash
# NetGuardian 项目清理脚本
# 用于清理构建产物和临时文件

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "NetGuardian 项目清理工具"
echo "=========================="
echo ""

# 清理构建目录
if [ -d "$PROJECT_ROOT/build" ]; then
    echo "[1/5] 清理构建目录..."
    rm -rf "$PROJECT_ROOT/build"
    echo "  ✓ 已删除 build/"
else
    echo "[1/5] 构建目录不存在，跳过"
fi

# 清理 CMake 缓存
echo "[2/5] 清理 CMake 缓存文件..."
find "$PROJECT_ROOT" -name "CMakeCache.txt" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name "CMakeFiles" -type d -exec rm -rf {} + 2>/dev/null || true
echo "  ✓ 已删除 CMake 缓存"

# 清理编译产物
echo "[3/5] 清理编译产物..."
find "$PROJECT_ROOT" -name "*.o" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name "*.a" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name "*.so" -delete 2>/dev/null || true
echo "  ✓ 已删除 .o, .a, .so 文件"

# 清理临时文件
echo "[4/5] 清理临时文件..."
find "$PROJECT_ROOT" -name "*~" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name "*.swp" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name "*.swo" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name ".DS_Store" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name "*.bak" -delete 2>/dev/null || true
echo "  ✓ 已删除临时文件"

# 清理测试输出
echo "[5/5] 清理测试输出..."
find "$PROJECT_ROOT" -name "*.pcap" -path "*/build/*" -delete 2>/dev/null || true
find "$PROJECT_ROOT" -name "test_*.log" -delete 2>/dev/null || true
echo "  ✓ 已删除测试输出文件"

echo ""
echo "清理完成！"
echo ""
echo "提示：要重新构建项目，运行："
echo "  mkdir build && cd build"
echo "  cmake .."
echo "  cmake --build . -j\$(nproc)"
