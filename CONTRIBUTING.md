# 贡献指南

感谢关注 scanbmc！这是一个纯 Python 标准库实现的局域网 BMC 扫描器，欢迎提 Issue、
PR，或者补充你实测过的设备指纹 / OEM ID 映射。

## 开发环境

```bash
git clone <本仓库地址>
cd scanbmc
python3 -m venv .venv
.venv/bin/pip install PySide6 pyinstaller   # 只有 GUI/打包需要，CLI 零依赖
```

Homebrew 的 python 是 externally-managed，装依赖必须走 venv，直接 `pip install` 会被
PEP 668 拒绝。

## 运行与测试

```bash
python3 scanbmc.py                                   # CLI，无参数自动检测本机网段
.venv/bin/python scanbmc_gui.py                       # GUI
python3 -m unittest discover -p 'test_*.py' -v        # 单元测试 + 集成测试
SCANBMC_GUI_SMOKE=1 .venv/bin/python scanbmc_gui.py   # GUI 冒烟测试（2 秒自动退出）
```

提交前请确保测试全部通过；新增探测/判定逻辑请在 `test_scanbmc.py` 或
`test_integration.py` 里补对应用例。

## 代码约定

详见 [AGENTS.md](AGENTS.md)，几条最重要的：

- 扫描核心（`scanbmc.py`）只允许标准库，不引入第三方依赖；第三方依赖仅限 GUI 层
  （`scanbmc_gui.py`，PySide6）。
- 兼容 Python 3.8 语法：用 `typing.Dict/List/Optional`，不用 `dict[str, ...]`
  这类新写法；文件头保留 `from __future__ import annotations`。
- 标识符用英文，注释/docstring/命令行输出文案用中文。
- 判定逻辑必须基于真实协议证据（IPMI/ASF/Redfish 应答），不能仅凭端口开放就报「确认」，
  避免把普通 Web 服务器误判成 BMC。

## 提交规范

- Commit message 用中文，说明改动的原因（why）而不只是改了什么（what）。
- 一次提交聚焦一件事；不要把无关的格式化/重排一起夹带进来。
- 涉及探测报文、判定逻辑或退出码语义的改动，请在 PR 描述里注明实测过的设备型号。

## 贡献者

- [ion-lgb](https://github.com/ion-lgb)
- Claude（Anthropic）—— 协助实现与代码评审
- DeepSeek —— 协助实现与代码评审
