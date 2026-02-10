# Jinja2 模糊测试与安全分析工具

基于 Atheris、AST/LibCST、Z3、PySnooper 与 PyDriller 的 Jinja2 综合分析平台。  
项目目标是对 Jinja2 模板引擎进行静态分析、动态追踪、约束求解、模糊测试与可视化展示。

## 项目亮点

- 使用 **Atheris** 实现 5 个核心 fuzz target（parse/render/sandbox/lexer/markup）。
- 对 Jinja2 源码执行 AST + LibCST 双路径分析，并输出结构化 JSON 数据。
- 使用 Z3 对模板语法约束、过滤器类型传播与沙箱策略进行形式化验证。
- 使用 PySnooper 追踪 parse/render/compile/sandbox 执行过程并保存日志。
- 使用 PyDriller + GitHub API 分析 Jinja2 历史提交，生成 14 张暖色系图表。
- `python main.py` 一键执行全流程。

## 技术栈

| 技术 | 用途 |
|------|------|
| Atheris | Python 覆盖引导模糊测试 |
| ast + radon | 语法树解析与圈复杂度统计 |
| LibCST | 类型注解、异常模式、字符串模式识别 |
| z3-solver | 约束求解与模型生成 |
| PySnooper | 动态执行追踪 |
| PyDriller | Git 提交历史采集与统计 |
| matplotlib + seaborn | 图表绘制 |
| wordcloud + networkx | 词云与依赖网络可视化 |

## 环境要求

- WSL2 Ubuntu
- Python 3.12+
- 已克隆 Jinja2 源码到：`/mnt/c/Users/l/Desktop/opensource/group4/jinja`

## 安装步骤

```bash
cd /mnt/c/Users/l/Desktop/opensource/group4/repo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

若中文字体缺失：

```bash
sudo apt-get install -y fonts-wqy-microhei
```

## 一键运行

```bash
cd /mnt/c/Users/l/Desktop/opensource/group4/repo
source .venv/bin/activate
python main.py
```

常用参数：

```bash
# 只跑部分模块
python main.py --tasks ast libcst z3

# 调整 fuzz 迭代次数
python main.py --fuzz-runs 20000

# 只规划 fuzz，不实际执行
python main.py --tasks fuzz --plan-fuzz-only
```

## 输出结果

### 数据目录 `data/`

- `commits.csv`、`commit_summary.json`
- `github_metadata.json`
- `ast_analysis.json`
- `libcst_analysis.json`
- `z3_results.json`
- `fuzz_results.json`
- `run_summary.json`
- `data/crashes/`：异常样本
- `data/fuzz_coverage/`：fuzz 覆盖与趋势明细
- `data/traces/`：PySnooper 追踪日志

### 图表目录 `output/`（14 张）

1. `01_年度提交趋势图.png`
2. `02_作者贡献饼图.png`
3. `03_提交时间热力图.png`
4. `04_提交消息词云.png`
5. `05_Bug修复频率趋势.png`
6. `06_圈复杂度分布.png`
7. `07_类型注解覆盖率.png`
8. `08_函数参数数量分布.png`
9. `09_异常处理模式分布.png`
10. `10_Z3约束求解结果.png`
11. `11_Fuzz覆盖率趋势.png`
12. `12_Crash异常分类统计.png`
13. `13_导入依赖关系图.png`
14. `14_文件修改热点Top20.png`

## 项目结构

```text
repo/
├── analyzers/      # AST / LibCST / Z3 / PySnooper
├── collectors/     # PyDriller + GitHub API
├── fuzzers/        # Atheris 引擎与 5 个 target
├── visualizers/    # 样式与图表
├── utils/          # 通用工具
├── tests/          # 单元测试
├── data/           # 分析数据与追踪日志
├── output/         # 图表输出（PNG）
├── docs/           # 报告文档
├── config.py
└── main.py
```

## 测试

```bash
cd /mnt/c/Users/l/Desktop/opensource/group4/repo
source .venv/bin/activate
pytest -q
```

## 团队信息

- 课程：开源软件基础
- 课题：Jinja2 模糊测试与安全分析
- 仓库维护：`breezefee`
