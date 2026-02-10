# Jinja2 模糊测试与安全分析工具

> 基于 Atheris + AST/LibCST/Z3/PySnooper 的 Jinja2 模板引擎模糊测试与代码分析平台

## 项目简介

本项目针对 Python 知名模板引擎 [Jinja2](https://github.com/pallets/jinja) 进行模糊测试(Fuzz Testing)，结合静态分析与动态追踪技术，发现潜在的安全漏洞与异常行为。

## 技术栈

| 技术 | 用途 |
|------|------|
| Atheris | Google 开发的 Python 模糊测试引擎 |
| ast | 抽象语法树静态分析 |
| libcst | 具体语法树分析 |
| z3-solver | 约束求解与路径分析 |
| pysnooper | 动态执行追踪 |
| matplotlib/seaborn | 数据可视化 |
