![Language](https://img.shields.io/badge/language-python-brightgreen) 

![Documentation](https://img.shields.io/badge/documentation-yes-brightgreen)

![badge](https://img.shields.io/badge/Default%20Security%20Group-Introduction%20to%20Information%20Security-green.svg?logo=unity)



# 关卡测试报告【共5关】

## 第一关-基本测试

## 第二关-交叉测试

## 第三关-扩展功能

## 第四关-多重加密
### 双重加密

### 中间相遇攻击

### 三重加密

## 第五关-工作模式



# 开发手册
## 概述
本手册提供了关于 S-AES 加密算法及其实现的详细说明和使用指南。该算法用于对16位明文和16位密钥进行加密/解密，具有简单、轻量化的特性，适用于教学和小型项目的加密需求。
## 环境配置
- 操作系统：Windows
- 编程语言：Python 3.8+
- 依赖库：
  - `numpy`: 处理矩阵运算
  - `matplotlib`: 进行数据可视化
## 安装步骤
1. 克隆项目代码：
   ```bash
   git clone https://github.com/CoffeeTau/DSG_S-AES_2024.git
   ```
2. 进入项目目录，安装依赖：
   ```bash
   cd DSG_S-AES_2024
   pip install -r requirements.txt
   ```
## 代码结构
项目代码结构如下:

```

```

## 模块说明
### 算法部分



### 前后端部分

#### 前端说明

前端使用 HTML、JavaScript 和 CSS 构建用户友好的界面，允许用户进行加解密操作及统计分析，功能包括：

- **服务展示**：
  - 介绍 SDES 算法功能，动态展示每项服务的详细内容。

- **用户输入区域**：
  - 选择加密或解密，输入明文或密文及密钥，实时反馈数据有效性。
  
- **统计分析功能**：
  - 输入明文数量进行统计分析，展示生成的 scatter 图及相关统计结果，如 Pearson 和 Spearman 相关性。
  
- **暴力破解功能**：
  - 用户输入8位二进制的明文和密文，通过按钮触发 `mybruteForce` 函数，向后端发送请求，返回破解所需时间和得到的密钥。
  
- **与后端交互**：
  - 使用 fetch API 实现与 Flask 后端交互，动态更新响应信息，提供友好体验。

#### 后端说明

后端使用 Flask 框架实现 S-AES 算法的加解密、统计分析及暴力破解功能，包括：

- **路由设置**：
  - 定义不同路由，如 `/encrypt`、`/decrypt`、`/generate-scatter` 和 `/brute-force`，处理相应请求。
  
- **加解密功能**：
  - 接收前端数据，调用 `encryptOrDecrypt` 方法进行加密或解密，并返回结果。
  
- **统计分析功能**：
  - 实现 `StatisticalAnalysis` 类功能，接受前端请求并返回生成的统计结果，包括相关性分析、雪崩效应检验等。
  
- **暴力破解功能**：
  - 接收前端输入的明文和密文，确保格式为8位二进制数。
  - 调用 `bruteForce` 方法，尝试通过暴力方式找出对应的密钥。
  - 返回破解所需的时间和得到的密钥，供前端展示。
  
- **数据格式处理**：
  - 解析前端数据，将明文、密钥和密文转换为必要格式，结果以 JSON 格式返回前端。


# 用户指南

欢迎使用 S-AES 加密算法工具！本指南将帮助您理解如何使用该工具进行加解密、多重加密、中间相遇攻击、CBC模式等功能。

## 1. 登录与注册

### 1.1 登录
1. 打开网页，您将首先看到登录界面。
2. 输入您的用户名和密码。
3. 点击“登录”按钮。
4. 如果凭证正确，系统将进入主界面；否则，将显示错误消息。
   ![system-login.png](images/login.png)

### 1.2 注册
1. 在登录界面，点击“注册”按钮。
2. 输入所需的注册信息，如用户名、密码等。
3. 点击“提交”按钮。
4. 注册成功后，您可以使用新账户登录。
   ![system-register.png](images/register.png)





## 关于我们
我们是一个致力于数据安全和加密技术的团队，旨在提供简洁易用的加密工具，以帮助用户保护他们的数据隐私。欢迎随时与我们联系，获取更多信息。
![system-about.png](images/system-about.png)


# 常见问题

## 1. **什么是 SAES 算法？**
   SAES（简化版高级加密标准）是一种简化的对称加密算法，常用于教学目的。它采用较小的密钥和数据块长度，通过多轮加密步骤，帮助理解 AES 的基本原理。

## 2. **如何在 SAES 中实现中间相遇攻击？**
   中间相遇攻击是一种常用的密码分析方法，适用于双重加密等多轮加密的破解。在 SAES 中，可以通过比对加密和解密的中间值来寻找密钥对，并记录执行时间来评估攻击的效率。

## 3. **SAES 与 AES 的区别是什么？**
   SAES 是 AES 的简化版本，通常使用较小的密钥和数据块。虽然两者加密流程相似，但 AES 采用更长的密钥、更大的数据块和更多的加密轮数，比 SAES 更加安全且适用于实际应用场景。
