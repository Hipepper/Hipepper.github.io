---
title: 深入分析AuraStealer MaaS混淆与对抗技术
date: 2026-01-07 15:48:25
categories: "Malware"
index_img: /img/postindex/b0e0de244ad7c75c4c293d6ecf8c4dfc.jpg
tags: 
 - "混淆"
 - "主机安全"
 - "MaaS"
---

## 前提要点
----------

* AuraStealer 是一种新兴的恶意软件即服务 (MaaS) 信息窃取者。
* 为了阻止静态和动态分析，AuraStealer 采用了广泛的反分析和混淆技术，包括间接控制流混淆和异常驱动的 API 哈希。
* 在这篇技术博客文章中，我们深入探讨了恶意软件的执行流程和功能，并提供了对抗其混淆的实用技巧和工作流程。

## 介绍
------------

AuraStealer 是一种快速发展的信息窃取程序即服务，自 2025 年 7 月以来在多个地下论坛上积极推广。该窃取程序采用 C++ 开发，构建大小约为 500-700 kB，针对从 Windows 7 到 Windows 11 的 Windows 系统。它被宣传为高效、占用空间少的窃取程序，能够从 110 多个浏览器、70 个应用程序（包括钱包和 2FA）窃取数据工具），以及超过 250 个浏览器扩展，能够通过可定制的配置进一步扩展其收集范围。与广告宣传相反，AuraStealer 仍然存在多个缺陷，这些缺陷削弱了其隐身和规避能力，为防御者提供了清晰的检测机会。

![](深入分析AuraStealer-MaaS混淆与对抗技术/b0e0de244ad7c75c4c293d6ecf8c4dfc.jpg)

图 1：AuraStealer 在地下论坛上推广。

infostealer 通过分层订阅模式提供，**基本** **计划** 定价为 $295/month and the **Advanced** **plan** at $585/月。这些层的主要区别在于配置灵活性、数据过滤和操作可扩展性。第三层，**团队计划**，目前正在开发中，预计将引入专为协作使用而定制的功能。此外，还提供临时**试用套餐**，两周订阅价格为 165 美元，其中包括 **基本计划** 的所有功能。 **试用版**仅在 30 天的时间内可供购买，旨在在新用户承诺完全订阅之前吸引他们。

订阅包括访问专用网络面板，用于管理和查看基于 Tabler 模板构建的被盗数据。鉴于该面板和窃取程序最初仅以俄语提供，因此可以合理地假设开发人员在俄语网络犯罪社区内运作。然而，这并不一定表明它们的确切起源。该面板现已更新，现在支持俄语和英语。

![](深入分析AuraStealer-MaaS混淆与对抗技术/0941aeaac5f47431f78feb2a47cc12f9.jpg)

图 2：AuraStealer 的网页面板概述。

![](深入分析AuraStealer-MaaS混淆与对抗技术/4e5c40fd3a2fb59d376eceef2660b656.jpg)

图 3：AuraStealer 的网络面板及其日志管理界面，包括过滤选项和被盗记录的详细列表。

## 概览

---------

AuraStealer 主要通过 Scam-Yourself 活动进行传播， [抖音视频](https://undercodenews.com/tiktoks-dark-trick-aura-stealer-malware-masquerades-as-product-activation-guides/) 伪装成产品激活指南就是其中之一。在这些视频中，受害者被看似简单的教程所吸引，承诺免费激活其他付费软件。观看者被指示在管理 PowerShell 中手动重新键入并运行显示的命令，但是，该命令不会激活软件，而是悄悄下载并执行恶意负载。可以找到这些视频的具体示例以及完整的执行链和其他 IoC [这里](https://isc.sans.edu/diary/32380). 

除了 TikTok Scam-Yourself 活动之外，AuraStealer 还通过所谓的破解游戏或软件进行分发，其交付链的复杂程度各不相同。在最简单的情况下，仅执行 AuraStealer 的 UPX 打包版本，而不需要额外的阶段，而更复杂的活动则采用多阶段执行流程，涉及自定义加载程序、DLL 侧面加载、注入合法进程或其他中间步骤。我们还观察到 AuraStealer 通过恶意 VS Code 扩展与 GlassWorm 一起交付。总而言之，这些观察表明 AuraStealer 纯粹作为窃取器本身出售，没有加载程序层或额外的交付机制。

确定 AuraStealer 威胁的确切范围具有挑战性，因为我们经常在最终有效负载执行之前的早期阶段阻止其传输链。虽然主动防御对于保证用户安全至关重要，但它也会导致许多 AuraStealer 有效负载永远无法到达系统。因此，不仅要观察和量化威胁的全部范围，而且要确定被阻止的有效负载是否确实旨在传递 AuraStealer，本身就变得困难。

例如，如果它通过 ClickFix（最近最广泛采用的交付技术之一）交付，我们将在剪贴板阶段主动防御这些攻击 [剪贴板保护](https://www.gendigital.com/blog/news/family-of-brands/clipboard-protection) 特征。 ClickFix 通常指的是一种技术，向用户呈现人为生成的错误或问题，必须解决这些错误或问题才能继续，同时向用户提供解决问题的分步说明。这些步骤通常包括复制命令并通过 Windows 运行对话框或其他系统提示符运行它，但这并没有解决问题，而是默默地检索并执行恶意负载。

总而言之，AuraStealer 尚未像目前主导威胁领域的更成熟的信息窃取者家族（例如 Lumma Stealer、StealC 或 Vidar）那样广泛和流行。

AuraStealer 混淆
-----------------------

AuraStealer 融合了多种旨在阻碍静态和动态分析的技术。其中包括控制流混淆、字符串加密、持续混淆以及标准的反调试、反篡改和反虚拟机检查。它还采用了先进的技术，例如异常驱动的 API 哈希、利用 Heaven's Gate 进行可疑的 NTDLL 调用以及执行检查以检测返回地址上的断点。

### 间接控制流混淆

在反汇编程序（例如 IDA Pro）中打开 AuraStealer 时，分析人员可能遇到的第一个混淆技术是其间接控制流混淆。这种混淆不仅可以立即引起注意，而且也是正确分析窃取者必须克服的最麻烦的障碍之一。混淆基于系统地用间接跳转和调用替换直接跳转和调用，其中实际目标地址仅在运行时计算。这种方法有效地破坏了静态分析，因为反汇编程序留下了一组看似不相关的基本块，从而有效地破坏了任何控制流图分析或反编译。 

为了演示这种混淆在实践中如何发挥作用以及如何克服它，我们重点关注 `WinMain` 函数，这是窃取器中最长且最复杂的函数。下面的图 4 显示了说明汇编级别的混淆机制的几个示例，其中与计算每个目标地址相关的指令以不同的颜色突出显示。值得注意的是，该屏幕截图还说明混淆成功地混淆了 IDA，导致其误解整个数据 `WinMain`作为单个基本块运行。

![](深入分析AuraStealer-MaaS混淆与对抗技术/b14c0de77b9ca7676ef579401776334f.jpg)

图 4：WinMain 函数的反汇编代码，通过间接控制流混淆进行混淆。不同的颜色用于标记影响特定间接跳转/调用的指令。

如图所示，根据分支上下文，目标地址以几种不同的方式计算，范围从两个值的简单算术和（以绿色、蓝色和红色突出显示）到更复杂的方式，其中生成的目标地址可能采用多种可能的形式，最终选择由条件指令确定，例如 `cmovz`（以粉红色突出显示）。

此时，读者可以很容易地得出结论，一些模式匹配、模拟和修补就足以消除混淆——这也是我们最初的假设。然而，事实证明，AuraStealer 使用了这些间接控制流混淆方案的多种变体，其中一些采用了更为复杂的模式。例如，目标地址甚至可能取决于多个先前函数调用的返回值，因为其计算涉及由这些结果驱动的条件指令（参见图 5）。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/339250d64e614d41ded2aaee1003b723.jpg)

图 5：用于计算间接条件跳转的目标地址的更复杂的混淆变体的示例。

尽管如此，尽管这些混淆方案具有多样性和潜在的复杂性，但仍然有办法处理它们并重建原始控制流。首先，用于混淆函数调用的最基本方案，该方案仅依赖于两个值的总和，可以通过 IDA Pro 中的一个简单技巧来解决。在这些情况下，向 IDA 提示有助于求和运算的偏移量实际上是恒定的就足够了。一旦被视为常量操作数，IDA 就可以自行评估算术并相应地对其进行优化，从而允许反编译器揭示实际调用的目标地址。

![](深入分析AuraStealer-MaaS混淆与对抗技术/0851ca4a4553c5292e5c531008ab4def.jpg)

图 6：使用 IDA Pro 中的“Set type”命令（快捷键 Y）将偏移标记为常量。

图 7 和图 8 说明了该技巧的效果以及反编译输出中产生的差异。可以看出，即使是这样的微小调整也可以显着改善分析，因为它用对实际目标函数的直接引用取代了这些原本无意义的偏移和计算。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/5fe4ab8193a67a48af207712d5ab7dd4.jpg)

图 7：将偏移量标记为常量之前 WinMain 函数的反编译代码。

![](深入分析AuraStealer-MaaS混淆与对抗技术/846c32e5ed163313e86d282497945630.jpg)

图 8：将偏移量标记为常量后 WinMain 函数的反编译代码。

由于这些偏移引用通常出现在连续的块中（图 9），因此自动化它们的处理是很实用的，图 10 中所示的 IDA Python 片段对此特别有用。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/dfb0eb0fe410f4ece0171210416394f7.jpg)

图 9：用于间接 jmp/call 计算的长偏移序列。

![](深入分析AuraStealer-MaaS混淆与对抗技术/6a667c29bbc885e3908e472fa0d2bbef.jpg)

图 10：将多个偏移引用标记为常量的 IDA Python 片段。

不幸的是，仅此技巧不足以解决 AuraStealer 间接控制流混淆的条件跳转和其他方案。尽管如此，考虑到有多少调用被这个简单的方案混淆，应用它仍然提供了有意义的进展，并且可以作为进一步反混淆的坚实起点。此外，AuraStealer 还应用相同的混淆方案来隐藏某些函数参数，使其也适用于这些情况。 

为了解决更复杂的模式，**向后切片**被证明是最有效的方法。对于那些有兴趣更详细地解释该技术如何工作的人，可以阅读以下文章 [_LummaC2：通过间接控制流进行混淆_](https://cloud.google.com/blog/topics/threat-intelligence/lummac2-obfuscation-through-indirect-control-flow) 作者：Nino Isakovic 和 Chuong Dong，以及 [_Rhadamanthys 加载器反混淆_](https://cyber.wtf/2025/11/19/rhadamanthys-loader-deobfuscation/) Melissa Eckardt 的著作提供了出色的解释，绝对值得一读。 

简而言之，向后切片是一种程序分析技术，它通过跟踪数据和控制依赖性来识别可能影响特定程序点处的特定寄存器或内存地址的指令。然后，所得指令集（也称为“切片”）可用于进一步分析，例如仿真或符号执行，以恢复目标寄存器或内存位置的值。

在我们的例子中，我们采用了一种启发式方法，其灵感主要来自向后切片，但经过简化并专门为 AuraStealer 量身定制。该启发式可以概括为以下步骤：

1.  找到间接的 `jmp/call` 操作说明。
2.  添加用作该间接的目标操作数的寄存器 `jmp/call` 指示给 `tracked_regs`放。
3.  反向迭代指令（从间接 `jmp/call` 朝向较低地址），分析每条指令是否影响任何被跟踪的寄存器。
    1.  如果指令**修改**跟踪的寄存器，则将其标记为**相关**。
    2.  对于相关指令，确定它是否完全覆盖跟踪的寄存器（例如， `MOV reg, imm`, `XOR reg, reg`_**,**_etc.)，如果是这样，则从中删除该寄存器 `tracked_reg`，结束其依赖链。
    3.  否则，识别该相关指令的所有源寄存器并将它们添加到 `tracked_reg`设置为进一步传播依赖关系。
4.  如果发生以下任何情况，请停止该过程：
    1.  这 `tracked_regs`设置为空（所有依赖项均已解决）。
    2.  遇到控制流指令（`call`, `jmp`, `ret`），表示基本块边界。
    3.  达到最大指令限制（故障安全）。
5.  最后，返回找到的最早（最低地址）相关指令的地址，标记切片的开始。

为了清楚起见，这种启发式并不意味着实现完全的向后切片。它故意省略内存写入跟踪并仅关注寄存器流。然而，值得注意的是，这种限制是有意为之的，因为寄存器级分析足以对 AuraStealer 使用的间接控制流混淆进行反混淆。我们仅使用启发式方法来识别切片的起始地址，然后使用 Angr 执行符号执行来计算目标地址。也就是说，如果 AuraStealer 的混淆方式发生变化，启发式方法可以很容易地扩展到也能解释记忆交互。

我们选择符号执行而不是仿真的原因是符号执行本质上是为了探索所有可能的执行路径而设计的，使其更容易实现。就计算要求而言，它仍然可行，因为我们仅象征性地执行小代码块。

细心的读者可能已经注意到这种方法有一个小缺陷。启发式在遇到以下情况时终止 `call` 操作说明。然而，如图5所示，一些目标地址 `jmps` 可能依赖于先前函数调用的结果，这可能导致错误识别切片开始。为了处理这种情况，每当寄存器不受约束时，我们都会为其分配一个符号布尔值（0或1），假设任何影响此类跳转的函数都会返回一个布尔值。然而，这种情况相对较少。 

整个过程可以通过一些脚本实现自动化，并且恢复的目标地址可以作为注释推回 IDA，这已经为导航代码提供了良好的基线。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/997d9070789729c0d6d25f1613e244e7.jpg)

图 11：恢复的目标地址在 IDA Pro 中设置为注释。

然而，我们可以更进一步——我们真正的目标是让 IDA 重建原始的控制流图，而不仅仅是对其进行注释。一旦间接的目标地址 `jmps/calls` 检索后，有多种方法可以继续。一种选择是修补二进制文件。 However, due to the variability of the patterns involved and the presence of an anti‑tamper protection in AuraStealer, we have opted for a different approach. 

我们没有对具有破坏性且容易被恶意软件检测到的二进制文件进行修补，而是利用 IDA SDK 直接挂钩指令分析过程。这个想法很简单——我们不是让 IDA 自己分析指令，而是干预分析过程并修改指令的解码方式。为此，IDA 提供 [`post_event_visitor_t`](https://cpp.docs.hex-rays.com/structpost__event__visitor__t.html)，一个类，允许通过重写虚函数来监听 IDA 中的特定事件并做出反应 `handle_post_event`. 

![](深入分析AuraStealer-MaaS混淆与对抗技术/1fc4b52665ecaad30ff2d522775df08d.jpg)

图 12：handle\_post\_event 虚函数的声明。

在所有可能的事件代码中，有趣的是 `processor_t::ev_ana_insn` （分析指令），在 IDA 调用处理器模块的指令解码器之后、结果之前立即触发 `insn_t` 结构最终确定并提交到数据库。此时，我们可以检查甚至修改解码后的指令。换句话说，我们可以改变 IDA 对代码的感知，而无需触及底层二进制文件。

在这一点上，有几点值得强调：

*   间接调用几乎总是有一个目标。
*   许多条件跳转只有两个目标，其中之一是紧随其后的指令。

因此，解决间接调用混淆很简单。每当我们拦截 `processor_t::ev_ana_insn` 事件，我们检查分析的指令是否是间接调用（`call reg`）。如果目标地址已知并且它是唯一可能的目标，我们将替换 `call reg` 指令与 `call <calculated_target_address>`.

对于间接条件跳转，原则上可以通过分析用于计算目标地址的条件移动并替换 `jmp` 指令与相应的条件跳转指令。然而，我们选择了一种更简单、更务实的策略。事实上，许多间接跳转只是混淆的循环或 `if-then/if-then-else` 使用指向紧随其后的指令的目标地址之一进行构造。所以，每当我们遇到间接的 `jmp` 指令恰好有两个可能的目标，其中之一是失败地址，我们替换 `jmp` 指令与 `jnz` （如果不为零则跳转）指向非失败目标地址。

这种转换不会产生完全准确的反编译。然而，如果我们接受这样一个事实，即某些比较可能会显示为 `condition != 0` 我们最终得到的是一个更容易遵循的控制流，而不是它们的确切形式。此外，只要精确的条件语义很重要，就始终可以在反汇编中直接检查原始条件。尽管可以为每种情况重建并替换精确的条件跳转，但我们认为这不值得付出努力。

![](深入分析AuraStealer-MaaS混淆与对抗技术/225ca91f531019c81796047334ed4275.jpg)

图 13：用 jnz 指令替换 jmp 指令的演示。

对于具有多个可能目标的间接跳转，或者没有一个目标不是紧随其后的指令的间接跳转，我们只需在 IDA 中添加用户定义的交叉引用即可。

通过这些步骤，我们成功地完全恢复了 AuraStealer 的控制流程。

![](深入分析AuraStealer-MaaS混淆与对抗技术/5da9fcaada4234824a815c6c7fcdb9d7.jpg)

图 14：反混淆后恢复的 WinMain 函数的控制流程图。

请注意，由于对代码位置的许多引用造成了严重的控制流混淆，IDA 经常难以识别正确的函数边界。因此，通常需要手动调整函数的开始和结束位置，以确保 IDA 分析整个函数。

### 异常驱动的 API 哈希

为了混淆其对 WinAPI 函数的使用，AuraStealer 采用了 API 哈希技术。出于这些目的，它首先通过 PEB 遍历解析二进制文件所需的所有函数，并构建两个基于哈希的查找表，将哈希映射到 XOR 掩码地址。 

维护两个表的原因是AuraStealer不直接调用这些函数。相反，它故意触发异常，但该异常会被自定义异常处理程序拦截。处理程序检查异常产生的地址，并使用该信息来调度适当的函数地址。

为了解析特定函数，AuraStealer 采用预先计算的 `MurmurHash3` 值（种子为 `0xDEADBEEF`) 函数名称，重新散列它 `FNV-1a`，并使用这两个值来查询第一个预先计算的查找表。该查询返回要抛出异常的 XOR 掩码地址，以及用于保护它的掩码。然后，AuraStealer 揭开该地址的掩码并对其进行调用，故意抛出一个 `EXCEPTION_ACCESS_VIOLATION`，它被自定义异常处理程序拦截。 

异常处理程序使用以下命令重新散列原始地址 `FNV-1a` 并使用这两个值来查询第二个预先计算的查找表。此查询返回实际目标函数的 XOR 掩码地址，同样与掩码一起返回。 The two values are XORed together and the resulting address is loaded into the `EIP` 注册，有效调用所请求的 WinAPI 函数。


#### ✅ 第一步：计算函数名的哈希值

```
MurmurHash3 value of a specific function's name (seed: 0xDEADBEEF)
```

- 使用 `MurmurHash3` 算法对某个函数名进行哈希；
- 种子（seed）固定为 `0xDEADBEEF`（常用于防止碰撞或标记）；
- 得到一个唯一的哈希值。

👉 这个哈希值将作为后续查找的“键”。


#### ✅ 第二步：生成 FNV_1_hash

```
FNVM_1_hash
```

- 将上面的 MurmurHash3 值再输入到 `FNV_1_hash` 算法中；
- 可能是为了进一步混淆或扩展哈希空间。

#### ✅ 第三步：第一次查表（First lookup table）

```
First lookup table
```

- 使用 `FNV_1_hash` 的结果去查询第一个查找表；
- 返回两个字段：
    - `EXCEPTION_ADDRESS_MASKED`：被掩码处理过的异常地址
    - `EXCEPTION_ADDRESS_MASK`：对应的掩码值

#### ✅ 第四步：XOR 操作 + 抛出异常


```
EXCEPTION_ADDRESS_MASKED XOR EXCEPTION_ADDRESS_MASK → Throw exception
```

- 对这两个值执行 **异或（XOR）操作**，还原出原始的异常地址；
- 然后主动抛出一个异常（`Throw exception`），触发系统的异常处理机制。

> ⚠️ 注意：这里的“抛出异常”不是错误，而是**人为构造的异常**，用来进入异常处理流程。


这允许我们预先计算所有 API 哈希函数的哈希值，并将反编译器计算的常量替换为相应的函数名称。但需要注意的是，这种方法依赖于 IDA 的反编译器，如果控制流没有完全反混淆，可能会产生不完整的结果。也就是说，还可以通过组合向后切片来恢复常量，以隔离影响最终常量值的指令，并使用仿真框架（例如，Unicorn）对其进行仿真。 此外，这些指令始终位于使用反混淆常量的同一基本块中。

![](深入分析AuraStealer-MaaS混淆与对抗技术/164cd129d724030973abedfe7deaa196.jpg)

图 16：函数名称的 MurmurHash3 值的不断混淆。

![](深入分析AuraStealer-MaaS混淆与对抗技术/620e1fcdd8428362e222480be5e00bce.jpg)

图 17：实践中 API 哈希函数调用的示例。

![](深入分析AuraStealer-MaaS混淆与对抗技术/87b7355f8d985de85a76efb77a7befb4.jpg)

图 18：AuraStealer 的自定义异常处理程序实现。

异常处理程序安装在 initterm 例程中，即在程序到达之前 `WinMain`，使其存在很容易被忽视。作为此设置的一部分，AuraStealer 不仅注册异常处理程序本身，还通过以下方式分配内存 blob `VirtualAlloc`，稍后用于构建查找表并作为触发异常的内存区域。  

![](深入分析AuraStealer-MaaS混淆与对抗技术/20538aaad9ed414af3ba7c18795e2041.jpg)

图 19：AuraStealer 的 initterm 例程。

![](深入分析AuraStealer-MaaS混淆与对抗技术/212e562ef2ffa88296865b994f3b579e.jpg)

图 20：异常处理程序安装。

这种机制有效地增加了另一层混淆。  尽管自定义处理程序最终会处理故意触发的异常，但调试器会首先拦截它们。因此，任何在调试器中分析 AuraStealer 的人都会被淹没 `EXCEPTION_ACCESS_VIOLATION`，使程序显得不稳定并掩盖其真实行为。这很容易导致分析人员禁用异常通知只是为了让程序运行。然而，通过这样做，他们故意在进程中隐藏了恶意软件的自定义异常处理程序，导致其逻辑的重要部分被忽视。此外，异常垃圾邮件还可以用作反调试技术，因为大量的异常流会扰乱调试工作流程。

### 字符串混淆

尽管 AuraStealer 中的大多数字符串都经过混淆，但动态解析并打算通过 API 哈希隐藏的函数名称仍保持明文形式。

![](深入分析AuraStealer-MaaS混淆与对抗技术/aab6d2cab5ca416a0c9a8c635c5c59ba.jpg)

图 21：AuraStealer 二进制文件中的纯文本函数名称。

然而，它们的地址使用与混淆间接调用的目标地址相同的基于算术的混淆进行混淆（图 22）。

![](深入分析AuraStealer-MaaS混淆与对抗技术/dd49b793daa4f3ad7bcd58b22878a1b5.jpg)

图 22：AuraStealer 隐藏函数参数。

尽管如此，由于计算仅依赖于常量值，因此可以使用上面介绍的相同技巧 - 将计算中使用的变量标记为常量 - 让 IDA 的反编译器计算目标地址。这是这个技巧如何显着加速分析的另一个很好的例子。反编译的代码直接显示所引用的函数名称，而不是无意义的偏移量（见图 23）。

![](深入分析AuraStealer-MaaS混淆与对抗技术/877b5168ac8ed197c9597182f29a023c.jpg)

图 23：应用将偏移量标记为常量的技巧后的反编译代码。

其余字符串使用基于堆栈的 XOR 混淆进行加密。加密的字符串及其相应的 XOR 密钥首先在内存中由常量值串联起来，进行异或运算，然后存储在内存中。图 24 显示了此类解密例程在汇编级别的示例。

![](深入分析AuraStealer-MaaS混淆与对抗技术/d3b7c308672a19722fdc4377bcaf73d1.jpg)

图 24：AuraStealer 在程序集级别的字符串解密。

这些解密例程通常遵循相同的逻辑，但包含细微的变化，并且它们的长度根据解密字符串的长度而变化。主要挑战是使用独立的基本块模拟指令并在解密完成后从内存中读取字符串不足以恢复所有字符串，因为字符串解密逻辑中涉及的许多常量在整个函数中重复使用。因此，必要的上下文分布在整个功能中。因此，恢复所有字符串需要模拟更大的代码区域来保留完整的上下文，这项任务很快就会变得容易出错且耗时。 

因此，为了解密 AuraStealer 字符串，我们使用 Unicorn 模拟框架实现了简化形式的函数模拟。我们不是模拟整个函数，而是有选择地单步执行它的指令，同时跳过调用指令和循环。当到达条件分支时（例如， `if`或者 `switch` 构造），我们分叉执行来探索并覆盖所有相关路径。这种简化的方法足以恢复大部分混淆的字符串，而无需诉诸完整的重量级仿真。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/4beddb776dc96484c8b5f1bb4bb6ed64.jpg)

图 25：恢复字符串的示例（来自单个函数）。


反分析执行链
-----------------------------

在执行过程中，AuraStealer 会执行多项反分析检查，范围从基本技术到更复杂的技术。其中一些检查是无条件执行的，而其他检查则取决于特定于特定 infostealer 版本的配置参数。

### 运行受保护的检查

AuraStealer 的反分析链首先检查二进制文件是否是从加载器、加壳器或加密器等保护层执行的。根据该结果，它执行或跳过其他检查，其中包括防篡改检查和对话框检查。 

### 防篡改检查

防篡改检查是使用 `MapFileAndCheckSumW` WinAPI 函数，计算文件的校验和并将其与 PE 标头中存储的值进行比较。如果这些值不同，AuraStealer 会停止执行。

此检查的目的是防止分析人员修补或以其他方式更改可执行文件。考虑到这一点，分析人员应该对二进制文件（包括软件断点）所做的任何更改保持谨慎，并在动态分析期间保持警惕，因为如果检测到篡改，恶意软件可能会故意表现出误导性行为。 

### 对话框检查

类似于什么 [鲁玛](https://outpost24.com/blog/lummac2-anti-sandbox-technique-trigonometry-human-detection/)，最近还 [拉达曼蒂斯](https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/)，如果 AuraStealer 检测到它正在不受保护的情况下运行，它会显示一个对话框，提示用户输入代码以继续。与 Lumma 和 Rhadamanthys 不同，它要求用户不仅要单击“确定”按钮，还要正确输入显示的代码。另一方面，它不会显示任何恶意软件将运行的警告消息，这正是 Lumma 和 Rhadamanthys 在消息框中显示的内容。

![](深入分析AuraStealer-MaaS混淆与对抗技术/dc93ea5c0dac8b95bb13ce72f17e81ab.jpg)

图 27：在不受保护的情况下运行时显示的 AuraStealer 对话框。

该机制会暂停 AuraStealer 的执行，直到提供正确的值，旨在迫使恶意软件传播者为窃取程序提供额外的保护层。此外，它还可以用作反沙箱保护，因为自动化沙箱几乎不会对该文本执行 OCR 并尝试粘贴它。窗口标题和要输入的代码都是在运行时基于 Mersenne-Twister 伪随机数生成器随机生成的。 

### 地理位置检查

为了避免在特定国家/地区执行，AuraStealer 通过使用 WinAPI 函数检索系统和用户语言设置来执行地理位置检查 `GetUserDefaultLCID` 和 `GetSystemDefaultLCID`**,** 并通过以下方式获取国家代码 `GetLocaleInfoA`。然后将检索到的国家代码与预定义的黑名单进行比较，如果发现任何匹配，恶意软件就会终止其执行。

![](深入分析AuraStealer-MaaS混淆与对抗技术/aeff1ca600bc33b5fab3816a5016df7a.jpg)

图 28：AuraStealer 列入黑名单的国家/地区列表。

值得注意的是，除了避免在独联体国家执行死刑外，盗窃者还忽略了波罗的海国家（立陶宛、拉脱维亚和爱沙尼亚）。   

据 AuraStealer 开发人员称，据称在服务器端执行了额外的 IP 检查。然而，我们无法证实这一说法。

### 反沙箱检查

如果之前的所有检查均通过，则该过程将继续进入反沙箱阶段，该阶段包括三项主要检查。

首先，AuraStealer 评估是否 `Sleep`函数已被挂钩或修改。为此，它使用记录系统时间 `GetSystemTimePreciseAsFileTime`，调用 `Sleep(1000 ms)`，并再次查询系统时间。如果测量到的延迟小于 900 毫秒，则窃取者会假设 `Sleep` 功能已被篡改。

接下来，它通过比较返回的值来执行 Microsoft Defender 模拟检查 `GetUserNameW` 和 `GetComputerNameW` 针对众所周知的模拟器工件 `JohnDoe` 和 `HAL9TH`. 

最后，AuraStealer 检查当前加载的模块列表，并将它们与以下列入黑名单的 DLL 列表进行比较：

![](深入分析AuraStealer-MaaS混淆与对抗技术/8d86156d0c3195163f4d327cfa53fa8f.jpg)

图 29：AuraStealer 列入黑名单的 DLL 列表。

### 配置提取

每个 AuraStealer 版本的配置都直接嵌入到二进制文件中，并受到 AES-CBC 加密的保护。加密配置存储为单个连续块，具有线性、序列化布局。加密后的配置结构如下：

![](深入分析AuraStealer-MaaS混淆与对抗技术/7711e00a68ab47310e06629a7e8109ca.jpg)

图 30：AuraStealer 的配置结构。

由于解密配置所需的所有信息都包含在二进制文件中，因此可以解密内容并提取恶意软件配置。

![](深入分析AuraStealer-MaaS混淆与对抗技术/9f5fc26f2566e7c3d588f7116a090911.jpg)

图 31：提取的 AuraStealer 配置示例。

根据配置，AuraStealer 执行额外的反分析检查。如果所有检查都通过，它会尝试与配置中列出的 C2 服务器建立连接并启动数据窃取过程。该配置还允许设置自定义用户代理、定义启动延迟以及选择恶意软件是否应在完成窃取过程后删除自身。有趣的是，尽管反调试在配置中显示为可配置选项，但无法从面板中禁用它。此外，即使配置中未明确列出代理支持，AuraStealer 仍有望处理代理的使用。 AuraStealer 面板中的可用构建选项以及二进制文件中的配置解析逻辑中观察到的字符串都表明了这一点。

![](深入分析AuraStealer-MaaS混淆与对抗技术/534759482b6225de6fb448977b0f0dbb.jpg)

图 32：AuraStealer 的构建设置选项（面板）。

![](深入分析AuraStealer-MaaS混淆与对抗技术/026b6b55eb02fa445efbf6a447815b08.jpg)

图 33：AuraStealer 的配置解析函数中解密的字符串“代理”。

为了简化从 AuraStealer 示例中检索构建配置数据的过程，我们提供了 [配置提取脚本](https://github.com/avast/ioc/blob/master/AuraStealer/extras/aurastealer_config_extractor.py)。该脚本可在我们的 GitHub 上公开访问。

### 人工检查

人工检查包括两个子检查，均以无限循环的形式实现。 

The first check monitors whether the user input changes over time.首先测量两个之间的刻度数 `GetTickCount` 呼叫与 `Sleep(1000 ms)` 之间。 while 循环然后重复执行 `Sleep(500 ms)` 随后致电 `GetLastInputInfo`，它返回一个 `LASTINPUTINFO` 结构。该结构体包含一个变量， `dwTime`，表示最后一个输入事件发生的滴答计数。然后，另一个电话 `GetTickCount` 被制成，并且 `dwTime` 从中减去。如果结果小于先前测量的一秒所测量的刻度数 `Sleep`，检查通过。否则，循环将重复直到检查通过。 

第二次检查从调用开始 `GetForegroundWindow`，它返回当前前台窗口的句柄。 A while loop then repeatedly calls `Sleep(500 ms)` 并检查 `GetForegroundWindow` 再次。如果返回的句柄与初始句柄不同，则检查通过。否则，循环将继续，直到前景窗口发生变化。 

### 反虚拟机检查

Anti-VM 检查由多个子检查组成。首先，使用以下命令检查虚拟机管理程序是否存在 `cpuid` 操作说明。什么时候 `cpuid` 执行的是 `EAX = 1`，第 31 位 `ECX` 表示环境——它是 `0` 在物理机器上并且 `1` 在虚拟机上。

接下来是WinAPI函数的组合 `GetDesktopWindow` 和 `GetWindowRect` 用于获取 `right` 来自结果的变量 `RECT` 结构，然后与 `1024` （预计会更大）。最后， `GlobalMemoryStatusEx` 被称为，并且 `ullTotalPhys` 返回的变量 `MEMORYSTATUSEX` 检查结构以确保它不是 `0`.

如果所有这些检查都通过，AuraStealer 会调用 `GetSystemInfo` 并检查返回的 `SYSTEM_INFO` 结构来验证 `dwNumberOfProcessors` 不少于四。如果系统有四个或更多处理器，则认为 Anti-VM 检查已通过。如果处理器数量低于此阈值，恶意软件将使用以下命令执行一项附加验证 `EnumProcesses` 检索正在运行的进程的列表。然后检查正在运行的进程总数是否至少为 `200`，假设这是真实的非虚拟化系统的典型情况。

![](深入分析AuraStealer-MaaS混淆与对抗技术/857962cb3acb22e34b74c7d44614b106.jpg)

图 34：反虚拟机检查 - 反编译代码。

![](深入分析AuraStealer-MaaS混淆与对抗技术/7aed61b3341f1e56c19c801040dc54d1.jpg)

图 35：AntiVM cpuid 位检查。

### 反调试检查

反调试检查包括几个子检查，首先检查文件中众所周知的调试标志 `PEB`， 包括 `BeingDebugged` 和 `NtGlobalFlag`，以及 `KUSER_SHARED_DATA` 结构。有关如何使用这些标志来检测调试器的详细说明，请参见 [这里](https://anti-debug.checkpoint.com/techniques/debug-flags.html).

![](深入分析AuraStealer-MaaS混淆与对抗技术/eb878ed9731ef1a92808f711246729bc.jpg)

图 36：反调试检查 - 反编译代码。

![](深入分析AuraStealer-MaaS混淆与对抗技术/77a160a49e9813e7cb97388ec175ac8f.jpg)

图 37：PEB!BeingDebugged 标志检查。

![](深入分析AuraStealer-MaaS混淆与对抗技术/8f769e3e5100534398ec3c2c52ae5680.jpg)

图 38：PEB!NtGlobalFlag 标志检查。

![](深入分析AuraStealer-MaaS混淆与对抗技术/837e279467854039f9a572ab14b6cd83.jpg)

图 39：KUSER\_SHARED\_DATA 结构检查。

如果之前的所有检查都通过，AuraStealer 将使用以下命令创建一个新的调试对象 `NtCreateDebugObject` 并随后调用 `NtQueryObject`。由于该对象刚刚创建，因此它应该只存在一个句柄——由程序本身持有的句柄。但是，如果附加了调试器或其他监视工具（通常会挂钩这些函数或重复句柄以进行分析），则 `HandleCount` 可能大于一。在这种情况下，AuraStealer 会继续将所有正在运行的进程的名称与硬编码的黑名单进行比较，如果发现任何匹配，则会终止其执行。

![](深入分析AuraStealer-MaaS混淆与对抗技术/85e5ee3b5f0ac4f84d1e95cbf4ca5328.jpg)

图 40：AuraStealer 的黑名单进程列表。

值得注意的是，细心的读者可能会注意到，在反编译的反调试和反虚拟机检查功能中，AuraStealer 采用了一种额外的反调试技术，该技术在其代码库中的各种功能中使用。该技术的工作原理是检查位于函数返回地址的操作码。如果断点指令（`INT3` 或者 `INT 3`）或一个 `UD2`检测到指令（通常用于挂钩），生成 64 到 127 之间的随机值并将其添加到偏移量处的堆栈变量中 `−4` 从返回地址。 The intent behind this technique is not to crash the program immediately, but to plant a subtle corruption that only results in a crash later during execution, making it very hard to determine the crash origin.

![](深入分析AuraStealer-MaaS混淆与对抗技术/dfbce4f218604a7aa9f5d3fcb062b938.jpg)

图 41：返回地址反调试技术的拆解图。

AuraStealer 执行流程
--------------------------

The high-level execution flow of AuraStealer can be summarized as follows.首先，恶意软件安装自定义异常处理程序并创建两个用于异常驱动 API 哈希的查找哈希表。接下来，它执行上述多重反分析检查并解密其嵌入配置。如果所有检查都通过，则继续创建互斥锁。 

根据配置中指定的主机，它尝试与其 C2 服务器建立连接，C2 服务器以指定应收集哪些信息和文件的附加配置进行响应。最后，恶意软件开始收集目标数据并将其渗透到远程基础设施。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/ddea1625cacf32208340762f0be13281.jpg)

图 42：AuraStealer 的执行流程。

至于AuraStealer的功能，它几乎针对用户数字生活的各个方面。具体来说，它能够收集：

*   来自基于 Chromium 和基于 Gecko 的浏览器的敏感数据
*   来自桌面应用程序和浏览器扩展的加密货币钱包
*   活动会话令牌（Discord、Telegram、Steam）
*   2FA 令牌（验证器）
*   恢复数据（恢复种子、私钥、助记词）
*   凭证和 API 密钥
*   远程访问和 FTP 配置（AnyDesk 配置、FileZilla 凭据）
*   密码管理器数据库（KeePass、Bitwarden、1Password、LastPass）
*   VPN 配置（OpenVPN、NordVPN、ProtonVPN）
*   剪贴板内容
*   受害者设备的屏幕截图
*   正在运行的进程列表以及一般系统指纹数据

然而，这并不是一个详尽的列表，因为 AuraStealer 允许包含针对特定构建的附加自定义配置模块（包括具有可配置掩码、路径和递归的基于通配符的文件搜索），从而有效地窃取几乎任何感兴趣的文件。

除了数据盗窃之外，AuraStealer 还能够执行额外的有效负载。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/521626468036146bf7b0bebf524096ca.jpg)

图 43：与附加有效负载执行相关的解密字符串。

![](深入分析AuraStealer-MaaS混淆与对抗技术/f52f5eb75f9d648ee3b2946719dd07cd.jpg)

图 44：通过 ShellExecuteExW 执行有效负载。

### 动态生成的互斥体

为了防止多个实例同时运行，AuraStealer 利用基于特定于构建和时间相关的值动态生成的互斥体。恶意软件首先加载 `build_id` 来自其配置的值（例如， `a0858933-16a7-433f-a9cc-68490ace0576`）并计算 `djb2` 散列它。然后将哈希值添加到整数除法的结果中 `_Xtime_get_ticks()/36000000000`，它有效地产生一个每小时变化一次的值。最终的和用作 Mersenne-Twister 伪随机数生成器的种子，该生成器用于生成长度在 16 到 32 个字符之间的随机字母数字字符串。生成的字符串前面带有 `Global\`，形成最终的互斥体名称。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/1dc2bb1f3362fe4ec4e1e5f7f18442e4.jpg)

图 45：AuraStealer 的互斥体创建（反编译代码）。

互斥锁每小时都会发生变化，这一事实凸显了窃取者被设计为仅运行很短的一段时间——这种趋势在现代信息窃取者中已经变得越来越普遍。目标是简短地执行，窃取尽可能多的数据，并且最好删除其存在的所有痕迹。

应用程序绑定的加密绕过
-----------------------------------

要从基于 Chromium 的浏览器中提取敏感数据，AuraStealer 必须首先克服应用程序绑定加密 (ABE)，它是通过使用以下命令在无头模式下生成目标浏览器来实现的： `CreateProcessW`，在挂起状态下创建进程，然后进行代码注入。从注入的上下文中，恶意软件调用 `IElevator::Decrypt` 来解密 `app_bound_encrypted_key`，它可以解密任何受 ABE 保护的数据，包括密码和 cookie。

![](深入分析AuraStealer-MaaS混淆与对抗技术/2104130012e6765ec08daa7a59460b9e.jpg)

图 46：AuraStealer 的 ABE 旁路。

注入本身是通过创建共享部分来实现的 `NtCreateSection` 并将其映射到目标浏览器进程中使用 `NtMapViewOfSection`，之后使用注入的有效负载执行 `NtCreateThreadEx`。注入中涉及的所有 NTDLL 调用都是通过 Heaven’s Gate 执行的，该技术允许从 64 位操作系统上的 32 位进程执行 64 位代码。这既确保了与 64 位浏览器的兼容性，也有助于逃避检测。

![](深入分析AuraStealer-MaaS混淆与对抗技术/59b4a11471027e7f46bc4cd9b8504cef.jpg)

图 47：AuraStealer 对天堂之门的使用。

注入的有效负载是与位置无关的 shellcode，在运行时针对每个目标浏览器进程稍作修改。在 shellcode 内的预定义偏移处，AuraStealer 使用以下形式的路径填充两个随机生成的文件名  
`C:\Users\<user>\AppData\Local\Temp\<random_alphanumeric_string_len_16_to_32>`,  
以及标识浏览器类型的值，该值稍后用于为浏览器选择适当的 CLSID 和 IID `CoCreateInstance` 调用。这两个文件充当 AuraStealer 和注入的 shellcode 之间的进程间通信机制。第一个文件用于传递加密后的文件 `app_bound_encrypted_key` 到注入的 shellcode，而 shellcode 使用第二个文件写回解密的密钥以供窃取者检索。

尽管 AuraStealer 能够解密 `app_bound_encrypted` 从某些基于 Chromium 的浏览器中解密应用程序绑定加密数据所需的密钥，它仍然无法在所有浏览器中可靠地工作，这表明该产品尚未达到完全完善的状态。

网络流量
---------------

AuraStealer 的网络流量可分为四个阶段。窃取者首先通过检查网络的可达性来验证互联网连接 `1.1.1.1:53` （云耀）。成功后，它会尝试通过查询来与其 C2 基础设施建立通信 `/api/live` 端点并期待响应 `true`。如果任何服务器可以访问，它就会请求 `/api/conf`，连同其 `build_id`，检索定义要收集的数据的特定于构建的配置（a [配置示例](https://github.com/avast/ioc/blob/master/AuraStealer/extras/aurastealer_config.json) 在我们的 GitHub 存储库上公开可用）。最后，收集的文件被分成较小的档案，并在通过收集时分批发送 `/api/send` 端点。

![](深入分析AuraStealer-MaaS混淆与对抗技术/81de41e52abb2dab3da0d6e42061b747.jpg)

图 48：捕获 AuraStealer 的网络流量。

所有网络流量均使用 AES-CBC 进行加密，其方式与配置加密非常相似，不同之处在于加密数据还进行了 Base64 编码。加密密钥和初始化向量在运行时随机生成。 

![](深入分析AuraStealer-MaaS混淆与对抗技术/9c838b42a8a404a67cd073a727699c95.jpg)

图 49：通过网络传输的加密数据的结构。

![](深入分析AuraStealer-MaaS混淆与对抗技术/83f7a41a2e5ed2e5f268ab54e76486db.jpg)

图 50：泄露数据示例。



### IOC

0223E39D9C26F065FABB1BCB8A1A03FE439BB18B8D14816646D8D236A6FD46A3（AuraStealer 1.0.0）
01E67139B59EED0FE1FCB4C66A9E88AD20DD8B55648C077AEC7FA2AE3431EA5F（AuraStealer 1.1.0）

9A46C8D884F4C59701D3AF7BEAD1E099E3DDEB1E2B75F98756CC5403D88BD370（AuraStealer 1.1.1）

FD3875225C1AB60E6DC52FC8F94B4D389624592B7E7B57EE86E54CEBE5D3EB6A（AuraStealer 1.1.2）

EC7BA08B1655963D6C9F7D996F3559C58893769A2C803DA1F99610A0AAA1224A（AuraStealer 1.2.0）

0F691762DA02ABBD94046381ECEDFD8B31CCBB835DED6049E9D6CD2AFDD3F551（AuraStealer 1.2.1）

F6E7341AB412EF16076901EA5835F61FBC3E94D0B9F2813355576BAD57376F29（AuraStealer 1.2.3）

D19274A14B905679DBD43FFB374CA0E11F9DC66FDB9E17236829A9A56F3E7D31（AuraStealer 1.3.0）

F0F7AE1FC2D569B8B9267D2EC81F7E539DB4BEAF275BCA41962C27ECFA5361BF（AuraStealer 1.4.0）

158369AD66EA4BACEEE19051425C21F657FFC1B3483EA812323816B612F324BD (AuraStealer 1.5.0)

F816558972F62D206757BAD4A95EE75290615F520F3B24D814FFBCDFC6998C6C（AuraStealer 1.5.1）

F7D0F099D042DE83AA2D0A13100640BEA49D28C77C2EB3087C0FB43EC0CD83D7（AuraStealer 1.5.2）

