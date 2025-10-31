---
title: 深入解析现代-Windows-结构化异常处理（SEH）（x64）
date: 2025-10-31 09:08:26
tags:
---

在-Windows-平台上，操作系统实现了一套独有的异常处理机制 —— **结构化异常处理（SEH）** 和 **向量化异常处理（VEH）**，这可以看作是对传统 C/C++ 语言异常处理机制的扩展，用于在运行时处理错误。

> 这些机制仅适用于-Windows-可执行文件，因为它们依赖于-Windows-内核来捕获异常并将控制权转移回程序！

这种独特的异常处理方式使得我们在逆向工程或追踪程序控制流时，如果不理解异常处理器的安装与实现方式，就会变得异常复杂。

本文将深入底层，探究这些异常处理器是如何实现的。

---

## x64 架构下的结构化异常处理（SEH）

SEH 在 **32 位与 64 位程序中的实现差异巨大**。

本文将主要研究 **64 位程序中 SEH 的工作原理**，随后简要对比 32 位实现及 VEH。

为了更好地理解 SEH 在编译后的程序中是如何呈现的，我们可以编译一个简单的程序并在 IDA 中查看其汇编代码。以下是示例程序：

```c
#include <windows.h>
#include <stdio.h>

int main() {
    __try {
        printf("__try block\\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("__except block\\n");
    }
    return 0;
}

```

在 IDA 中查看其汇编代码，我们可以识别出 `try` 和 `except` 代码块。然而，**控制流似乎从未跳转到 except 块**。那么程序是如何知道异常处理器的位置的呢？

![image](深入解析现代-Windows-结构化异常处理（SEH）（x64）/image.png)

接下来，我们将深入探究程序是如何追踪这些异常处理器的。

---

### 在 x64 中如何定位异常处理器？

在 PE 文件中，有多个目录用于存储映像信息。例如，如果映像包含导出函数，就会有一个导出目录来描述这些导出。

对于 x64 映像，存在一个**异常目录（Exception Directory）**，我们可以使用如 CFF Explorer 这类工具查看：

![image1](深入解析现代-Windows-结构化异常处理（SEH）（x64）/image1.png)

异常目录中包含多个 `RUNTIME_FUNCTION` 结构体，其定义如下：

```c
typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

```

我们可以简单理解为：

> 每个 RUNTIME_FUNCTION 条目通过 UnwindData 字段定义了一组指令，用于处理在 BeginAddress 和 EndAddress 之间发生的异常。

为了更深入地查看异常目录的内容，我们可以在 IDA 中使用快捷键 `g` 跳转到 `ExceptionDir`。在那里，我们可以立即看到 `main` 函数的条目！

![image2](深入解析现代-Windows-结构化异常处理（SEH）（x64）/image2.png)

我们可以看到 `RUNTIME_FUNCTION` 结构体的各个字段以及它如何与实际的 try-except 块对应：

```c
struct _RUNTIME_FUNCTION {
    ULONG BeginAddress = main;
    ULONG EndAddress = end;
    ULONG UnwindData = unwind_data;
};

```

我们还可以通过查看 `unwind_data` 指向的 `UNWIND_INFO` 结构体来了解异常是如何被处理的。

![image3](深入解析现代-Windows-结构化异常处理（SEH）（x64）/image3.png)

![image4](深入解析现代-Windows-结构化异常处理（SEH）（x64）/image4.png)

如你所见，unwind 数据确实包含一个指向异常处理器的指针，当异常发生时会调用它。然而，`UNWIND_INFO` 中的其他字段是做什么的呢？

---

### 在 NTDLL 中查看异常处理器的实现

到目前为止，我们已经简要介绍了 64 位程序中 SEH 异常的处理方式。然而，实际上背后发生的事情远不止这些。为了深入了解，我们需要查看异常处理的源代码。

> 我最初是通过在 IDA 中逆向分析 ntdll.dll 开始的 😅
>
>
> 不过为了大家的 sanity，我们将尽可能引用 ReactOS（一个开源的-Windows-实现）中的代码片段，只有在 ReactOS 不足以说明问题时才会回到 ntdll。

一旦异常被触发（无论是 VEH 还是 SEH），内核会捕获异常并将控制权传递给 `ntdll!KiUserExceptionDispatcher` 函数，该函数会找到合适的异常处理器来处理异常。

以下是从异常调度器出发的一些重要函数调用链：

```
KiUserExceptionDispatcher //-Windows-内核内部 API
  -> RtlDispatchException // 异常处理的主逻辑
    -> RtlpCallVectoredHandlers // 调用任何 VEH
    -> RtlLookupFunctionEntry // 在 ExceptionDirectory 中查找有效的 PRUNTIME_FUNCTION 条目
      -> RtlpLookupDynamicFunctionEntry // 如果没有找到有效的 PRUNTIME_FUNCTION，则运行动态回调
    -> RtlVirtualUnwind / RtlpxVirtualUnwind // 执行栈帧展开
    -> RtlpExecuteHandlerForException // 执行异常处理器！

```

我们将详细解释 `RtlLookupFunctionEntry` 和 `RtlpxVirtualUnwind`。

---

### ContextRecord

从 `KiUserExceptionDispatcher` 传递到 `RtlDispatchException` 的一个重要数据结构是 `CONTEXT` 结构体。

该结构体包含了异常发生时寄存器的状态信息。

```c
typedef struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    WORD    SegCs;
    WORD    SegDs;
    WORD    SegEs;
    WORD    SegFs;
    WORD    SegGs;
    WORD    SegSs;
    DWORD   EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union {
        XMM_SAVE_AREA32 FltSave;
        NEON128         Q[16];
        ULONGLONG       D[32];
        struct {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
        DWORD           S[32];
    } DUMMYUNIONNAME;
    M128A   VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

```

例如，`Context->Rip` 会保存导致异常的指令指针。

---

### RtlLookupFunctionEntry

该函数遍历异常目录中的 `RUNTIME_FUNCTION` 结构体，查找满足 `BeginAddress` < `Context->Rip` < `EndAddress` 的条目。

如果找不到有效条目，它会调用 `RtlpLookupDynamicFunctionEntry` 来查找动态函数条目。

---

### RtlpLookupDynamicFunctionEntry

之前我们提到，`RUNTIME_FUNCTION` 条目存储在编译时嵌入到可执行文件中的 `ExceptionDir` 中。

然而，为了支持动态生成或即时编译的代码，Windows 提供了两个 API 用于在运行时添加更多的 `RUNTIME_FUNCTION` 条目：

> 注意，这只有在可执行文件的 ExceptionDir 中找不到有效的 RUNTIME_FUNCTION 时才会被调用。

第一种方式是使用 `RtlInstallFunctionTableCallback`，它接受一个回调函数作为参数。

该回调函数将被调用，并期望返回一个 `RUNTIME_FUNCTION` 结构体。

```c
BOOLEAN RtlInstallFunctionTableCallback(
    DWORD64 TableIdentifier,          // 最低 3 位必须为 0x3
    DWORD64 BaseAddress,              // 代码的基地址
    DWORD Length,                     // 代码区域的长度
    PGET_RUNTIME_FUNCTION_CALLBACK Callback,  // 你的回调函数
    PVOID Context,                    // 可选的上下文参数
    PCWSTR OutOfProcessCallbackDll    // 通常为 NULL，表示进程内回调
);

```

第二种方式是使用 `RtlAddFunctionTable` 或 `RtlAddGrowableFunctionTable`。与前者不同，你需要提前提供 `RUNTIME_FUNCTION` 条目，这些条目会被添加到一个数组中，在异常发生时被查找。

```c
NTSTATUS RtlAddGrowableFunctionTable(
    PVOID *DynamicTable,              // 输出参数，接收表句柄
    PRUNTIME_FUNCTION FunctionTable,  // 初始的 RUNTIME_FUNCTION 条目数组
    DWORD EntryCount,                 // 当前条目数量
    DWORD MaximumEntryCount,          // 表可增长到的最大条目数
    ULONG_PTR RangeBase,              // 代码范围的基地址
    ULONG_PTR RangeEnd                // 代码范围的结束地址
);

```

酷！能够在运行时安装 `RUNTIME_FUNCTION` 条目（尤其是通过调用我们自己的函数）无疑会让逆向工程变得更加复杂 :)

---

### RtlVirtualUnwind

> 异常可能发生在极其复杂的函数中，此时栈和寄存器状态一片混乱。为了将执行权交还给异常处理器，我们必须恢复栈的状态。

**栈展开（Stack Unwinding）** 确保即使在异常发生时，程序也能通过**系统地回溯函数帧、执行清理处理器并恢复程序状态**来维持程序的完整性和资源管理。

前面我们简要提到了 `UnwindData` 和 `UNWIND_INFO`。`RUNTIME_FUNCTION` 中的 `UnwindData` 包含了指向 `UNWIND_INFO` 结构体的偏移。

```c
typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp:4;
        UBYTE OpInfo:4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UBYTE Version:3;
    UBYTE Flags:5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister:4;
    UBYTE FrameOffset:4;
    UNWIND_CODE UnwindCode[1];
    /*
    union {
        OPTIONAL ULONG ExceptionHandler;
        OPTIONAL ULONG FunctionEntry;
    };
    OPTIONAL ULONG ExceptionData[];
    */
} UNWIND_INFO, *PUNWIND_INFO;

```

简而言之，`UNWIND_INFO` 包含一个 `UNWIND_CODE` 数组，定义了一组指令，用于在将执行权交还给 `ExceptionHandler` 之前恢复栈和寄存器的状态。

Unwind 操作码的详细文档可以参考 [Microsoft 官方文档](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#unwind-codes)。

```powershell
    /* Process the remaining unwind ops */
    while (i < UnwindInfo->CountOfCodes)
    {
        UnwindCode = UnwindInfo->UnwindCode[i];
        switch (UnwindCode.UnwindOp)
        {
            case UWOP_PUSH_NONVOL:
                Reg = UnwindCode.OpInfo;
                PopReg(Context, ContextPointers, Reg);
                i++;
                break;

            case UWOP_ALLOC_LARGE:
                if (UnwindCode.OpInfo)
                {
                    Offset = *(ULONG*)(&UnwindInfo->UnwindCode[i+1]);
                    Context->Rsp += Offset;
                    i += 3;
                }
                else
                {
                    Offset = UnwindInfo->UnwindCode[i+1].FrameOffset;
                    Context->Rsp += Offset * 8;
                    i += 2;
                }
                break;

            case UWOP_ALLOC_SMALL:
                Context->Rsp += (UnwindCode.OpInfo + 1) * 8;
                i++;
                break;

            case UWOP_SET_FPREG:
                Reg = UnwindInfo->FrameRegister;
                Context->Rsp = GetReg(Context, Reg) - UnwindInfo->FrameOffset * 16;
                i++;
                break;

            case UWOP_SAVE_NONVOL:
                Reg = UnwindCode.OpInfo;
                Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
                SetRegFromStackValue(Context, ContextPointers, Reg, (DWORD64*)Context->Rsp + Offset);
                i += 2;
                break;

            case UWOP_SAVE_NONVOL_FAR:
                Reg = UnwindCode.OpInfo;
                Offset = *(ULONG*)(&UnwindInfo->UnwindCode[i + 1]);
                SetRegFromStackValue(Context, ContextPointers, Reg, (DWORD64*)Context->Rsp + Offset);
                i += 3;
                break;

            case UWOP_EPILOG:
                i += 1;
                break;

            case UWOP_SPARE_CODE:
                ASSERT(FALSE);
                i += 2;
                break;

            case UWOP_SAVE_XMM128:
                Reg = UnwindCode.OpInfo;
                Offset = UnwindInfo->UnwindCode[i + 1].FrameOffset;
                SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A*)Context->Rsp + Offset);
                i += 2;
                break;

            case UWOP_SAVE_XMM128_FAR:
                Reg = UnwindCode.OpInfo;
                Offset = *(ULONG*)(&UnwindInfo->UnwindCode[i + 1]);
                SetXmmRegFromStackValue(Context, ContextPointers, Reg, (M128A*)Context->Rsp + Offset);
                i += 3;
                break;

            case UWOP_PUSH_MACHFRAME:
                /* OpInfo is 1, when an error code was pushed, otherwise 0. */
                Context->Rsp += UnwindCode.OpInfo * sizeof(DWORD64);

                /* Now pop the MACHINE_FRAME (RIP/RSP only. And yes, "magic numbers", deal with it) */
                Context->Rip = *(PDWORD64)(Context->Rsp + 0x00);
                Context->Rsp = *(PDWORD64)(Context->Rsp + 0x18);
                ASSERT((i + 1) == UnwindInfo->CountOfCodes);
                goto Exit;
        }
    }

```

---

### 与 32 位 SEH 的对比

如你所见，64 位 SEH 处理器**几乎总是（默认情况下）**存储在编译时嵌入的只读异常目录中。

而 32 位 SEH 处理器则存储在运行时的栈上，形成一个异常处理器链表。每个使用 SEH 的函数都必须运行如下汇编代码来**安装**处理器：

```nasm
push    DWORD PTR fs:[0]      # 保存当前处理器
push    <exception_handler>    # 压入新处理器的地址
mov     DWORD PTR fs:[0], esp # 将 SEH 链指向新记录

```

当异常发生时，系统从最新到最旧遍历该链，直到找到一个处理器。每个函数在返回前必须解除其处理器的链接。

---

## SEH 与 VEH 的对比

尽管 SEH 和 VEH 的目标都是处理异常，但它们的实现方式差异巨大。

---

### 向量化异常处理（VEH）

关于 `VEH`，最重要的是它**在整个进程范围内监控异常**，并通过在运行时调用 `AddVectoredExceptionHandler` 函数来注册。

以下是一个使用 VEH 的示例程序：

```c
#include <windows.h>
#include <stdio.h>

LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // 检查是否为访问违规
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        printf("Access Violation Detected!\\n");
        printf("Violation Address: 0x%p\\n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
        printf("Memory Address: 0x%p\\n", (void*)pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
        // 返回 EXCEPTION_CONTINUE_SEARCH 让其他处理器处理
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
    // 安装我们的 VEH，第二个参数为 TRUE 表示将其添加到 VEH 链的前端
    PVOID handler = AddVectoredExceptionHandler(1, VectoredHandler);
    // 触发访问违规
    int* p = NULL;
    *p = 42;  // 这将导致访问违规
    // 由于崩溃，我们不会执行到这里
    RemoveVectoredExceptionHandler(handler);
    return 0;
}

```

当 `VEH` 处理器被注册时，它会被添加到异常链的末尾。

当异常发生时，系统从链表头部开始遍历，寻找合适的处理器。如果找不到，进程将被终止。

---

## 结语

本文并不全面，**绝对没有涵盖-Windows-异常处理的所有细节**。如有任何不准确之处，请联系我或者留言。

---

## 延伸阅读

以下是一些关于-Windows-异常处理内部机制及其在安全领域应用的优秀文章：

- [Using VEH for Defense Evasion Process Injection, Security Intelligence](https://www.microsoft.com/en-us/security/blog/2023/08/01/using-veh-for-defense-evasion-process-injection/)
- [Exception Oriented Programming: Abusing Exceptions for Code Execution, Bill Demirkapi](https://www.youtube.com/watch?v=J33J2L4VdMg)
- [A Journey through KiUserExceptionDispatcher, Maurice Heumann](https://mauriceheumann.com/posts/a-journey-through-kiuserexceptiondispatcher/)

---

## 参考链接

- [Microsoft Docs - Exception Handling (x64)](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [ReactOS GitHub - RtlVirtualUnwind](https://github.com/reactos/reactos/blob/master/reactos/lib/rtl/amd64/virtunwind.c)
- [CFF Explorer - NTCore](https://ntcore.com/?page_id=388)
- [IDA Pro - Hex-Rays](https://hex-rays.com/ida-pro/)