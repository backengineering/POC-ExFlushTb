#include <fltKernel.h>
#include <ntimage.h>

#define YOUR_APP_NAME "dwm.exe"

#define dprintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

EXTERN_C
PCCHAR
NTAPI
PsGetProcessImageFileName(IN PEPROCESS Process);

EXTERN_C
PVOID
PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

using fnMiObtainReferencedVadEx = void *(NTAPI *)(void *a1, char a2, int *a3);

__declspec(naked) PVOID GetNtosBase()
{
    _asm {
        mov     rax, qword ptr gs:[18h]
        mov     rcx, [rax+38h]
        mov     rax, 0FFFFFFFFFFFFF000h
        and     rax, [rcx+4h]
        jmp      while_begin
        search_begin:
        add     rax, 0FFFFFFFFFFFFF000h
        while_begin: 
        xor     ecx, ecx
        jmp     search_cmp
        search_next: 
        add     rcx, 1
        cmp     rcx, 0FF9h
        jz      search_begin
        search_cmp:  
        cmp     byte ptr[rax+rcx], 48h
        jnz     search_next
        cmp     byte ptr[rax+rcx+1], 8Dh
        jnz     search_next
        cmp     byte ptr[rax+rcx+2], 1Dh
        jnz     search_next
        cmp     byte ptr[rax+rcx+6], 0FFh
        jnz     search_next
        mov     r8d,[rax+rcx+3]
        lea     edx,[rcx+r8]
        add     edx, eax
        add     edx, 7
        test    edx, 0FFFh
        jnz     search_next
        mov     rdx, 0FFFFFFFF00000000h
        and     rdx, rax
        add     r8d, eax
        lea     eax,[rcx+r8]
        add     eax, 7
        or      rax, rdx
        ret
    }
}

static PUCHAR
FindPattern(PVOID Module, ULONG Size, LPCSTR Pattern, LPCSTR Mask)
{
    auto checkMask = [](PUCHAR Buffer, LPCSTR Pattern, LPCSTR Mask) -> bool {
        for (auto x = Buffer; *Mask; Pattern++, Mask++, x++)
        {
            auto addr = *(UCHAR *)(Pattern);
            if (addr != *x && *Mask != '?')
                return false;
        }

        return true;
    };

    for (auto x = 0; x < Size - strlen(Mask); x++)
    {
        auto addr = (PUCHAR)Module + x;
        if (checkMask(addr, Pattern, Mask))
            return addr;
    }

    return nullptr;
}

static PEPROCESS
FindDWMEprocess(ULONG &OutPid)
{
    OutPid = 0;
    PEPROCESS pEpDWM = nullptr;
    for (ULONG i = 0; i < 0x5000; i += 4)
    {
        PEPROCESS pEp = nullptr;
        auto lStatus = PsLookupProcessByProcessId((HANDLE)i, &pEp);
        if (!NT_SUCCESS(lStatus) || !pEp)
        {
            continue;
        }

        auto pName = PsGetProcessImageFileName(pEp);
        // A more casual code
        if (pName && strstr(pName, YOUR_APP_NAME))
        {
            pEpDWM = pEp;
        }
        ObDereferenceObject(pEp);

        if (pEpDWM)
        {
            OutPid = i;
            break;
        }
    }

    return pEpDWM;
}

PVOID
IdontKnow(PVOID SvmData, unsigned int Number, PVOID *VA);

decltype(&IdontKnow) gOriPtr = nullptr;

PVOID gHalIommuDispatch = nullptr;

PULONG gExTbFlushActive = nullptr;

bool
IsUserAddress(void *Address)
{
    return (SIZE_T)(Address) < ((SIZE_T)(1) << (8 * sizeof(SIZE_T) - 1));
}

PVOID
IdontKnow(PVOID SvmData, unsigned int Number, PVOID *VA)
{
    PCHAR name = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (name && IsUserAddress(*VA))
    {
        dprintf("IdontKnow: name=%s,va=%p,number=%d\n", name, *VA, Number);
    }
    // return gOriPtr(SvmData, Number, VA);
    return nullptr;
}

void
DriverUnLoad(_In_ struct _DRIVER_OBJECT *DriverObject)
{
    if (gExTbFlushActive)
    {
        *(PULONG)gExTbFlushActive = 0;
    }

    if (gHalIommuDispatch && gOriPtr)
    {
        _asm {
        push rax
        push rbx
        mov rax, [gHalIommuDispatch]
        mov rax, [rax]
        mov rbx, gOriPtr
        mov [rax+0x48], rbx
        pop rbx
        pop rax
        }
    }

    dprintf("free world\n");
}

EXTERN_C
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    DriverObject->DriverUnload = DriverUnLoad;

    dprintf("new world!\n");

    PVOID pNtosBase = GetNtosBase();
    dprintf("pNtosBase=%p\n", pNtosBase);

    UNICODE_STRING usAPI1;
    RtlInitUnicodeString(&usAPI1, L"ExShareAddressSpaceWithDevice");
    PVOID pExShareAddressSpaceWithDevice = MmGetSystemRoutineAddress(&usAPI1);
    if (!pExShareAddressSpaceWithDevice)
    {
        dprintf("Error: Not found ExShareAddressSpaceWithDevice!\n");
        return -1;
    }
    dprintf("pExShareAddressSpaceWithDevice=%p\n", pExShareAddressSpaceWithDevice);

    // 48 83 EC 28 65 48 8B 04 25 88 01 00 00 44 8B C9 48 8B 88 B8 00 00 00 41 83 F8 01 74 14 48 8B 05
    PUCHAR pExFlushTb = (PUCHAR)(fnMiObtainReferencedVadEx)FindPattern(
        ((PUCHAR)pExShareAddressSpaceWithDevice - 0x500),
        0x2000,
        "\x48\x83\xEC\x28\x65\x48\x8B\x04\x25\x88\x01\x00\x00\x44\x8B\xC9\x48\x8B\x88\xB8\x00\x00\x00\x41\x83\xF8\x01\x74\x14\x48\x8B\x05",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    if (!pExFlushTb)
    {
        dprintf("Error: Not found ExFlushTb!\n");
        return -1;
    }
    dprintf("pExFlushTb=%p\n", pExFlushTb);

    UNICODE_STRING usAPI2;
    RtlInitUnicodeString(&usAPI2, L"KeFlushEntireTb");
    PVOID pKeFlushEntireTb = MmGetSystemRoutineAddress(&usAPI2);
    dprintf("pKeFlushEntireTb=%p\n", pKeFlushEntireTb);

    // B9 02 00 00 00 E8 ?? ?? ?? ?? 83 3D
    PUCHAR pExTbFlushActive1 = (PUCHAR)(fnMiObtainReferencedVadEx)FindPattern(
        ((PUCHAR)pKeFlushEntireTb), 0x1000, "\xB9\x02\x00\x00\x00\xE8\x00\x00\x00\x00\x83\x3D", "xxxxxx????xx");
    if (!pExTbFlushActive1)
    {
        dprintf("Error: Not found ExTbFlushActive1!\n");
        return -1;
    }
    dprintf("ExTbFlushActive1=%p\n", pExTbFlushActive1);
    PUCHAR pExTbFlushActive = pExTbFlushActive1 + 10 + *(PLONG)(pExTbFlushActive1 + 12) + 7;
    dprintf("pExTbFlushActive=%p\n", pExTbFlushActive);
    gExTbFlushActive = (PULONG)pExTbFlushActive;

    PUCHAR pHalIommuDispatch = pExFlushTb + 29 + *(PLONG)(pExFlushTb + 32) + 7;
    gHalIommuDispatch = pHalIommuDispatch;
    dprintf("pHalIommuDispatch=%p\n", pHalIommuDispatch);
    _asm {
        push rax
        push rbx
        mov rax, [pHalIommuDispatch]
        mov rax, [rax]
        mov gOriPtr, rax
        lea rbx, IdontKnow
        mov [rax+0x48], rbx
        pop rbx
        pop rax
    }
    dprintf("gOriPtr=%p\n", gOriPtr);

    ULONG uDWMPID;
    PEPROCESS pEpDWM = FindDWMEprocess(uDWMPID);
    dprintf("pEpDWM=%p, uDWMPID=%d!\n", pEpDWM, uDWMPID);
    if (uDWMPID == 0)
    {
        dprintf("Error: Not found DWM!\n");
        return -2;
    }

    PVOID TempSvmData = ExAllocatePool(NonPagedPool, 0x1000);

    // Tcb.ApcState.Process->SvmData
    *(PVOID *)((PUCHAR)pEpDWM + 0x888) = TempSvmData;

    *(PULONG)pExTbFlushActive = 1;

    return 0;
}
