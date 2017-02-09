#include <windows.h>
#include <stdio.h>

int gtfo(const char* text = "")
{
    printf("gtfo! (%s)\n", text);
    return -1;
}

int main(int argc, char* argv[])
{
    //LEAKY AND UNSAFE!
    if(argc < 2)
        return gtfo("argc");

    //read the file
    auto hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if(hFile == INVALID_HANDLE_VALUE)
        return gtfo("CreateFile");

    //map the file
    auto hMappedFile = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr); //notice SEC_IMAGE
    if(!hMappedFile)
        return gtfo("CreateFileMappingA");

    //map the sections appropriately
    auto fileMap = MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
    if(!fileMap)
        return gtfo("MapViewOfFile");

    auto pidh = PIMAGE_DOS_HEADER(fileMap);
    if(pidh->e_magic != IMAGE_DOS_SIGNATURE)
        return gtfo("IMAGE_DOS_SIGNATURE");

    auto pnth = PIMAGE_NT_HEADERS(ULONG_PTR(fileMap) + pidh->e_lfanew);
    if(pnth->Signature != IMAGE_NT_SIGNATURE)
        return gtfo("IMAGE_NT_SIGNATURE");

#ifdef _WIN64
    if(pnth->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
#else
    if(pnth->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
#endif //_WIN64
        return gtfo("FileHeader.Machine");

    if(pnth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return gtfo("IMAGE_NT_OPTIONAL_HDR_MAGIC");

    auto importDir = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    puts("Import Directory");
    printf(" RVA: %08X\n", importDir.VirtualAddress);
    printf("Size: %08X\n\n", importDir.Size);

    if(!importDir.VirtualAddress || !importDir.Size)
        return gtfo("No Import directory!");

    auto importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ULONG_PTR(fileMap) + importDir.VirtualAddress);
    auto count = 0;
    if(!IsBadReadPtr((char*)fileMap + importDir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
    {
        for(; importDescriptor->FirstThunk; importDescriptor++)
        {
            printf("OriginalFirstThunk: %08X\n", importDescriptor->OriginalFirstThunk);
            printf("     TimeDateStamp: %08X\n", importDescriptor->TimeDateStamp);
            printf("    ForwarderChain: %08X\n", importDescriptor->ForwarderChain);
            if(!IsBadReadPtr((char*)fileMap + importDescriptor->Name, 2))
                printf("              Name: %08X \"%s\"\n", importDescriptor->Name, (char*)fileMap + importDescriptor->Name);
            else
                printf("              Name: %08X INVALID\n", importDescriptor->Name);
            printf("        FirstThunk: %08X\n", importDescriptor->FirstThunk);

            auto thunkData = PIMAGE_THUNK_DATA(ULONG_PTR(fileMap) + importDescriptor->FirstThunk);
            for(; thunkData->u1.AddressOfData; thunkData++, count++)
            {
                auto rva = ULONG_PTR(thunkData) - ULONG_PTR(fileMap);

                auto data = thunkData->u1.AddressOfData;
                if(data & IMAGE_ORDINAL_FLAG)
                    printf("              Ordinal: %p\n", data & ~IMAGE_ORDINAL_FLAG);
                else
                {
                    auto importByName = PIMAGE_IMPORT_BY_NAME(ULONG_PTR(fileMap) + data);
                    if(!IsBadReadPtr(importByName, 2))
                        printf("             Function: %p \"%s\"\n", data, (char*)importByName->Name);
                    else
                        printf("             Function: %p INVALID\n", data);
                }
            }

            puts("");
        }
    }
    else
        puts("INVALID IMPORT DESCRIPTOR");

    printf("%d imports parsed!\n", count);

    return 0;
}