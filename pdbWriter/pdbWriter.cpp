// pdbWriter.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "pdb.h"
#include "cvinfo.h"

#include <iostream>
#include <fstream>
#include <string>
#include <locale>
#include <codecvt>

#include <filesystem>

#include "args.hxx"
#include "csv.h"

#define ARRAYCOUNT(x) (sizeof(x)/sizeof((x)[0]))

using namespace std;

template <typename CloseTraits>
class CloseObject
{
public:
    typedef typename CloseTraits::Type StoredType;

    CloseObject()
        : stored(CloseTraits::GetInvalidValue())
    {}

    CloseObject(StoredType value)
        : stored(value)
    {}

    CloseObject(const CloseObject&) = delete;
    CloseObject& operator=(const CloseObject&) = delete;

    ~CloseObject()
    { 
        if (stored != CloseTraits::GetInvalidValue())
        {
            CloseTraits::Close(stored);
        }
    }

    operator StoredType()
    {
        return stored;
    }

    StoredType Get()
    {
        return stored;
    }

protected:
    StoredType stored;
};

template <typename T>
struct InvokeCloseCloseTrait
{
    typedef T* Type;

    static constexpr T* GetInvalidValue() { return nullptr; }

    static void Close(T* object)
    {
        object->Close();
    }
};

template <HANDLE InvalidValue>
struct CloseHandleCloseTrait
{
    typedef HANDLE Type;

    static constexpr HANDLE GetInvalidValue() { return InvalidValue; }

    static void Close(HANDLE object)
    {
        CloseHandle(object);
    }
};

struct UnmapFileMappingCloseTrait
{
    typedef void* Type;

    static constexpr void* GetInvalidValue() { return nullptr; }

    static void Close(void* object)
    {
        UnmapViewOfFile(object);
    }
};

template <typename T>
class ClosePtr : public CloseObject<InvokeCloseCloseTrait<T>> 
{
public:
    typename T* operator->()
    {
        return stored;
    }

    typename T** operator &()
    {
        return &stored;
    }
};

typedef CloseObject<CloseHandleCloseTrait<INVALID_HANDLE_VALUE>> FileHandle;
typedef CloseObject<CloseHandleCloseTrait<nullptr>> FileMappingHandle;
typedef CloseObject<UnmapFileMappingCloseTrait> ViewOfFileHandle;

std::tuple<wstring, wstring> ParseArgs(int argc, char** argv)
{
    args::ArgumentParser parser("Dummy PDB Generator for EXEs based", "");
    args::HelpFlag help(parser, "help", "Display this help menu", { 'h', "help" });
    args::Positional<std::string> exePath(parser, "Executable Path", "Path for executable for PDB generation");
    args::Positional<std::string> symbolsPath(parser, "Symbols Path", "Path for a text file with symbols and addresses");

    try
    {
        parser.ParseCLI(argc, argv);

        if (!exePath)
        {
            throw args::Help("");
        }

        if (!symbolsPath)
        {
            throw args::Help("");
        }
    }
    catch (args::Help)
    {
        std::cout << parser;
        exit(0);
    }
    catch (args::ParseError e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        exit(1);
    }
    catch (args::ValidationError e)
    {
        std::cerr << e.what() << std::endl;
        std::cerr << parser;
        exit(1);
    }

    // convert the paths to a wstring
    wstring_convert<codecvt<wchar_t, char, mbstate_t>> converter;
    wstring wideExePath = converter.from_bytes(exePath.Get());
    wstring wideSymbolsPath = converter.from_bytes(symbolsPath.Get());

    return make_tuple(wideExePath, wideSymbolsPath);
}

struct SegmentData
{
    USHORT flags;
    DWORD size;
    DWORD baseAddress;
};

struct ExeMetadata
{
    wstring exeName;
    DWORD baseAddress;
    vector<SegmentData> segments;
};

ExeMetadata ReadExeMetadata(const wstring& exePath)
{
    ExeMetadata metadata;

    wchar_t filename[_MAX_FNAME];
    if (_wsplitpath_s(exePath.c_str(), nullptr, 0, nullptr, 0, filename, ARRAYCOUNT(filename), 0, 0) != EINVAL)
    {
        metadata.exeName += filename;
    }

    FileHandle file(CreateFile(exePath.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ, 
                               nullptr,                               
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, 
                               nullptr));

    if (file == INVALID_HANDLE_VALUE) 
    {
        throw new std::exception("unable to exe file");
    };

    FileMappingHandle fileMapping(CreateFileMapping(file,
                                                    nullptr,
                                                    PAGE_READONLY,
                                                    0,
                                                    0,
                                                    nullptr));

    ViewOfFileHandle exeMemory(MapViewOfFile(fileMapping,
                                             FILE_MAP_READ,
                                             0,
                                             0, 
                                             0));

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(exeMemory.Get());
    PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((DWORD)(dosHeader)+(dosHeader->e_lfanew));

    metadata.baseAddress = ntHeader->OptionalHeader.ImageBase;

    metadata.segments.reserve(ntHeader->FileHeader.NumberOfSections);

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
    {
        SegmentData data;
        data.flags = 0x108; // assuming for now that all segments in symbols are selectors 
        data.flags |= 0x8;  // and 32 - bit linear addresses, probably wrong but it's all I've observed so far

        if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)
        {
            data.flags |= 0x4;
        }
        if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)
        {
            data.flags |= 0x2;
        }
        if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ)
        {
            data.flags |= 0x1;
        }

        data.size = pSectionHeader->Misc.VirtualSize;
        data.baseAddress = metadata.baseAddress + pSectionHeader->VirtualAddress;

        metadata.segments.push_back(data);
    }

    return metadata;
}

void AddSymbol(const ExeMetadata& metadata, Mod* mod, const string& symbolName, DWORD symbolAddress, CV_pubsymflag_t flags)
{
    bool foundSymbol = false;
    int segmentId = 1;
    DWORD offset = 0;
    for (auto segment : metadata.segments)
    {
        offset = symbolAddress - segment.baseAddress;
        if (offset < segment.size)
        {
            foundSymbol = true;
            break;
        }
        segmentId++;
    }

    if (foundSymbol)
    {
        mod->AddPublic2(symbolName.c_str(), segmentId, offset, flags);
    }
    else
    {
        cerr << L"Unable to find segment for " << symbolName << L" with address " << symbolAddress << endl;
    }
}

int main(int argc, char** argv)
{
    wstring exePath;
    wstring symbolPath;

    std::tie(exePath, symbolPath) = ParseArgs(argc, argv);

    ExeMetadata metadata;
    try
    {
        metadata = ReadExeMetadata(exePath);
    }
    catch (std::exception e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    ifstream symbolsFile;
    symbolsFile.open(symbolPath);
    if ((symbolsFile.rdstate() & ifstream::failbit) != 0)
    {
        wcerr << L"Error opening symbols file" << endl;
        exit(1);
    }

    {
        EC errorCode;
        wchar_t buffer[1024];

        wstring pdbName = metadata.exeName + L".pdb";

        ClosePtr<PDB> pdb;
        PDBOpen2W(pdbName.c_str(), pdbWrite, &errorCode, buffer, ARRAYSIZE(buffer), &pdb);
        {
            ClosePtr<DBI> dbi;
            pdb->OpenDBI("", pdbWrite, &dbi);

            int segmentId = 1;
            for (auto segment : metadata.segments)
            {
                dbi->AddSec(segmentId, segment.flags, 0x0, segment.size);
                segmentId++;
            }

            ClosePtr<Mod> mod;
            dbi->OpenModW(L"__Globals", L"__Globals", &mod);


            csv<string, DWORD> symbols(symbolsFile, ',');

            for (auto row : symbols)
            {
                AddSymbol(metadata, mod, get<0>(row), get<1>(row), cvpsfFunction);
            }
        }

        pdb->Commit();
    }
    return 0;
}

