#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <windows.h>

const std::unordered_set<std::string> vulnerable_imports = { "MmMapIoSpace", "ZwMapViewOfSection", "MmCopyMemory", "MmMapIoSpaceEx" };
const std::unordered_set<std::string> device_driver_imports = { "IoCreateDevice" };
const std::unordered_set<std::string> irp_handler_imports = { "IofCompleteRequest" };

std::unordered_map<std::string, std::unordered_set<std::string>> get_file_imports(std::string file_path)
{
    std::unordered_map<std::string, std::unordered_set<std::string>> result = {};

    HANDLE handle = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return result;

    auto map_object = CreateFileMapping(handle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map_object)
        return result;

    auto base_pointer = MapViewOfFile(map_object, FILE_MAP_READ, 0, 0, 0);
    if (!base_pointer)
        return result;

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base_pointer);
    if (!dos_header)
        return result;

    auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>((DWORD64)base_pointer + dos_header->e_lfanew);
    auto file_header = &nt_header->FileHeader;
    auto optional_header = &nt_header->OptionalHeader;

    // Get the first section header and number of imports
    auto section_header = IMAGE_FIRST_SECTION(nt_header);
    auto number_of_sections = file_header->NumberOfSections;

    // Get the relative virtual address of the import directory
    auto rva_import_directory = optional_header->DataDirectory[1].VirtualAddress;

    // Find the section that contains the import directory
    PIMAGE_SECTION_HEADER import_section = nullptr;
    for (int i = 1; i <= number_of_sections; i++, section_header++)
    {
        if (rva_import_directory >= section_header->VirtualAddress && rva_import_directory < section_header->VirtualAddress + section_header->Misc.VirtualSize)
            import_section = section_header;
    }
    if (!import_section)
        return result;

    // Calculate the offset of the import table and get the first import descriptor
    auto import_table_offset = (DWORD64)base_pointer + import_section->PointerToRawData;
    auto import_image_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(import_table_offset + (optional_header->DataDirectory[1].VirtualAddress - import_section->VirtualAddress));

    // Loop through all import descriptors
    for (; import_image_descriptor->Name != 0; import_image_descriptor++)
    {
        // Get the name of the imported DLL
        auto imported_dll = import_table_offset + (import_image_descriptor->Name - import_section->VirtualAddress);
        std::string imported_file(reinterpret_cast<const char*>(imported_dll));

        result[imported_file] = {};

        // Get the OriginalFirstThunk and FirstThunk arrays
        auto original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(import_table_offset + (import_image_descriptor->OriginalFirstThunk - import_section->VirtualAddress));
        auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(import_table_offset + (import_image_descriptor->FirstThunk - import_section->VirtualAddress));

        // Loop through the arrays and print the imported functions
        while (original_first_thunk && original_first_thunk->u1.AddressOfData != 0)
        {
            if (!(original_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                // Get the name of the imported function
                auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(import_table_offset + original_first_thunk->u1.AddressOfData - import_section->VirtualAddress);
                result[imported_file].insert(import_by_name->Name);
            }
            original_first_thunk++;
            first_thunk++;
        }
    }

    return result;
}

bool has_required_imports(const std::unordered_set<std::string>& import_set, const std::unordered_set<std::string>& required_imports)
{
    return std::any_of(import_set.begin(), import_set.end(), [&](const auto& imp) {
        return required_imports.count(imp) > 0;
        });
}

void process_driver(const std::filesystem::path& driver_path)
{
    std::cout << "Scanning driver: " << driver_path.filename() << std::endl;
    auto imports = get_file_imports(driver_path.string());

    if (!imports.contains("ntoskrnl.exe"))
        return;

    bool handles_irps = has_required_imports(imports.at("ntoskrnl.exe"), irp_handler_imports);
    bool device_driver = has_required_imports(imports.at("ntoskrnl.exe"), device_driver_imports);

    std::vector<std::string> import_list{};
    std::copy_if(imports.at("ntoskrnl.exe").begin(), imports.at("ntoskrnl.exe").end(), std::back_inserter(import_list), [&](const auto& imp) {
        return vulnerable_imports.count(imp) > 0;
        });

    if (!import_list.empty())
    {
        if (handles_irps)
            std::cout << " - Handles IRPs\n";
        if (device_driver)
            std::cout << " - Device driver\n";
        std::cout << " - Vulnerable imported functions:\n";
        for (const auto& imp : import_list)
        {
            std::cout << "   + " << imp << "\n";
        }
    }
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " [directory]" << std::endl;
        return 1;
    }

    std::filesystem::path dir_path(argv[1]);
    if (!std::filesystem::exists(dir_path))
    {
        std::cerr << "Error: directory does not exist" << std::endl;
        return 1;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir_path))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".sys")
        {
            process_driver(entry.path());
        }
    }

    return 0;
}