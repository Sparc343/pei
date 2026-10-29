
#include <windows.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

static bool in_bounds(size_t size, uint64_t offset,
                      uint64_t length) {
    return offset <= size && length <= size - offset;
}

static void print_hex(uint64_t value) {
    std::cout << "0x" << std::uppercase << std::hex
              << value << std::dec;
}

static std::string hex_string(uint64_t value) {
    std::string result;
    const char digits[] = "0123456789ABCDEF";

    result = "0x";

    bool started = false;

    for (int shift = 60; shift >= 0; shift -= 4) {
        unsigned digit =
            static_cast<unsigned>((value >> shift) & 0xF);

        if (digit != 0 || started || shift == 0) {
            result += digits[digit];
            started = true;
        }
    }

    return result;
}

static std::string difference_string(uint64_t va,
                                     uint64_t raw) {
    if (va >= raw) {
        return hex_string(va - raw);
    }

    return "-" + hex_string(raw - va);
}

int main(int argc, char* argv[]) {
    // ---------------------------------------------------------
    // 1. Display help when no filename is provided.
    // ---------------------------------------------------------

    if (argc != 2) {
        std::cout
            << "\n"
            << "PE Section Inspector\n"
            << "====================\n"
            << "\n"
            << "Examines PE executable headers and section mappings.\n"
            << "\n"
            << "Usage:\n"
            << "  " << argv[0] << " <file.exe>\n"
            << "\n"
            << "Example:\n"
            << "  " << argv[0] << " \"<file.exe>\"\n"
            << "\n"
            << "Supported formats: PE32 (x86) and PE32+ (x64)\n"
            << "\n";

        return 1;
    }

    // Use the supplied filename throughout the entire report.
    const char* filename = argv[1];

    std::ifstream file(filename,
                       std::ios::binary | std::ios::ate);

    if (!file) {
        std::cerr << "ERROR: Cannot open file: "
                  << filename << '\n';
        return 1;
    }

    const std::streamoff end = file.tellg();

    if (end < 0) {
        std::cerr << "ERROR: Cannot determine file size.\n";
        return 1;
    }

    const uint64_t file_size = static_cast<uint64_t>(end);

    if (file_size > std::numeric_limits<size_t>::max()) {
        std::cerr << "ERROR: File is too large for this program.\n";
        return 1;
    }

    std::vector<uint8_t> data(static_cast<size_t>(file_size));

    file.seekg(0, std::ios::beg);

    if (!data.empty() &&
        !file.read(reinterpret_cast<char*>(data.data()),
                   static_cast<std::streamsize>(data.size()))) {
        std::cerr << "ERROR: Failed to read file.\n";
        return 1;
    }

    // ---------------------------------------------------------
    // 2. Read and validate the DOS header.
    // ---------------------------------------------------------

    if (!in_bounds(data.size(), 0, sizeof(IMAGE_DOS_HEADER))) {
        std::cerr << "ERROR: File is too small for a DOS header.\n";
        return 1;
    }

    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, data.data(), sizeof(dos));

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "ERROR: Not a valid MZ/PE executable.\n";
        return 1;
    }

    if (dos.e_lfanew < 0) {
        std::cerr << "ERROR: Invalid PE header offset.\n";
        return 1;
    }

    const uint64_t nt = static_cast<uint32_t>(dos.e_lfanew);

    // ---------------------------------------------------------
    // 3. Read and validate the PE and COFF headers.
    // ---------------------------------------------------------

    if (!in_bounds(data.size(), nt,
                   sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) {
        std::cerr << "ERROR: PE header is outside the file.\n";
        return 1;
    }

    DWORD signature = 0;

    std::memcpy(&signature, data.data() + nt,
                sizeof(signature));

    if (signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "ERROR: PE signature not found.\n";
        return 1;
    }

    IMAGE_FILE_HEADER fh{};

    std::memcpy(&fh,
                data.data() + nt + sizeof(DWORD),
                sizeof(fh));

    const uint64_t opt =
        nt + sizeof(DWORD) + sizeof(fh);

    if (!in_bounds(data.size(), opt,
                   fh.SizeOfOptionalHeader) ||
        fh.SizeOfOptionalHeader < sizeof(WORD)) {
        std::cerr << "ERROR: Invalid Optional Header size.\n";
        return 1;
    }

    WORD magic = 0;

    std::memcpy(&magic, data.data() + opt, sizeof(magic));

    uint64_t image_base = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    std::string architecture;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (fh.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER32)) {
            std::cerr << "ERROR: Truncated PE32 Optional Header.\n";
            return 1;
        }

        IMAGE_OPTIONAL_HEADER32 oh{};

        std::memcpy(&oh, data.data() + opt, sizeof(oh));

        image_base = oh.ImageBase;
        section_alignment = oh.SectionAlignment;
        file_alignment = oh.FileAlignment;
        architecture = "x86 (PE32)";
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (fh.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64)) {
            std::cerr << "ERROR: Truncated PE32+ Optional Header.\n";
            return 1;
        }

        IMAGE_OPTIONAL_HEADER64 oh{};

        std::memcpy(&oh, data.data() + opt, sizeof(oh));

        image_base = oh.ImageBase;
        section_alignment = oh.SectionAlignment;
        file_alignment = oh.FileAlignment;
        architecture = "x64 (PE32+)";
    }
    else {
        std::cerr << "ERROR: Unknown PE Optional Header format.\n";
        return 1;
    }

    // ---------------------------------------------------------
    // 4. Locate and validate the section table.
    // ---------------------------------------------------------

    const uint64_t table =
        opt + static_cast<uint64_t>(fh.SizeOfOptionalHeader);

    const uint64_t table_size =
        static_cast<uint64_t>(fh.NumberOfSections) *
        sizeof(IMAGE_SECTION_HEADER);

    if (!in_bounds(data.size(), table, table_size)) {
        std::cerr << "ERROR: Section table extends beyond the file.\n";
        return 1;
    }

    std::vector<IMAGE_SECTION_HEADER> sections;
    sections.reserve(fh.NumberOfSections);

    for (unsigned i = 0; i < fh.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};

        const uint64_t pos =
            table + static_cast<uint64_t>(i) *
                    sizeof(IMAGE_SECTION_HEADER);

        std::memcpy(&sh, data.data() + pos, sizeof(sh));
        sections.push_back(sh);
    }

    // ---------------------------------------------------------
    // 5. Print the file and PE header information.
    // ---------------------------------------------------------

    std::cout << "Architecture: " << architecture << '\n';
    std::cout << "File: " << filename << '\n';

    std::cout << "File size: " << std::dec << file_size
              << " bytes (";
    print_hex(file_size);
    std::cout << ")\n";

    std::cout << "Image Base: ";
    print_hex(image_base);

    std::cout << "\nSection Alignment: ";
    print_hex(section_alignment);

    std::cout << "\nFile Alignment: ";
    print_hex(file_alignment);

    std::cout << "\nNumber of Sections: "
              << std::dec << fh.NumberOfSections
              << "\n\n";

    // ---------------------------------------------------------
    // 6. Print the detailed section-by-section report.
    // ---------------------------------------------------------

    std::cout << "SECTION DETAILS\n";
    std::cout << "===============\n";

    for (size_t i = 0; i < sections.size(); ++i) {
        const IMAGE_SECTION_HEADER& sh = sections[i];

        char name[9]{};
        std::memcpy(name, sh.Name, 8);

        const uint64_t va = sh.VirtualAddress;
        const uint64_t raw = sh.PointerToRawData;
        const uint64_t virtual_size = sh.Misc.VirtualSize;
        const uint64_t raw_size = sh.SizeOfRawData;

        const int64_t delta =
            static_cast<int64_t>(va) -
            static_cast<int64_t>(raw);

        std::cout << "\n[" << i + 1 << "] " << name << '\n';

        std::cout << "  VirtualAddress (RVA): ";
        print_hex(va);
        std::cout << '\n';

        std::cout << "  PointerToRawData:     ";
        print_hex(raw);
        std::cout << '\n';

        std::cout << "  VirtualSize:          ";
        print_hex(virtual_size);
        std::cout << '\n';

        std::cout << "  SizeOfRawData:        ";
        print_hex(raw_size);
        std::cout << '\n';

        std::cout << "  Difference calculation:\n    ";
        print_hex(va);
        std::cout << " - ";
        print_hex(raw);
        std::cout << " = ";

        if (delta < 0) {
            std::cout << "-";
            print_hex(static_cast<uint64_t>(-delta));
        }
        else {
            print_hex(static_cast<uint64_t>(delta));
        }

        std::cout << '\n';

        std::cout << "  File offset adjustment: ";

        if (delta > 0) {
            std::cout << "subtract ";
            print_hex(static_cast<uint64_t>(delta));
        }
        else if (delta < 0) {
            std::cout << "add ";
            print_hex(static_cast<uint64_t>(-delta));
        }
        else {
            std::cout << "no adjustment (0)";
        }

        std::cout << '\n';

        // Check whether the section's raw bytes fit in the file.
        if (raw_size == 0) {
            std::cout << "  File mapping: no raw data\n";
        }
        else if (raw == 0) {
            std::cout << "  File mapping: raw pointer is zero\n";
        }
        else if (in_bounds(data.size(), raw, raw_size)) {
            std::cout << "  File mapping: raw data fits in file\n";
        }
        else {
            std::cout << "  File mapping: WARNING - raw data "
                         "extends beyond file\n";
        }

        if (virtual_size > raw_size) {
            std::cout << "  Note: virtual size exceeds raw size; "
                         "the excess may have no file bytes.\n";
        }
    }

    // ---------------------------------------------------------
    // 7. Print the compact section table.
    // ---------------------------------------------------------

    std::cout << "\nDone.\n";

    std::cout << "PE Section Table\n";
    std::cout << "================\n";

    std::cout << "File: " << filename << '\n';

    std::cout << "File size: " << std::dec << file_size
              << " bytes (";
    print_hex(file_size);
    std::cout << ")\n";

    std::cout << "Architecture: "
              << (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                      ? "x64"
                      : "x86")
              << '\n';

    std::cout << "Image Base: ";
    print_hex(image_base);

    std::cout << "\nSection Alignment: ";
    print_hex(section_alignment);

    std::cout << "\nFile Alignment: ";
    print_hex(file_alignment);

    std::cout << "\nNumber of Sections: "
              << std::dec << fh.NumberOfSections << "\n\n";

    // 80-character table width: five characters narrower
    // than the original 85-character table.
    constexpr int w_section = 12;
    constexpr int w_va = 21;
    constexpr int w_raw = 22;
    constexpr int w_diff = 20;

    auto print_border = []() {
        std::cout << '+'
                  << std::string(w_section, '-') << '+'
                  << std::string(w_va, '-') << '+'
                  << std::string(w_raw, '-') << '+'
                  << std::string(w_diff, '-') << "+\n";
    };

    print_border();

    std::cout << '|'
              << std::left << std::setw(w_section) << "Section" << '|'
              << std::left << std::setw(w_va)
              << "VirtualAddress (RVA)" << '|'
              << std::left << std::setw(w_raw)
              << "PointerToRawData" << '|'
              << std::left << std::setw(w_diff)
              << "Difference" << "|\n";

    print_border();

    for (const IMAGE_SECTION_HEADER& sh : sections) {
        char name[9]{};
        std::memcpy(name, sh.Name, 8);

        std::cout << '|'
                  << std::left << std::setw(w_section) << name << '|'
                  << std::left << std::setw(w_va)
                  << hex_string(sh.VirtualAddress) << '|'
                  << std::left << std::setw(w_raw)
                  << hex_string(sh.PointerToRawData) << '|'
                  << std::left << std::setw(w_diff)
                  << difference_string(
                         sh.VirtualAddress,
                         sh.PointerToRawData)
                  << "|\n";
    }

    print_border();

    std::cout << "\n";
    std::cout << "Difference = VirtualAddress - PointerToRawData\n";
    std::cout << "For a section RVA, file offset = RVA - Difference,\n";
    std::cout << "provided the RVA maps to bytes present in the file.\n";

    return 0;
}
