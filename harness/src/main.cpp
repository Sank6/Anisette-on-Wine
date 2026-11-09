#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <iphlpapi.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using CFTypeRef = const void*;
using CFStringRef = const void*;
using CFDictionaryRef = const void*;
using CFIndex = long long;

using CFStringCreateWithCString = CFStringRef(__cdecl*)(
    const void*, const char*, unsigned int
);
using CFDictionaryGetValue = const void*(__cdecl*)(CFDictionaryRef, const void*);
using CFStringGetCString = unsigned char(__cdecl*)(
    CFStringRef, char*, CFIndex, unsigned int
);
using CFStringGetLength = CFIndex(__cdecl*)(CFStringRef);
using CFStringGetMaximumSizeForEncoding = CFIndex(__cdecl*)(CFIndex, unsigned int);
using CFRelease = void(__cdecl*)(CFTypeRef);
using CopyOtpHeaders = CFDictionaryRef(__cdecl*)(CFStringRef);

constexpr unsigned int kCFStringEncodingUTF8 = 0x08000100;

CFStringCreateWithCString cf_string_create = nullptr;
CFDictionaryGetValue cf_dictionary_get_value = nullptr;
CFStringGetCString cf_string_get_c_string = nullptr;
CFStringGetLength cf_string_get_length = nullptr;
CFStringGetMaximumSizeForEncoding cf_string_get_maximum_size = nullptr;
CFRelease cf_release = nullptr;

template <typename Result>
Result load_export(HMODULE module, const char* name) {
    static_assert(sizeof(Result) == sizeof(FARPROC));
    FARPROC address = GetProcAddress(module, name);
    Result result{};
    std::memcpy(&result, &address, sizeof(result));
    return result;
}

std::wstring join_path(const std::wstring& directory, const std::wstring& name) {
    if (directory.empty()) {
        return name;
    }
    if (directory.back() == L'\\' || directory.back() == L'/') {
        return directory + name;
    }
    return directory + L"\\" + name;
}

std::wstring environment_value(const wchar_t* name) {
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) {
        return {};
    }
    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0 || written >= required) {
        return {};
    }
    value.resize(written);
    return value;
}

std::wstring registry_string(const wchar_t* path, REGSAM access, const wchar_t* name) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, access, &key) != ERROR_SUCCESS) {
        return {};
    }
    DWORD type = 0;
    DWORD bytes = 0;
    LONG status = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(wchar_t)) {
        RegCloseKey(key);
        return {};
    }
    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    status = RegQueryValueExW(
        key,
        name,
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(value.data()),
        &bytes
    );
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        return {};
    }
    while (!value.empty() && value.back() == L'\0') {
        value.pop_back();
    }
    if (type == REG_EXPAND_SZ) {
        const DWORD expanded_size = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
        if (expanded_size > 0) {
            std::wstring expanded(expanded_size, L'\0');
            if (ExpandEnvironmentStringsW(value.c_str(), expanded.data(), expanded_size) > 0) {
                while (!expanded.empty() && expanded.back() == L'\0') {
                    expanded.pop_back();
                }
                value = std::move(expanded);
            }
        }
    }
    return value;
}

std::wstring registry_install_directory() {
    constexpr wchar_t path[] = L"SOFTWARE\\Apple Inc.\\Apple Application Support";
    std::wstring value = registry_string(path, KEY_READ | KEY_WOW64_32KEY, L"InstallDir");
    if (!value.empty()) {
        return value;
    }
    // Keep the classic installer lookup as a compatibility fallback for
    // users who point a current helper at an extracted Apple directory.
    constexpr wchar_t redirected_path[] =
        L"SOFTWARE\\WOW6432Node\\Apple Inc.\\Apple Application Support";
    return registry_string(redirected_path, KEY_READ, L"InstallDir");
}

bool regular_file(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring apple_support_directory() {
    std::wstring directory = environment_value(L"ANISETTE_ON_WINE_APPLE_SUPPORT");
    if (!directory.empty()) {
        return directory;
    }
    directory = registry_install_directory();
    if (!directory.empty() && regular_file(join_path(directory, L"CoreFoundation.dll"))) {
        return directory;
    }
    std::wstring common = environment_value(L"CommonProgramFiles(x86)");
    if (common.empty()) {
        common = environment_value(L"CommonProgramFiles");
    }
    return join_path(join_path(common, L"Apple"), L"Apple Application Support");
}

std::wstring internet_services_directory(const std::wstring& support) {
    std::wstring directory = environment_value(L"ANISETTE_ON_WINE_INTERNET_SERVICES");
    if (!directory.empty()) {
        return directory;
    }
    const std::size_t slash = support.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        return join_path(support.substr(0, slash), L"Internet Services");
    }
    std::wstring common = environment_value(L"CommonProgramFiles");
    return join_path(join_path(common, L"Apple"), L"Internet Services");
}

std::string json_escape(const char* value) {
    std::string escaped;
    if (value == nullptr) {
        return escaped;
    }
    for (const unsigned char character : std::string(value)) {
        switch (character) {
            case '\\': escaped += "\\\\"; break;
            case '"': escaped += "\\\""; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (character < 0x20) {
                    constexpr char hex[] = "0123456789abcdef";
                    escaped += "\\u00";
                    escaped += hex[(character >> 4) & 0x0f];
                    escaped += hex[character & 0x0f];
                } else {
                    escaped += static_cast<char>(character);
                }
        }
    }
    return escaped;
}

std::string utf8_string(CFStringRef string) {
    if (string == nullptr || cf_string_get_length == nullptr ||
        cf_string_get_maximum_size == nullptr || cf_string_get_c_string == nullptr) {
        return {};
    }
    const CFIndex length = cf_string_get_length(string);
    const CFIndex capacity = cf_string_get_maximum_size(length, kCFStringEncodingUTF8) + 1;
    if (capacity <= 1 || capacity > 1024 * 1024) return {};
    std::string output(static_cast<std::size_t>(capacity), '\0');
    if (!cf_string_get_c_string(string, output.data(), capacity, kCFStringEncodingUTF8)) {
        return {};
    }
    output.resize(std::char_traits<char>::length(output.c_str()));
    return output;
}

CFStringRef make_string(const char* value) {
    return cf_string_create == nullptr
        ? nullptr
        : cf_string_create(nullptr, value, kCFStringEncodingUTF8);
}

CFStringRef exported_string(HMODULE module, const char* name) {
    auto** address = load_export<const void**>(module, name);
    return address == nullptr ? nullptr : *address;
}

CFStringRef dictionary_value(CFDictionaryRef dictionary, CFStringRef key) {
    if (dictionary == nullptr || key == nullptr || cf_dictionary_get_value == nullptr) {
        return nullptr;
    }
    return static_cast<CFStringRef>(cf_dictionary_get_value(dictionary, key));
}

std::vector<unsigned char> registry_bytes(
    HKEY root,
    const char* path,
    REGSAM access,
    const char* name
) {
    HKEY key = nullptr;
    if (RegOpenKeyExA(root, path, 0, access, &key) != ERROR_SUCCESS) {
        return {};
    }
    DWORD type = 0;
    DWORD bytes = 0;
    LONG status = RegQueryValueExA(key, name, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || bytes == 0) {
        RegCloseKey(key);
        return {};
    }
    std::vector<unsigned char> value(bytes);
    status = RegQueryValueExA(key, name, nullptr, &type, value.data(), &bytes);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        return {};
    }
    value.resize(bytes);
    while (!value.empty() && value.back() == 0) {
        value.pop_back();
    }
    return value;
}

std::vector<unsigned char> wide_bytes(const std::wstring& value) {
    const auto* first = reinterpret_cast<const unsigned char*>(value.data());
    return {first, first + value.size() * sizeof(wchar_t)};
}

std::array<unsigned char, 16> md5(const unsigned char* data, std::size_t size) {
    std::array<unsigned char, 16> digest{};
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_MD5, 0, 0, &hash) ||
        !CryptHashData(hash, data, static_cast<DWORD>(size), 0)) {
        if (hash != 0) CryptDestroyHash(hash);
        if (provider != 0) CryptReleaseContext(provider, 0);
        return digest;
    }
    DWORD digest_size = static_cast<DWORD>(digest.size());
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &digest_size, 0) ||
        digest_size != digest.size()) {
        digest.fill(0);
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    return digest;
}

std::array<unsigned char, 16> md5(const std::vector<unsigned char>& value) {
    static const unsigned char empty = 0;
    return md5(value.empty() ? &empty : value.data(), value.size());
}

std::string digest_prefix(const std::vector<unsigned char>& value, bool upper) {
    const auto digest = md5(value);
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    if (upper) output << std::uppercase;
    for (std::size_t index = 0; index < 4; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }
    return output.str();
}

std::string hex_bytes(const unsigned char* value, std::size_t size, bool upper) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    if (upper) output << std::uppercase;
    for (std::size_t index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(value[index]);
    }
    return output.str();
}

struct MachineIdentity {
    std::string device_id;
    std::string legacy_device_id;
    std::string local_user;
};

std::string read_state(const char* name);

bool identity_component(const std::string& value, std::size_t size, bool dots) {
    if (value.size() != size) return false;
    return std::all_of(value.begin(), value.end(), [dots](unsigned char character) {
        return std::isxdigit(character) != 0 || (dots && character == '.');
    });
}

MachineIdentity machine_identity() {
    const MachineIdentity persisted = {
        read_state("DeviceId"),
        read_state("LegacyDeviceId"),
        read_state("LocalUser"),
    };
    if (identity_component(persisted.device_id, 62, true) &&
        identity_component(persisted.legacy_device_id, 40, false) &&
        identity_component(persisted.local_user, 16, false)) {
        return persisted;
    }
    std::vector<unsigned char> mac;
    ULONG bytes = 0;
    GetAdaptersInfo(nullptr, &bytes);
    if (bytes > 0 && bytes <= 1024 * 1024) {
        std::vector<unsigned char> buffer(bytes);
        auto* addresses = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
        if (GetAdaptersInfo(addresses, &bytes) == NO_ERROR) {
            for (auto* address = addresses; address != nullptr; address = address->Next) {
                if (address->AddressLength > 0) {
                    mac.assign(
                        address->Address,
                        address->Address + address->AddressLength
                    );
                    break;
                }
            }
        }
    }

    DWORD volume_serial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0);
    std::vector<unsigned char> volume(sizeof(volume_serial));
    std::copy_n(
        reinterpret_cast<const unsigned char*>(&volume_serial),
        sizeof(volume_serial),
        volume.begin()
    );

    const auto product = registry_bytes(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        KEY_READ,
        "ProductId"
    );
    const auto cpu = registry_bytes(
        HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        KEY_READ,
        "ProcessorNameString"
    );
    const auto bios = registry_bytes(
        HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System",
        KEY_READ,
        "SystemBiosVersion"
    );

    DWORD computer_name_size = MAX_COMPUTERNAME_LENGTH + 1;
    std::wstring computer_name(computer_name_size, L'\0');
    if (GetComputerNameW(computer_name.data(), &computer_name_size)) {
        computer_name.resize(computer_name_size);
    } else {
        computer_name.clear();
    }
    HW_PROFILE_INFOW profile{};
    std::wstring profile_guid;
    if (GetCurrentHwProfileW(&profile)) {
        profile_guid = profile.szHwProfileGuid;
    }

    const std::array<std::vector<unsigned char>, 7> modern_inputs = {
        mac,
        volume,
        product,
        cpu,
        bios,
        wide_bytes(computer_name),
        wide_bytes(profile_guid),
    };
    std::string modern;
    for (const auto& input : modern_inputs) {
        if (!modern.empty()) modern += '.';
        modern += digest_prefix(input, true);
    }

    auto ascii_as_wide = [](const std::vector<unsigned char>& value) {
        std::wstring converted;
        converted.reserve(value.size());
        for (const unsigned char character : value) {
            converted.push_back(static_cast<wchar_t>(character));
        }
        return wide_bytes(converted);
    };
    std::string legacy = digest_prefix(mac, false) + digest_prefix(volume, false) +
        digest_prefix(ascii_as_wide(bios), false) + digest_prefix(ascii_as_wide(cpu), false) +
        digest_prefix(product, false);
    const auto local_digest = md5(
        reinterpret_cast<const unsigned char*>(modern.data()),
        modern.size()
    );
    return {modern, legacy, hex_bytes(local_digest.data(), 8, true)};
}

std::string base64_encode(const unsigned char* value, DWORD size) {
    DWORD required = 0;
    if (!CryptBinaryToStringA(
            value,
            size,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
            &required
        ) || required == 0) {
        return {};
    }
    std::string output(required, '\0');
    if (!CryptBinaryToStringA(
            value,
            size,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            output.data(),
            &required
        )) {
        return {};
    }
    output.resize(required);
    while (!output.empty() && output.back() == '\0') output.pop_back();
    return output;
}

std::vector<unsigned char> base64_decode(const std::string& value) {
    DWORD required = 0;
    if (!CryptStringToBinaryA(
            value.data(),
            static_cast<DWORD>(value.size()),
            CRYPT_STRING_BASE64,
            nullptr,
            &required,
            nullptr,
            nullptr
        ) || required == 0 || required > 1024 * 1024) {
        return {};
    }
    std::vector<unsigned char> output(required);
    if (!CryptStringToBinaryA(
            value.data(),
            static_cast<DWORD>(value.size()),
            CRYPT_STRING_BASE64,
            output.data(),
            &required,
            nullptr,
            nullptr
        )) {
        return {};
    }
    output.resize(required);
    return output;
}

std::wstring widen_ascii(const std::string& value) {
    return {value.begin(), value.end()};
}

std::string client_time() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    char output[32]{};
    std::snprintf(
        output,
        sizeof(output),
        "%04u-%02u-%02uT%02u:%02u:%02uZ",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond
    );
    return output;
}

bool http_post(
    const wchar_t* path,
    const std::string& body,
    const MachineIdentity& identity,
    std::string& response
) {
    HINTERNET session = WinHttpOpen(
        L"com.apple.AuthKitWin/7.3",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (session == nullptr) return false;
    WinHttpSetTimeouts(session, 15000, 15000, 15000, 30000);
    HINTERNET connection = WinHttpConnect(session, L"gsa.apple.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET request = connection == nullptr
        ? nullptr
        : WinHttpOpenRequest(
              connection,
              L"POST",
              path,
              nullptr,
              WINHTTP_NO_REFERER,
              WINHTTP_DEFAULT_ACCEPT_TYPES,
              WINHTTP_FLAG_SECURE
          );
    bool ok = request != nullptr;
    if (ok) {
        const std::wstring headers =
            L"Content-Type: text/xml\r\n"
            L"X-Apple-Client-App-Name: Setup\r\n"
            L"X-Mme-Client-Info: <PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/7.3 (com.apple.iCloud/15.10.0.39)>\r\n"
            L"X-Mme-Device-Id: " + widen_ascii(identity.device_id) + L"\r\n" +
            L"X-Mme-Legacy-Device-Id: " + widen_ascii(identity.legacy_device_id) + L"\r\n" +
            L"X-Apple-I-MD-LU: " + widen_ascii(identity.local_user) + L"\r\n" +
            L"X-Apple-I-Client-Time: " + widen_ascii(client_time()) + L"\r\n";
        ok = WinHttpSendRequest(
                 request,
                 headers.c_str(),
                 static_cast<DWORD>(headers.size()),
                 const_cast<char*>(body.data()),
                 static_cast<DWORD>(body.size()),
                 static_cast<DWORD>(body.size()),
                 0
             ) && WinHttpReceiveResponse(request, nullptr);
    }
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (ok) {
        ok = WinHttpQueryHeaders(
                 request,
                 WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                 WINHTTP_HEADER_NAME_BY_INDEX,
                 &status,
                 &status_size,
                 WINHTTP_NO_HEADER_INDEX
             ) && status == 200;
    }
    response.clear();
    while (ok) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available)) {
            ok = false;
            break;
        }
        if (available == 0) break;
        if (available > 1024 * 1024 || response.size() + available > 1024 * 1024) {
            ok = false;
            break;
        }
        const std::size_t offset = response.size();
        response.resize(offset + available);
        DWORD read = 0;
        if (!WinHttpReadData(request, response.data() + offset, available, &read)) {
            ok = false;
            break;
        }
        response.resize(offset + read);
    }
    if (request != nullptr) WinHttpCloseHandle(request);
    if (connection != nullptr) WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return ok && !response.empty();
}

std::string xml_unescape(std::string value) {
    const std::array<std::pair<const char*, const char*>, 5> entities = {{
        {"&amp;", "&"},
        {"&lt;", "<"},
        {"&gt;", ">"},
        {"&quot;", "\""},
        {"&apos;", "'"},
    }};
    for (const auto& entity : entities) {
        std::size_t offset = 0;
        while ((offset = value.find(entity.first, offset)) != std::string::npos) {
            value.replace(offset, std::strlen(entity.first), entity.second);
            offset += std::strlen(entity.second);
        }
    }
    return value;
}

std::string plist_value(const std::string& plist, const std::string& key) {
    const std::string marker = "<key>" + key + "</key>";
    std::size_t offset = plist.find(marker);
    if (offset == std::string::npos) return {};
    offset += marker.size();
    const std::array<std::pair<const char*, const char*>, 2> tags = {{
        {"<string>", "</string>"},
        {"<integer>", "</integer>"},
    }};
    for (const auto& tag : tags) {
        const std::size_t start = plist.find(tag.first, offset);
        if (start == std::string::npos) continue;
        const std::size_t value_start = start + std::strlen(tag.first);
        const std::size_t end = plist.find(tag.second, value_start);
        if (end != std::string::npos) {
            return xml_unescape(plist.substr(value_start, end - value_start));
        }
    }
    return {};
}

bool write_state(const char* name, const std::string& value) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    if (RegCreateKeyExA(
            HKEY_CURRENT_USER,
            "Software\\WindowsAnisette",
            0,
            nullptr,
            0,
            KEY_SET_VALUE,
            nullptr,
            &key,
            &disposition
        ) != ERROR_SUCCESS) {
        return false;
    }
    const LONG status = RegSetValueExA(
        key,
        name,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>(value.size() + 1)
    );
    RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

std::string read_state(const char* name) {
    const auto value = registry_bytes(
        HKEY_CURRENT_USER,
        "Software\\WindowsAnisette",
        KEY_READ,
        name
    );
    return {value.begin(), value.end()};
}

bool import_root_certificate(const std::wstring& path) {
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return false;
    const DWORD size = GetFileSize(file, nullptr);
    std::vector<unsigned char> encoded(size);
    DWORD read = 0;
    const bool loaded = size > 0 && size <= 1024 * 1024 &&
        ReadFile(file, encoded.data(), size, &read, nullptr) && read == size;
    CloseHandle(file);
    if (!loaded) return false;
    PCCERT_CONTEXT certificate = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        encoded.data(),
        size
    );
    if (certificate == nullptr) return false;
    HCERTSTORE store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"ROOT"
    );
    const bool imported = store != nullptr && CertAddCertificateContextToStore(
        store,
        certificate,
        CERT_STORE_ADD_REPLACE_EXISTING,
        nullptr
    );
    if (store != nullptr) CertCloseStore(store, 0);
    CertFreeCertificateContext(certificate);
    return imported;
}

void unload(HMODULE aoskit, HMODULE core_foundation) {
    if (aoskit != nullptr) FreeLibrary(aoskit);
    if (core_foundation != nullptr) FreeLibrary(core_foundation);
}

int fail(const char* message, int code) {
    std::cerr << "anisette-helper: " << message << '\n';
    return code;
}

std::wstring utf8_to_wide(const char* value) {
    if (value == nullptr) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, nullptr, 0);
    if (required <= 0) return {};
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, output.data(), required) <= 0) {
        return {};
    }
    while (!output.empty() && output.back() == L'\0') output.pop_back();
    return output;
}

bool byte_signature(
    std::uintptr_t base,
    std::uintptr_t offset,
    const std::initializer_list<unsigned char>& expected
) {
    const auto* actual = reinterpret_cast<const unsigned char*>(base + offset);
    return std::equal(expected.begin(), expected.end(), actual);
}

bool known_aoskit_build(HMODULE aoskit) {
    if (aoskit == nullptr || sizeof(void*) != 8) return false;
    const auto base = reinterpret_cast<std::uintptr_t>(aoskit);
    const auto register_client = reinterpret_cast<std::uintptr_t>(
        GetProcAddress(aoskit, "AOSRegisterClientInfo")
    );
    return register_client == base + 0x16d10 &&
        exported_string(aoskit, "kAOSMDOneTimePasswordHeaderName") != nullptr &&
        exported_string(aoskit, "kAOSMDMachineIdHeaderName") != nullptr &&
        byte_signature(base, 0x28400, {0x40, 0x55, 0x57, 0x41, 0x54, 0x41, 0x57}) &&
        byte_signature(base, 0x1080, {0x41, 0x57, 0x41, 0x56, 0x56, 0x57, 0x53}) &&
        byte_signature(base, 0x5a70, {0x56, 0xb8, 0x50, 0x10}) &&
        byte_signature(base, 0x7910, {0x56, 0xb8, 0x50, 0x10}) &&
        byte_signature(base, 0x5830, {0x56, 0x57, 0x53});
}

CopyOtpHeaders copy_otp_function(HMODULE aoskit) {
    const auto base = reinterpret_cast<std::uintptr_t>(aoskit);
    return reinterpret_cast<CopyOtpHeaders>(base + 0x28400);
}

int provision_machine(HMODULE aoskit) {
    if (!known_aoskit_build(aoskit)) {
        return fail("unsupported AOSKit build; expected iCloud 15.10.39", 30);
    }
    const MachineIdentity identity = machine_identity();
    const std::string start_body =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><dict><key>Header</key><dict/>"
        "<key>Request</key><dict/></dict></plist>";
    std::string start_response;
    if (!http_post(
            L"/grandslam/MidService/startMachineProvisioning",
            start_body,
            identity,
            start_response
        )) {
        return fail("Apple machine provisioning start request failed", 31);
    }
    const std::vector<unsigned char> spim = base64_decode(plist_value(start_response, "spim"));
    if (spim.empty()) {
        return fail("Apple machine provisioning start response was invalid", 32);
    }

    using ProvisionStart = int(__cdecl*)(
        std::uint64_t,
        const unsigned char*,
        unsigned int,
        unsigned char**,
        unsigned int*,
        unsigned int*
    );
    using ProvisionEnd = int(__cdecl*)(
        unsigned int,
        const unsigned char*,
        unsigned int,
        const unsigned char*,
        unsigned int
    );
    using ProvisionDestroy = int(__cdecl*)(unsigned int);
    using Dispose = int(__cdecl*)(void*);
    const auto base = reinterpret_cast<std::uintptr_t>(aoskit);
    const auto start = reinterpret_cast<ProvisionStart>(base + 0x1080);
    const auto finish = reinterpret_cast<ProvisionEnd>(base + 0x5a70);
    const auto destroy = reinterpret_cast<ProvisionDestroy>(base + 0x7910);
    const auto dispose = reinterpret_cast<Dispose>(base + 0x5830);

    // Trigger AOSKit's normal CoreADI initialization before entering the
    // guarded provisioning wrappers. An unprovisioned result is expected.
    CFStringRef dsid = make_string("-2");
    if (dsid == nullptr) {
        return fail("could not create the CoreADI environment identifier", 33);
    }
    CFDictionaryRef initial_headers = copy_otp_function(aoskit)(dsid);
    if (initial_headers != nullptr) cf_release(initial_headers);

    unsigned char* cpim_pointer = nullptr;
    unsigned int cpim_size = 0;
    unsigned int session = 0;
    const int start_status = start(
        static_cast<std::uint64_t>(-2LL),
        spim.data(),
        static_cast<unsigned int>(spim.size()),
        &cpim_pointer,
        &cpim_size,
        &session
    );
    if (start_status != 0 || cpim_pointer == nullptr || cpim_size == 0 || cpim_size > 1024 * 1024 ||
        session == 0) {
        if (cpim_pointer != nullptr) dispose(cpim_pointer);
        if (session != 0) destroy(session);
        cf_release(dsid);
        return fail("CoreADI rejected the machine provisioning start payload", 33);
    }
    const std::string cpim = base64_encode(cpim_pointer, cpim_size);
    dispose(cpim_pointer);
    if (cpim.empty()) {
        destroy(session);
        cf_release(dsid);
        return fail("CoreADI returned invalid provisioning metadata", 34);
    }

    const std::string finish_body =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><dict><key>Header</key><dict/>"
        "<key>Request</key><dict><key>cpim</key><string>" + cpim +
        "</string></dict></dict></plist>";
    std::string finish_response;
    if (!http_post(
            L"/grandslam/MidService/finishMachineProvisioning",
            finish_body,
            identity,
            finish_response
        )) {
        destroy(session);
        cf_release(dsid);
        return fail("Apple machine provisioning finish request failed", 35);
    }
    const std::vector<unsigned char> ptm = base64_decode(plist_value(finish_response, "ptm"));
    const std::vector<unsigned char> trust_key = base64_decode(plist_value(finish_response, "tk"));
    const std::string routing = plist_value(finish_response, "X-Apple-I-MD-RINFO");
    if (ptm.empty() || trust_key.empty() || routing.empty() ||
        !std::all_of(routing.begin(), routing.end(), [](unsigned char character) {
            return std::isdigit(character) != 0;
        })) {
        destroy(session);
        cf_release(dsid);
        return fail("Apple machine provisioning finish response was invalid", 36);
    }
    const int finish_status = finish(
        session,
        ptm.data(),
        static_cast<unsigned int>(ptm.size()),
        trust_key.data(),
        static_cast<unsigned int>(trust_key.size())
    );
    destroy(session);
    if (finish_status != 0) {
        cf_release(dsid);
        return fail("CoreADI rejected the machine provisioning finish payload", 37);
    }
    if (!write_state("DeviceId", identity.device_id) ||
        !write_state("LegacyDeviceId", identity.legacy_device_id) ||
        !write_state("LocalUser", identity.local_user) || !write_state("RoutingInfo", routing)) {
        cf_release(dsid);
        return fail("could not persist machine identity metadata", 38);
    }

    CFDictionaryRef headers = copy_otp_function(aoskit)(dsid);
    const std::string otp = utf8_string(dictionary_value(
        headers,
        exported_string(aoskit, "kAOSMDOneTimePasswordHeaderName")
    ));
    const std::string machine = utf8_string(dictionary_value(
        headers,
        exported_string(aoskit, "kAOSMDMachineIdHeaderName")
    ));
    if (headers != nullptr) cf_release(headers);
    if (dsid != nullptr) cf_release(dsid);
    if (otp.empty() || machine.empty()) {
        return fail("CoreADI was provisioned but OTP verification failed", 39);
    }
    std::cout << "{\"ok\":true,\"provisioned\":true}\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    const bool install_root = argc == 3 && std::string(argv[1]) == "--install-root";
    if (install_root) {
        const std::wstring certificate_path = utf8_to_wide(argv[2]);
        if (certificate_path.empty() || !import_root_certificate(certificate_path)) {
            return fail("could not import the Apple root certificate", 3);
        }
        std::cout << "{\"ok\":true,\"certificate_installed\":true}\n";
        return 0;
    }
    const bool probe_only = argc == 2 && std::string(argv[1]) == "--probe";
    const bool inspect_only = argc == 2 && std::string(argv[1]) == "--inspect";
    const bool provision = argc == 2 && std::string(argv[1]) == "--provision";
    const bool output_json = argc == 1 || (argc == 2 && std::string(argv[1]) == "--json");
    if (!probe_only && !inspect_only && !provision && !output_json) {
        return fail(
            "usage: anisette-helper [--json|--probe|--inspect|--provision|--install-root FILE]",
            2
        );
    }

    const std::wstring support = apple_support_directory();
    const std::wstring internet_services = internet_services_directory(support);
    const std::wstring core_foundation_path = join_path(support, L"CoreFoundation.dll");
    const std::wstring aoskit_path = join_path(internet_services, L"AOSKit.dll");
    if (!regular_file(core_foundation_path) || !regular_file(aoskit_path)) {
        return fail("required iCloud 15 DLLs were not found", 10);
    }

    SetCurrentDirectoryW(support.c_str());
    SetDllDirectoryW(support.c_str());
    HMODULE core_foundation = LoadLibraryW(core_foundation_path.c_str());
    if (core_foundation == nullptr) {
        return fail("could not load CoreFoundation.dll", 11);
    }
    cf_string_create = load_export<CFStringCreateWithCString>(
        core_foundation, "CFStringCreateWithCString"
    );
    cf_dictionary_get_value = load_export<CFDictionaryGetValue>(
        core_foundation, "CFDictionaryGetValue"
    );
    cf_string_get_c_string = load_export<CFStringGetCString>(
        core_foundation, "CFStringGetCString"
    );
    cf_string_get_length = load_export<CFStringGetLength>(core_foundation, "CFStringGetLength");
    cf_string_get_maximum_size = load_export<CFStringGetMaximumSizeForEncoding>(
        core_foundation, "CFStringGetMaximumSizeForEncoding"
    );
    cf_release = load_export<CFRelease>(core_foundation, "CFRelease");
    if (cf_string_create == nullptr || cf_dictionary_get_value == nullptr ||
        cf_string_get_c_string == nullptr || cf_string_get_length == nullptr ||
        cf_string_get_maximum_size == nullptr || cf_release == nullptr) {
        unload(nullptr, core_foundation);
        return fail("CoreFoundation exports are missing", 12);
    }

    HMODULE aoskit = LoadLibraryW(aoskit_path.c_str());
    if (aoskit == nullptr) {
        unload(nullptr, core_foundation);
        return fail("could not load AOSKit.dll", 14);
    }
    if (!known_aoskit_build(aoskit)) {
        unload(aoskit, core_foundation);
        return fail("unsupported AOSKit build; expected iCloud 15.10.39", 15);
    }
    if (provision) {
        const int status = provision_machine(aoskit);
        unload(aoskit, core_foundation);
        return status;
    }
    if (probe_only) {
        std::cout << "{\"ok\":true,\"backend\":\"windows-aoskit-15.10-x64\"}\n";
        unload(aoskit, core_foundation);
        return 0;
    }

    CFStringRef dsid = make_string("-2");
    CFDictionaryRef headers = dsid == nullptr ? nullptr : copy_otp_function(aoskit)(dsid);
    if (headers == nullptr) {
        if (dsid != nullptr) cf_release(dsid);
        unload(aoskit, core_foundation);
        return fail("AOSKit did not return OTP headers", 20);
    }
    const std::string otp_text = utf8_string(dictionary_value(
        headers,
        exported_string(aoskit, "kAOSMDOneTimePasswordHeaderName")
    ));
    const std::string machine_text = utf8_string(dictionary_value(
        headers,
        exported_string(aoskit, "kAOSMDMachineIdHeaderName")
    ));
    const MachineIdentity identity = machine_identity();
    const std::string persisted_routing = read_state("RoutingInfo");
    const std::string& udid_text = identity.device_id;
    const std::string& local_user_text = identity.local_user;
    const std::string& routing_text = persisted_routing;
    if (inspect_only) {
        std::cout
            << "{\"ok\":true,\"otp\":" << (!otp_text.empty() ? "true" : "false")
            << ",\"machine\":" << (!machine_text.empty() ? "true" : "false")
            << ",\"device_id\":" << (!udid_text.empty() ? "true" : "false")
            << ",\"local_user\":" << (!local_user_text.empty() ? "true" : "false")
            << ",\"routing_info\":" << (!routing_text.empty() ? "true" : "false")
            << "}\n";
        cf_release(headers);
        cf_release(dsid);
        unload(aoskit, core_foundation);
        return 0;
    }
    if (otp_text.empty() || machine_text.empty()) {
        cf_release(headers);
        cf_release(dsid);
        unload(aoskit, core_foundation);
        return fail("AOSKit returned incomplete anisette data", 21);
    }

    std::cout
        << "{\"X-Apple-I-MD\":\"" << json_escape(otp_text.c_str())
        << "\",\"X-Apple-I-MD-M\":\"" << json_escape(machine_text.c_str())
        << "\",\"machine_udid\":\"" << json_escape(udid_text.c_str())
        << "\",\"local_user\":\"" << json_escape(local_user_text.c_str())
        << "\",\"routing_info\":\"" << json_escape(routing_text.c_str())
        << "\",\"serial_number\":\""
        << "\"}\n";

    cf_release(headers);
    cf_release(dsid);
    unload(aoskit, core_foundation);
    return 0;
}
