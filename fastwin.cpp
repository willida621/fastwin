#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <wininet.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "wininet.lib")

struct ActivationData {
    std::string activationId;
    std::string genericKey;
    int skuId;
    std::string partNumber;
    bool isWorking;
    std::string keyType;
    std::string editionId;
};

class HWIDActivation {
private:
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    int winBuild = 0;
    int osSKU = 0;
    std::string osEdition;
    std::string activationKey;
    
    std::vector<ActivationData> activationDatabase = {
        {"8b351c9c-f398-4515-9900-09df49427262", "XGVPP-NMH47-7TTHJ-W3FW7-8HV2C", 4, "X19-99683", true, "OEM:NONSLP", "Enterprise"},
        {"c83cef07-6b72-4bbc-a28f-a00386872839", "3V6Q6-NQXCX-V8YXR-9QCYV-QPFCT", 27, "X19-98746", true, "Volume:MAK", "EnterpriseN"},
        {"4de7cb65-cdf1-4de9-8ae8-e3cce27b9f2c", "VK7JG-NPHTM-C97JM-9MPGT-3V66T", 48, "X19-98841", true, "Retail", "Professional"},
        {"9fbaf5d6-4d83-4422-870d-fdda6e5858aa", "2B87N-8KFHP-DKV6R-Y2C8J-PKCKT", 49, "X19-98859", true, "Retail", "ProfessionalN"},
        {"f742e4ff-909d-4fe9-aacb-3231d24a0c58", "4CPRK-NM3K3-X6XXQ-RXX86-WXCHW", 98, "X19-98877", true, "Retail", "CoreN"},
        {"1d1bac85-7365-4fea-949a-96978ec91ae0", "N2434-X9D7W-8PF6X-8DV9T-8TYMD", 99, "X19-99652", true, "Retail", "CoreCountrySpecific"},
        {"3ae2cc14-ab2d-41f4-972f-5e20142771dc", "BT79Q-G7N6G-PGBYW-4YWX6-6F4BT", 100, "X19-99661", true, "Retail", "CoreSingleLanguage"},
        {"2b1f36bb-c1cd-4306-bf5c-a0367c2d97d8", "YTMG3-N6DKC-DKB77-7M9GH-8HVX7", 101, "X19-98868", true, "Retail", "Core"},
        {"2a6137f3-75c0-4f26-8e3e-d83d802865a4", "XKCNC-J26Q9-KFHD2-FKTHY-KD72Y", 119, "X19-99606", true, "OEM:NONSLP", "PPIPro"},
        {"e558417a-5123-4f6f-91e7-385c1c7ca9d4", "YNMGQ-8RYV3-4PGQ3-C8XTP-7CFBY", 121, "X19-98886", true, "Retail", "Education"},
        {"c5198a66-e435-4432-89cf-ec777c9d0352", "84NGF-MHBT6-FXBX8-QWJK7-DRR8H", 122, "X19-98892", true, "Retail", "EducationN"},
        {"f6e29426-a256-4316-88bf-cc5b0f95ec0c", "PJB47-8PN2T-MCGDY-JTY3D-CBCPV", 125, "X23-50331", true, "Volume:MAK", "EnterpriseS_Ge"},
        {"cce9d2de-98ee-4ce2-8113-222620c64a27", "KCNVH-YKWX8-GJJB9-H9FDT-6F7W2", 125, "X22-66075", true, "Volume:MAK", "EnterpriseS_VB"},
        {"d06934ee-5448-4fd1-964a-cd077618aa06", "43TBQ-NH92J-XKTM7-KT3KK-P39PB", 125, "X21-83233", true, "OEM:NONSLP", "EnterpriseS_RS5"},
        {"706e0cfd-23f4-43bb-a9af-1a492b9f1302", "NK96Y-D9CD8-W44CQ-R8YTK-DYJWX", 125, "X21-05035", true, "OEM:NONSLP", "EnterpriseS_RS1"},
        {"faa57748-75c8-40a2-b851-71ce92aa8b45", "FWN7H-PF93Q-4GGP8-M8RF3-MDWWW", 125, "X19-99617", true, "OEM:NONSLP", "EnterpriseS_TH"},
        {"3d1022d8-969f-4222-b54b-327f5a5af4c9", "2DBW3-N2PJG-MVHW3-G7TDK-9HKR4", 126, "X21-04921", true, "Volume:MAK", "EnterpriseSN_RS1"},
        {"60c243e1-f90b-4a1b-ba89-387294948fb6", "NTX6B-BRYC2-K6786-F6MVQ-M7V2X", 126, "X19-98770", true, "Volume:MAK", "EnterpriseSN_TH"},
        {"01eb852c-424d-4060-94b8-c10d799d7364", "3XP6D-CRND4-DRYM2-GM84D-4GG8Y", 139, "X23-37869", true, "Retail", "ProfessionalCountrySpecific_Zn"},
        {"eb6d346f-1c60-4643-b960-40ec31596c45", "DXG7C-N36C4-C4HTG-X4T3X-2YV77", 161, "X21-43626", true, "Retail", "ProfessionalWorkstation"},
        {"89e87510-ba92-45f6-8329-3afa905e3e83", "WYPNQ-8C467-V2W6J-TX4WX-WT2RQ", 162, "X21-43644", true, "Retail", "ProfessionalWorkstationN"},
        {"62f0c100-9c53-4e02-b886-a3528ddfe7f6", "8PTT6-RNW4C-6V7J2-C2D3X-MHBPB", 164, "X21-04955", true, "Retail", "ProfessionalEducation"},
        {"13a38698-4a49-4b9e-8e83-98fe51110953", "GJTYN-HDMQY-FRR76-HVGC7-QPF8P", 165, "X21-04956", true, "Retail", "ProfessionalEducationN"},
        {"df96023b-dcd9-4be2-afa0-c6c871159ebe", "NJCF7-PW8QT-3324D-688JX-2YV66", 175, "X21-41295", true, "Retail", "ServerRdsh"},
        {"d4ef7282-3d2c-4cf0-9976-8854e64a8d1e", "V3WVW-N2PV2-CGWC3-34QGF-VMJ2C", 178, "X21-32983", true, "Retail", "Cloud"},
        {"af5c9381-9240-417d-8d35-eb40cd03e484", "NH9J3-68WK7-6FB93-4K3DF-DJ4F6", 179, "X21-32987", true, "Retail", "CloudN"},
        {"8ab9bdd1-1f67-4997-82d9-8878520837d9", "XQQYW-NFFMW-XJPBH-K8732-CKFFD", 188, "X21-99378", true, "OEM:DM", "IoTEnterprise"},
        {"ed655016-a9e8-4434-95d9-4345352c2552", "QPM6N-7J2WJ-P88HH-P3YRH-YY74H", 191, "X21-99682", true, "OEM:NONSLP", "IoTEnterpriseS_VB"},
        {"6c4de1b8-24bb-4c17-9a77-7b939414c298", "CGK42-GYN6Y-VD22B-BX98W-J8JXD", 191, "X23-12617", true, "OEM:NONSLP", "IoTEnterpriseS_Ge"},
        {"d4bdc678-0a4b-4a32-a5b3-aaa24c3b0f24", "K9VKN-3BGWV-Y624W-MCRMQ-BHDCD", 202, "X22-53884", true, "Retail", "CloudEditionN"},
        {"92fb8726-92a8-4ffc-94ce-f82e07444653", "KY7PN-VR6RX-83W6Y-6DDYQ-T6R4W", 203, "X22-53847", true, "Retail", "CloudEdition"},
        {"5a85300a-bfce-474f-ac07-a30983e3fb90", "N979K-XWD77-YW3GB-HBGH6-D32MH", 205, "X23-15042", true, "OEM:DM", "IoTEnterpriseSK"},
        {"80083eae-7031-4394-9e88-4901973d56fe", "P8Q7T-WNK7X-PMFXY-VXHBG-RRK69", 206, "X23-62084", true, "OEM:DM", "IoTEnterpriseK"},
        {"1bc2140b-285b-4351-b99c-26a126104b29", "TMP2N-KGFHJ-PWM6F-68KCQ-3PJBP", 210, "X23-60513", true, "Retail", "WNC"}
    };

    bool InitializeWMI() {
        HRESULT hres;
        
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
            return false;
        }

        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);

        if (FAILED(hres)) {
            std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
            CoUninitialize();
            return false;
        }

        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

        if (FAILED(hres)) {
            std::cerr << "Could not connect to WMI. Error code = 0x" << std::hex << hres << std::endl;
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

        if (FAILED(hres)) {
            std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        return true;
    }

    void Cleanup() {
        if (pSvc) pSvc->Release();
        if (pLoc) pLoc->Release();
        CoUninitialize();
    }

    bool GetWindowsBuild() {
        OSVERSIONINFOEX osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

        typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        HMODULE hMod = GetModuleHandle(TEXT("ntdll.dll"));
        if (hMod) {
            RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
            if (RtlGetVersion) {
                RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
                winBuild = osvi.dwBuildNumber;
                return true;
            }
        }
        return false;
    }

    bool GetOSSKU() {
        HRESULT hres;
        IEnumWbemClassObject* pEnumerator = NULL;

        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT OperatingSystemSKU FROM Win32_OperatingSystem"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator);

        if (FAILED(hres)) {
            std::cerr << "ERROR: Failed to execute WMI query for OS SKU" << std::endl;
            return false;
        }

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        bool found = false;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pclsObj->Get(L"OperatingSystemSKU", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr)) {
                osSKU = vtProp.intVal;
                found = true;
            }
            VariantClear(&vtProp);
            pclsObj->Release();
        }

        pEnumerator->Release();
        return found;
    }

    bool CheckInternetConnection() {
        return InternetCheckConnection("http://www.microsoft.com", FLAG_ICC_FORCE_CONNECTION, 0);
    }

    bool InstallProductKey(std::string key) {
        bool success = false;

        std::string cmd = "slmgr /ipk " + key + " >nul 2>&1";

        int result = system(cmd.c_str());
        if (result == 0)
            success = true;

        return success;
    }

    bool GenerateGenuineTicket() {
        std::string sessionId = "OSMajorVersion=10;OSMinorVersion=0;OSPlatformId=2;PP=0;";
        sessionId += "Pfn=Microsoft.Windows." + std::to_string(osSKU) + ".";
        sessionId += "TimeStampClient=2024-11-19T12:00:00Z";

        std::string ticketXml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
        ticketXml += "<genuineAuthorization xmlns=\"http://www.microsoft.com/DRM/SL/GenuineAuthorization/1.0\">";
        ticketXml += "<version>1.0</version>";
        ticketXml += "<genuineProperties origin=\"sppclient\">";
        ticketXml += "<properties>OA3xOriginalProductId=;OA3xOriginalProductKey=;SessionId=";
        ticketXml += sessionId + "</properties>";
        ticketXml += "</genuineProperties></genuineAuthorization>";

        std::string ticketDir = std::string(getenv("ProgramData")) + 
            "\\Microsoft\\Windows\\ClipSVC\\GenuineTicket\\";
        
        CreateDirectoryA(ticketDir.c_str(), NULL);

        std::string ticketPath = ticketDir + "GenuineTicket.xml";

        std::ofstream ticketFile(ticketPath, std::ios::binary);
        if (!ticketFile.is_open()) {
            std::cerr << "ERROR: Failed to create GenuineTicket file" << std::endl;
            return false;
        }

        ticketFile << "\xEF\xBB\xBF";
        ticketFile << ticketXml;
        ticketFile.close();

        system("sc stop ClipSVC >nul 2>&1");
        Sleep(2000);
        system("sc start ClipSVC >nul 2>&1");
        Sleep(3000);

        return true;
    }

    std::string FindKeyForSKU() {
        std::cout << "[*] Searching for activation key for SKU " << osSKU << "..." << std::endl;
        
        for (const auto& data : activationDatabase) {
            if (data.skuId == osSKU && data.isWorking) {
                std::cout << "[+] Found exact match: " << data.editionId << " (" << data.keyType << ")" << std::endl;
                return data.genericKey;
            }
        }
        
        std::cout << "[!] No exact match found for SKU " << osSKU << ", trying alternatives..." << std::endl;
        
        std::vector<int> alternativeSKUs;
        
        if (osSKU == 191 || osSKU == 100) { // IoT Enterprise S or Core Single Language
            alternativeSKUs = {191, 100, 48, 101, 4}; // IoT -> Single Language -> Professional -> Core -> Enterprise
        }
        else if (osSKU >= 125 && osSKU <= 126) { // Enterprise S options
            alternativeSKUs = {125, 126, 4, 48}; // EnterpriseS -> Enterprise -> Professional
        }
        else if (osSKU == 161 || osSKU == 162) { // Workstation
            alternativeSKUs = {161, 162, 48, 4}; // Workstation -> Professional -> Enterprise
        }
        else if (osSKU == 164 || osSKU == 165) { // Education Professional
            alternativeSKUs = {164, 165, 121, 48}; // Pro Education -> Education -> Professional
        }
        else if (osSKU == 121 || osSKU == 122) { // Education
            alternativeSKUs = {121, 122, 48, 101}; // Education -> Professional -> Core
        }
        else if (osSKU == 48 || osSKU == 49) { // Professional
            alternativeSKUs = {48, 49, 101, 121, 4}; // Professional -> Core -> Education -> Enterprise
        }
        else if (osSKU == 101 || osSKU == 98 || osSKU == 99 || osSKU == 100) { // Core variants
            alternativeSKUs = {101, 98, 99, 100, 48}; // Core -> Professional
        }
        else if (osSKU == 4 || osSKU == 27) { // Enterprise
            alternativeSKUs = {4, 27, 48, 125}; // Enterprise -> Professional -> EnterpriseS
        }
        else if (osSKU >= 178 && osSKU <= 179) { // Cloud
            alternativeSKUs = {178, 179, 48, 101}; // Cloud -> Professional -> Core
        }
        else if (osSKU >= 202 && osSKU <= 203) { // Cloud Edition
            alternativeSKUs = {202, 203, 178, 48}; // CloudEdition -> Cloud -> Professional
        }
        else if (osSKU >= 188 && osSKU <= 191) { // IoT Enterprise
            alternativeSKUs = {188, 191, 100, 48}; // IoT -> Single Language -> Professional
        }
        else if (osSKU >= 205 && osSKU <= 206) { // IoT Enterprise K/SK
            alternativeSKUs = {205, 206, 188, 191, 48}; // IoT K/SK -> IoT -> Professional
        }
        else {
            alternativeSKUs = {48, 101, 121, 4, 125, 191}; // Professional, Core, Education, Enterprise, EnterpriseS, IoT
        }
        
        for (int altSKU : alternativeSKUs) {
            for (const auto& data : activationDatabase) {
                if (data.skuId == altSKU && data.isWorking) {
                    std::cout << "[+] Using alternative key for SKU " << data.skuId << ": " 
                        << data.editionId << " (" << data.keyType << ")" << std::endl;
                    return data.genericKey;
                }
            }
        }
        
        std::cout << "[!] No suitable alternative found, trying any available key..." << std::endl;
        for (const auto& data : activationDatabase) {
            if (data.isWorking) {
                std::cout << "[+] Using fallback key for SKU " << data.skuId << ": " 
                    << data.editionId << " (" << data.keyType << ")" << std::endl;
                return data.genericKey;
            }
        }
        
        std::cerr << "[ERROR] No working activation keys found in database!" << std::endl;
        return "";
    }

    void PrintSKUInfo() {
        std::cout << "[*] Detected Windows SKU: " << osSKU << std::endl;
        std::cout << "[*] Available activation keys in database:" << std::endl;
        for (const auto& data : activationDatabase) {
            if (data.isWorking) {
                std::cout << "    - SKU " << data.skuId << ": " << data.editionId 
                     << " (" << data.keyType << ")" << std::endl;
            }
        }
    }

public:
    bool Run() {
        std::cout << "==================================================" << std::endl;
        std::cout << "         HWID Activation Tool      " << std::endl;
        std::cout << "==================================================" << std::endl << std::endl;

        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }

        if (!isAdmin) {
            std::cerr << "ERROR: This program requires administrator privileges!" << std::endl;
            std::cerr << "Please run as administrator." << std::endl;
            return false;
        }

        std::cout << "[*] Initializing..." << std::endl;

        if (!InitializeWMI()) {
            std::cerr << "ERROR: Failed to initialize WMI" << std::endl;
            return false;
        }

        if (!GetWindowsBuild()) {
            std::cerr << "ERROR: Failed to get Windows build" << std::endl;
            Cleanup();
            return false;
        }

        if (winBuild < 10240) {
            std::cerr << "ERROR: HWID activation only supports Windows 10/11" << std::endl;
            Cleanup();
            return false;
        }

        std::cout << "[+] Windows Build: " << winBuild << std::endl;

        if (!GetOSSKU()) {
            std::cerr << "ERROR: Failed to get OS SKU" << std::endl;
            Cleanup();
            return false;
        }

        PrintSKUInfo();

        if (!CheckInternetConnection()) {
            std::cerr << "WARNING: No internet connection detected" << std::endl;
            std::cerr << "Internet is required for HWID activation" << std::endl;
            std::cout << "[*] Continuing offline activation attempt..." << std::endl;
        } else {
            std::cout << "[+] Internet connection: OK" << std::endl;
        }

        activationKey = FindKeyForSKU();
        if (activationKey.empty()) {
            std::cerr << "ERROR: No activation key found for SKU " << osSKU << std::endl;
            std::cerr << "This edition may not support HWID activation" << std::endl;
            Cleanup();
            return false;
        }

        std::cout << "[+] Using product key: " << activationKey << std::endl;

        std::cout << "[*] Installing product key..." << std::endl;
        if (!InstallProductKey(activationKey)) {
            std::cerr << "ERROR: Failed to install product key" << std::endl;
            Cleanup();
            return false;
        }
        std::cout << "[+] Product key installed successfully" << std::endl;

        std::cout << "[*] Generating GenuineTicket..." << std::endl;
        if (!GenerateGenuineTicket()) {
            std::cerr << "WARNING: Failed to generate GenuineTicket, continuing..." << std::endl;
        } else {
            std::cout << "[+] GenuineTicket generated and installed" << std::endl;
        }

        std::cout << "[*] Activating Windows..." << std::endl;
        Sleep(5000);

        system("slmgr /ato >nul 2>&1");
        Sleep(3000);

        std::cout << std::endl;
        std::cout << "==================================================" << std::endl;
        std::cout << "[SUCCESS] Activation process completed!" << std::endl;
        std::cout << "Please check activation status in:" << std::endl;
        std::cout << "Settings > Update & Security > Activation" << std::endl;
        std::cout << "==================================================" << std::endl;

        Cleanup();
        return true;
    }
};

int main() {
    SetConsoleOutputCP(CP_UTF8);
    
    HWIDActivation activator;
    bool result = activator.Run();

    std::cout << std::endl << "Press any key to exit...";
    std::cin.get();

    return result ? 0 : 1;
}