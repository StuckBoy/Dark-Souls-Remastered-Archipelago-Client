#include "GameHook.h"

DWORD64 qItemEquipComms = 0;

DWORD64 rItemRandomiser = 0;
DWORD64 rAutoEquip = 0;
DWORD64 rNoWeaponRequirements = 0;
DWORD64 rEquipLock = 0;

LPVOID itemGibDataCodeCave;

extern CItemRandomiser* ItemRandomiser;
extern CArchipelago* ArchipelagoInterface;
extern CCore* Core;

BOOL CGameHook::preInitialize() {
	if (MH_Initialize() != MH_OK) {
		return false;
	}
	//Init code cave for Item Randomizer
	return Hook(0x0018004A, (DWORD64)&tItemRandomiser, &rItemRandomiser, 5);
}

BOOL CGameHook::Hook(DWORD64 qAddress, DWORD64 qDetour, DWORD64* pReturn, DWORD dByteLen) {
	MH_STATUS status = MH_CreateHook((LPVOID)qAddress, (LPVOID)qDetour, 0);
	if (status != MH_OK) {
		return false;
	}
	if (MH_EnableHook((LPVOID)qAddress) != MH_OK) {
		return false;
	}
	*pReturn = (qAddress + dByteLen);

	return true;
}

BOOL CGameHook::initialize() {

	BOOL bReturn = true;

	//Inject ItemGibData
	itemGibDataCodeCave = InjectShellCode(nullptr, ItemGibDataShellcode, 17);

	//Modify ItemGibShellcode
	bReturn &= replaceShellCodeAddress(ItemGibShellcode, 15, itemGibDataCodeCave, 0, sizeof(void*));
	bReturn &= replaceShellCodeAddress(ItemGibShellcode, 26, itemGibDataCodeCave, 4, 4);
	bReturn &= replaceShellCodeAddress(ItemGibShellcode, 33, itemGibDataCodeCave, 8, 4);

	//Inject ItemGibShellcode
	LPVOID itemGibCodeCave = InjectShellCode((LPVOID)0x1400003f0, ItemGibShellcode, 93);

	return bReturn;
}

/*
TODO Support deathlink
VOID CGameHook::manageDeathLink() {
	if (lastHealthPoint == 0 && healthPoint != 0) {	//The player just respawned
		deathLinkData = false;
	} else if (deathLinkData && lastHealthPoint != 0 && healthPoint != 0 ) { //The player received a deathLink
		killThePlayer();
	} else if(lastHealthPoint != 0 && healthPoint == 0) { //The player just died, ignore the deathLink if received
		if (deathLinkData) {
			deathLinkData = false;
			return;
		}
		ArchipelagoInterface->sendDeathLink();
	}
}

VOID CGameHook::killThePlayer() {
	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);
	//TODO Test that these offsets are correct
	std::vector<unsigned int> hpOffsets = { 0x3F8, 0x38, 0x18, 0x68 };
	uintptr_t healthPointAddr = FindExecutableAddress(0x4768E78, hpOffsets); //BaseB + HP Offsets

	int newHP = 0;
	WriteProcessMemory(hProcess, (BYTE*)healthPointAddr, &newHP, sizeof(newHP), nullptr);
}
*/

BOOL CGameHook::updateRuntimeValues() {
	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

	int executableSize = 49108 * 1000;
	BYTE* patternBAddr = findPattern((BYTE*)GetModuleBaseAddress(), (BYTE*)baseBPattern, baseBMask, executableSize);
	int thirdInteger = -1;
	ReadProcessMemory(hProcess, (BYTE*)(patternBAddr + 3), &thirdInteger, sizeof(thirdInteger), 0);
	BYTE* finalBAddr = patternBAddr + thirdInteger + 7;
	BaseB = (uintptr_t)finalBAddr;
	BYTE* patternXAddr = findPattern((BYTE*)GetModuleBaseAddress(), (BYTE*)baseXPattern, baseXMask, executableSize);
	thirdInteger = -1;
	ReadProcessMemory(hProcess, (BYTE*)(patternBAddr + 3), &thirdInteger, sizeof(thirdInteger), 0);
	BYTE* finalXAddr = patternXAddr + thirdInteger + 7;
	BaseX = (uintptr_t)finalXAddr;
	//Returned 141C8A530 for BaseB
	//Returned 141C77E50 for BaseX
#if DEBUG
	printf("%" PRIxPTR "\n", BaseX);
#endif

	//Read value of health to determine if the character is alive
	std::vector<unsigned int> hpOffsets = { 0x68, 0x3E8 };
	uintptr_t healthPointAddr = FindDMAAddyStandalone(0x141C77E50, hpOffsets); //BaseX + HP Offsets

	//Read value of play time to know that a character is active
	std::vector<unsigned int> playTimeOffsets = { 0xA4 };
	uintptr_t playTimeAddr = FindDMAAddyStandalone(0x141C8A530, playTimeOffsets); //BaseB + PlayTime Offsets	

	/*
	TODO Options are: 
	Clear state(none, good, bad) with offset(s) ( 0x78 )
	Clear count with offset(s) ( 0x7C )
	Both use BaseB
	*/
	//std::vector<unsigned int> lordOfCinderDefeatedFlagOffsets = { 0x00, 0x5F67 };
	//uintptr_t soulOfCinderDefeatedFlagAddress = FindExecutableAddress(0x473BE28, lordOfCinderDefeatedFlagOffsets); //GameFlagData + Lord of Cinder defeated flag Offsets	

	printf_s("\nReading process for Clear Count\n");
	std::vector<unsigned int> clearCountFlagOffsets = { 0x78 };
	uintptr_t clearCountAddr = FindDMAAddyStandalone(0x141C8A530, clearCountFlagOffsets); //BaseB + PlayTime Offsets	

	ReadProcessMemory(hProcess, (BYTE*)healthPointAddr, &healthPoint, sizeof(healthPoint), &healthPointRead);
	ReadProcessMemory(hProcess, (BYTE*)playTimeAddr, &playTime, sizeof(playTime), &playTimeRead);
	//TODO There's clear state and clear count, whichever is easier to verify
	ReadProcessMemory(hProcess, (BYTE*)clearCountAddr, &clearCount, sizeof(clearCount), &clearCountFlagRead);

	lastHealthPoint = healthPoint;

#if DEBUG
	printf_s("Your health is apparently: %zu\n", healthPointRead);
	printf_s("Your play time is apparently: %zu\n", playTimeRead);
#endif
	printf_s("Your health is apparently: %d\n", healthPoint);
	printf_s("Your play time is apparently: %d\n", playTime);
	printf_s("Your clear count is apparently: %c\n\n", clearCount);
}

VOID CGameHook::giveItems() {
	//Send the next item in the list
	if (!ItemRandomiser->receivedItemsQueue.empty()) {
		itemGib(ItemRandomiser->receivedItemsQueue.back());
	}
}

BOOL CGameHook::endingAchieved() {
	/*
	TODO Update once either flag location for Gwyn's defeat or an ending achieved flag has been found
	constexpr std::uint8_t mask7{ 0b1000'0000 };
	return lordOfCinderDefeatedFlagRead != 0 && (int)(lordOfCinderDefeated & mask7) == 128;
	*/
	constexpr std::uint8_t mask7{ 0b1000'0000 };
	return clearCountFlagRead != 0 && (int)(clearCount & mask7) == 128;
}

VOID CGameHook::itemGib(DWORD itemId) {

	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

	uintptr_t gibItem = (uintptr_t)itemGibDataCodeCave + 4;

	char* littleEndianItemId = (char*)malloc(sizeof(DWORD));
	ConvertToLittleEndianByteArray((uintptr_t)itemId, littleEndianItemId);

	DWORD memory = 0;
	ReadProcessMemory(hProcess, (BYTE*)gibItem, &memory, sizeof(memory), nullptr);
	DWORD newMemory = itemId;
	WriteProcessMemory(hProcess, (BYTE*)gibItem, &newMemory, sizeof(newMemory), nullptr);

	typedef int func(void);
	func* f = (func*)0x1400003F0; //Must match address for itemGibCodeCave

	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)f, NULL, NULL, NULL);
}

BOOL CGameHook::replaceShellCodeAddress(BYTE *shellcode, int shellCodeOffset, LPVOID codeCave, int codeCaveOffset, int length) {

	char* addressArray = (char*)malloc(sizeof(void*));
	ConvertToLittleEndianByteArray((uintptr_t)codeCave + codeCaveOffset, addressArray);
	if (addressArray == 0) {
		return false;
	}
	memcpy(shellcode + shellCodeOffset, addressArray, length);
	free(addressArray);

	return true;
}

LPVOID CGameHook::InjectShellCode(LPVOID address, BYTE* shellCode, size_t len) {
	
	//TODO Is this hex value still accurate?
	LPVOID pCodeCave = VirtualAlloc(address, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pCodeCave) {
		return nullptr;
	}

	// copy the machine code into that memory:
	std::memcpy(pCodeCave, shellCode, len);

	// mark the memory as executable:
	DWORD lpflOldProtect;
	VirtualProtect(pCodeCave, len, PAGE_EXECUTE_READ, &lpflOldProtect);

	return pCodeCave;
}

void CGameHook::ConvertToLittleEndianByteArray(uintptr_t address, char* output) {
	for (int i = 0; i < sizeof(void*); ++i) {
		output[i] = address & 0xff;
		address >>= 8;
	}
}


uintptr_t CGameHook::FindExecutableAddress(uintptr_t ptrOffset, std::vector<unsigned int> offsets) {
	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

	uintptr_t moduleBase = GetModuleBaseAddress();
	uintptr_t dynamicPtrAddr = moduleBase + ptrOffset;

	return FindDMAAddy(hProcess, dynamicPtrAddr, offsets);
}

uintptr_t CGameHook::FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {

	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i) {

		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
		addr += offsets[i];
	}
	return addr;
}

uintptr_t CGameHook::FindDMAAddyStandalone(uintptr_t ptr, std::vector<unsigned int> offsets) {

	DWORD processId = GetCurrentProcessId();
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i) {
		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
		addr += offsets[i];
	}
	return addr;
}

uintptr_t CGameHook::GetModuleBaseAddress() {
	const char* lpModuleName = "DarkSoulsRemastered.exe";
	DWORD procId = GetCurrentProcessId();

	MODULEENTRY32 lpModuleEntry = { 0 };
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);
	if (!hSnapShot) {
		return NULL;
	}
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	BOOL bModule = Module32First(hSnapShot, &lpModuleEntry);
	while (bModule) {
		if (!strcmp(lpModuleEntry.szModule, lpModuleName)) {
			CloseHandle(hSnapShot);
			return (uintptr_t)lpModuleEntry.modBaseAddr;
		}
		bModule = Module32Next(hSnapShot, &lpModuleEntry);
	}
	CloseHandle(hSnapShot);
	return NULL;
}

BYTE* CGameHook::findPattern(BYTE* pBaseAddress, BYTE* pbMask, const char* pszMask, size_t nLength) {
	auto DataCompare = [](const BYTE* pData, const BYTE* mask, const char* cmask, BYTE chLast, size_t iEnd) -> bool {
		if (pData[iEnd] != chLast) return false;
		for (; *cmask; ++cmask, ++pData, ++mask) {
			if (*cmask == 'x' && *pData != *mask) {
				return false;
			}
		}

		return true;
	};

	auto iEnd = strlen(pszMask) - 1;
	auto chLast = pbMask[iEnd];

	auto* pEnd = pBaseAddress + nLength - strlen(pszMask);
	for (; pBaseAddress < pEnd; ++pBaseAddress) {
		if (DataCompare(pBaseAddress, pbMask, pszMask, chLast, iEnd)) {
			return pBaseAddress;
		}
	}

	return nullptr;
}
