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
	Core->Logger("CGameHook::preInitialize", true, false);

	try {
		if (MH_Initialize() != MH_OK) return false;
	} catch (const std::exception&) {
		Core->Logger("Cannot initialize MinHook");
		return false;
	}

	try {
		Core->Logger("Hooking in at 0x140000010");
		return Hook(itemRandomizerAddress, (DWORD64)&tItemRandomiser, &rItemRandomiser, 5);
	} catch (const std::exception&) {
		Core->Logger("Cannot hook the game 0x140000010");
	}
	return false;
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
	Core->Logger("CGameHook::initialize", true, false);

	BOOL bReturn = true;

	//Inject ItemGibData
	try {
		itemGibDataCodeCave = InjectShellCode(nullptr, ItemGibDataShellcode, 17);
		Core->Logger("Deposited data shellcode into data code cave at <null> (not 140000168)");
	} catch (const std::exception&) {
		Core->Logger("Cannot inject ItemGibData");
		return false;
	}

	//Modify ItemGibShellcode
	try {
		bReturn &= replaceShellCodeAddress(ItemGibShellcode, 15, itemGibDataCodeCave, 0, sizeof(void*));
		Core->Logger("Replaced code in Data code cave at offset 15");
		bReturn &= replaceShellCodeAddress(ItemGibShellcode, 26, itemGibDataCodeCave, 4, 4);
		Core->Logger("Replaced code in Data code cave at offset 26");
		bReturn &= replaceShellCodeAddress(ItemGibShellcode, 33, itemGibDataCodeCave, 8, 4);
		Core->Logger("Replaced code in Data code cave at offset 33");
	} catch (const std::exception&) {
		Core->Logger("Cannot modify ItemGibShellcode");
		return false;
	}

	//Inject ItemGibShellcode
	try {
		//LPVOID itemGibCodeCave = InjectShellCode((LPVOID)itemGibCodeAddress, ItemGibShellcode, 93);
		LPVOID itemGibCodeCave = InjectShellCode((LPVOID)itemGibCodeAddress, innocentShellCode, 12);
		Core->Logger("Deposited ItemGib shell code at 13ffe0000");
	} catch (const std::exception&) {
		Core->Logger("Cannot inject ItemGibShellcode");
		return false;
	}

	/*
	//Replace call destination @ 1403fb144
	try {
		LPVOID pCodeCave = VirtualAlloc((LPVOID)0x140efb1ee, 5, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		//InjectShellCode((LPVOID)0x1403fb144, Jumperino, 5);
		// blank it
		//std::memcpy((LPVOID)0x1403FB144, Jumperino, 5);
		std::memcpy((LPVOID)0x1403fb1ee, Jumperino, 5);
		// copy the machine code into that memory:
		//std::memcpy((LPVOID)0x1403fb144, Jumperino, 5);
		// mark the memory as executable:
		DWORD lpflOldProtect;
		//VirtualProtect((LPVOID)0x1403fb144, 5, PAGE_EXECUTE_READ, & lpflOldProtect);
		VirtualProtect((LPVOID)0x1403fb1ee, 5, PAGE_EXECUTE_READ, & lpflOldProtect);

		Core->Logger("We're in?");
	}
	catch (const std::exception&) {
		Core->Logger("He didn't make it.");
		return false;
	}
	*/

	return bReturn;
}

BOOL CGameHook::redirectJump() {
	try {
		LPVOID pCodeCave = VirtualAlloc((LPVOID)0x1403fb149, 6, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		//LPVOID pCodeCave = VirtualAlloc((LPVOID)0x140efb1ee, 5, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		//InjectShellCode((LPVOID)0x1403fb144, Jumperino, 5);
		// blank it
		std::memcpy((LPVOID)0x1403fb149, DoublyBlankerino, 6);
		std::memcpy((LPVOID)0x1403fb149, Jumperino, 5);
		//std::memcpy((LPVOID)0x1403fb1ee, Jumperino, 5);
		// copy the machine code into that memory:
		//std::memcpy((LPVOID)0x1403fb144, Jumperino, 5);
		// mark the memory as executable:
		DWORD lpflOldProtect;
		VirtualProtect((LPVOID)0x1403fb149, 6, PAGE_EXECUTE_READ, & lpflOldProtect);
		//VirtualProtect((LPVOID)0x1403fb1ee, 5, PAGE_EXECUTE_READ, & lpflOldProtect);

		Core->Logger("We're in?");
		return true;
	}
	catch (const std::exception&) {
		Core->Logger("He didn't make it.");
		return false;
	}
}

BOOL CGameHook::applySettings() {
	BOOL bReturn = true;
/*
	if (dIsAutoEquip) { bReturn &= Hook(0x1407BBE92, (DWORD64)&tAutoEquip, &rAutoEquip, 6); }
	if (dIsNoWeaponRequirements) { bReturn &= Hook(0x140C073B9, (DWORD64)&tNoWeaponRequirements, &rNoWeaponRequirements, 7); }
	if (dIsNoSpellsRequirements) { RemoveSpellsRequirements(); }
	if (dLockEquipSlots) { LockEquipSlots(); }
	if (dIsNoEquipLoadRequirements) { RemoveEquipLoad(); }
	if (dEnableDLC) {
		if (!checkIsDlcOwned()) {
			Core->Panic("You must own both the ASHES OF ARIANDEL and THE RINGED CITY DLC in order to enable the DLC option in Archipelago", "Missing DLC detected", FE_MissingDLC, 1);
		}
	}
*/
	return bReturn;
}

VOID CGameHook::manageDeathLink() {
	if (lastHealthPoint == 0 && healthPoint != 0) {	//The player just respawned
		deathLinkData = false;
	} else if (deathLinkData && lastHealthPoint != 0 && healthPoint != 0 ) { //The player received a deathLink
		killThePlayer();
	} else if (lastHealthPoint != 0 && healthPoint == 0) { //The player just died, ignore the deathLink if received
		if (deathLinkData) {
			Core->Logger("The player just died, a death link has been ignored", true, false);
			deathLinkData = false;
			return;
		}
		ArchipelagoInterface->sendDeathLink();
	}
}

VOID CGameHook::killThePlayer() {
	Core->Logger("Kill the player", true, false);
	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);
	std::vector<unsigned int> hpOffsets = { 0x68, 0x3E8 };
	uintptr_t healthPointAddr = FindDMAAddyStandalone(0x141C77E50, hpOffsets);

	int newHP = 0;
	WriteProcessMemory(hProcess, (BYTE*)healthPointAddr, &newHP, sizeof(newHP), nullptr);
}

BOOL CGameHook::updateRuntimeValues() {

	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

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

	//printf_s("\nReading process for Clear Count\n");
	std::vector<unsigned int> clearCountFlagOffsets = { 0x78 };
	uintptr_t clearCountAddr = FindDMAAddyStandalone(0x141C8A530, clearCountFlagOffsets); //BaseB + PlayTime Offsets	

	lastHealthPoint = healthPoint;

	ReadProcessMemory(hProcess, (BYTE*)healthPointAddr, &healthPoint, sizeof(healthPoint), &healthPointRead);
	ReadProcessMemory(hProcess, (BYTE*)playTimeAddr, &playTime, sizeof(playTime), &playTimeRead);
	//TODO There's clear state and clear count, whichever is easier to verify
	//TODO Would checking for achievement earned state be easier? (Age of Fire/Darkness)
	ReadProcessMemory(hProcess, (BYTE*)clearCountAddr, &clearCount, sizeof(clearCount), &clearCountFlagRead);

#if DEBUG
	printf_s("Your health is apparently: %zu\n", healthPointRead);
	printf_s("Your play time is apparently: %zu\n", playTimeRead);
	printf_s("Your clear count is apparently: %c\n\n", clearCount);
#endif
}

VOID CGameHook::giveItems() {
	//Send the next item in the list
	int size = ItemRandomiser->receivedItemsQueue.size();
	if (size > 0) {
		Core->Logger("Send an item from the list of items", true, false);
		itemGib(ItemRandomiser->receivedItemsQueue.back());
	}
}

BOOL CGameHook::endingAchieved() {
	/*
	TODO Update once either flag location for Gwyn's defeat or an ending achieved flag has been found
	constexpr std::uint8_t mask7{ 0b1000'0000 };
	return lordOfCinderDefeatedFlagRead != 0 && (int)(lordOfCinderDefeated & mask7) == 128;
	*/
	//constexpr std::uint8_t mask7{ 0b1000'0000 };
	//return clearCountFlagRead != 0 && (int)(clearCount & mask7) == 128;

	//TODO Implement Win Condition
	return false;
}

VOID CGameHook::itemGib(DWORD itemId) {

	DWORD processId = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, processId);

	uintptr_t gibItem = (uintptr_t)itemGibDataCodeCave + 4;

	char* littleEndianItemId = (char*)malloc(sizeof(DWORD));
	ConvertToLittleEndianByteArray((uintptr_t)itemId, littleEndianItemId);

	try {
		DWORD memory = 0;
		ReadProcessMemory(hProcess, (BYTE*)gibItem, &memory, sizeof(memory), nullptr);
		Core->Logger("Read process memory inside itemGib(), preparing to give item w/id: " + itemId);
		DWORD newMemory = itemId;
		WriteProcessMemory(hProcess, (BYTE*)gibItem, &newMemory, sizeof(newMemory), nullptr);
		Core->Logger("Wrote new item id out.");
	} catch (const std::exception&) {
		Core->Logger("Cannot write the item to the memory");
	}

	try {
		typedef int func(void);
		func* f = (func*)itemGibCodeAddress;
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)f, NULL, NULL, NULL);
	} catch (const std::exception&) {
		Core->Logger("Cannot start the 0x1400003F0 thread");
	}
}


//replaceShellCodeAddress(ItemGibShellcode, 15, itemGibDataCodeCave, 0, sizeof(void*));
//replaceShellCodeAddress(ItemGibShellcode, 26, itemGibDataCodeCave, 4, 4);
//replaceShellCodeAddress(ItemGibShellcode, 33, itemGibDataCodeCave, 8, 4);

/*
shellcode - Byte Array
shellcodeoffset - int
codeCave - LPVOID
codeCaveOffset - int
length - int
*/
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
	
	//TODO Is this hex value still accurate? (0x3000?)
	//Can using the length of the shell code work as the dwSize?
	LPVOID pCodeCave = VirtualAlloc(address, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
