// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 21/07/17
*/
// --------------------------------------------------------------
#include "snapshot.h"

#include <Shlwapi.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <ntstatus.h>

#include "process.h"
#include "util.h"

#define ThreadQuerySetWin32StartAddress 9
typedef NTSTATUS(WINAPI *pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);

// credits: https://forum.sysinternals.com/how-to-get-the-start-address-and-modu_topic5127_post18072.html#18072
static DWORD WINAPI GetThreadStartAddress(HANDLE hThread)
{

	NTSTATUS ntStatus;
	HANDLE hDupHandle;
	DWORD dwStartAddress;

	pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");

	if (NtQueryInformationThread == NULL)
		return 0;

	HANDLE hCurrentProcess = GetCurrentProcess();

	if (!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0))
	{

		SetLastError(ERROR_ACCESS_DENIED);
		return 0;
	}

	ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD), NULL);

	CloseHandle(hDupHandle);

	if (ntStatus != STATUS_SUCCESS)
		return 0;

	return dwStartAddress;

}


namespace Codefinder
{
	bool ProcessSnapshot::Snapshot()
	{
		UpdateModules();
		UpdateMemoryRegions();
		UpdateThreads();

		//...

		return true;
	}

	/*
		Builds a list of process threads, checking there starting addresses to see if they are
		starting inside a page which doesnt belong to any legit modules in the process
	*/
	void ProcessSnapshot::UpdateThreads()
	{
		m_Threads.clear();

		HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

		if (hThreadSnapshot != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 tEntry = { 0 };
			tEntry.dwSize = sizeof(THREADENTRY32);

			// Iterate threads
			for (BOOL success = Thread32First(hThreadSnapshot, &tEntry); success == TRUE;
				success = Thread32Next(hThreadSnapshot, &tEntry))
			{
				if (tEntry.th32OwnerProcessID != m_pProcess->GetProcessID())
					continue;

				ProcessThread pt;
				pt.m_theadID = tEntry.th32ThreadID;
				pt.m_hThreadHandle = OpenThread(THREAD_ALL_ACCESS, false, pt.m_theadID);
				pt.m_dwStartAddress = GetThreadStartAddress(pt.m_hThreadHandle);
				pt.m_pModule = nullptr; pt.m_pPage = nullptr;

				// Check where this thread started...
				if (pt.m_dwStartAddress)
				{
					ProcessMemoryPage* page = GetContainingPage(pt.m_dwStartAddress);

					if (page && page->IsExecutable())
					{
						pt.m_pPage = page;

						ProcessModule* mod = page->m_pContainingModule;
						if (mod && mod->GetFlag(ProcessModule::MF_Manual) == false)
						{
							// Legit thread
							pt.m_pModule = mod;
						}
						else
						{
							// In this case, the thread is started in a manually mapped module, or a peice of shellcode
							pt.m_bIsManualCode = true;
							printf("[+] Found suspicious thread starting at 0x%x\n", pt.m_dwStartAddress);

							// Link it to the hidden module
							if (mod)
							{
								pt.m_pModule = mod;

								printf("[+] Thread belongs to hidden module %s\n", mod->m_strModuleName.c_str());
								m_Finds.push_back({ page->m_addrRange, std::string("Stray Thread Execution in ") + mod->m_strModuleName.c_str() });
							}
							else
							{
								m_Finds.push_back({ page->m_addrRange, std::string("Stray Thread Execution") });
							}


							printf("[+] Thread code page 0x%x - 0x%x\n", page->m_addrRange.m_dwBaseAddress, page->m_addrRange.m_dwBaseAddress + page->m_addrRange.m_cbSize);
						}
					}
					else
					{
						// possibly it got freed?
					}
				}

				m_Threads.push_back(pt);
			}

			CloseHandle(hThreadSnapshot);
		}

	}

	/*
		Builds a list of modules currently loaded in the process. This list will be used to check
		if pages and threads belong to any of these legit modules later on
	*/
	void ProcessSnapshot::UpdateModules()
	{
		m_Modules.clear();

		HMODULE hMods[1024];
		DWORD cbNeeded;
		unsigned int i;

		if (EnumProcessModules(m_pProcess->GetProcessHandle(), hMods, sizeof(hMods), &cbNeeded))
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				char szModName[MAX_PATH];

				// Get the full path to the module's file.
				if (GetModuleFileNameEx(m_pProcess->GetProcessHandle(), hMods[i], szModName,
					sizeof(szModName) / sizeof(char)))
				{

					ProcessModule pm;
					pm.SetFlag(ProcessModule::MF_Live,   true);
					pm.SetFlag(ProcessModule::MF_Manual, false);

					pm.m_strModulePath = szModName;
					PathStripPath(szModName);
					pm.m_strModuleName = szModName;

					pm.m_addrRange.m_dwBaseAddress = (DWORD)(hMods[i]);
					pm.m_addrRange.m_cbSize = 0x1000; // In case of failure, keep a default value

					// 0x1000 Is usual size of the full header block
					char buffer[0x1000];
					if (m_pProcess->RemoteRead(pm.m_addrRange.m_dwBaseAddress, &buffer, 0x1000))
					{
						PEParse::PEParser pe(buffer, true);
						if (pe.IsValid())
						{
							// Get the size the module should take up in memory
							pm.m_addrRange.m_cbSize = pe.GetNTHeader()->OptionalHeader.SizeOfImage;
						}
					}
					
					m_Modules.push_back(pm);
				}
			}
		}
	}

	/*
		Builds a list of all allocated memory pages in the process. For each block, it tries to associate
		them with known modules. If it doesn't belong to anything legit, it applies a number of checks and
		heuristic scans to try figure out what this is
	*/
	void ProcessSnapshot::UpdateMemoryRegions()
	{
		m_Memory.clear();
		m_Memory.reserve(200);

		SIZE_T numBytes = 0;
		DWORD pageStart = 0;
		DWORD allocationBase = 0;

		do
		{
			// Get info for current page
			MEMORY_BASIC_INFORMATION mbi;
			memset(&mbi, 0, sizeof(mbi));
			numBytes = VirtualQueryEx(m_pProcess->GetProcessHandle(), (LPVOID)pageStart, &mbi, sizeof(mbi));

			// Exclude pages that have been freed
			if (mbi.State != MEM_FREE)
			{
				bool bReserved		= mbi.State == MEM_RESERVE;
				bool bPrevReserved	= m_Memory.size() ? m_Memory.back().m_MBI.State == MEM_RESERVE : false; 

				if ( bReserved || bPrevReserved || allocationBase != DWORD(mbi.AllocationBase) )
				{
					ProcessMemoryPage newProcMem;
					memset(&newProcMem, 0, sizeof(ProcessMemoryPage));
					memcpy(&newProcMem.m_MBI, &mbi, sizeof(mbi));

					newProcMem.m_addrRange.m_dwBaseAddress = (uintptr_t)mbi.AllocationBase; 
					newProcMem.m_addrRange.m_cbSize = mbi.RegionSize;

					if (bReserved)
					{
						newProcMem.m_strLabel = "Reserved";
					}
					else
					{
						// Attempt to determine what this page belongs to
						if (!ScanMemoryRegion(newProcMem))
						{
							// Maybe needed later...
						}
					}

					m_Memory.push_back(newProcMem);
				}
				else
				{
					// Append the page to the last created entry
					if (m_Memory.size()) 
						m_Memory.back().m_MBI.RegionSize += mbi.RegionSize;
				}
			}

			// Calculate the next page start
			DWORD newAddress = DWORD(mbi.BaseAddress) + mbi.RegionSize;

			// If we've looped back to the start, stop
			if (newAddress <= pageStart)
				break;

			pageStart = newAddress;

		} while (numBytes);
	}

	/*
		Applies a number of techniques to attempt to use a pages data to determine what it is or belongs to
	*/
	bool ProcessSnapshot::ScanMemoryRegion(ProcessMemoryPage& page)
	{
		// Regular module case
		ProcessModule* mod = GetContainingModule(page.m_addrRange.m_dwBaseAddress);
		if (mod)
		{
			page.m_pContainingModule = mod;
			return true;
		}

		// Try take some guesses based on what the page contains
		unsigned char *buffer = new unsigned char[page.m_MBI.RegionSize];
		if (m_pProcess->RemoteRead(page.m_addrRange, buffer))
		{
			PEParse::PEParser pe(buffer, true);
			
			// Page contains a valid PE header
			if (pe.IsValid())
			{
				// At this point we have located a valid PE header inside a region of memory not associated with any modules
				// We can only assume that this is either a live manually mapped module
				// OR a module the program is holding in memory for whatever reason (the program is going to map it somewhere else?)

				// In either case, we should add it to our modules list
				ProcessModule pm;
				pm.SetFlag(ProcessModule::MF_Manual, true);
				pm.SetFlag(ProcessModule::MF_Live, page.m_MBI.RegionSize <= 0x1000);

				pm.m_addrRange.m_dwBaseAddress = page.m_addrRange.m_dwBaseAddress;
				pm.m_addrRange.m_cbSize		   = pe.GetNTHeader()->OptionalHeader.SizeOfImage;

				pm.m_strModuleName = NameHiddenModule(pe, page.m_MBI, pm);
				m_Modules.push_back(pm);

				page.m_pContainingModule = &m_Modules.back();

				printf("[+] Found hidden module %s @ 0x%x\n", pm.m_strModuleName.c_str(), page.m_addrRange.m_dwBaseAddress);

				m_Finds.push_back({ page.m_addrRange, std::string("Unlisted PE Module ") + pm.m_strModuleName.c_str() });

				delete buffer;
				return true;
			}
			else
			{

				// See if it contains data or code that we recognise
				if (CheckCommonPatterns(buffer, page))
				{
					delete buffer;
					return true;
				}
			}
		}
		delete buffer;
		
		return false;
	}

	bool ProcessSnapshot::CheckCommonPatterns(unsigned char* pageStart, ProcessMemoryPage& page)
	{
		// VS 2015 x86 DLL - ___security_init_cookie - 8D 45 F4 50 FF 15 ? ? ? ? 8B 45 F8
		if (Utilities::FindPattern((uintptr_t)pageStart, page.m_MBI.RegionSize, (BYTE*)"\x8D\x45\xF4\x50\xFF\x15\x00\x00\x00\x00\x8B\x45\xF8", "xxxxxx????xxx") != NULL)
		{
			printf("[+] Code page matches VS 2015 x86 CRT\n");
			page.m_strLabel = "UNKN .text";

			m_Finds.push_back({ page.m_addrRange, std::string("Stray .text section (VS 2015 x86)")});
			return true;
		}

		// TODO: add more
		// possibly common strings that the crt and libs add to rdata?

		return false;
	}

	ProcessModule* ProcessSnapshot::GetContainingModule(uintptr_t address)
	{
		for (auto& mod : m_Modules)
		{
			if (mod.m_addrRange.Contains(address))
				return &mod;
		}

		return nullptr;
	}

	ProcessMemoryPage* ProcessSnapshot::GetContainingPage(uintptr_t address)
	{
		for (auto& page : m_Memory)
		{
			if (page.m_addrRange.Contains(address))
				return &page;
		}

		return nullptr;
	}

	std::string ProcessSnapshot::NameHiddenModule(PEParse::PEParser& pe, MEMORY_BASIC_INFORMATION &mbi, ProcessModule& mod)
	{
		static int counter = 0; counter++;
		DWORD address = (DWORD)mbi.BaseAddress;

		// Generate default name incase of no success
		char tempName[255];
		sprintf_s(tempName, "unknown%d.dll", counter);

		//
		// Attempt 1: Retrieval by debug directory PDB path
		//
		DWORD addr = pe.GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG)->VirtualAddress + address;

		IMAGE_DEBUG_DIRECTORY reloc_dir;
		if (addr && m_pProcess->RemoteRead(addr, &reloc_dir, sizeof(IMAGE_DEBUG_DIRECTORY)))
		{
			if (reloc_dir.Type == IMAGE_DEBUG_TYPE_CODEVIEW)
			{
				PEParse::PdbInfo pdbInfo;
				if (reloc_dir.AddressOfRawData && m_pProcess->RemoteRead((DWORD)reloc_dir.AddressOfRawData + address, &pdbInfo, sizeof(PEParse::PdbInfo)))
				{
					char filenamebuilder[255];
					strcpy_s(filenamebuilder, pdbInfo.m_szPdbFileName);

					// Strip path and replace .pdb with .dll
					PathStripPathA(filenamebuilder);
					char* dot = strrchr(filenamebuilder, '.');
					dot += 1; dot[0] = 'd'; dot[1] = 'l'; dot[2] = 'l';

					return filenamebuilder;
				}
			}
		}


		//
		// Attempt 2: Check if it's a file mapping
		//
		if (mod.GetFlag(ProcessModule::MF_Live) == false)
		{
			char szMappedName[255];
			ZeroMemory(szMappedName, 255);

			if ((mbi.Type == MEM_MAPPED) &&
				(GetMappedFileNameA(m_pProcess->GetProcessHandle(), mbi.AllocationBase, szMappedName, 255) != 0))
			{
				mod.m_strModulePath = szMappedName; // We also get a full path this way :^)
				auto fileStart = strrchr(szMappedName, '\\');

				return fileStart + 1;
			}
		}

		return tempName;
	}

	// TODO: CRT init hunting
	
	  
}