// --------------------------------------------------------------
/*
Codefinder
An experiment for finding injected code in windows processes

Author: Synraw ( Mike )
Date: 21/07/17
*/
// --------------------------------------------------------------
#undef UNICODE
#include "snapshot.h"

#include <Shlwapi.h>
#include <TlHelp32.h>
#include <Psapi.h>

namespace Codefinder
{
	bool ProcessSnapshot::Snapshot()
	{

	}

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
					pm.m_addrRange.m_cbSize = 0xffffffff; // TODO: parse PE header to get this

					m_Modules.push_back(pm);
				}
			}
		}
	}

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

		} while (numBytes);
	}

	bool ScanMemoryRegion(ProcessMemoryPage& page)
	{

	}
}