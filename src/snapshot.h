// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 21/07/17
*/
// --------------------------------------------------------------
#pragma once

#include <string>
#include <vector>
#include <Windows.h>

#include "peparse.h"

namespace Codefinder
{
	class Process;

	/*
		Stores an address range in the form of a base address and a size in bytes
	*/
	struct AddressRange
	{
		AddressRange() : m_dwBaseAddress(0), m_cbSize(0) {}
		AddressRange(uintptr_t base, size_t size) : m_dwBaseAddress(base), m_cbSize(size) {}

		uintptr_t m_dwBaseAddress;
		size_t	  m_cbSize;

		// Checks if the address in contained within the range
		bool Contains(uintptr_t addr)
		{
			if (m_cbSize == 0xffffffff)
				return false;

			if (m_dwBaseAddress <= addr && (m_dwBaseAddress + m_cbSize) >= addr)
				return true;

			return false;
		}
	};

	/*
		Stores information about a single module inside of a process
	*/
	struct ProcessModule
	{
		ProcessModule() {}

		// Meta data
		std::string m_strModuleName;
		std::string m_strModulePath;

		// Details
		AddressRange m_addrRange;

		enum ModuleFlags : char
		{
			MF_Live = 1 << 0, // Module is live and running, as opposed to just being a buffer containing the module file
			MF_Manual = 1 << 1, // Module was mapped manually into the process, or was an attempt was made to hide the module
		};

		ModuleFlags m_fFlags;

		inline void SetFlag(ModuleFlags flag, bool value = true)
		{
			if (value)
				(char&)m_fFlags |= (char)flag;
			else
				(char&)m_fFlags &= ~(char)flag;
		}

		inline bool GetFlag(ModuleFlags flag)
		{
			return ((char)m_fFlags & (char)flag) != 0;
		}
	};

	/*
		Stores information about a single allocated page inside of a process
	*/
	struct ProcessMemoryPage
	{
		AddressRange m_addrRange;
		MEMORY_BASIC_INFORMATION m_MBI;

		// If the page is a section of a module, this ptr will be set
		ProcessModule * m_pContainingModule;
		
		// Any extra info about the section to be displayed
		std::string m_strLabel;

		inline bool IsExecutable()
		{
			return m_MBI.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		}
	};

	/*
		Stores information about a thread which has ran in the process
	*/
	struct ProcessThread
	{
		DWORD m_theadID;
		HANDLE m_hThreadHandle;
		uintptr_t m_dwStartAddress;

		bool m_bIsManualCode;
		ProcessMemoryPage*	m_pPage;
		ProcessModule*		m_pModule;
	};

	/*
		Stores a small summary about something interesting that has been found
	*/
	struct SuspiciousData
	{
		AddressRange		m_addrLocation;   // Where it was found
		std::string			m_strDesc; // Description to be displayed to the user
	};

	/*
		Stores a state snapshot of a process. The reason for splitting this from the process class is so that
		states can be compared over time to see changes being made in the process (new memory allocated, new modules..)
	*/
	class ProcessSnapshot
	{
	public:
		ProcessSnapshot(Codefinder::Process* process) : m_pProcess{ process } { }

		// Go!!!
		bool Snapshot( );

		std::vector<ProcessModule>&		GetModules() { return m_Modules; }
		std::vector<ProcessMemoryPage>&	GetMemory() { return m_Memory; }
		std::vector<ProcessThread>&		GetThreads() { return m_Threads; }
		std::vector<SuspiciousData>&	GetFoundItems() { return m_Finds; }

	private:
		Codefinder::Process* m_pProcess;

		// Retrieved data
		std::vector<ProcessModule>		m_Modules;
		std::vector<ProcessMemoryPage>	m_Memory;
		std::vector<ProcessThread>		m_Threads;
		std::vector<SuspiciousData>		m_Finds;

		void UpdateModules();
		void UpdateMemoryRegions(); // Assumes module list is already populated ( with UpdateModules() )
		void UpdateThreads();

		// Uses the contents of the page to try discover if it is anything of use to us
		bool ScanMemoryRegion(ProcessMemoryPage& page);
		bool CheckCommonPatterns(unsigned char* pageStart, ProcessMemoryPage& page);

		// Returns the module containing the given address. Returns nullptr otherwise
		ProcessModule* GetContainingModule(uintptr_t address);

		// Returns the module containing the given address. Returns nullptr otherwise
		ProcessMemoryPage* GetContainingPage(uintptr_t address);

		// Attemps to guess the name of or atleast provide a dummy name for a hidden module
		std::string NameHiddenModule(PEParse::PEParser& pe, MEMORY_BASIC_INFORMATION &mbi, ProcessModule& mod);
	};
	
}