// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 20/07/17
*/
// --------------------------------------------------------------
#pragma once

#include <string>
#include <Windows.h>

#include "snapshot.h"

namespace Codefinder
{

	/*
		Provides a way to retrieve information about a given process
	*/
	class Process
	{
	public:
		Process();
		Process(unsigned int processID);
		Process(std::string processName);

		~Process();

		static unsigned int GetProcessIDFromName(std::string processName);

		bool Initialise(unsigned int processID);

		inline bool IsConnected() { return m_hProcess != NULL; }
		inline DWORD GetProcessID() { return m_dwProcID; }

		inline const char* GetProcessPath() { return m_szPath; }
		inline const char* GetProcessName() { return m_szName; }
		inline HANDLE	   GetProcessHandle() { return m_hProcess; }

		// VirtualAlloc Wrapper
		inline uintptr_t	RemoteAllocate(size_t bytes, uintptr_t remoteAddress, DWORD allocType, DWORD protection)
		{
			return (uintptr_t)VirtualAllocEx(m_hProcess, (LPVOID)remoteAddress, bytes, allocType, protection);
		}

		// WPM Wrapper
		inline bool		RemoteWrite(uintptr_t remoteAddress, void* localBuffer, size_t bytes)
		{
			return WriteProcessMemory(m_hProcess, (LPVOID)remoteAddress, localBuffer, bytes, nullptr) == TRUE;
		}

		// RPM Wrappers
		inline bool		RemoteRead(uintptr_t remoteAddress, void* localBuffer, size_t bytes)
		{
			return ReadProcessMemory(m_hProcess, (LPVOID)remoteAddress, localBuffer, bytes, nullptr) == TRUE;
		}

		inline bool		RemoteRead(AddressRange range, void* localBuffer)
		{
			return RemoteRead(range.m_dwBaseAddress, localBuffer, range.m_cbSize);
		}

		bool FreePage(ProcessMemoryPage page)
		{
			return VirtualFreeEx(m_hProcess, page.m_MBI.BaseAddress, page.m_MBI.RegionSize, MEM_RELEASE) == TRUE;
		}

	private:

		HANDLE	m_hProcess;
		DWORD	m_dwProcID;

		char	m_szPath[MAX_PATH];
		char	m_szName[MAX_PATH];

	};

}

