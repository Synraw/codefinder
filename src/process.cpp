// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 20/07/17
*/
// --------------------------------------------------------------

#undef UNICODE

#include "process.h"

#include <Shlwapi.h>
#include <TlHelp32.h>
#include <Psapi.h>

namespace Codefinder
{
	/*
		Don't setup the process just yet. 
	*/
	Process::Process() : m_dwProcID{0}, m_hProcess{0}
	{

	}

	/*
		Connects to a new process by name
	*/
	Process::Process(std::string processName) : m_dwProcID{ 0 }, m_hProcess{ 0 }
	{
		unsigned int processID = GetProcessIDFromName(processName);

		if (processID)
		{
			Initialise(processID);
		}
	}

	/*
		Connects to a new process by process ID
	*/
	Process::Process(unsigned int processID) : m_dwProcID{ 0 }, m_hProcess{ 0 }
	{
		Initialise(processID);
	}

	Process::~Process()
	{
		if (m_hProcess)
		{
			CloseHandle(m_hProcess);
		}
	}

	/*
		Attempts to get a process ID from a process name (eg notepad.exe)
		Returns 0 on failure
	*/
	unsigned int Process::GetProcessIDFromName(std::string processName)
	{
		DWORD dwPID = 0;
		PROCESSENTRY32 pEntry;
		HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		pEntry.dwSize = sizeof(pEntry);

		do
		{
			if (!strcmp(pEntry.szExeFile, processName.c_str()))
			{
				dwPID = pEntry.th32ProcessID;
			}
		}
		while (Process32Next(hPID, &pEntry));

		if (hPID)
			CloseHandle(hPID);

		return dwPID;
	}

	/*
		Attempts to connect to the process, Returns true on success
	*/
	bool Process::Initialise(unsigned int processID)
	{
		if (processID != NULL)
		{
			m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

			if (m_hProcess != NULL && m_hProcess != INVALID_HANDLE_VALUE)
			{
				m_dwProcID = processID;

				memset(m_szPath, 0, MAX_PATH);
				memset(m_szName, 0, MAX_PATH);

				GetModuleFileNameEx(m_hProcess, NULL, m_szPath, MAX_PATH);
				strcpy_s(m_szName, m_szPath);
				PathStripPath(m_szName);

				return true;
			}
		}

		return false;
	}

}