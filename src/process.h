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

	private:

		HANDLE	m_hProcess;
		DWORD	m_dwProcID;

	};

}

