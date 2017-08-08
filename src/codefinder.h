// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 08/08/17
*/
// --------------------------------------------------------------
#pragma once

#include <string>
#include <Windows.h>

namespace Codefinder
{
	class Process;

	/*
		Handles the main program state and acts as a link between the program
		functionality and the dialogs. Bit of a god class but w/e :^)
	*/
	class CodefinderApp
	{
	public:
		// Singleton getter ughhh
		inline static CodefinderApp* GetInstance()
		{
			if (m_pInstance == nullptr)
			{
				m_pInstance = new CodefinderApp();
			}

			return m_pInstance;
		}

		Process* m_pCurrentProcess;
		std::string m_strOutputPath;

		HWND m_hwndMainDialog;

	private:

	protected:
		// Singleton related garbage
		CodefinderApp(CodefinderApp const&) {};
		CodefinderApp& operator=(CodefinderApp&){}
		static CodefinderApp* m_pInstance;

		CodefinderApp();
	};
}