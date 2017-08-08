// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 08/08/17
*/
// --------------------------------------------------------------
#include "codefinder.h"

namespace Codefinder
{
	CodefinderApp::CodefinderApp()
	{
		m_pCurrentProcess = nullptr;
	}

	CodefinderApp* CodefinderApp::m_pInstance = nullptr;
}