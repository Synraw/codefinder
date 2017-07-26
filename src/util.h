// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 27/07/17
*/
// --------------------------------------------------------------
#pragma once

#include <Windows.h>

namespace Codefinder
{
	namespace Utilities
	{
		uintptr_t FindPattern(uintptr_t startAddress, size_t length, unsigned char* bytes, char* mask);
	}
}