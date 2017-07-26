// --------------------------------------------------------------
/*
Codefinder
An experiment for finding injected code in windows processes

Author: Synraw ( Mike )
Date: 27/07/17
*/
// --------------------------------------------------------------
#include "util.h"

namespace Codefinder
{
	namespace Utilities
	{
		/*
			Checks to see if the source data and the pattern match with the given mask
		*/
		bool bytePatternCompare(unsigned char* source, unsigned char* pattern, char* mask)
		{
			while( *mask )
			{
				if (*mask == 'x' && *source != *pattern)
					return false;

				++mask; ++source; ++pattern;
			}

			return true;
		}

		/*
			Tries to find a place in the given region of data that matches the pattern and mask
			Returns NULL if pattern is not found
		*/
		uintptr_t FindPattern(uintptr_t startAddress, size_t length, unsigned char* bytes, char* mask)
		{
			for (size_t count = 0; count < length; count++)
			{
				uintptr_t location = startAddress + count;

				if (bytePatternCompare((unsigned char*)location, bytes, mask))
					return location;
			}

			return 0;
		}
	}
}