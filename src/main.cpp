/*
	THIS FILE IS JUST A TEMP TESTING GROUND FOR NOW
*/

#include <iostream>
#include "process.h"
#include <winplusplus.h>

int main (int argc, char* argv[])
{
	Codefinder::Process p("bf3.exe");

	if (p.IsConnected())
	{
		std::printf("Attached to process...\n");
		std::printf("Path: %s\n", p.GetProcessPath());
		std::printf("Name: %s\n", p.GetProcessName());
		std::printf("Process ID: %d\n\n", p.GetProcessID());

		Codefinder::ProcessSnapshot* snapper = p.Snapshot();
		if (snapper)
		{
			for (auto& mod : snapper->GetModules())
			{
				std::printf("0x%x\t\t%s\n", mod.m_addrRange.m_dwBaseAddress, mod.m_strModuleName.c_str());
			}
		}
		else
		{
			std::printf("Snapshot failed!\n");
		}
	}
	else
	{
		std::printf("Failed to find process\n");
	}
	
	return 0;
}