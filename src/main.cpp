/*
	THIS FILE IS JUST A TEMP TESTING GROUND FOR NOW
*/

#include <iostream>
#include "process.h"

int main (int argc, char* argv[])
{
	Codefinder::Process p("bf3.exe");

	if (p.IsConnected())
	{
		std::printf("Attached to process...\n");
		std::printf("Path: %s\n", p.GetProcessPath());
		std::printf("Name: %s\n", p.GetProcessName());
		std::printf("Process ID: %d\n", p.GetProcessID());
	}
	else
	{
		std::printf("Failed to find process\n");
	}
	
	return 0;
}