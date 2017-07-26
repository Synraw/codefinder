/*
	THIS FILE IS JUST A TEMP TESTING GROUND FOR NOW
*/

#include <iostream>
#include "process.h"
#include <winplusplus.h>

#include "resource.h"

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace WPP;

class MainDialog : public Dialog
{
public:
	MainDialog() : Dialog(IDD_DIALOG)
	{
		
	}

	MESSAGE_ONINITDIALOG()
	{

		return Dialog::OnInitDialog(hWnd, wParam, lParam);
	}
};

int main (int argc, char* argv[])
{
	InitCommonControls();
	HMODULE hRichEd = LoadLibrary(TEXT("riched20.dll"));

	//(new MainDialog())->RunDlg();

	Codefinder::Process p("hl2.exe");

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
				if(mod.GetFlag(Codefinder::ProcessModule::MF_Manual))
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

	FreeLibrary(hRichEd);
	
	return 0;
}