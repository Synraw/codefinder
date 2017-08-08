/*
	THIS FILE IS JUST A TEMP TESTING GROUND FOR NOW
*/

#include <iostream>
#include <winplusplus.h>
#include <ShlObj.h>

#include "resource.h"
#include "codefinder.h"
#include "process.h"
#include "procselect.h"

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

using namespace WPP;

/*
	This is the first dialog the user sees.
	It has a menu bar for accessing all the other parts of the program
*/
class MainDialog : public Dialog
{
public:
	
	MainDialog() : Dialog(IDD_DIALOG)
	{
		AddCommandEvent(ID_PROC_ATTACH, &MainDialog::OnProcessAttach);
		AddCommandEvent(ID_PROC_SETPATH, &MainDialog::OnSelectOutPath);
		AddCommandEvent(ID_REFRESH_STATE, &MainDialog::OnRefreshState);
	}

	MESSAGE_ONINITDIALOG()
	{
		Codefinder::CodefinderApp::GetInstance()->m_hwndMainDialog = hWnd;

		// Grab our controls
		RegisterControl(IDC_SUSLIST, &m_view);
		RegisterControl(IDC_PROCNAME, &m_procName);
		RegisterControl(IDC_PROCID, &m_procID);

		// Set up the menu bar
		HMENU hMenu = CreateMenu(), hSubMenu = CreatePopupMenu();

		AppendMenu(hSubMenu, MF_STRING, ID_PROC_ATTACH, "&Attach...");
		AppendMenu(hSubMenu, MF_STRING, ID_PROC_DETACH, "&Detach");
		AppendMenu(hSubMenu, MF_STRING, ID_PROC_SETPATH, "&Set Output Path...");
		AppendMenu(hMenu, MF_STRING | MF_POPUP, (UINT)hSubMenu, "&File");

		hSubMenu = CreatePopupMenu();
		AppendMenu(hSubMenu, MF_STRING, ID_VIEW_LATESTSNAP, "&Current Snapshot...");
		AppendMenu(hSubMenu, MF_STRING, ID_VIEW_SNAPLIST, "&List Snapshots...");
		AppendMenu(hMenu, MF_STRING | MF_POPUP, (UINT)hSubMenu, "&View");

		SetMenu(hWnd, hMenu);

		// Set up the list view
		m_view->InsertColumn(0, "Address", 0, 70, 0);
		m_view->InsertColumn(1, "Info", 0, 170, 1);

		return Dialog::OnInitDialog(hWnd, wParam, lParam);
	}

	COMMAND_HANDLER(OnProcessAttach)
	{
		// Close the current open process
		if (Codefinder::CodefinderApp::GetInstance()->m_pCurrentProcess)
		{
			delete Codefinder::CodefinderApp::GetInstance()->m_pCurrentProcess;
			Codefinder::CodefinderApp::GetInstance()->m_pCurrentProcess = nullptr;
		}

		Codefinder::UIComponents::SpawnProcessSelectionDialog();

		return FALSE;
	}

	COMMAND_HANDLER(OnSelectOutPath)
	{
		// Spawn a windows folder browser
		TCHAR szDir[MAX_PATH];

		BROWSEINFO bInfo;
		bInfo.hwndOwner = hWnd;
		bInfo.pidlRoot = NULL;
		bInfo.pszDisplayName = szDir;
		bInfo.lpszTitle = "Select file output folder";
		bInfo.ulFlags = 0;
		bInfo.lpfn = NULL;
		bInfo.lParam = 0;
		bInfo.iImage = -1;

		LPITEMIDLIST lpItem = SHBrowseForFolder(&bInfo);
		if (lpItem != NULL)
		{
			SHGetPathFromIDList(lpItem, szDir);
			Codefinder::CodefinderApp::GetInstance()->m_strOutputPath = szDir;
		}

		printf("[+] New output path: %s\n", Codefinder::CodefinderApp::GetInstance()->m_strOutputPath.c_str());
		return FALSE;
	}

	COMMAND_HANDLER(OnRefreshState)
	{
		// Reset the list incase it had previous results
		m_view->DeleteAllItems();

		// Validate we actually opened our handle successfully
		auto p = Codefinder::CodefinderApp::GetInstance()->m_pCurrentProcess;
		if (p && p->IsConnected())
		{
			std::printf("[+] Attached to process...\n");
			
			// Prepare to start filling our listview
			LVITEMA meme; ZeroMemory(&meme, sizeof(LVITEMA));
			meme.mask = LVIF_TEXT;
			meme.iItem = 0;
			meme.iSubItem = 0;
			meme.cchTextMax = 32;
			int item = 0;
			char buffer[64];

			// Set the labels on the main window
			sprintf_s(buffer, "Target Process: %s", p->GetProcessName());
			m_procName->SetText(buffer);

			sprintf_s(buffer, "Target PID: %d", p->GetProcessID());
			m_procID->SetText(buffer);

			// Take an initial snapshot of the process
			Codefinder::ProcessSnapshot* snapper = p->Snapshot();
			if (snapper)
			{
				// Display some basic info about what we found
				for (auto& thing : snapper->GetFoundItems())
				{
					meme.iItem = item;

					// Address
					sprintf_s(buffer, "0x%X", thing.m_addrLocation.m_dwBaseAddress);
					meme.iSubItem = 0;
					meme.pszText = buffer;
					m_view->InsertItem(&meme);
					m_view->SetItem(&meme);
					
					// Info
					meme.iSubItem = 1;
					meme.pszText = const_cast<char*>(thing.m_strDesc.c_str());
					m_view->InsertItem(&meme);
					m_view->SetItem(&meme);

					item++;
				}
			}
			else
			{
				std::printf("Snapshot failed!\n");
			}
		}

		return FALSE;
	}

private:
	ListView *m_view = nullptr;
	Static *m_procName = nullptr;
	Static *m_procID = nullptr;

};

/*
	Entry point
	Launches main dialog
*/
int main (int argc, char* argv[])
{
	InitCommonControls();
	HMODULE hRichEd = LoadLibrary(TEXT("riched20.dll"));

	(new MainDialog())->RunDlg();

	// Codefinder::Process p("hl2.exe");

	//if (p.IsConnected())
	//{
	//	std::printf("Attached to process...\n");
	//	std::printf("Path: %s\n", p.GetProcessPath());
	//	std::printf("Name: %s\n", p.GetProcessName());
	//	std::printf("Process ID: %d\n\n", p.GetProcessID());

	//	Codefinder::ProcessSnapshot* snapper = p.Snapshot();
	//	if (snapper)
	//	{
	//		for (auto& mod : snapper->GetModules())
	//		{
	//			if(mod.GetFlag(Codefinder::ProcessModule::MF_Manual))
	//				std::printf("0x%x\t\t%s\n", mod.m_addrRange.m_dwBaseAddress, mod.m_strModuleName.c_str());
	//		}
	//	}
	//	else
	//	{
	//		std::printf("Snapshot failed!\n");
	//	}
	//}
	//else
	//{
	//	std::printf("Failed to find process\n");
	//}

	FreeLibrary(hRichEd);
	
	return 0;
}