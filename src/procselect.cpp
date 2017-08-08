// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 08/08/17
*/
// --------------------------------------------------------------
#include "procselect.h"

#include <iostream>
#include <winplusplus.h>
#include <ShlObj.h>
#include <Windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "resource.h"
#include "codefinder.h"
#include "process.h"

using namespace WPP;

namespace Codefinder
{
	namespace UIComponents
	{
		class ProcSelect : public Dialog
		{
		public:
			ProcSelect() : Dialog(IDD_PROCDIAG)
			{
				AddCommandEvent(IDC_PROCATTACH, &ProcSelect::OnProcessAttach);
			}

			MESSAGE_ONINITDIALOG()
			{
				RegisterControl(IDC_PROCLIST, &m_view);

				PROCESSENTRY32 pEntry;
				HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
				pEntry.dwSize = sizeof(pEntry);

				// Add all running processes to the list box
				do
				{
					std::string name = pEntry.szExeFile;

					if (name.length() > 0 && strstr(name.c_str(), ".exe"))
					{
						m_view->Add(name.c_str());
						m_Processes.push_back(name);
					}

				} while (Process32Next(hPID, &pEntry));

				if (hPID)
					CloseHandle(hPID);

				return Dialog::OnInitDialog(hWnd, wParam, lParam);
			}

			/*
				Attach to the process:
				Create a new instance of a Codefinder Process wrapper
				Inform the main window that it needs to refresh
			*/
			COMMAND_HANDLER(OnProcessAttach)
			{
				auto cf = Codefinder::CodefinderApp::GetInstance();
				std::string strNewProc = m_Processes.at(m_view->GetSelected());

				if (strNewProc.length() > 4)
				{
					cf->m_pCurrentProcess = new Codefinder::Process(strNewProc);
					SendMessageA(cf->m_hwndMainDialog, WM_COMMAND, MAKEWPARAM(ID_REFRESH_STATE, ID_REFRESH_STATE), ID_REFRESH_STATE);
					this->EndDialog();
				}
				else
				{
					this->MsgBoxError("Invalid Selection", "Please select a valid process");
				}


				return FALSE;
			}

		private:
			ListBox *m_view = nullptr;
			std::vector<std::string> m_Processes;
		};

		DWORD WINAPI ProcessSelectionThread(LPVOID param)
		{
			(new ProcSelect())->RunDlg();
			return 0;
		}

		void SpawnProcessSelectionDialog()
		{
			CreateThread(0, 0, ProcessSelectionThread, 0, 0, 0);
		}

	
	}
}