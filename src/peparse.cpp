// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 22/07/17
*/
// --------------------------------------------------------------
#include "peparse.h"

#include <memory>
#include <algorithm>

namespace Codefinder
{
	namespace PEParse
	{

		//
		// Setup from an existing loaded PE
		//
		PEParser::PEParser(void* dataPointer, bool loaded)
		{
			Error = PE_Error::None;
			m_Debug.m_uAge = NULL;
			m_Debug.m_uSignature = NULL;
			strcpy_s(m_Debug.m_szPdbFileName, "No PDB Path");

			m_bytes = dataPointer;
			m_loaded = loaded;
			SetupPE();
		}

		PEParser::PEParser(std::string FileName)
		{
			Error = PE_Error::None;
			m_Debug.m_uAge = NULL;
			m_Debug.m_uSignature = NULL;
			strcpy_s(m_Debug.m_szPdbFileName, "No PDB Path");
			m_loaded = false;

			HANDLE file_handle = CreateFile(FileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (file_handle > 0)
			{
				DWORD file_size = GetFileSize(file_handle, NULL);

				if (file_size != INVALID_FILE_SIZE)
				{
					std::unique_ptr<uint8_t[]> file_buffer(new uint8_t[file_size]);

					if (ReadFile(file_handle, file_buffer.get(), file_size, &file_size, NULL))
					{
						m_bytes = file_buffer.get();
						SetupPE();
					}
				}
				CloseHandle(file_handle);
			}

		}

		void PEParser::SetupPE()
		{
			m_setupSuccess = false;

			// Data pointer isn't valid
			if (m_bytes == nullptr)
			{
				Error = PE_Error::FileDataInvalid;
				return;
			}

			// Check DOS header is valid
			m_pDosHeader = (PIMAGE_DOS_HEADER)m_bytes;
			if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				Error = PE_Error::DOSHeaderInvalid;
				return;
			}

			// Get the NT header
			m_pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD)m_pDosHeader + m_pDosHeader->e_lfanew);

			// Make sure it's valid
			if (m_pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				Error = PE_Error::PEHeaderInvalid;
				return;
			}

			// We won't accept 64 bit files
			if (m_pNTHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			{
				Error = PE_Error::FileIsx64;
				return;
			}

			m_setupSuccess = true;

			/*GetSections();
			GetImports();
			GetExports();
			GetRelocs();*/
		}

		//
		// RVA to file offset
		//
		DWORD PEParser::RVAOffset(DWORD RVA)
		{
			if (m_setupSuccess)
			{
				if (m_loaded)
				{
					return (DWORD)m_bytes + RVA;
				}
				else
				{
					for (auto Section : GetSections())
					{
						if (RVA >= Section.VirtualAddress &&
							RVA < (Section.VirtualAddress + (Section.Misc.VirtualSize == 0 ? Section.SizeOfRawData : Section.Misc.VirtualSize)))
						{
							DWORD delta = (DWORD)(Section.VirtualAddress - Section.PointerToRawData);
							return (DWORD)((DWORD)m_bytes + RVA - delta);
						}
					}
				}


				return RVA;

			}
			return 0;
		}

		std::vector<IMAGE_SECTION_HEADER> PEParser::GetSections()
		{
			if (m_setupSuccess && m_Sections.empty())
			{
				m_Sections.reserve(GetNTHeader()->FileHeader.NumberOfSections);
				PIMAGE_SECTION_HEADER iter_section = IMAGE_FIRST_SECTION(m_pNTHeader);

				for (unsigned int i = 0; i < m_pNTHeader->FileHeader.NumberOfSections; i++, iter_section++)
				{
					m_Sections.push_back(*iter_section);
				}

			}

			return m_Sections;
		}

		PIMAGE_DATA_DIRECTORY PEParser::GetDataDirectory(unsigned int index)
		{
			if (m_setupSuccess && index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
			{
				return &GetNTHeader()->OptionalHeader.DataDirectory[index];
			}

			return nullptr;
		}

		std::vector<Imports> PEParser::GetImports()
		{
			if (m_Imports.empty() && m_setupSuccess)
			{
				PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(RVAOffset(GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress));
				if (import_desc)
				{
					while (import_desc->OriginalFirstThunk && import_desc->Name)
					{
						PIMAGE_THUNK_DATA32 current_thunk = (PIMAGE_THUNK_DATA32)RVAOffset(import_desc->OriginalFirstThunk);

						while (current_thunk->u1.AddressOfData > 0)
						{
							Imports im;
							im.m_strModuleName = (const char*)(RVAOffset(import_desc->Name));

							if (std::find(m_ImportModules.begin(), m_ImportModules.end(), im.m_strModuleName) == m_ImportModules.end())
							{
								m_ImportModules.push_back(im.m_strModuleName);
							}

							if (current_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							{
								im.m_bIsOrdinal = true;
								im.m_strFunctionName = "Ordinal";
								im.m_uOrdinal = (uint16_t)(current_thunk->u1.Ordinal & ~(IMAGE_ORDINAL_FLAG32));
								im.m_uFunctionAddress = (uintptr_t)current_thunk->u1.Function;
							}
							else {
								im.m_bIsOrdinal = false;
								im.m_strFunctionName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(RVAOffset(current_thunk->u1.AddressOfData))->Name;
								im.m_uFunctionAddress = (uintptr_t)current_thunk->u1.Function;
							}

							m_Imports.push_back(im);
							current_thunk++;
						}

						import_desc++;
					}
				}
			}

			return m_Imports;
		}

		std::vector<std::string> PEParser::GetImportModules()
		{
			return m_ImportModules;
		}

		std::vector<Exports> PEParser::GetExports()
		{
			if (m_Exports.empty() && m_setupSuccess && GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)->Size > 0)
			{
				PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)RVAOffset(GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress);

				if (export_dir)
				{
					m_Exports.reserve(export_dir->NumberOfNames);

					uint16_t *ordinal_table = (uint16_t *)(RVAOffset(export_dir->AddressOfNameOrdinals));
					uint32_t *name_table = (uint32_t *)(RVAOffset(export_dir->AddressOfNames));
					uint32_t *function_table = (uint32_t *)(RVAOffset(export_dir->AddressOfFunctions));

					for (unsigned int i = 0; i < export_dir->NumberOfNames; i++)
					{
						Exports ex;
						ex.m_uOrdinal = ordinal_table[i] + (uint16_t)export_dir->Base;
						ex.m_uOffset = function_table[ordinal_table[i]];
						ex.m_strName = (const char*)RVAOffset(name_table[i]);

						m_Exports.push_back(ex);
					}
				}
			}

			return m_Exports;
		}

		std::vector<Relocs>  PEParser::GetRelocs()
		{
			if (m_Relocs.empty() && m_setupSuccess)
			{
				PIMAGE_BASE_RELOCATION reloc_dir = (PIMAGE_BASE_RELOCATION)RVAOffset(GetDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress);

				while (reloc_dir->VirtualAddress > 0)
				{
					if (reloc_dir && reloc_dir->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
					{
						int relocCount = (reloc_dir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
						PWORD relocList = (PWORD)(reloc_dir + 1);

						for (int i = 0; i < relocCount; i++)
						{
							if (relocList[i])
							{
								Relocs rl;
								rl.m_uIndex = i;
								rl.m_uOffset = reloc_dir->VirtualAddress + (relocList[i] & 0xFFF);
								rl.m_fFlag = relocList[i] >> 12;
								m_Relocs.push_back(rl);
							}
						}
					}

					reloc_dir = (PIMAGE_BASE_RELOCATION)(((char *)reloc_dir) + reloc_dir->SizeOfBlock);
				}

			}

			return m_Relocs;
		}

		bool PEParser::IsDLL()
		{
			return ((GetNTHeader()->FileHeader.Characteristics & IMAGE_FILE_DLL) && m_setupSuccess) ? true : false;
		}

		PdbInfo PEParser::GetDebug()
		{
			if (m_Debug.m_uAge == NULL && m_Debug.m_uSignature == NULL)
			{
				PIMAGE_DEBUG_DIRECTORY reloc_dir = (PIMAGE_DEBUG_DIRECTORY)RVAOffset(GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG)->VirtualAddress);
				if (reloc_dir && reloc_dir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
				{
					PdbInfo* pdb_info = reinterpret_cast<PdbInfo*>(RVAOffset(reloc_dir->AddressOfRawData));
					memcpy(&m_Debug, pdb_info, sizeof(PdbInfo));
				}
			}

			return m_Debug;
		}
	}
}