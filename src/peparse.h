// --------------------------------------------------------------
/*
	Codefinder
	An experiment for finding injected code in windows processes

	Author: Synraw ( Mike )
	Date: 22/07/17
*/
// --------------------------------------------------------------
#pragma once

#include <iostream>
#include <string>
#include <vector>

#include <Windows.h>

namespace Codefinder
{
	namespace PEParse
	{

		// Stores info on a single module function export
		struct Exports
		{
			std::string m_strName;

			uint16_t m_uOrdinal = 0;
			uint32_t m_uOffset = 0;

			bool operator == (std::string name)
			{
				return m_strName == name;
			}
		};

		// Stores info on a single module function import
		struct Imports
		{
			bool		m_bIsOrdinal = false;
			uint16_t	m_uOrdinal = 0;
			std::string m_strModuleName, m_strFunctionName;
			uintptr_t	m_uFunctionAddress;

			bool operator == (std::string name)
			{
				return m_strFunctionName == name;
			}
		};

		// Stores info on a single module relocation
		struct Relocs
		{
			uint32_t m_uOffset, m_uIndex;
			uint8_t m_fFlag;
			inline bool IsHighlow() { return m_fFlag == IMAGE_REL_BASED_HIGHLOW; }
		};

		// PDB Debug file info
		struct PdbInfo
		{
			uint32_t	m_uSignature;
			uint8_t		m_uGuid[16];
			uint32_t	m_uAge;
			char		m_szPdbFileName[MAX_PATH];
		};

		/*
			Parses a PE file and provides an easy way to retrieve information from the header
			Works on both live modules and the files themselves
		*/
		class PEParser
		{
		private:
			void SetupPE();

			bool m_setupSuccess;
			bool m_fileLoaded;

			enum class PE_Error
			{
				None,
				FileDataInvalid,
				DOSHeaderInvalid,
				PEHeaderInvalid,
				FileIsx64
			} Error;

			bool  m_loaded;
			void* m_bytes;
			PIMAGE_DOS_HEADER m_pDosHeader;
			PIMAGE_NT_HEADERS m_pNTHeader;

			std::vector<IMAGE_SECTION_HEADER>	m_Sections;
			std::vector<Imports>				m_Imports;
			std::vector<std::string>			m_ImportModules;
			std::vector<Exports>				m_Exports;
			std::vector<Relocs>					m_Relocs;
			PdbInfo								m_Debug;

		public:
			PEParser(void* dataPointer, bool loaded = false);
			PEParser(std::string FileName);

			inline bool IsValid() { return m_setupSuccess; };
			inline int GetError() { return (int)Error; };
			bool IsDLL();

			inline PIMAGE_DOS_HEADER GetDosHeader() { return m_pDosHeader; }
			inline PIMAGE_NT_HEADERS GetNTHeader() { return m_pNTHeader; }

			PIMAGE_DATA_DIRECTORY				GetDataDirectory(unsigned int index);

			std::vector<IMAGE_SECTION_HEADER>	GetSections();
			std::vector<Imports>				GetImports();
			std::vector<std::string>			GetImportModules();
			std::vector<Exports>				GetExports();
			std::vector<Relocs>					GetRelocs();
			PdbInfo								GetDebug();

			DWORD RVAOffset(DWORD RVA);
		};
	}
}