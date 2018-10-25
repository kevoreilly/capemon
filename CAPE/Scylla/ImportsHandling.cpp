#include "ImportsHandling.h"

#include "Thunks.h"
#include "Architecture.h"

//#define DEBUG_COMMENTS

extern "C" void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern "C" void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

void ImportThunk::invalidate()
{
	ordinal = 0;
	hint = 0;
	valid = false;
	suspect = false;
	moduleName[0] = 0;
	name[0] = 0;
}

bool ImportModuleThunk::isValid() const
{
	std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin();
	while (iterator != thunkList.end())
	{
		if (iterator->second.valid == false)
		{
			return false;
		}
		iterator++;
	}

	return true;
}

DWORD_PTR ImportModuleThunk::getFirstThunk() const
{
	if (thunkList.size() > 0)
	{
		const std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin();
		return iterator->first;
	}
	else
	{
		return 0;
	}
}

ImportsHandling::ImportsHandling()
{
	m_thunkCount = m_invalidThunkCount = m_suspectThunkCount = 0;
}

ImportsHandling::~ImportsHandling()
{
}

void ImportsHandling::updateCounts()
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	std::map<DWORD_PTR, ImportThunk>::iterator it_import;

	m_thunkCount = m_invalidThunkCount = m_suspectThunkCount = 0;

	it_module = moduleList.begin();
	while (it_module != moduleList.end())
	{
		ImportModuleThunk &moduleThunk = it_module->second;

		it_import = moduleThunk.thunkList.begin();
		while (it_import != moduleThunk.thunkList.end())
		{
			ImportThunk &importThunk = it_import->second;

			m_thunkCount++;
			if(!importThunk.valid)
				m_invalidThunkCount++;
			else if(importThunk.suspect)
				m_suspectThunkCount++;

			it_import++;
		}

		it_module++;
	}
}

void ImportsHandling::clearAllImports()
{
	moduleList.clear();
	updateCounts();
}

void ImportsHandling::selectImports(bool invalid, bool suspect)
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	std::map<DWORD_PTR, ImportThunk>::iterator it_import;

	it_module = moduleList.begin();
	while (it_module != moduleList.end())
	{
		ImportModuleThunk &moduleThunk = it_module->second;

		it_import = moduleThunk.thunkList.begin();
		while (it_import != moduleThunk.thunkList.end())
		{
			ImportThunk &importThunk = it_import->second;
			it_import++;
		}

		it_module++;
	}
}

void ImportsHandling::scanAndFixModuleList()
{
	CHAR prevModuleName[MAX_PATH] = {0};
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	std::map<DWORD_PTR, ImportThunk>::iterator it_import;

	it_module = moduleList.begin();
	while (it_module != moduleList.end())
	{
		ImportModuleThunk &moduleThunk = it_module->second;

		it_import = moduleThunk.thunkList.begin();

		ImportThunk * importThunkPrev;
		importThunkPrev = &it_import->second;

		while (it_import != moduleThunk.thunkList.end())
		{
			ImportThunk &importThunk = it_import->second;

			if (importThunk.moduleName[0] == 0 || importThunk.moduleName[0] == L'?')
			{
				DoOutputDebugString("API not found - added to module list.");
                addNotFoundApiToModuleList(&importThunk);
			}
			else 
			{
				
				if (_stricmp(importThunk.moduleName, prevModuleName))
				{
                    DoOutputDebugString("Adding module to module list: %s", importThunk.moduleName);
					addModuleToModuleList(importThunk.moduleName, importThunk.rva);
				}
				
				addFunctionToModuleList(&importThunk);
			}

			strcpy_s(prevModuleName, importThunk.moduleName);
			it_import++;
		}

		moduleThunk.thunkList.clear();

		it_module++;
	}

	moduleList = moduleListNew;
	moduleListNew.clear();
}

bool ImportsHandling::findNewModules(std::map<DWORD_PTR, ImportThunk> & thunkList)
{
	throw std::exception("The method or operation is not implemented.");
}

bool ImportsHandling::addModuleToModuleList(const CHAR * moduleName, DWORD_PTR firstThunk)
{
	ImportModuleThunk module;

	module.firstThunk = firstThunk;
	strcpy_s(module.moduleName, moduleName);

	module.key = module.firstThunk;
	moduleListNew[module.key] = module;
	return true;
}

bool ImportsHandling::isNewModule(const CHAR * moduleName)
{
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;

	it_module = moduleListNew.begin();
	while (it_module != moduleListNew.end())
	{
		if (!_stricmp(it_module->second.moduleName, moduleName))
		{
			return false;
		}

		it_module++;
	}

	return true;
}

void ImportsHandling::addUnknownModuleToModuleList(DWORD_PTR firstThunk)
{
	ImportModuleThunk module;

	module.firstThunk = firstThunk;
	strcpy_s(module.moduleName, "?");

	module.key = module.firstThunk;
	moduleListNew[module.key] = module;
}

bool ImportsHandling::addNotFoundApiToModuleList(const ImportThunk * apiNotFound)
{
	ImportThunk import;
	ImportModuleThunk  * module = 0;
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;
	DWORD_PTR rva = apiNotFound->rva;

	if (moduleListNew.size() > 0)
	{
		it_module = moduleListNew.begin();
		while (it_module != moduleListNew.end())
		{
			if (rva >= it_module->second.firstThunk)
			{
				it_module++;
				if (it_module == moduleListNew.end())
				{
					it_module--;
					//new unknown module
					if (it_module->second.moduleName[0] == L'?')
					{
						module = &(it_module->second);
					}
					else
					{
						addUnknownModuleToModuleList(apiNotFound->rva);
						module = &(moduleListNew.find(rva)->second);
					}

					break;
				}
				else if (rva < it_module->second.firstThunk)
				{
					it_module--;
					module = &(it_module->second);
					break;
				}
			}
			else
			{
#ifdef DEBUG_COMMENTS
				DoOutputDebugString("Error iterator1 != (*moduleThunkList).end()");
#endif
				break;
			}
		}
	}
	else
	{
		//new unknown module
		addUnknownModuleToModuleList(apiNotFound->rva);
		module = &(moduleListNew.find(rva)->second);
	}

	if (!module)
	{
#ifdef DEBUG_COMMENTS		
        DoOutputDebugString("ImportsHandling::addFunction module not found rva " PRINTF_DWORD_PTR_FULL, rva);
#endif
		return false;
	}


	import.suspect = true;
	import.valid = false;
	import.va = apiNotFound->va;
	import.rva = apiNotFound->rva;
	import.apiAddressVA = apiNotFound->apiAddressVA;
	import.ordinal = 0;

	strcpy_s(import.moduleName, "?");
	strcpy_s(import.name, "?");

	import.key = import.rva;
	module->thunkList[import.key] = import;
	return true;
}

bool ImportsHandling::addFunctionToModuleList(const ImportThunk * apiFound)
{
	ImportThunk import;
	ImportModuleThunk  * module = 0;
	std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;

	if (moduleListNew.size() > 1)
	{
		it_module = moduleListNew.begin();
		while (it_module != moduleListNew.end())
		{
			if (apiFound->rva >= it_module->second.firstThunk)
			{
				it_module++;
				if (it_module == moduleListNew.end())
				{
					it_module--;
					module = &(it_module->second);
					break;
				}
				else if (apiFound->rva < it_module->second.firstThunk)
				{
					it_module--;
					module = &(it_module->second);
					break;
				}
			}
			else
			{
#ifdef DEBUG_COMMENTS
				DoOutputDebugString("Error iterator1 != moduleListNew.end()");
#endif
				break;
			}
		}
	}
	else
	{
		it_module = moduleListNew.begin();
		module = &(it_module->second);
	}

	if (!module)
	{
#ifdef DEBUG_COMMENTS		
        DoOutputDebugString("ImportsHandling::addFunction module not found rva " PRINTF_DWORD_PTR_FULL, apiFound->rva);
#endif
		return false;
	}


	import.suspect = apiFound->suspect;
	import.valid = apiFound->valid;
	import.va = apiFound->va;
	import.rva = apiFound->rva;
	import.apiAddressVA = apiFound->apiAddressVA;
	import.ordinal = apiFound->ordinal;
	import.hint = apiFound->hint;

	strcpy_s(import.moduleName, apiFound->moduleName);
	strcpy_s(import.name, apiFound->name);

	import.key = import.rva;
	module->thunkList[import.key] = import;
	return true;
}
