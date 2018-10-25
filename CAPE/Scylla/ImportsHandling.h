#pragma once

#include <windows.h>
#include <map>
#include <hash_map>

class ImportThunk;
class ImportModuleThunk;

class ImportsHandling
{
public:
	std::map<DWORD_PTR, ImportModuleThunk> moduleList;
	std::map<DWORD_PTR, ImportModuleThunk> moduleListNew;

	ImportsHandling();
	~ImportsHandling();

	unsigned int thunkCount() const { return m_thunkCount; }
	unsigned int invalidThunkCount() const { return m_invalidThunkCount; }
	unsigned int suspectThunkCount() const { return m_suspectThunkCount; }

	void clearAllImports();
	void selectImports(bool invalid, bool suspect);

	void scanAndFixModuleList();

private:
	DWORD numberOfFunctions;

	unsigned int m_thunkCount;
	unsigned int m_invalidThunkCount;
	unsigned int m_suspectThunkCount;

	CHAR stringBuffer[600];

	void updateCounts();

	bool findNewModules(std::map<DWORD_PTR, ImportThunk> & thunkList);

	bool addModuleToModuleList(const CHAR * moduleName, DWORD_PTR firstThunk);
	void addUnknownModuleToModuleList(DWORD_PTR firstThunk);
	bool addNotFoundApiToModuleList(const ImportThunk * apiNotFound);
	bool addFunctionToModuleList(const ImportThunk * apiFound);
	bool isNewModule(const CHAR * moduleName);
};
