#pragma once
/*
CAPE - Config And Payload Extraction
Copyright(C) 2026 CAPE Sandbox developers

This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include <windows.h>

// Called by the compileMethod hook once a managed method has been JIT compiled
// and its name resolved. If the method is in the .NET API allowlist a persistent
// software breakpoint is placed on its native entry and each call is logged as
// one behaviour-log record in the "dotnet_api" category.
void DotNetApiOnMethodCompiled(const char *NamespaceName, const char *ClassName, const char *MethodName, PVOID NativeCode);
