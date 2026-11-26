/*
CAPE - Config And Payload Extraction
Copyright(C) 2026 CAPE Sandbox developers

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __HOOK_STATIC_CRYPTO_H
#define __HOOK_STATIC_CRYPTO_H

#include <windows.h>

// Register a YARA match from the internal 'static_crypto' rule. Matches discovered
// before InitialiseDebugger() completes are queued and armed by StaticCryptoProcessPending();
// later matches (e.g. unpacked or reflectively loaded regions) are armed immediately.
void StaticCryptoRegisterMatch(PVOID RegionBase, PBYTE MatchAddress, const char *Identifier);

// Arm any init-time static crypto matches once the debugger is initialised in CAPE_post_init().
void StaticCryptoProcessPending(void);

#endif
