#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
get_all.py - The Ultimate .NET Runtime Extractor for Capemon
Downloads, extracts, and organizes both .NET Core/Modern .NET (via NuGet) and
classic .NET Framework runtime engines (surgically from official offline installers).

Usage:
    python get_all.py --core       # Extracts .NET Core / .NET 5+ CoreCLR DLLs
    python get_all.py --framework  # Surgically extracts .NET Framework CLR DLLs
    python get_all.py --all        # Extracts everything (Core + Framework)
"""

import os
import sys
import zipfile
import subprocess
import urllib.request
import json
import shutil
import argparse
import glob

# Destination Library Folder
DEST_LIBRARY = "C:\\Users\\Doome\\Dotnet libs"
TEMP_EXTRACT_DIR = os.path.abspath("./dotnet_temp_extraction")

# ------------------------------------------------------------------------------
# .NET CORE CONFIGURATION (NuGet packages)
# ------------------------------------------------------------------------------
CORE_PACKAGES = [
    # Legacy CoreCLR 1.0 - 2.0
    "runtime.win7-x64.microsoft.netcore.runtime.coreclr",
    "runtime.win7-x86.microsoft.netcore.runtime.coreclr",
    # Modern CoreCLR 2.1 - 10.0+
    "microsoft.netcore.app.runtime.win-x64",
    "microsoft.netcore.app.runtime.win-x86",
]

# ------------------------------------------------------------------------------
# .NET FRAMEWORK CONFIGURATION (Offline Installers & Surgical Mappings)
# ------------------------------------------------------------------------------
FRAMEWORK_INSTALLERS = {
    "Framework_1.1": {
        "url": "https://download.microsoft.com/download/1/a/5/1a53f118-006c-4f81-a88f-7b752dfbc637/dotnetfx.exe",
        "method": "Express11"
    },
    "Framework_3.5_SP1": {
        "url": "https://download.microsoft.com/download/2/0/e/20e90413-712f-438c-988e-fdaa79a8ac3d/dotnetfx35.exe",
        "method": "MSP20"
    },
    "Framework_4.5.2": {
        "url": "https://go.microsoft.com/fwlink/?LinkId=397708",
        "method": "MZZ452"
    },
    "Framework_4.6.2": {
        "url": "https://go.microsoft.com/fwlink/?linkid=780600",
        "method": "WixPayload"
    },
    "Framework_4.7.2": {
        "url": "https://go.microsoft.com/fwlink/?LinkId=863265",
        "method": "WixPayload"
    },
    "Framework_4.8.0": {
        "url": "https://go.microsoft.com/fwlink/?linkid=2088631",
        "method": "WixPayload"
    }
}

HEADERS = {"User-Agent": "DotNetExtractor/2.0"}
SEVEN_ZIP = "C:\\Program Files\\7-Zip\\7z.exe"

# ------------------------------------------------------------------------------
# HELPER UTILITIES
# ------------------------------------------------------------------------------
def get_seven_zip():
    if os.path.exists(SEVEN_ZIP):
        return SEVEN_ZIP
    path_7z = shutil.which("7z") or shutil.which("7z.exe")
    if path_7z:
        return path_7z
    print("[-] Error: 7-Zip (7z.exe) not found. Please install 7-Zip or specify path in SEVEN_ZIP.")
    sys.exit(1)

def download_file(url, dest_path):
    print(f"[+] Descargando: {url} ...")
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req) as response, open(dest_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception as e:
        print(f"[-] Error descargando: {e}")
        return False

def run_7z_extract(archive_path, out_dir, files_to_extract=None):
    seven_zip = get_seven_zip()
    cmd = [seven_zip, "x", "-y", f"-o{out_dir}", archive_path]
    if files_to_extract:
        if isinstance(files_to_extract, list):
            cmd.extend(files_to_extract)
        else:
            cmd.append(files_to_extract)
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_7z_extract_flat(archive_path, out_dir, files_to_extract=None):
    seven_zip = get_seven_zip()
    cmd = [seven_zip, "e", "-y", f"-o{out_dir}", archive_path]
    if files_to_extract:
        if isinstance(files_to_extract, list):
            cmd.extend(files_to_extract)
        else:
            cmd.append(files_to_extract)
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ------------------------------------------------------------------------------
# .NET CORE PROCESSING (NuGet based)
# ------------------------------------------------------------------------------
def get_package_versions(pkg_id):
    url = f"https://api.nuget.org/v3-flatcontainer/{pkg_id.lower()}/index.json"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get("versions", [])
    except Exception as e:
        print(f"[-] Error obteniendo versiones de {pkg_id}: {e}")
        return []

def download_and_extract_core(pkg_id, version):
    pkg_ver_dir = os.path.join(DEST_LIBRARY, pkg_id, version)
    coreclr_dest = os.path.join(pkg_ver_dir, "coreclr.dll")
    clrjit_dest = os.path.join(pkg_ver_dir, "clrjit.dll")

    if os.path.exists(coreclr_dest) and os.path.exists(clrjit_dest):
        print(f"[=] Ya existe completo: {pkg_id} @ {version}")
        return coreclr_dest

    os.makedirs(pkg_ver_dir, exist_ok=True)
    nupkg_url = f"https://api.nuget.org/v3-flatcontainer/{pkg_id.lower()}/{version}/{pkg_id.lower()}.{version}.nupkg"
    nupkg_path = os.path.join(pkg_ver_dir, f"{version}.nupkg")

    if download_file(nupkg_url, nupkg_path):
        try:
            with zipfile.ZipFile(nupkg_path, 'r') as zip_ref:
                for item in zip_ref.namelist():
                    lower_name = item.lower()
                    if lower_name.endswith("coreclr.dll") or lower_name.endswith("clrjit.dll"):
                        filename = os.path.basename(item)
                        with open(os.path.join(pkg_ver_dir, filename), "wb") as f_out:
                            f_out.write(zip_ref.read(item))
            if os.path.exists(nupkg_path):
                os.remove(nupkg_path)
            print(f"[+] Extraido exitosamente: {pkg_id} @ {version}")
            return coreclr_dest
        except Exception as e:
            print(f"[-] Error descomprimiendo {nupkg_path}: {e}")
            return None
    return None

def fetch_core_symbols(dll_path, output_dir):
    cmd = ["dotnet-symbol", "--symbols", "--windows-pdbs", "-o", output_dir, dll_path]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception as e:
         pass

def process_core_runtimes():
    print("\n=======================================================")
    print("[*] Iniciando descarga de .NET Core / Modern .NET")
    print("=======================================================")
    for pkg in CORE_PACKAGES:
        print(f"\n[*] Consultando NuGet para: {pkg}...")
        versions = get_package_versions(pkg)
        print(f"[i] Total versiones encontradas: {len(versions)}")
        
        # Filtramos para limitar o procesar las versiones deseadas
        for ver in versions:
            dll_path = download_and_extract_core(pkg, ver)
            if dll_path and os.path.exists(dll_path):
                out_dir = os.path.dirname(dll_path)
                pdb_file = os.path.join(out_dir, "coreclr.pdb")
                if not os.path.exists(pdb_file):
                    print(f"    -> Obteniendo PDB para versión {ver}...")
                    fetch_core_symbols(dll_path, out_dir)

# ------------------------------------------------------------------------------
# .NET FRAMEWORK PROCESSING (Installer extraction based)
# ------------------------------------------------------------------------------
def process_framework_runtimes():
    print("\n=======================================================")
    print("[*] Iniciando extracción quirúrgica de .NET Framework")
    print("=======================================================")
    
    os.makedirs(TEMP_EXTRACT_DIR, exist_ok=True)
    
    for name, config in FRAMEWORK_INSTALLERS.items():
        print(f"\n[*] Procesando {name}...")
        installer_path = os.path.join(TEMP_EXTRACT_DIR, f"{name}_installer.exe")
        
        # Descargar instalador offline
        if not os.path.exists(installer_path):
            if not download_file(config["url"], installer_path):
                continue
        else:
            print(f"[=] Instalador ya descargado para {name}")

        temp_out = os.path.join(TEMP_EXTRACT_DIR, f"{name}_temp")
        os.makedirs(temp_out, exist_ok=True)

        dest_x86 = os.path.join(DEST_LIBRARY, name, "x86")
        dest_x64 = os.path.join(DEST_LIBRARY, name, "x64")

        # ---------------------------------------------------------
        # METODO 11: .NET Framework 1.1 SP1
        # ---------------------------------------------------------
        if config["method"] == "Express11":
            os.makedirs(dest_x86, exist_ok=True)
            if not os.path.exists(os.path.join(dest_x86, "mscorwks.dll")):
                print(f"    -> Extrayendo componentes de {name}...")
                run_7z_extract(installer_path, temp_out)
                cab_file = os.path.join(temp_out, "netfx1.cab")
                if os.path.exists(cab_file):
                    # Extraer mscorwks
                    run_7z_extract_flat(cab_file, dest_x86, "mscorwks_dll_4_____X86.3643236F_FC70_11D3_A536_0090278A1BB8")
                    old_wks = os.path.join(dest_x86, "mscorwks_dll_4_____X86.3643236F_FC70_11D3_A536_0090278A1BB8")
                    if os.path.exists(old_wks):
                        shutil.move(old_wks, os.path.join(dest_x86, "mscorwks.dll"))
                    # Extraer mscorjit
                    run_7z_extract_flat(cab_file, dest_x86, "FL_mscorjit_dll_____X86.3643236F_FC70_11D3_A536_0090278A1BB8")
                    old_jit = os.path.join(dest_x86, "FL_mscorjit_dll_____X86.3643236F_FC70_11D3_A536_0090278A1BB8")
                    if os.path.exists(old_jit):
                        shutil.move(old_jit, os.path.join(dest_x86, "mscorjit.dll"))
                    print(f"    [+] Extraído exitosamente: {name} x86")

        # ---------------------------------------------------------
        # METODO 20: .NET Framework 3.5 SP1 (Legacy CLR 2.0)
        # ---------------------------------------------------------
        elif config["method"] == "MSP20":
            os.makedirs(dest_x86, exist_ok=True)
            os.makedirs(dest_x64, exist_ok=True)
            
            wks_x86 = os.path.join(dest_x86, "mscorwks.dll")
            wks_x64 = os.path.join(dest_x64, "mscorwks.dll")

            if not os.path.exists(wks_x86) or not os.path.exists(wks_x64):
                print(f"    -> Extrayendo componentes de {name}...")
                run_7z_extract(installer_path, temp_out, [
                    "wcu/dotNetFramework/dotNetFX20/clr.msp",
                    "wcu/dotNetFramework/dotNetFX20/clr_64.msp"
                ])
                
                # Procesar x86
                msp_x86 = os.path.join(temp_out, "wcu/dotNetFramework/dotNetFX20/clr.msp")
                if os.path.exists(msp_x86):
                    sub_temp = os.path.join(temp_out, "clr_x86")
                    run_7z_extract(msp_x86, sub_temp)
                    cab = os.path.join(sub_temp, "PCW_CAB_NetFX")
                    if os.path.exists(cab):
                        run_7z_extract_flat(cab, dest_x86, "mscorwks_dll_4_____X86.3643236F_FC70_11D3_A536_0090278A1BB8")
                        shutil.move(os.path.join(dest_x86, "mscorwks_dll_4_____X86.3643236F_FC70_11D3_A536_0090278A1BB8"), os.path.join(dest_x86, "mscorwks.dll"))
                        run_7z_extract_flat(cab, dest_x86, "FL_mscorjit_dll_____X86.3643236F_FC70_11D3_A536_0090278A1BB8")
                        shutil.move(os.path.join(dest_x86, "FL_mscorjit_dll_____X86.3643236F_FC70_11D3_A536_0090278A1BB8"), os.path.join(dest_x86, "mscorjit.dll"))
                
                # Procesar x64
                msp_x64 = os.path.join(temp_out, "wcu/dotNetFramework/dotNetFX20/clr_64.msp")
                if os.path.exists(msp_x64):
                    sub_temp_64 = os.path.join(temp_out, "clr_x64")
                    run_7z_extract(msp_x64, sub_temp_64)
                    cab_64 = os.path.join(sub_temp_64, "PCW_CAB_NetFX")
                    if os.path.exists(cab_64):
                        run_7z_extract_flat(cab_64, dest_x64, "mscorwks_dll_4_____A64.3643236F_FC70_11D3_A536_0090278A1BB8")
                        shutil.move(os.path.join(dest_x64, "mscorwks_dll_4_____A64.3643236F_FC70_11D3_A536_0090278A1BB8"), os.path.join(dest_x64, "mscorwks.dll"))
                        run_7z_extract_flat(cab_64, dest_x64, "FL_mscorjit_dll_____A64.3643236F_FC70_11D3_A536_0090278A1BB8")
                        shutil.move(os.path.join(dest_x64, "FL_mscorjit_dll_____A64.3643236F_FC70_11D3_A536_0090278A1BB8"), os.path.join(dest_x64, "mscorjit.dll"))
                print(f"    [+] Extraído exitosamente: {name} x86 & x64")

        # ---------------------------------------------------------
        # METODO MZZ452: .NET Framework 4.5.2 (MZZ archive)
        # ---------------------------------------------------------
        elif config["method"] == "MZZ452":
            os.makedirs(dest_x86, exist_ok=True)
            os.makedirs(dest_x64, exist_ok=True)
            
            clr_x86 = os.path.join(dest_x86, "clr.dll")
            clr_x64 = os.path.join(dest_x64, "clr.dll")

            if not os.path.exists(clr_x86) or not os.path.exists(clr_x64):
                print(f"    -> Extrayendo componentes de {name}...")
                run_7z_extract(installer_path, temp_out, "netfx_Full_GDR.mzz")
                mzz_file = os.path.join(temp_out, "netfx_Full_GDR.mzz")
                if os.path.exists(mzz_file):
                    # Extraer x86
                    run_7z_extract_flat(mzz_file, dest_x86, ["clr_dll_x86", "clrjit_dll_x86"])
                    shutil.move(os.path.join(dest_x86, "clr_dll_x86"), os.path.join(dest_x86, "clr.dll"))
                    shutil.move(os.path.join(dest_x86, "clrjit_dll_x86"), os.path.join(dest_x86, "clrjit.dll"))
                    
                    # Extraer x64
                    run_7z_extract_flat(mzz_file, dest_x64, ["clr_dll_amd64", "clrjit_dll_amd64"])
                    shutil.move(os.path.join(dest_x64, "clr_dll_amd64"), os.path.join(dest_x64, "clr.dll"))
                    shutil.move(os.path.join(dest_x64, "clrjit_dll_amd64"), os.path.join(dest_x64, "clrjit.dll"))
                print(f"    [+] Extraído exitosamente: {name} x86 & x64")

        # ---------------------------------------------------------
        # METODO WixPayload: .NET Framework 4.6.2 / 4.7.2 / 4.8.0
        # ---------------------------------------------------------
        elif config["method"] == "WixPayload":
            os.makedirs(dest_x86, exist_ok=True)
            os.makedirs(dest_x64, exist_ok=True)

            clr_x86 = os.path.join(dest_x86, "clr.dll")
            clr_x64 = os.path.join(dest_x64, "clr.dll")

            if not os.path.exists(clr_x86) or not os.path.exists(clr_x64):
                print(f"    -> Extrayendo componentes de {name} (Wix payload)...")
                run_7z_extract(installer_path, temp_out, [
                    "x86_netfx4-clr_dll*", "x86_netfx4-clrjit_dll*",
                    "amd64_netfx4-clr_dll*", "amd64_netfx4-clrjit_dll*"
                ])
                
                # Buscamos de forma recursiva los archivos extraídos
                subfiles = glob.glob(os.path.join(temp_out, "**", "*.dll"), recursive=True)
                for sf in subfiles:
                    sf_lower = sf.lower()
                    parent_dir = os.path.basename(os.path.dirname(sf)).lower()
                    
                    if "x86_netfx4-clr_dll" in parent_dir and "clr.dll" in sf_lower:
                        shutil.copy2(sf, os.path.join(dest_x86, "clr.dll"))
                    elif "x86_netfx4-clrjit_dll" in parent_dir and "clrjit.dll" in sf_lower:
                        shutil.copy2(sf, os.path.join(dest_x86, "clrjit.dll"))
                    elif "amd64_netfx4-clr_dll" in parent_dir and "clr.dll" in sf_lower:
                        shutil.copy2(sf, os.path.join(dest_x64, "clr.dll"))
                    elif "amd64_netfx4-clrjit_dll" in parent_dir and "clrjit.dll" in sf_lower:
                        shutil.copy2(sf, os.path.join(dest_x64, "clrjit.dll"))
                print(f"    [+] Extraído exitosamente: {name} x86 & x64")

        # Limpiar carpetas temporales de extracción de este instalador
        if os.path.exists(temp_out):
            shutil.rmtree(temp_out)

    # Limpiar todo el directorio temporal final
    if os.path.exists(TEMP_EXTRACT_DIR):
        shutil.rmtree(TEMP_EXTRACT_DIR)

    print("\n[+] Extracción y organización de .NET Framework completada en:")
    print(f"    {DEST_LIBRARY}")

# ------------------------------------------------------------------------------
# MAIN ENTRY POINT
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Unificado .NET Runtime Extractor para Capemon.")
    parser.add_argument("--core", action="store_true", help="Descargar y extraer runtimes de .NET Core / .NET 5+.")
    parser.add_argument("--framework", action="store_true", help="Surgicamente descargar y extraer runtimes de .NET Framework (1.1 a 4.8).")
    parser.add_argument("--all", action="store_true", help="Descargar y extraer absolutamente todos los runtimes (Core + Framework).")
    
    args = parser.parse_args()

    # Si no se pasan argumentos, mostramos la ayuda
    if not (args.core or args.framework or args.all):
        parser.print_help()
        sys.exit(1)

    if args.all or args.framework:
        process_framework_runtimes()

    if args.all or args.core:
        process_core_runtimes()

if __name__ == "__main__":
    main()
