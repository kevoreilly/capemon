# capemon: The monitor DLL for CAPE: Config And Payload Extraction (https://github.com/kevoreilly/CAPEv2).

Much of the functionality of CAPE is contained within the monitor; the CAPE debugger, extracted payloads, process dumps and import reconstruction are implemented within capemon. CAPE's loader is also part of this project.

capemon is derived from cuckoomon-modified from spender-sandbox (https://github.com/spender-sandbox/cuckoomon-modified) from which it inherits the API hooking engine. It also includes a PE dumping engine and import reconstruction derived from Scylla (https://github.com/NtQuery/Scylla), WOW64Ext Library from ReWolf (http://blog.rewolf.pl/) and W64oWoW64 from George Nicolaou. 

## How to compile capemon
If you need to locally inspect the code of capemon and/or modify it, it is recommended to download [Microsoft Visual Studio](https://visualstudio.microsoft.com/). The following instructions were performed using the latest version at the time of writing, MSVS2022 Community (64-bit, Version 17.4.2).

First you have to clone this repo. Then, in Visual Studio you can select the `Open a project or solution` option and specify the folder where you cloned it. When asked about updating the configuration files (aka **Retarget Project**), you can click OK, allowing Visual Studio to update the 3 configuration files. 

![Retarget Project](./images/auto_update_MSVS2022.png)

You must select the `Release` configuration before building the solution. Select the target platform (either Win32 or x64), and go to Build -> Build Solution or Build Capemon. If there are no compilation errors, in the _Release_ folder of your repo (for Win32) or _x64/Release_ (for x64) you will find `capemon.dll` or `capemon_x64.dll`. These are the libraries you want to place into your [CAPEv2](https://github.com/kevoreilly/CAPEv2) directory so the modified libraries are used during analysis. The specific path is: `CAPEv2/analyzer/windows/dll/`.

## How to add hooks to capemon
If you want to add more hooks to capemon or change those already existing, you can take a look at past commits that did just that. You can do so by searching for [commits containing "hook for"](https://github.com/kevoreilly/capemon/search?q=hook+for&type=commits) in its description (or any other keyword combination). For instance, you can take a look at [the commit](https://github.com/kevoreilly/capemon/commit/4c31b16a17e3ce0efbdfea6723c70a9082e925e8) that added the hook for `GetCommandLineA`.

There are three main files that define the hooks implemented in capemon:

1. [hooks.h](./hooks.h). This file contains the definition of the hook (`HOOKDEF`) using Windows [SAL](https://learn.microsoft.com/en-us/cpp/code-quality/understanding-sal?view=msvc-170) notation. That is, `HOOKDEF(ReturnValue, CallingConvention, ApiName, _ParameterAnnotation_ ParameterName)`.
2. [hooks.c](./hooks.c). This file defines the hooks that will be employed depending upon the configuration selected when submitting the analysis. Please notice there are several `hook_t` arrays. For example, `hook_t full_hooks[]`,`hook_t min_hooks[]` or `hook_t office_hooks[]`, among others. You should add the hooks you want capemon to perform in the corresponding array. By default, `full_hooks` is executed (so probably you want to add your hooks there). The hooks must be added using the following naming pattern: `HOOK(dllname, ApiName)`.
3. [hook_{category}.c](./hook_process.c) _(Link is just an example, in this case hook_process.c)_. This set of files is where the implementation of each hook is defined. When defining the behavior of a given hook, you must copy the corresponding definition from the `hooks.h` file and write the code. Remember you can call the original function with `Old_{ApiName}` .