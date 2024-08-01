# <span style="color:#004F98;">**Lab 11-1 :**</span>
Analyze the malware found in Lab11-01.exe

**General information:**

>Type :  EXE     
CPU :  32-bit      
Subsystem :  Console      
Packing :   NO    
md5 Hash : A9C55BB87A7C5C3C923C4FA12940E719

<span style="color:#00FFFF;">**Q1:**</span>
What does the malware drop to disk?


<span style="color:#00FFFF;">**Short Answer:**</span>
The malware drops a DLL from the `TGAD` resource called `msgina32.dll`.


<span style="color:#00FFFF;">**Detailed Answer :**</span>

First searching the hash on [Virus-Total](https://www.virustotal.com/gui/file/57d8d248a8741176348b5d12dcf29f34c8f48ede0ca13c30d12e5ba0384056d7) I found that it was identified as dropper, so, I open PE-Studio to have a look on the resources and I found an exe file named `TGAD`.

![PE-Studio](Images/pestudio.png)

Opening IDA and searching for `FindResourceA` in imports window we can see that it was called only one time by `sub_401080` at the beginning of the main function.

![alt text](Images/FindResourceA.png)

By getting into the call we can see that the typical 4 standard functions are called to drop a resource.

![alt text](Images/LoadingResource.png)

By opening IDA debugger and setting a breakpoint at `FindResourceA` API call, we see that the resource name is `TGAD` with type binary, then the `LoadResource` API retrieves the handle to the data associated with the resource, the `LockResource` API obtains the pointer to the actual resource, finally, the binary determines the size of the resource (PE file) using the `SizeofResource` API which is 1A00 (6,656 bytes).

![alt text](Images/parametrs.png)

After that the binary drops the resource as a DLL called `msgina32.dll`

![alt text](Images/dropping-resource.png)

Going back to main, we see a call to `sub_401000`, inside it, `RegCreateKeyExA` is called to create the regkey `hKey\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, notice that the samDesired parameter is set to `0F003F` which according to [MSDN Registry Key Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) stands for `KEY_ALL_ACCESS`

![alt text](Images/registry1.png)

After that, `RegSetValueExA` API is called to set the value to the created key to be `GinaDLL`, After that it closes the handle.

![alt text](Images/registry2.png)

So, we know that, the binary drops a DLL called msgina32.dll from resourses then installs it as GINA DLL by adding it to *HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDLL* which leads us to think that this is a `GINA Interception` which is a known technique for harvesting credentials.

___

<span style="color:#00FFFF;">**Q2:**</span>
How does the malware achieve persistence?

<span style="color:#00FFFF;">**Short Answer:**</span>
The malware achieve persistence by registering the dropped `msgina32.dll` as a custom GINA DLL in the following Windows Registry 
> HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDLL

<span style="color:#00FFFF;">**Detailed Answer :**</span>

As mentioned previously persistence is achieved by registering `msgina32.dll`, which was dropped from `TGAD` resource, as a custom GINA DLL in the Windows Registry at the following location:

> HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GinaDLL

According to [MSDN's GINA documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/gina), The GINA operates in the context of the Winlogon process and, as such, the GINA DLL is loaded very early in the boot process, which mean that the malicious dropped DLL will run whenever a user tries to logon to the infected device.

___

<span style="color:#00FFFF;">**Q3:**</span>
How does the malware steal user credentials?

<span style="color:#00FFFF;">**Short Answer:**</span>

The malware steals user credentials by performing GINA interception. The 
`msgina32.dll` file intercepts user credentials submitted to the system for authentication.

<span style="color:#00FFFF;">**Detailed Answer :**</span>

Let's switch our analysis to the malicious dropped file.

**General information:**

>Type :  DLL     
CPU :  32-bit      
Packing :   NO    
md5 Hash : 7CE4F799946F0FA44E5B2B5E6A702F27

**Now, Let's open it in IDA.**

First, let's have a look on the **DllMain** function.

A call to `DisableThreadLibraryCalls` is made to Disables the *DLL_THREAD_ATTACH* and *DLL_THREAD_DETACH* notifications, then a call to `GetSystemDirectoryW` to retrieve the path of the system directory which contains system files such as dynamic-link libraries and drivers, then a call to `lstrcatw` is used to appends `\\MSGina` string to the system directory retrieve previously, finally, it calls `LoadLibraryW` to load the dll with the appended name.

![alt text](Images/DllMain.png)

Using **x32dbg**, we can see that the library being load is at`C:\\Windows\\system32\\MSGina` which is the original msgina.dll.

![alt text](Images/LoadLibraryW.png)

After that, the handle to the original msgina.dll is passed to `hLibModule` to be used later then the DllMain ends.

**Now, let's have a look to the other exports.**

As we see there is about 21 API that starts with `Wlx` which was expected in a GINA replacement,

![alt text](Images/Exports.png)

If we analyzed any function of these we will see that it only passes through to the true API contained in the original msgina.dll except for `WlxLoggedOutSAS`, So we will focus on `WlxLoggedOutSAS` API as it will be passed user credentials whenever someone tries to logon at the logon screen.

In the `WlxLoggedOutSAS `, we see the usual passing to the true msgina API in addition to some extra code, a bunch of arguments and a format string that will be passed to `sub_10001570`

![alt text](Images/formatting.png)

**Examining the `sub_10001570` we see that:**
- A file called `msutil32.sys` is opened
- Date and time are recorded using `_wstrtime` and `_wstrdate`.
- logging some info using the format "%s %s %s" in the `msutil32.sys` file.

![alt text](Images/sub_10001570.png)

So, we know that the `WlxLoggedOutSAS` is the resposible for the logging process but **what are the data being logged?**

We can see that these Data in EAX (Args) were in the ESI register which contains  the `pNprNotifyInfo` parameter that will be passed to the original `WlxLoggedOutSAS`.

![alt text](Images/logged-data.png)

According to [MSDN Page](https://learn.microsoft.com/en-us/windows/win32/api/winwlx/nf-winwlx-wlxloggedoutsas), the `pNprNotifyInfo` parameter contains a pointer to an `WLX_MPR_NOTIFY_INFO` structure that contains:
- User Name
- Domain
- Password
- Old Password

**Working Mechanism :**

1. Replacing the malicious dropped DLL with the original one in the winlogon registry key.
2. When `Winlogon.exe` calls a function, the malicious GINA reforwards the call the the original GINA.
3. When `winlogon.exe` calls `WlxLoggedOutSAS` API, the malicious GINA calls the original `WlxLoggedOutSAS` API then logs the info in `msutil32.sys`.
 
![alt text](Images/illustration.png)

___
<span style="color:#00FFFF;">**Q4:**</span>
What does the malware do with stolen credentials?

<span style="color:#00FFFF;">**Answer:**</span>

As we mentiond, the malware will create a file called `msutil32.sys` which will contain Username, Domain, and Password which will be logged with a timestamp of a particular user every time a call is made to the exported function `WlxLoggedOutSAS` of `msgina32.dll`.

We can tell that the directory to the logging file is `C:\Windows\System32\msutil32.sys` since that is where Winlogon 
resides (and msgina32.dll is running in the Winlogon process).

___

<span style="color:#00FFFF;">**Q5:**</span>
How can you use this malware to get user credentials from your test 
environment?

<span style="color:#00FFFF;">**Answer:**</span>

Once the GINA DLL is dropped and installed, the system needs to be rebooted so that the GINA interception starts, the malware logs credentials 
only when the `WlxLoggedOutSAS` API is called, so log out and back in to see the stolen credentials.

<span style="color:#00FFFF;">**NOTE**</span>**:**
GINA DLLs no longer exist in Windows Vista and later versions, this stealing tactic will only work in Windows XP or older versions.
___
___

# <span style="color:#004F98;">**Lab 11-2 :**</span>
Analyze the malware found in Lab11-02.dll. Assume that a suspicious file named Lab11-02.ini was also found with this malware.

**General information:**

>Type :  DLL     
CPU :  32-bit      
Packing :   NO    
md5 Hash : BE4F4B9E88F2E1B1C38E0A0858EB3DD9

<span style="color:#00FFFF;">**Q1:**</span>
What are the exports for this DLL malware?

<span style="color:#00FFFF;">**Answer:**</span>

First, by opening the binary in **CFF Explorer**, we can see that it has only one exported function called `installer`


![alt text](Images/CFF-exports.png)

___

<span style="color:#00FFFF;">**Q2:**</span>
What happens after you attempt to install this malware using 
rundll32.exe?

<span style="color:#00FFFF;">**Short Answer:**</span>

When we install the malware it does two jobs:
1. Add the `spoolvxx32.dll` to the `AppInit_DLLs` registry key.
2. Copy the malware to another executable named `spoolvxx32.dll` at the address `C:\\Windows\\system32\\spoolvxx32.dll` if it not aleardy exists.



<span style="color:#00FFFF;">**Detailed Answer :**</span>

First, let's install the malware using the following command line while monitoring using **procmon**.

```
rundll32.exe Lab11-02.dll , installer
```
After applying some filters, we can see that malware tries to open  the `Lab11-02.ini` file, then it creates a file called `spoolvxx32.dll` with path `C:\Windows\SysWOW64\spoolvxx32.dll`.

![alt text](Images/procmon.png)

Now, let's open the malware in **IDA** to see what is happening.

Inside the **installer** exported function, we can see that the malware open the `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` and adds the value `spoolvxx32.dll` to the `AppInit_DLLs`.

After that, a call to `sub_1000105B` happened which will simply call `GetSystemDirectoryA` API, then the malware copies a file to the retrieved system directory using `CopyFileA` API.

![alt text](Images/installer.png)

To know the details of the copying process, I opened x64dbg and set the EIP to the address of the **installer** function, I inserted a break-point in the address of **CopyFileA** API and looked for the pushed parameters, we get these parameters.

![alt text](Images/CopyFileA.png)

So, Now we know that the installer exported function does two jobs:
1. Add the `spoolvxx32.dll` to the `AppInit_DLLs` registry key.
2. Copy the malware to another executable named `spoolvxx32.dll` at the address `C:\\Windows\\system32\\spoolvxx32.dll` if it not aleardy there.

___

<span style="color:#00FFFF;">**Q3:**</span>
Where must Lab11-02.ini reside in order for the malware to install 
properly?

<span style="color:#00FFFF;">**Short Answer:**</span>

The .ini file must reside in `C:\\Windows\\system32\\Lab11-02.ini` so that the malwere installation goes successfully.

<span style="color:#00FFFF;">**Detailed Answer :**</span>

Going back to the **DllMain** function, we see a call to `GetModuleFileNameA` API to retrieves the path for the file that contains module loaded by the current process, then a call to `sub_1000105B` again which calls `GetSystemDirectoryA` API, then `strncat` is called to concatenate the full path of the file that will be created (or opened)
next using `CreateFileA` API.

![alt text](Images/DllMain2.png)

To get the full concatenated path I used x32dbg and set a break point at `strncat`'s address, we can see that the two strings passed to be concatenated are `C:\\Windows\\system32` and `\\Lab11-02.ini`, we can see that they were concatenated successfully and stored as a return value in the EAX 

![alt text](Images/strncat-params.png)                                                       
![alt text](Images/EAX.png)

As we said, the malware will try to access the .ini file in the mentioned path using `CreateFileA` API function, this API function can be used to either create or open a file.

The `dwCreationDisposition` parameter is the one responsible for the action that will be taken, according to [MSDN page](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea), the value `3` stands for `OPEN_EXISTING` which means that the function will open a file or device only if it exists, if the specified file or device does not exist, the function will fail.

If the malware successfully opens the .ini file, it will call `ReadFile` to read about `0x100` byte (256 byte in decimal) from the .ini file and copy them to a global variable `byte_100034A0`, after that the malware checks if the read process is successful by checking that the file size is greater than 0, if successful, the malware will call `sub_100010B3` subroutine, close the handle then call `sub_100014B6` then DllMain finishes.

![alt text](Images/ReadFile2.png)

___

<span style="color:#00FFFF;">**Q4:**</span>
How is this malware installed for persistence?

<span style="color:#00FFFF;">**Short Answer:**</span>

The malware adds a copied version of itself to the `AppInit_DLLs` registry value, which causes the malware to be loaded into the address space everytime a process loads **User32.dll**.

<span style="color:#00FFFF;">**Detailed Answer :**</span>

Based on our analysis to **installer** function, we knows that the malware adds a copied version of itself with the name `spoolvxx32.dll` to the `AppInit_DLLs` registry key.

According to [AppInit_DLLs Documentation](https://learn.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls?source=recommendations#about-appinit_dlls), 
the AppInit_DLLs infrastructure provides an easy way to hook system APIs by allowing custom DLLs to be loaded into the address space of every interactive application. Applications and malicious software both use AppInit DLLs for the same basic reason, which is to hook APIs.


AppInit_DLLs are loaded into every process that loads **User32.dll**, and a simple insertion into the registry -Like the one that installer does- will make 
AppInit_DLLs persistent.


___

<span style="color:#00FFFF;">**Q5:**</span>
What user-space rootkit technique does this malware employ?

<span style="color:#00FFFF;">**Short Answer:**</span>

This malware installs an inline hook at the beginning of the `send` API function.

<span style="color:#00FFFF;">**Detailed Answer :**</span>

Based on our analysis to the **DllMain** function, we know that if the malware successfully read the `Lab11-02.ini` it will call `sub_100010B3` subroutine, close the handle then call `sub_100014B6` then DllMain finishes.

By analyzing the `sub_100010B3` subroutine, we can assume that it's a decoding mechanism, so we will exceed it for now and continue our analysis for `sub_100014B6`

![alt text](Images/decoder.png)

Inside the `sub_100014B6`, we can see that it first calls `sub_10001075` which will call `GetModuleFileNameA` which will return the full path to the process in which the DLL is loaded because the argument hModule is set to 0 before the call to this function, then it calls `sub_10001104` to return the value in `var_4` (the string pointer passed to the function).

![alt text](Images/sub_100014B6-1.png)

After that, a call to `sub_1000102D` happens to convert the process name to uppercase, then it compares it with [THEBAT.EXE, OUTLOOK.EXE, MSIMN.EXE], if it matches any of those processes then the malware calls `sub_100013BD` followed by a call to `sub_100012A3` and `sub_10001499`

![alt text](Images/sub_100014B6-2.png)

The `sub_100013BD` subroutine start with a call to `GetCurrentProcessId` then another call to `sub100012FE` which will suspend all of the threads in the current process (except for th  current thread) using calls to `SuspendThread` API

![alt text](Images/sub_100013BD.png)

Later in `sub_10001499` the Converse action will be taken to resume all the previously suspended threads using calls to `ResumeThread`.

![alt text](Images/sub_10001499.png)

So, we have a subroutine that suspends all threads and another that resumes all of them back and between them we have a function call to `sub_100012A3`,  so we can assume that this is where the hook is being installed

The `sub_100012A3` first calls `GetModuleHandleA` and `LoadLibraryA` to resolve the `send` API function, after that it push the `sub_1000113D` and `dword_10003484` as parameters to the `sub_10001203` subroutine.

![alt text](Images/sub_100012A3.png)

At the beginning of the `sub_10001203`, the malware calculates the difference between the memory address of the `send` function and the start of `sub_1000113D`. This difference has an additional 5 bytes subtracted from it before being moved into var_4 which will be insrted to the start of the `send` function. 

![alt text](Images/sub_10001203.png)

Next, the malware call `VirtualProtect` to change the memory protection enabling execution, then calla `malloc` to allocates 0xFF bytes of memory (256 bytes in decimal) then stores the handle to the newly allocated memory
in `var_8`.

![alt text](Images/sub_10001203-1.png)

After that, a call to `memcpy` is called to copy the first 5 bytes from the `send` function into the `var_8`.

![alt text](Images/sub_10001203-3.png)

Then, the malware modifies the first 5 bytes from the `send` function so that the code jumps to the `sub_1000113D` then jump back to `send` everytime `send` is being called.

This technique is know as an **inline hook** which means that the malware overwrites the API function code contained in the imported DLLs.  

![alt text](Images/sub_10001203-4.png)

The malware will recall the `VirtualProtect` API to restore the original memory-protection settings.

![alt text](Images/sub_10001203-5.png)


This technique is know as an **inline hook** which means that the malware overwrites the API function code contained in the imported DLLs.  

___

<span style="color:#00FFFF;">**Q6:**</span>
What does the hooking code do?

<span style="color:#00FFFF;">**Short Answer:**</span>

The malware add a recipient to all outgoing email messages if the `RCPT TO:` was found.

<span style="color:#00FFFF;">**Detailed Answer :**</span>

Going back to the `sub_1000113D`, the malware searchs for the string `RCPT TO:` in the **Str** argument , if it's not found, it will call `dword_10003484` which will executes the original `send` API.

![alt text](Images/sub_1000113D.png)

If the string `RCPT TO:` is found, the malware will concatenate the following strings together **RCPT TO:** < + **byte_100034A0** + **>\r\n** to become `RCPT TO: <byte_100034A0>\r\n`, the `dword_10003484` was holding the read bytes from the `Lab11-02.ini`then passed as an argument to `sub_100010B3` to be decoded which we can assume will be an email address.

Then the malware calls  `dword_10003484`  twice, which will add a recipient to all outgoing email messages.

![alt text](Images/sub_1000113D-1.png)


___

<span style="color:#00FFFF;">**Q7:**</span>
Which process(es) does this malware attack and why?

<span style="color:#00FFFF;">**Short Answer:**</span>

Based on our analysis for `sub_100014B6`, this malware only attacks the following processes:

- MSIMN.exe
- THEBAT.exe
- OUTLOOK.exe

This is because they are specific email clients and this malware is designed to hook a specific API call (`send` API) only for the specified email clients.



___

<span style="color:#00FFFF;">**Q8:**</span>
What is the significance of the .ini file?

<span style="color:#00FFFF;">**Short Answer:**</span>

The .ini file contains an encoded email address. After decoding Lab11-02.ini, we see that it contains `billy@malwareanalysisbook.com`. 

<span style="color:#00FFFF;">**Detailed Answer :**</span>

To determine what actually is the significance of the .ini file, I went back to the **DllMain** function, I used x64dbg and start executing the whole function, first the `CreateFileA` will fail to open the .ini file due to code signing requirements.

We can assume that this malware was craft for a windows xp or older machines when code signing requirements wasn't introduced yet.

However, we know that if the opening process was successful the malware will read about 255 byte from the .ini file then pass the to `sub_100010B3` to be decoded.

I used `HxD` hex editor to copy the bytes inside the .ini file then I patched them manually at the `byte_100034A0` which is the passed parameter to `sub_100010B3`

![alt text](Images/HxD.png)

![alt text](Images/Dump.png)

After that, I put a breakpoint just after the call to `sub_100010B3`  to see the return value which will contain the decoded string from the .ini file, as we expected in Q6 it is an eamil address for `billy@malwareanalysisbook.com`

![alt text](Images/decoder2.png)                                                
![alt text](Images/Email.png)


___

<span style="color:#00FFFF;">**Q9:**</span>
How can you dynamically capture this malware’s activity with Wireshark?

<span style="color:#00FFFF;">**Short Answer:**</span>

  1. Install the malware.
  2. Setup an instance of `wireshark`.
  3. Use the `Outlook Express` client, `msimn.exe` to send an email.

<span style="color:#00FFFF;">**Detailed Answer :**</span>

- First, We need to isolate the VM from access the outside world,  we do that by setting up the network adapter to host-only, then begin capturing packets on this adapter in Wireshark.

- Next, we run the `installer` function like we did before.

    ```sh
    rundll32.exe Lab11-02.dll , installer
    ```

- Then, we set up Outlook Express to send email to the host system, and we  setup a fake smtp daemon debugging server to receive emails on our host OS. 

    ```sh
    python -m smtpd -n -c DebuggingServer 192.168.56.1:25
    ```
- Now, we can send an email from Outlook Express.

- Going back to wireshark, we can see the modification of recipients has alredy happened and it is now also includes `billy@malwareanalysisbook.com`.

    ![alt text](Images/wireshark.jpg)

___
___

<p align="center"><span style="color:#00FFFF;">THE END</span></p>


___
___