#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>


void inject_dll(DWORD Pid, PCHAR DllName) {
	HANDLE ProcessHandle;
	PVOID Alloc;
	SIZE_T DllLen;
	HINSTANCE Kernel32Base;
	PVOID LoadLibAddress;



	if (Pid != 0 && DllName != NULL) {

		DllLen = strlen(DllName);

		Kernel32Base = GetModuleHandleA("kernel32.dll");
		if (Kernel32Base == NULL) {
			system("echo Kernel NULL");
			goto ExitPoint;
		}

		LoadLibAddress = GetProcAddress(Kernel32Base, "LoadLibraryA");
		if (LoadLibAddress == NULL) {
			system("echo LoadLibAddress NULL");
			goto ExitPoint;
		}

		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
		if (ProcessHandle == NULL){
			system("echo ProcessHandle NULL");
			goto ExitPoint;
		}

		Alloc = VirtualAllocEx(ProcessHandle, NULL, DllLen + 1, MEM_COMMIT, PAGE_READWRITE);
		if (Alloc == NULL) {
			system("echo Alloc NULL");
			goto ExitPoint;
		}

		if (!WriteProcessMemory(ProcessHandle, Alloc, DllName, DllLen + 1, NULL)) {
			system("echo WriteProcessMemory NULL");
			goto ExitPoint;
		}

		CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibAddress, Alloc, 0, NULL);


	}

ExitPoint:
	system("echo Exitpoint happen");
	return;
}


DWORD get_pid(PCHAR ProcessName) {
	PROCESSENTRY32 ProcEntry = { 0 };
	HANDLE lehandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);

	if (lehandle != NULL) {
		if (Process32First(lehandle, &ProcEntry)) {
			do {
				if (!strcmp(ProcEntry.szExeFile, ProcessName)) {
					return ProcEntry.th32DefaultHeapID;
				}
			} while (Process32Next(lehandle, &ProcEntry));


		}
	}

};

DWORD FindProcessId(const char *processname)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return(FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

										  // Retrieve information about the first process,
										  // and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		printf("!!! Failed to gather information on system processes! \n");
		return(NULL);
	}

	do
	{
		printf("Checking process %ls\n", pe32.szExeFile);
		if (0 == strcmp(processname, pe32.szExeFile))
		{
			result = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return result;
}

int main(int argc, char *argv[]) {

	//DWORD pid = get_pid("notepad++.exe");
	DWORD pid = FindProcessId("notepad++.exe");
	printf("%lu", pid);
	if (pid) {
		inject_dll(pid, "C:\\Users\\User\\Desktop\\TestDll.dll");
		system("echo hi");
	}

ExitPoint:
	system("Pause");
	return 0;
}