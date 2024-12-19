#include <dylib.hpp>
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include "converteddll.hpp"
using namespace std;
namespace fs = std::filesystem;
inline dylib GetDLL() {
	dylib lib(".\\lib", "DLLInjector", true);
	return lib;
}
int main() {
	DWORD pid;
	HWND hwnd = FindWindowA(0, "File Explorer");
	DWORD word = GetWindowThreadProcessId(hwnd, &pid);
	HANDLE targ = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!targ) 
	{
		cout << "Failed to Open Explorer.exe" << endl;
	}
	else 
	{
		fs::path pathx{ "HelloWorldFromDLLInjector.dll" };
		if (fs::exists(pathx)) {
			cout << "This File Is Exists" << endl;
			auto ManualMapEasy = GetDLL().get_function<bool(HANDLE, BYTE*)>("ManualMapEasy");
			if (!ManualMapEasy(targ, reinterpret_cast<BYTE*>(mydll)))
			{
				cout << "Failed to Inject DLL!!!" << endl;
				exit(333);
			}
		}
		else {
			cout << "This File is Not Exists" << endl;
			exit(211);
		}
	}
	return 0;
}