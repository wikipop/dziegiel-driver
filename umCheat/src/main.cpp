#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

static DWORD getProcessId(const wchar_t* processName) {
	DWORD process_id = 0;

	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapShot == INVALID_HANDLE_VALUE) {
		return process_id;
	}

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Process32FirstW(snapShot, &entry) == TRUE) {
		if (_wcsicmp(entry.szExeFile, processName) == 0) {
			process_id = entry.th32ProcessID;
		}
		else {
			while (Process32NextW(snapShot, &entry) == TRUE) {
				if (_wcsicmp(processName, entry.szExeFile) == 0) {
					process_id = entry.th32ProcessID;
					break;
				}
			}
		}
	}

	CloseHandle(snapShot);
	return process_id;
}

static std::uintptr_t getModuleBaseAddress(DWORD processId, const wchar_t* moduleName) {
	std::uintptr_t base_address = 0;

	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (snapShot == INVALID_HANDLE_VALUE) {
		return base_address;
	}

	MODULEENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Module32FirstW(snapShot, &entry) == TRUE) {
		if (wcsstr(moduleName, entry.szModule) != nullptr) {
			base_address = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
		}
		else {
			while (Module32NextW(snapShot, &entry) == TRUE) {
				if (wcsstr(moduleName, entry.szModule) != nullptr) {
					base_address = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
					break;
				}
			}
		}
	}

	CloseHandle(snapShot);
	return base_address;
}

namespace driver {
	namespace codes {
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	struct Request {
		HANDLE processId;
		PVOID targerAddress;
		PVOID buffer;
		SIZE_T size;
		SIZE_T returnSize;
	};

	// TODO: Class approach
	bool attach_to_process(HANDLE driverHandle, const DWORD pid) {
		Request r;
		r.processId = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(driverHandle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

	template <class T>
	T readMemory(HANDLE driverHandle, const std::uintptr_t addr) {
		T temp = {};

		Request r;
		r.targerAddress = reinterpret_cast<PVOID>(addr);
		r.buffer = &temp;
		r.size = sizeof(T);

		DeviceIoControl(driverHandle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

		return temp;
	}

	template<class T>
	void writeMemory(HANDLE driverHandle, const std::uintptr_t addr, const T& value) {
		Request r;
		r.targerAddress = reinterpret_cast<PVOID>(addr);
		r.buffer = const_cast<PVOID>(reinterpret_cast<const void*>(&value));
		r.size = sizeof(T);

		DeviceIoControl(driverHandle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

};

int main() {
	const DWORD pid = getProcessId(L"notepad.txt");

	if (pid == 0) {
		std::cout << "Process not found" << std::endl;
		std::cin.get();
		return 1;
	}

	const HANDLE driverHandle = CreateFileW(L"\\\\.\\DziegielDriver", GENERIC_READ, 0, nullptr, FILE_ATTRIBUTE_NORMAL, 0, nullptr);
	if (driverHandle == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to get driver handle" << std::endl;
		std::cin.get();
		return 1;
	}

	if (driver::attach_to_process(driverHandle, pid) == true) {
		std::cout << "Attached to process" << std::endl;
	}
	else {
		std::cout << "Failed to attach to process" << std::endl;
	}

	CloseHandle(driverHandle);

	std::cin.get();
	return 0;
}