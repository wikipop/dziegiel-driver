#include <ntifs.h>

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, 
										PDRIVER_INITIALIZE InitializationFunction);

	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS FromProcess, 
											PVOID FromAddress, 
											PEPROCESS ToProcess, 
											PVOID ToAddress, 
											SIZE_T BufferSize, 
											KPROCESSOR_MODE PreviousMode, 
											PSIZE_T NumberOfBytesCopied);
}

void debugPrint(PCSTR text) {
#ifndef DEBUG
	UNREFERENCED_PARAMETER(text);
#endif
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
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

	NTSTATUS create(PDEVICE_OBJECT deviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(deviceObject);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	};

	NTSTATUS close(PDEVICE_OBJECT deviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(deviceObject);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	};

	NTSTATUS deviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
		UNREFERENCED_PARAMETER(deviceObject);

		debugPrint("[+] DeviceControl - Otrzymano request\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (stack_irp == nullptr || request == nullptr) {
			debugPrint("[-] Nie udalo sie pobrac stack_irp lub request\n");
			irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return irp->IoStatus.Status;
		}

		static PEPROCESS targetProcess = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;

		switch (control_code) {
		case codes::attach:
			status = PsLookupProcessByProcessId(request->processId, &targetProcess);
			if (status != STATUS_SUCCESS) {
				debugPrint("[-] Nie udalo sie znalezc procesu\n");
				irp->IoStatus.Status = status;
				break;
			}
			break;

		case codes::read:
			if (targetProcess != nullptr)
				status = MmCopyVirtualMemory(targetProcess, request->targerAddress, PsGetCurrentProcess(), request->buffer, request->size, KernelMode, &request->returnSize);
			else
				status = STATUS_UNSUCCESSFUL;

			break;

		case codes::write:
			if (targetProcess != nullptr)
				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer, targetProcess, request->targerAddress, request->size, KernelMode, &request->returnSize);
			else
				status = STATUS_UNSUCCESSFUL;

			break;

		default:
			break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof request;

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	};
}


NTSTATUS driverMain(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(registryPath);

	UNICODE_STRING deviceName = {};
	RtlInitUnicodeString(&deviceName, L"\\Device\\DziegielDriver");

	PDEVICE_OBJECT deviceObject = nullptr;
	NTSTATUS status = IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

	if (status != STATUS_SUCCESS) {
		debugPrint("[-] Nie udalo sie stworzyc urzadzenia\n");
		return status;
	}

	debugPrint("[+] Utworzono urzadzenie\n");

	UNICODE_STRING symlinkName = {};
	RtlInitUnicodeString(&symlinkName, L"\\DosDevices\\DziegielDriver");

	status = IoCreateSymbolicLink(&symlinkName, &deviceName);
	if (status != STATUS_SUCCESS){
		debugPrint("[-] Nie udalo sie stworzyc symlinku\n");
		IoDeleteDevice(deviceObject);
		return status;
	}

	debugPrint("[+] Utworzono symlink\n");

	SetFlag(deviceObject->Flags, DO_BUFFERED_IO);

	driverObject->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driverObject->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::deviceControl;

	ClearFlag(deviceObject->Flags, DO_DEVICE_INITIALIZING);

	debugPrint("[+] Zainicjalizowano sterownik\n");

	return status;
}

NTSTATUS DriverEntry() {
	debugPrint("[+] Halo dzwonimy z kernela!\n");

	UNICODE_STRING driverName = {};
	RtlInitUnicodeString(&driverName, L"\\Driver\\DziegielDriver");

	return IoCreateDriver(&driverName, &driverMain);
}