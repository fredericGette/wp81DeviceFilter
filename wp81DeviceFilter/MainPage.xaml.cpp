//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include "Win32Api.h"

using namespace wp81DeviceFilter;

using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace Windows::Storage;
using namespace concurrency;
using namespace Windows::UI::Core;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

#define BTH_MAX_NAME_SIZE          (248)
typedef ULONGLONG BTH_ADDR, *PBTH_ADDR;
typedef ULONG BTH_COD, *PBTH_COD;

#pragma pack(8)
typedef struct _BTH_DEVICE_INFO {
	ULONG flags;
	BTH_ADDR address;
	BTH_COD classOfDevice;
	CHAR name[BTH_MAX_NAME_SIZE];
} BTH_DEVICE_INFO, *PBTH_DEVICE_INFO;
#pragma pack(1)
typedef struct _BTH_RADIO_INFO {
	ULONGLONG lmpSupportedFeatures;
	USHORT mfg;
	USHORT lmpSubversion;
	UCHAR lmpVersion;
} BTH_RADIO_INFO, *PBTH_RADIO_INFO;
typedef struct _BTH_LOCAL_RADIO_INFO {
	BTH_DEVICE_INFO localInfo;
	ULONG           flags;
	USHORT          hciRevision;
	UCHAR           hciVersion;
	BTH_RADIO_INFO  radioInfo;
} BTH_LOCAL_RADIO_INFO, *PBTH_LOCAL_RADIO_INFO;
#pragma pack(8)

typedef struct _BTH_AUTHENTICATE_DEVICE {
	ULONG unknown1;
	BTH_ADDR address;
	UCHAR unknown2[560];
	ULONG unknown3;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
} BTH_AUTHENTICATE_DEVICE, *PBTH_AUTHENTICATE_DEVICE;

typedef UCHAR BTHSTATUS;

#define BTH_MAX_PIN_SIZE            (16)

typedef struct _BTH_PIN_INFO {
	UCHAR pin[BTH_MAX_PIN_SIZE];
	UCHAR pinLength;
} BTH_PIN_INFO, *PBTH_PIN_INFO;

typedef struct _BTH_AUTHENTICATE_RESPONSE {
	ULONG unknown1;
	BTH_ADDR address;
	UCHAR unknown2[520];
	ULONG unknown3;
	BTH_PIN_INFO info;
	ULONG unknown4;
	ULONG unknown5;
	ULONG unknown6;
	ULONG unknown7;
} BTH_AUTHENTICATE_RESPONSE, *PBTH_AUTHENTICATE_RESPONSE;

Win32Api win32Api;

MainPage::MainPage()
{
	InitializeComponent();
}

void debug(WCHAR* format, ...)
{
	va_list args;
	va_start(args, format);

	WCHAR buffer[1000];
	_vsnwprintf_s(buffer, sizeof(buffer), format, args);

	OutputDebugStringW(buffer);

	va_end(args);
}

void debugMultiSz(WCHAR *multisz)
{
	WCHAR* c = multisz;
	WCHAR* value = nullptr;
	boolean isFirstString = true;
	do
	{
		if (isFirstString)
		{
			isFirstString = false;
		}
		else
		{
			debug(L",");
		}
		value = c;
		while (*c != L'\0')
		{
			c++;
		}
		c++; // skip \0
		debug(L"%ls\n", value);
	} while (*c != L'\0');
}

void MainPage::UIConsoleAddText(Platform::String ^ text) {
	Dispatcher->RunAsync(
		CoreDispatcherPriority::Normal,
		ref new DispatchedHandler([this, text]()
	{
		TextTest->Text += text;
	}));
}

/// <summary>
/// Invoked when this page is about to be displayed in a Frame.
/// </summary>
/// <param name="e">Event data that describes how this page was reached.  The Parameter
/// property is typically used to configure the page.</param>
void MainPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	(void) e;	// Unused parameter

	TextTest->Text = "Checking test-signed drivers...";

	HKEY HKEY_LOCAL_MACHINE = (HKEY)0x80000002;
	DWORD retCode;

	HKEY controlKey = {};
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control", 0, KEY_ALL_ACCESS, &controlKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		return;
	}

	WCHAR ValueName[16383]; // buffer for value name
	DWORD ValueType;
	PBYTE ValueData = new BYTE[32767];

	DWORD i = 0;
	do
	{
		DWORD ValueNameSize = 16383;
		DWORD ValueDataSize = 32767;
		retCode = win32Api.RegEnumValueW(controlKey, i,
			ValueName,
			&ValueNameSize,
			NULL,
			&ValueType,
			ValueData,
			&ValueDataSize);

		debug(L"retCode %d Value name: %s\n", retCode, ValueName);

		if (wcscmp(L"SystemStartOptions", ValueName) == 0)
		{
			debug(L"Value: %s\n", ValueData);
			if (wcsstr((WCHAR*)ValueData, L"TESTSIGNING"))
			{
				debug(L"OK\n");
				TextTest->Text += L"OK\n";
			}
			else
			{
				TextTest->Text += L"Failed\n";
				TextTest->Text += L"Please enable test-signed drivers to load!!\n";
			}
		}

		i++;
	} while (retCode == ERROR_SUCCESS);
}

void wp81DeviceFilter::MainPage::AppBarButton_Click(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	Button^ b = (Button^)sender;
	if (b->Tag->ToString() == "Install")
	{
		Install();
	}
	else if (b->Tag->ToString() == "Ioctl")
	{
		SendIoctl();
	}
}

DWORD appendMultiSz(WCHAR* src, WCHAR* dst)
{
	DWORD size = 0;
	WCHAR* s = src;
	WCHAR* d = dst;
	do
	{
		*d = *s;
		s++;
		d++;
		size++;
	} while (*s != L'\0');
	*d = L'\0';
	size++;
	return size;
}

void wp81DeviceFilter::MainPage::Install()
{
	TextTest->Text += L"Create driver WP81DeviceFilter in registry... ";

	HKEY HKEY_LOCAL_MACHINE = (HKEY)0x80000002;
	DWORD retCode;

	// Configure WP81DeviceFilter driver

	HKEY servicesKey = {};
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	HKEY wp81driverKey = {};
	retCode = win32Api.RegCreateKeyExW(servicesKey, L"wp81devicefilter", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &wp81driverKey, NULL);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCreateKeyExW 'wp81devicefilter': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	PBYTE ValueData = new BYTE[256];

	ZeroMemory(ValueData, 256);
	wcscpy_s((WCHAR*)ValueData, 128, L"WP81 Device Filter driver");
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Description", NULL, REG_SZ, ValueData, (wcslen((WCHAR*)ValueData) + 1) * sizeof(WCHAR));
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Description': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	ZeroMemory(ValueData, 256);
	wcscpy_s((WCHAR*)ValueData, 128, L"wp81DeviceFilter");
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"DisplayName", NULL, REG_SZ, ValueData, (wcslen((WCHAR*)ValueData) + 1) * sizeof(WCHAR));
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'DisplayName': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 1; // Normal: If the driver fails to load or initialize, startup proceeds, but a warning message appears.
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"ErrorControl", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'ErrorControl': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 3; // SERVICE_DEMAND_START (started by the PlugAndPlay Manager)
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Start", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Start': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	*(PDWORD)ValueData = 1; // 	A kernel-mode device driver
	retCode = win32Api.RegSetValueExW(wp81driverKey, L"Type", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Type': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(wp81driverKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'wp81devicefilter': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'servicesKey': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	// Set wp81devicefilter as an upper filter of BTHMINI

	WCHAR *newValueData = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 5000);
	DWORD newValueDataSize = 0;
	//newValueDataSize += appendMultiSz(L"wp81devicefilter", newValueData);
	//newValueDataSize++; // add final \0
	//debug(L"First MultiString:\n");
	//debugMultiSz(newValueData);

	HKEY pdoKey = {};
	//// lumia 520
	//retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Enum\\SystemBusQc\\SMD_BT\\4&315a27b&0&4097", 0, KEY_ALL_ACCESS, &pdoKey);
	//if (retCode != ERROR_SUCCESS)
	//{
	//	debug(L"Error RegOpenKeyExW : %d\n", retCode);
	//	TextTest->Text += L"Failed\n";
	//	return;
	//}

	//retCode = win32Api.RegSetValueExW(pdoKey, L"UpperFilters", NULL, REG_MULTI_SZ, (BYTE*)newValueData, newValueDataSize * 2);
	//if (retCode != ERROR_SUCCESS)
	//{
	//	debug(L"Error RegSetValueExW 'UpperFilters': %d\n", retCode);
	//	TextTest->Text += L"Failed\n";
	//	return;
	//}

	//retCode = win32Api.RegCloseKey(pdoKey);
	//if (retCode != ERROR_SUCCESS)
	//{
	//	debug(L"Error RegCloseKey 'pdoKey': %d\n", retCode);
	//	TextTest->Text += L"Failed\n";
	//	return;
	//}

	//// Set wp81devicefilter as an upper filter of Bluetooth class

	newValueDataSize = 0;
	newValueDataSize += appendMultiSz(L"bthl2cap", newValueData + newValueDataSize); 
//	newValueDataSize += appendMultiSz(L"bthl2cap", newValueData + newValueDataSize);
	newValueDataSize += appendMultiSz(L"wp81devicefilter", newValueData + newValueDataSize);
	newValueDataSize++; // add final \0
	debug(L"Second MultiString:\n");
	debugMultiSz(newValueData);

	// lumia 520
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Class\\{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}", 0, KEY_ALL_ACCESS, &pdoKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegSetValueExW(pdoKey, L"UpperFilters", NULL, REG_MULTI_SZ, (BYTE*)newValueData, newValueDataSize * 2);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'UpperFilters': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	retCode = win32Api.RegCloseKey(pdoKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'pdoKey': %d\n", retCode);
		TextTest->Text += L"Failed\n";
		return;
	}

	TextTest->Text += L"OK\n";


	TextTest->Text += L"Install/Update driver...";

	Uri^ uri = ref new Uri("ms-appx:///Payload/wp81devicefilter.sys");
	create_task(StorageFile::GetFileFromApplicationUriAsync(uri)).then([=](task<StorageFile^> t)
	{
		StorageFile ^storageFile = t.get();
		Platform::String^ filePath = storageFile->Path;
		debug(L"FilePath : %ls\n", filePath->Data());
		if (!win32Api.CopyFileW(filePath->Data(), L"C:\\windows\\system32\\drivers\\wp81devicefilter.sys", FALSE))
		{
			debug(L"CopyFileW error: %d (32=ERROR_SHARING_VIOLATION)\n", GetLastError());
			UIConsoleAddText(L"Failed\n");
		}
		else
		{
			debug(L"File copied\n");
			UIConsoleAddText(L"OK\n");
		}
	});
}

VOID printBufferContent(PVOID buffer, size_t bufSize)
{
	CHAR hexString[256];
	CHAR chrString[256];
	CHAR tempString[8];
	size_t length;
	RtlZeroMemory(hexString, 256);
	RtlZeroMemory(chrString, 256);
	RtlZeroMemory(tempString, 8);
	unsigned char *p = (unsigned char*)buffer;
	unsigned int i = 0;
	BOOLEAN multiLine = FALSE;
	for (; i<bufSize && i < 608; i++)
	{
		sprintf_s(tempString, 8, "%02X ", p[i]);
		strcat_s(hexString, 256, tempString);

		sprintf_s(tempString, 8, "%c", p[i]>31 && p[i]<127 ? p[i] : '.');
		strcat_s(chrString, 256, tempString);

		if ((i + 1) % 38 == 0)
		{
			debug(L"%S%S\n", hexString, chrString);
			RtlZeroMemory(hexString, 256);
			RtlZeroMemory(chrString, 256);
			multiLine = TRUE;
		}
	}
	length = strlen(hexString);
	if (length != 0)
	{
		CHAR padding[256];
		RtlZeroMemory(padding, 256);
		if (multiLine)
		{
			sprintf_s(padding, 256, "%*s", 3 * (38 - (i % 38)), "");
		}

		debug(L"%S%S%S\n", hexString, padding, chrString);
	}

	if (i == 608)
	{
		debug(L"...\n");
	}
}

WCHAR* BthStatusDesc(BTHSTATUS error)
{
	WCHAR* desc;
	switch (error)
	{
	case 0x00:
		desc = L"SUCCESS";
		break;
	case 0x01:
		desc = L"UNKNOWN_HCI_COMMAND";
		break;
	case 0x02:
		desc = L"NO_CONNECTION";
		break;
	case 0x03:
		desc = L"HARDWARE_FAILURE";
		break;
	case 0x04:
		desc = L"PAGE_TIMEOUT";
		break;
	case 0x05:
		desc = L"AUTHENTICATION_FAILURE";
		break;
	case 0x06:
		desc = L"KEY_MISSING";
		break;
	case 0x07:
		desc = L"MEMORY_FULL";
		break;
	case 0x08:
		desc = L"CONNECTION_TIMEOUT";
		break;
	case 0x09:
		desc = L"MAX_NUMBER_OF_CONNECTIONS";
		break;
	case 0x0a:
		desc = L"MAX_NUMBER_OF_SCO_CONNECTIONS";
		break;
	case 0x0b:
		desc = L"ACL_CONNECTION_ALREADY_EXISTS";
		break;
	case 0x0c:
		desc = L"COMMAND_DISALLOWED";
		break;
	case 0x0d:
		desc = L"HOST_REJECTED_LIMITED_RESOURCES";
		break;
	case 0x0e:
		desc = L"HOST_REJECTED_SECURITY_REASONS";
		break;
	case 0x0f:
		desc = L"HOST_REJECTED_PERSONAL_DEVICE";
		break;
	case 0x10:
		desc = L"HOST_TIMEOUT";
		break;
	case 0x11:
		desc = L"UNSUPPORTED_FEATURE_OR_PARAMETER";
		break;
	case 0x12:
		desc = L"INVALID_HCI_PARAMETER";
		break;
	case 0x13:
		desc = L"REMOTE_USER_ENDED_CONNECTION";
		break;
	case 0x14:
		desc = L"REMOTE_LOW_RESOURCES";
		break;
	case 0x15:
		desc = L"REMOTE_POWERING_OFF";
		break;
	case 0x16:
		desc = L"LOCAL_HOST_TERMINATED_CONNECTION";
		break;
	case 0x17:
		desc = L"REPEATED_ATTEMPTS";
		break;
	case 0x18:
		desc = L"PAIRING_NOT_ALLOWED";
		break;
	case 0x19:
		desc = L"UKNOWN_LMP_PDU";
		break;
	case 0x1a:
		desc = L"UNSUPPORTED_REMOTE_FEATURE";
		break;
	case 0x1b:
		desc = L"SCO_OFFSET_REJECTED";
		break;
	case 0x1c:
		desc = L"SCO_INTERVAL_REJECTED";
		break;
	case 0x1d:
		desc = L"SCO_AIRMODE_REJECTED";
		break;
	case 0x1e:
		desc = L"INVALID_LMP_PARAMETERS";
		break;
	case 0x1f:
		desc = L"UNSPECIFIED_ERROR";
		break;
	case 0x20:
		desc = L"UNSUPPORTED_LMP_PARM_VALUE";
		break;
	case 0x21:
		desc = L"ROLE_CHANGE_NOT_ALLOWED";
		break;
	case 0x22:
		desc = L"LMP_RESPONSE_TIMEOUT";
		break;
	case 0x23:
		desc = L"LMP_TRANSACTION_COLLISION";
		break;
	case 0x24:
		desc = L"LMP_PDU_NOT_ALLOWED";
		break;
	case 0x25:
		desc = L"ENCRYPTION_MODE_NOT_ACCEPTABLE";
		break;
	case 0x26:
		desc = L"UNIT_KEY_NOT_USED";
		break;
	case 0x27:
		desc = L"QOS_IS_NOT_SUPPORTED";
		break;
	case 0x28:
		desc = L"INSTANT_PASSED";
		break;
	case 0x29:
		desc = L"PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED";
		break;
	case 0xFF:
		desc = L"UNSPECIFIED";
		break;
	default:
		desc = L"Unknown";
	}
	return desc;
}

void wp81DeviceFilter::MainPage::SendIoctl()
{
	TextTest->Text += L"Calling device IOCTL_BTH_GET_LOCAL_INFO...";
	create_task([this]()
	{
		// lumia 520
		HANDLE hDevice = win32Api.CreateFileW(L"\\??\\SystemBusQc#SMD_BT#4&315a27b&0&4097#{0850302a-b344-4fda-9be9-90576b8d46f0}", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE)
		{
			debug(L"Failed to open device! 0x%X\n", GetLastError());
			UIConsoleAddText(L"Failed to open device.\n");
			return;
		}

		
		// IOCTL_BTH_GET_LOCAL_INFO(0x410000)
		BTH_LOCAL_RADIO_INFO localRadioInfo;
		debug(L"BTH_LOCAL_RADIO_INFO size=%u\n",sizeof(localRadioInfo));
		DWORD returned;
		BOOL success = win32Api.DeviceIoControl(hDevice, 0x410000, nullptr, 0, &localRadioInfo, 292, &returned, nullptr);
		if (success)
		{
			debug(L"Device call IOCTL_BTH_GET_LOCAL_INFO succeeded! returned=%u\n", returned);
			UIConsoleAddText(L"succeeded!\n");

			printBufferContent(&localRadioInfo, returned);
			debug(L"BTH_LOCAL_RADIO_INFO.localInfo.flags=0x%08X\n", localRadioInfo.localInfo.flags);
			debug(L"BTH_LOCAL_RADIO_INFO.localInfo.address=%#I64x\n", localRadioInfo.localInfo.address);
			debug(L"BTH_LOCAL_RADIO_INFO.localInfo.classOfDevice=0x%08X\n", localRadioInfo.localInfo.classOfDevice);
			debug(L"BTH_LOCAL_RADIO_INFO.localInfo.name=%S\n", localRadioInfo.localInfo.name);
			debug(L"BTH_LOCAL_RADIO_INFO.flags=0x%08X\n", localRadioInfo.flags);
			debug(L"BTH_LOCAL_RADIO_INFO.hciRevision=0x%04X\n", localRadioInfo.hciRevision);
			debug(L"BTH_LOCAL_RADIO_INFO.hciVersion=0x%02X\n", localRadioInfo.hciVersion);
			debug(L"BTH_LOCAL_RADIO_INFO.radioInfo.lmpSupportedFeatures=%#I64x\n", localRadioInfo.radioInfo.lmpSupportedFeatures);
			debug(L"BTH_LOCAL_RADIO_INFO.radioInfo.mfg=0x%04X (1D=Qualcomm)\n", localRadioInfo.radioInfo.mfg);
			debug(L"BTH_LOCAL_RADIO_INFO.radioInfo.lmpSubversion=0x%04X\n", localRadioInfo.radioInfo.lmpSubversion);
			debug(L"BTH_LOCAL_RADIO_INFO.radioInfo.lmpVersion=0x%02X (6=Bluetooth 4.0)\n", localRadioInfo.radioInfo.lmpVersion);
			ULONG highLmpFeature = (localRadioInfo.radioInfo.lmpSupportedFeatures >> 32);
			ULONG lowLmpFeature = ((localRadioInfo.radioInfo.lmpSupportedFeatures << 32) >> 32);
			debug(L"LMP features:\n", highLmpFeature);
			debug(L"highLmpFeature=0x%08X\n", highLmpFeature);
			debug(L"lowLmpFeature=0x%08X\n", lowLmpFeature);
			debug(L"3_SLOT_PACKETS %d\n", LMP_3_SLOT_PACKETS(lowLmpFeature));
			debug(L"5_SLOT_PACKETS %d\n", LMP_5_SLOT_PACKETS(lowLmpFeature));
			debug(L"ENCRYPTION %d\n", LMP_ENCRYPTION(lowLmpFeature));
			debug(L"SLOT_OFFSET %d\n", LMP_SLOT_OFFSET(lowLmpFeature));
			debug(L"TIMING_ACCURACY %d\n", LMP_TIMING_ACCURACY(lowLmpFeature));
			debug(L"SWITCH %d\n", LMP_SWITCH(lowLmpFeature));
			debug(L"HOLD_MODE %d\n", LMP_HOLD_MODE(lowLmpFeature));
			debug(L"SNIFF_MODE %d\n", LMP_SNIFF_MODE(lowLmpFeature));
			debug(L"PARK_MODE %d\n", LMP_PARK_MODE(lowLmpFeature));
			debug(L"RSSI %d\n", LMP_RSSI(lowLmpFeature));
			debug(L"CHANNEL_QUALITY_DRIVEN_MODE %d\n", LMP_CHANNEL_QUALITY_DRIVEN_MODE(lowLmpFeature));
			debug(L"SCO_LINK %d\n", LMP_SCO_LINK(lowLmpFeature));
			debug(L"HV2_PACKETS %d\n", LMP_HV2_PACKETS(lowLmpFeature));
			debug(L"HV3_PACKETS %d\n", LMP_HV3_PACKETS(lowLmpFeature));
			debug(L"MU_LAW_LOG %d\n", LMP_MU_LAW_LOG(lowLmpFeature));
			debug(L"A_LAW_LOG %d\n", LMP_A_LAW_LOG(lowLmpFeature));
			debug(L"CVSD %d\n", LMP_CVSD(lowLmpFeature));
			debug(L"PAGING_SCHEME %d\n", LMP_PAGING_SCHEME(lowLmpFeature));
			debug(L"POWER_CONTROL %d\n", LMP_POWER_CONTROL(lowLmpFeature));
			debug(L"TRANSPARENT_SCO_DATA %d\n", LMP_TRANSPARENT_SCO_DATA(lowLmpFeature));
			debug(L"FLOW_CONTROL_LAG %d\n", LMP_FLOW_CONTROL_LAG(lowLmpFeature));
			debug(L"BROADCAST_ENCRYPTION %d\n", LMP_BROADCAST_ENCRYPTION(lowLmpFeature));
			debug(L"ENHANCED_DATA_RATE_ACL_2MBPS_MODE %d\n", LMP_ENHANCED_DATA_RATE_ACL_2MBPS_MODE(lowLmpFeature));
			debug(L"ENHANCED_DATA_RATE_ACL_3MBPS_MODE %d\n", LMP_ENHANCED_DATA_RATE_ACL_3MBPS_MODE(lowLmpFeature));
			debug(L"ENHANCED_INQUIRY_SCAN %d\n", LMP_ENHANCED_INQUIRY_SCAN(lowLmpFeature));
			debug(L"INTERLACED_INQUIRY_SCAN %d\n", LMP_INTERLACED_INQUIRY_SCAN(lowLmpFeature));
			debug(L"INTERLACED_PAGE_SCAN %d\n", LMP_INTERLACED_PAGE_SCAN(lowLmpFeature));
			debug(L"RSSI_WITH_INQUIRY_RESULTS %d\n", LMP_RSSI_WITH_INQUIRY_RESULTS(lowLmpFeature));
			debug(L"ESCO_LINK %d\n", LMP_ESCO_LINK(lowLmpFeature));
			debug(L"EV4_PACKETS %d\n", LMP_EV4_PACKETS(highLmpFeature));
			debug(L"EV5_PACKETS %d\n", LMP_EV5_PACKETS(highLmpFeature));
			debug(L"AFH_CAPABLE_SLAVE %d\n", LMP_AFH_CAPABLE_SLAVE(highLmpFeature));
			debug(L"AFH_CLASSIFICATION_SLAVE %d\n", LMP_AFH_CLASSIFICATION_SLAVE(highLmpFeature));
			debug(L"BR_EDR_NOT_SUPPORTED %d\n", LMP_BR_EDR_NOT_SUPPORTED(highLmpFeature));
			debug(L"LE_SUPPORTED %d\n", LMP_LE_SUPPORTED(highLmpFeature));
			debug(L"3SLOT_EDR_ACL_PACKETS %d\n", LMP_3SLOT_EDR_ACL_PACKETS(highLmpFeature));
			debug(L"5SLOT_EDR_ACL_PACKETS %d\n", LMP_5SLOT_EDR_ACL_PACKETS(highLmpFeature));
			debug(L"SNIFF_SUBRATING %d\n", LMP_SNIFF_SUBRATING(highLmpFeature));
			debug(L"PAUSE_ENCRYPTION %d\n", LMP_PAUSE_ENCRYPTION(highLmpFeature));
			debug(L"AFH_CAPABLE_MASTER %d\n", LMP_AFH_CAPABLE_MASTER(highLmpFeature));
			debug(L"AFH_CLASSIFICATION_MASTER %d\n", LMP_AFH_CLASSIFICATION_MASTER(highLmpFeature));
			debug(L"EDR_ESCO_2MBPS_MODE %d\n", LMP_EDR_ESCO_2MBPS_MODE(highLmpFeature));
			debug(L"EDR_ESCO_3MBPS_MODE %d\n", LMP_EDR_ESCO_3MBPS_MODE(highLmpFeature));
			debug(L"3SLOT_EDR_ESCO_PACKETS %d\n", LMP_3SLOT_EDR_ESCO_PACKETS(highLmpFeature));
			debug(L"EXTENDED_INQUIRY_RESPONSE %d\n", LMP_EXTENDED_INQUIRY_RESPONSE(highLmpFeature));
			debug(L"SIMULT_LE_BR_TO_SAME_DEV %d\n", LMP_SIMULT_LE_BR_TO_SAME_DEV(highLmpFeature));
			debug(L"SECURE_SIMPLE_PAIRING %d\n", LMP_SECURE_SIMPLE_PAIRING(highLmpFeature));
			debug(L"ENCAPSULATED_PDU %d\n", LMP_ENCAPSULATED_PDU(highLmpFeature));
			debug(L"ERRONEOUS_DATA_REPORTING %d\n", LMP_ERRONEOUS_DATA_REPORTING(highLmpFeature));
			debug(L"NON_FLUSHABLE_PACKET_BOUNDARY_FLAG %d\n", LMP_NON_FLUSHABLE_PACKET_BOUNDARY_FLAG(highLmpFeature));
			debug(L"LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT %d\n", LMP_LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT(highLmpFeature));
			debug(L"INQUIRY_RESPONSE_TX_POWER_LEVEL %d\n", LMP_INQUIRY_RESPONSE_TX_POWER_LEVEL(highLmpFeature));
			debug(L"EXTENDED_FEATURES %d\n", LMP_EXTENDED_FEATURES(highLmpFeature));
			debug(L"Local radio flags:\n");
			debug(L"DISCOVERABLE %d\n", (localRadioInfo.flags & LOCAL_RADIO_DISCOVERABLE) != 0);
			debug(L"CONNECTABLE %d\n", (localRadioInfo.flags & LOCAL_RADIO_CONNECTABLE) != 0);
			debug(L"Local info flags:\n");
			debug(L"ADDRESS %d\n", (localRadioInfo.localInfo.flags & BDIF_ADDRESS) != 0);
			debug(L"COD %d\n", (localRadioInfo.localInfo.flags & BDIF_COD) != 0);
			debug(L"NAME %d\n", (localRadioInfo.localInfo.flags & BDIF_NAME) != 0);
			debug(L"PAIRED %d\n", (localRadioInfo.localInfo.flags & BDIF_PAIRED) != 0);
			debug(L"PERSONAL %d\n", (localRadioInfo.localInfo.flags & BDIF_PERSONAL) != 0);
			debug(L"CONNECTED %d\n", (localRadioInfo.localInfo.flags & BDIF_CONNECTED) != 0);
			debug(L"SHORT_NAME %d\n", (localRadioInfo.localInfo.flags & BDIF_SHORT_NAME) != 0);
			debug(L"VISIBLE %d\n", (localRadioInfo.localInfo.flags & BDIF_VISIBLE) != 0);
			debug(L"SSP_SUPPORTED %d\n", (localRadioInfo.localInfo.flags & BDIF_SSP_SUPPORTED) != 0);
			debug(L"SSP_PAIRED %d\n", (localRadioInfo.localInfo.flags & BDIF_SSP_PAIRED) != 0);
			debug(L"SSP_MITM_PROTECTED %d\n", (localRadioInfo.localInfo.flags & BDIF_SSP_MITM_PROTECTED) != 0);
			debug(L"RSSI %d\n", (localRadioInfo.localInfo.flags & BDIF_RSSI) != 0);
			debug(L"EIR %d\n", (localRadioInfo.localInfo.flags & BDIF_EIR) != 0);
			debug(L"BR %d\n", (localRadioInfo.localInfo.flags & BDIF_BR) != 0);
			debug(L"LE %d\n", (localRadioInfo.localInfo.flags & BDIF_LE) != 0);
			debug(L"LE_PAIRED %d\n", (localRadioInfo.localInfo.flags & BDIF_LE_PAIRED) != 0);
			debug(L"LE_PERSONAL %d\n", (localRadioInfo.localInfo.flags & BDIF_LE_PERSONAL) != 0);
			debug(L"LE_MITM_PROTECTED %d\n", (localRadioInfo.localInfo.flags & BDIF_LE_MITM_PROTECTED) != 0);
			debug(L"LE_PRIVACY_ENABLED %d\n", (localRadioInfo.localInfo.flags & BDIF_LE_PRIVACY_ENABLED) != 0);
			debug(L"LE_RANDOM_ADDRESS_TYPE %d\n", (localRadioInfo.localInfo.flags & BDIF_LE_RANDOM_ADDRESS_TYPE) != 0);
			ULONG highAddress = (localRadioInfo.localInfo.address >> 32);
			ULONG lowAddress = ((localRadioInfo.localInfo.address << 32) >> 32);
			debug(L"Local radio address: %02X %02X %02X %02X %02X %02X\n", ((highAddress >> 8) & 0xFF), (highAddress & 0xFF), ((lowAddress >> 24) & 0xFF), ((lowAddress >> 16) & 0xFF), ((lowAddress >> 8) & 0xFF), (lowAddress & 0xFF));
			debug(L"Local info classOfDevice:\n");
			debug(L"FORMAT 0x%X (0x0=VERSION)\n", GET_COD_FORMAT(localRadioInfo.localInfo.classOfDevice));
			debug(L"MAJOR 0x%02X (0x02=PHONE)\n", GET_COD_MAJOR(localRadioInfo.localInfo.classOfDevice));
			debug(L"MINOR 0x%02X (0x03=SMART)\n", GET_COD_MINOR(localRadioInfo.localInfo.classOfDevice));
			debug(L"SERVICE:\n");
			debug(L"LIMITED %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_LIMITED) != 0);
			debug(L"POSITIONING %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_POSITIONING) != 0);
			debug(L"NETWORKING %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_NETWORKING) != 0);
			debug(L"RENDERING %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_RENDERING) != 0);
			debug(L"CAPTURING %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_CAPTURING) != 0);
			debug(L"OBJECT_XFER %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_OBJECT_XFER) != 0);
			debug(L"AUDIO %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_AUDIO) != 0);
			debug(L"TELEPHONY %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_TELEPHONY) != 0);
			debug(L"INFORMATION %d\n", (GET_COD_SERVICE(localRadioInfo.localInfo.classOfDevice) & COD_SERVICE_INFORMATION) != 0);
		}
		else
		{
			debug(L"Device call IOCTL_BTH_GET_LOCAL_INFO failed! 0x%X\n", GetLastError());
			UIConsoleAddText(L"failed!\n");
		}

		CloseHandle(hDevice);

		HANDLE timeout = CreateEventEx(nullptr, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);

		OVERLAPPED ov;
		ov.hEvent = CreateEventEx(nullptr, nullptr, CREATE_EVENT_MANUAL_RESET, EVENT_ALL_ACCESS);
		if (ov.hEvent == INVALID_HANDLE_VALUE)
		{
			debug(L"Failed to create event! 0x%X\n", GetLastError());
			UIConsoleAddText(L"Failed to create event.\n");
			return;
		}
		hDevice = win32Api.CreateFileW(L"\\??\\SystemBusQc#SMD_BT#4&315a27b&0&4097#{0850302a-b344-4fda-9be9-90576b8d46f0}", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
		if (hDevice == INVALID_HANDLE_VALUE)
		{
			debug(L"Failed to open device! 0x%X\n", GetLastError());
			UIConsoleAddText(L"Failed to open device.\n");
			return;
		}

		UIConsoleAddText(L"Calling device IOCTL_BTH_PAIR_DEVICE...");
		// IOCTL_BTH_PAIR_DEVICE(0x411010)
		BTH_AUTHENTICATE_DEVICE pairDevice;
		debug(L"BTH_AUTHENTICATE_DEVICE size=%u\n", sizeof(pairDevice));
		ZeroMemory(&pairDevice, sizeof(pairDevice));
		pairDevice.unknown1 = 0x4000;
		pairDevice.address = 0xE0E751333260;
		pairDevice.unknown3 = 0x3; // 0x0...0x5
		printBufferContent(&pairDevice, 592);
		BTHSTATUS bthStatus;

		success = win32Api.DeviceIoControl(hDevice, 0x411010, &pairDevice, 592, &bthStatus, 1, &returned, &ov);
		if (success)
		{
			debug(L"Device call IOCTL_BTH_PAIR_DEVICE succeeded! returned=%u\n", returned);
			UIConsoleAddText(L"succeeded!\n");

			printBufferContent(&bthStatus, returned);
			debug(L"response=%s\n", BthStatusDesc(bthStatus));
		}
		else
		{
			if (GetLastError() != ERROR_IO_PENDING)
			{
				debug(L"Device call IOCTL_BTH_PAIR_DEVICE failed! 0x%X (0x57=ERROR_INVALID_PARAMETER)\n", GetLastError());
				UIConsoleAddText(L"failed!\n");
			}
			else
			{
				debug(L"Waiting result...\n");
				UIConsoleAddText(L"Waiting result...");

				WaitForSingleObject(timeout, 2000);

				// IOCTL_BTH_AUTH_RESPONSE(0x411004)
				BTH_AUTHENTICATE_RESPONSE sendPin;
				debug(L"IOCTL_BTH_AUTH_RESPONSE size=%u\n", sizeof(sendPin));
				ZeroMemory(&sendPin, sizeof(sendPin));
				sendPin.unknown1 = 0x4000;
				sendPin.address = 0xE0E751333260;
				sendPin.unknown3 = 0x01;
				memcpy(sendPin.info.pin, "1234", 4);
				sendPin.info.pinLength = 4;
				printBufferContent(&sendPin, 576);
				BTHSTATUS bthStatus2;

				success = win32Api.DeviceIoControl(hDevice, 0x411004, &sendPin, 576, &bthStatus2, 1, &returned, NULL);
				if (success)
				{
					debug(L"Device call IOCTL_BTH_AUTH_RESPONSE succeeded! returned=%u\n", returned);
					UIConsoleAddText(L"succeeded!\n");

					printBufferContent(&bthStatus2, returned);
					debug(L"IOCTL_BTH_AUTH_RESPONSE response=%s\n", BthStatusDesc(bthStatus2));
				}
				else
				{
					debug(L"Device call IOCTL_BTH_AUTH_RESPONSE failed! 0x%X (0x57=ERROR_INVALID_PARAMETER 0x48F=ERROR_DEVICE_NOT_CONNECTED 0xAA=ERROR_BUSY)\n", GetLastError());
					UIConsoleAddText(L"failed!\n");
				}
			}
		}

		WaitForSingleObject(ov.hEvent, INFINITE);
		GetOverlappedResult(hDevice, &ov, &returned, FALSE);

		debug(L"Device call IOCTL_BTH_PAIR_DEVICE succeeded! returned=%u\n", returned);
		UIConsoleAddText(L"succeeded!\n");
		
		debug(L"returned=%u\n", returned);
		printBufferContent(&bthStatus, returned);
		debug(L"IOCTL_BTH_PAIR_DEVICE response=%s\n", BthStatusDesc(bthStatus));

		CloseHandle(timeout);
		CloseHandle(ov.hEvent);
		CloseHandle(hDevice);
	});
}
