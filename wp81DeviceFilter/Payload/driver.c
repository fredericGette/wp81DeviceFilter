// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} bootlog Yes
// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} testsigning yes
//
// set PATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\x86_arm;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin;%PATH%
//
// BthEnum x3	BthLEEnum x1
//      \        /
//      BthMini x3		lumia520: System\\CurrentControlSet\\Enum\\SystemBusQc\\SMD_BT\\4&315a27b&0&4097
//          |
//     QcBluetooth x2
//
// https://github.com/uri247/wdk80/blob/67e3dc8fada017ff2f49fefb9ac670a955a27e36/Bluetooth%20Serial%20HCI%20Bus%20Driver/Solution/Fdo.c

#include <ntifs.h>
#include <wdf.h>
#include <ntstrsafe.h>

#define REQUIRED_ACCESS_FROM_CTL_CODE(ctrlCode)     (((ULONG)(ctrlCode & 0xC000)) >> 14)

typedef struct _DEVICEFILTER_CONTEXT
{
    //
    // Framework device this context is associated with
    //
    WDFDEVICE Device;
	
	CHAR Name[32];

} DEVICEFILTER_CONTEXT, *PDEVICEFILTER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICEFILTER_CONTEXT, GetDeviceContext);


typedef ULONGLONG BTH_ADDR, *PBTH_ADDR;
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

typedef enum _BTHX_HCI_PACKET_TYPE {
    HciPacketCommand    = 0x01,
    HciPacketAclData    = 0x02,
    HciPacketEvent      = 0x04
} BTHX_HCI_PACKET_TYPE;

#pragma pack(1)
typedef struct _BTHX_HCI_READ_WRITE_CONTEXT {
    ULONG   DataLen;    // Size of Data
    UCHAR   Type;       // Packet Type
    _Field_size_bytes_(DataLen) UCHAR   Data[1];    // Actual data
} BTHX_HCI_READ_WRITE_CONTEXT, *PBTHX_HCI_READ_WRITE_CONTEXT;
#pragma pack(8)

CHAR* ErrorCodeDesc(UCHAR ErrorCode, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR ErrorCodeValue[16];
	
	// Find what:^  (.*) = (.*),$
	// Replace with:case \2:\n\tRtlStringCbCatA\(buffer, bufSize, "\1"\);\n\tbreak;
	switch(ErrorCode)
	{
		case 0x00:
			RtlStringCbCatA(buffer, bufSize, "SUCCESS");
			break;
		case 0x01:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN_HCI_COMMAND");
			break;
		case 0x02:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN_CONNECTION");
			break;
		case 0x03:
			RtlStringCbCatA(buffer, bufSize, "HARDWARE_FAILURE");
			break;
		case 0x04:
			RtlStringCbCatA(buffer, bufSize, "PAGE_TIMEOUT");
			break;
		case 0x05:
			RtlStringCbCatA(buffer, bufSize, "AUTHENTICATION_FAILURE");
			break;
		case 0x06:
			RtlStringCbCatA(buffer, bufSize, "PIN_OR_KEY_MISSING");
			break;
		case 0x07:
			RtlStringCbCatA(buffer, bufSize, "MEMORY_CAPACITY_EXCEEDED");
			break;
		case 0x08:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_TIMEOUT");
			break;
		case 0x09:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_LIMIT_EXCEEDED");
			break;
		case 0x0A:
			RtlStringCbCatA(buffer, bufSize, "SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED");
			break;
		case 0x0B:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_ALREADY_EXISTS");
			break;
		case 0x0C:
			RtlStringCbCatA(buffer, bufSize, "COMMAND_DISALLOWED");
			break;
		case 0x0D:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_REJECTED_LIMITED_RESOURCES");
			break;
		case 0x0E:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_REJECTED_SECURITY_REASONS");
			break;
		case 0x0F:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_REJECTED_UNACCEPTABLE_BD_ADDR");
			break;
		case 0x10:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_ACCEPT_TIMEOUT");
			break;
		case 0x11:
			RtlStringCbCatA(buffer, bufSize, "UNSUPORTED_FEATURE_OR_PARAMETER_VALUE");
			break;
		case 0x12:
			RtlStringCbCatA(buffer, bufSize, "INVALID_HCI_COMMAND_PARAMETERS");
			break;
		case 0x13:
			RtlStringCbCatA(buffer, bufSize, "REMOTE_USER_TERMINATED_CONNECTION");
			break;
		case 0x14:
			RtlStringCbCatA(buffer, bufSize, "REMOTE_DEVICE_TERMINATED_CONNECTION_LOW_RESOURCES");
			break;
		case 0x15:
			RtlStringCbCatA(buffer, bufSize, "REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF");
			break;
		case 0x16:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_TERMINATED_BY_LOCAL_HOST");
			break;
		case 0x17:
			RtlStringCbCatA(buffer, bufSize, "REPEATED_ATTEMPTS");
			break;
		case 0x18:
			RtlStringCbCatA(buffer, bufSize, "PAIRING_NOT_ALLOWED");
			break;
		case 0x19:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN_LMP_PDU");
			break;
		case 0x1A:
			RtlStringCbCatA(buffer, bufSize, "UNSUPPORTED_REMOTE_OR_LMP_FEATURE");
			break;
		case 0x1B:
			RtlStringCbCatA(buffer, bufSize, "SCO_OFFSET_REJECTED");
			break;
		case 0x1C:
			RtlStringCbCatA(buffer, bufSize, "SCO_INTERVAL_REJECTED");
			break;
		case 0x1D:
			RtlStringCbCatA(buffer, bufSize, "SCO_AIR_MODE_REJECTED");
			break;
		case 0x1E:
			RtlStringCbCatA(buffer, bufSize, "INVALID_LMP_OR_LL_PARAMETERS");
			break;
		case 0x1F:
			RtlStringCbCatA(buffer, bufSize, "UNSPECIFIED_ERROR");
			break;
		case 0x20:
			RtlStringCbCatA(buffer, bufSize, "UNSUPPORTED_LMP_OR_LL_PARAMETER");
			break;
		case 0x21:
			RtlStringCbCatA(buffer, bufSize, "ROLE_CHANGE_NOT_ALLOWED");
			break;
		case 0x22:
			RtlStringCbCatA(buffer, bufSize, "LMP_RESPONSE_TIMEOUT");
			break;
		case 0x23:
			RtlStringCbCatA(buffer, bufSize, "LINK_LAYER_COLLISION");
			break;
		case 0x24:
			RtlStringCbCatA(buffer, bufSize, "LMP_PDU_NOT_ALLOWED");
			break;
		case 0x25:
			RtlStringCbCatA(buffer, bufSize, "ENCRYPTION_MODE_NOT_ACCEPTABLE");
			break;
		case 0x26:
			RtlStringCbCatA(buffer, bufSize, "UNIT_KEY_USED");
			break;
		case 0x27:
			RtlStringCbCatA(buffer, bufSize, "QOS_NOT_SUPPORTED");
			break;
		case 0x28:
			RtlStringCbCatA(buffer, bufSize, "INSTANT_PASSED");
			break;
		case 0x29:
			RtlStringCbCatA(buffer, bufSize, "PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED");
			break;
		case 0x35:
			RtlStringCbCatA(buffer, bufSize, "ROLE_SWITCH_FAILED");
			break;
		case 0x3A:
			RtlStringCbCatA(buffer, bufSize, "CONTROLLER_BUSY");
			break;
		case 0x3E:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_FAILED_ESTABLISHMENT");
			break;		
		default:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN");
	}
	RtlStringCbPrintfA(ErrorCodeValue, 16, "(0x%02X) ", ErrorCode);
	RtlStringCbCatA(buffer, bufSize, ErrorCodeValue);

	return buffer;
}		
		

CHAR* EventCodeDesc(UCHAR EventCode, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR EventCodeValue[16];
	
	// Find what:^  (.*) = (.*),$
	// Replace with:case \2:\n\tRtlStringCbCatA\(buffer, bufSize, "\1"\);\n\tbreak;
	switch(EventCode)
	{
		case 0x01:
			RtlStringCbCatA(buffer, bufSize, "INQUIRY_COMPLETE"); // Indicates the Inquiry has finished.
			break;
		case 0x02:
			RtlStringCbCatA(buffer, bufSize, "INQUIRY_RESULT"); // Indicates that Bluetooth device(s) have responded for the inquiry.
			break;
		case 0x03:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_COMPLETE"); // Indicates to both hosts that the new connection has been formed.
			break;
		case 0x04:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_REQUEST"); // Indicates that a new connection is trying to be established.
			break;
		case 0x05:
			RtlStringCbCatA(buffer, bufSize, "DISCONNECTION_COMPLETE"); // Occurs when a connection has been disconnected.
			break;
		case 0x06:
			RtlStringCbCatA(buffer, bufSize, "AUTHENTICATION_COMPLETE"); // Occurs when an authentication has been completed.
			break;
		case 0x07:
			RtlStringCbCatA(buffer, bufSize, "REMOTE_NAME_REQUEST_COMPLETE"); // Indicates that the request for the remote name has been completed.
			break;
		case 0x08:
			RtlStringCbCatA(buffer, bufSize, "ENCRYPTION_CHANGE"); // Indicates that a change in the encryption has been completed.
			break;
		case 0x09:
			RtlStringCbCatA(buffer, bufSize, "CHANGE_CONNECTION_LINK_KEY_COMPLETE"); // Indicates that the change in the link key has been completed.
			break;
		case 0x0A:
			RtlStringCbCatA(buffer, bufSize, "CENTRAL_LINK_KEY_COMPLETE"); // Indicates that the change in the temporary link key or semi permanent link key on the master device is complete.
			break;
		case 0x0B:
			RtlStringCbCatA(buffer, bufSize, "READ_REMOTE_SUPPORTED_FEATURES_COMPLETE"); // Indicates that the reading of the supported features on the remote device is complete.
			break;
		case 0x0C:
			RtlStringCbCatA(buffer, bufSize, "READ_REMOTE_VERSION_INFORMATION_COMPLETE"); // Indicates that the version number on the remote device has been read and completed.
			break;
		case 0x0D:
			RtlStringCbCatA(buffer, bufSize, "QOS_SETUP_COMPLETE"); // Indicates that the Quality of Service setup has been complete.
			break;
		case 0x0E:
			RtlStringCbCatA(buffer, bufSize, "COMMAND_COMPLETE"); // Used by controller to send status and event parameters to the host for the particular command.
			break;
		case 0x0F:
			RtlStringCbCatA(buffer, bufSize, "COMMAND_STATUS"); // Indicates that the command has been received and is being processed in the host controller.
			break;
		case 0x10:
			RtlStringCbCatA(buffer, bufSize, "HARDWARE_ERROR"); // Indicates a hardware failure of the Bluetooth device.
			break;
		case 0x11:
			RtlStringCbCatA(buffer, bufSize, "FLUSH_OCCURRED"); // Indicates that the data has been flushed for a particular connection.
			break;
		case 0x12:
			RtlStringCbCatA(buffer, bufSize, "ROLE_CHANGE"); // Indicates that the current bluetooth role for a connection has been changed.
			break;
		case 0x13:
			RtlStringCbCatA(buffer, bufSize, "NUMBER_OF_COMPLETED_PACKETS"); // Indicates to the host the number of data packets sent compared to the last time the same event was sent.
			break;
		case 0x14:
			RtlStringCbCatA(buffer, bufSize, "MODE_CHANGE"); // Indicates the change in mode from hold, sniff, park or active to another mode.
			break;
		case 0x15:
			RtlStringCbCatA(buffer, bufSize, "RETURN_LINK_KEYS"); // Used to return stored link keys after a Read_Stored_Link_Key command was issued.
			break;
		case 0x16:
			RtlStringCbCatA(buffer, bufSize, "PIN_CODE_REQUEST"); // Indicates the a PIN code is required for a new connection.
			break;
		case 0x17:
			RtlStringCbCatA(buffer, bufSize, "LINK_KEY_REQUEST"); // Indicates that a link key is required for the connection.
			break;
		case 0x18:
			RtlStringCbCatA(buffer, bufSize, "LINK_KEY_NOTIFICATION"); // Indicates to the host that a new link key has been created.
			break;
		case 0x19:
			RtlStringCbCatA(buffer, bufSize, "LOOPBACK_COMMAND"); // Indicates that command sent from the host will be looped back.
			break;
		case 0x1A:
			RtlStringCbCatA(buffer, bufSize, "DATA_BUFFER_OVERFLOW"); // Indicates that the data buffers on the host has overflowed.
			break;
		case 0x1B:
			RtlStringCbCatA(buffer, bufSize, "MAX_SLOTS_CHANGE"); // Informs the host when the LMP_Max_Slots parameter changes.
			break;
		case 0x1C:
			RtlStringCbCatA(buffer, bufSize, "READ_CLOCK_OFFSET_COMPLETE"); // Indicates the completion of reading the clock offset information.
			break;
		case 0x1D:
			RtlStringCbCatA(buffer, bufSize, "CONNECTION_PACKET_TYPE_CHANGED"); // Indicate the completion of the packet type change for a connection.
			break;
		case 0x1E:
			RtlStringCbCatA(buffer, bufSize, "QOS_VIOLATION"); // Indicates that the link manager is unable to provide the required Quality of Service.
			break;
		case 0x1F:
			RtlStringCbCatA(buffer, bufSize, "PAGE_SCAN_MODE_CHANGE"); // Indicates that the remote device has successfully changed the Page Scan mode.
			break;
		case 0x20:
			RtlStringCbCatA(buffer, bufSize, "PAGE_SCAN_REPETITION_MODE_CHANGE"); // Indicates that the remote device has successfully changed the Page Scan Repetition mode.
			break;
		case 0x21:
			RtlStringCbCatA(buffer, bufSize, "FLOW_SPECIFICATION_COMPLETE");
			break;
		case 0x22:
			RtlStringCbCatA(buffer, bufSize, "INQUIRY_RESULT_WITH_RSSI");
			break;
		case 0x23:
			RtlStringCbCatA(buffer, bufSize, "READ_REMOTE_EXTENDED_FEATURES_COMPLETE");
			break;
		case 0x2C:
			RtlStringCbCatA(buffer, bufSize, "SYNCHRONOUS_CONNECTION_COMPLETE");
			break;
		case 0x2D:
			RtlStringCbCatA(buffer, bufSize, "SYNCHRONOUS_CONNECTION_CHANGED");
			break;
		case 0x2E:
			RtlStringCbCatA(buffer, bufSize, "SNIFF_SUBRATING");
			break;
		case 0x2F:
			RtlStringCbCatA(buffer, bufSize, "EXTENDED_INQUIRY_RESULT");
			break;
		case 0x30:
			RtlStringCbCatA(buffer, bufSize, "ENCRYPTION_KEY_REFRESH_COMPLETE");
			break;
		case 0x31:
			RtlStringCbCatA(buffer, bufSize, "IO_CAPABILITY_REQUEST");
			break;
		case 0x32:
			RtlStringCbCatA(buffer, bufSize, "IO_CAPABILITY_RESPONSE");
			break;
		case 0x33:
			RtlStringCbCatA(buffer, bufSize, "USER_CONFIRMATION_REQUEST");
			break;
		case 0x34:
			RtlStringCbCatA(buffer, bufSize, "USER_PASSKEY_REQUEST");
			break;
		case 0x35:
			RtlStringCbCatA(buffer, bufSize, "REMOTE_OOB_DATA_REQUEST");
			break;
		case 0x36:
			RtlStringCbCatA(buffer, bufSize, "SIMPLE_PAIRING_COMPLETE");
			break;
		case 0x38:
			RtlStringCbCatA(buffer, bufSize, "LINK_SUPERVISION_TIMEOUT_CHANGED");
			break;
		case 0x39:
			RtlStringCbCatA(buffer, bufSize, "ENHANCED_FLUSH_COMPLETE");
			break;
		case 0x3B:
			RtlStringCbCatA(buffer, bufSize, "USER_PASSKEY_NOTIFICATION");
			break;
		case 0x3C:
			RtlStringCbCatA(buffer, bufSize, "KEYPRESS_NOTIFICATION");
			break;
		case 0x3D:
			RtlStringCbCatA(buffer, bufSize, "REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION");
			break;
		case 0x3e:
			RtlStringCbCatA(buffer, bufSize, "LE_META_EVENT");
			break;
		case 0x48:
			RtlStringCbCatA(buffer, bufSize, "NUMBER_OF_COMPLETED_DATA_BLOCKS");
			break;
		case 0xFE:
			RtlStringCbCatA(buffer, bufSize, "BLUETOOTH_LOGO_TESTING");
			break;
		case 0xFF:
			RtlStringCbCatA(buffer, bufSize, "VENDOR_SPECIFIC");
			break;
		default:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN");
	}
	RtlStringCbPrintfA(EventCodeValue, 16, "(0x%02X) ", EventCode);
	RtlStringCbCatA(buffer, bufSize, EventCodeValue);

	return buffer;
}

CHAR* OGF_OCF_Desc(ULONG OGF, ULONG OCF,CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR OGF_OCF_Value[16];
	
	// http://www.dziwior.org/Bluetooth/HCI_Commands_Link_Control.html
	// https://android.googlesource.com/platform//system/bt/+/95bb8d8eb533b5ddbb67bf6dd0b6e9d3c523f8ce/gd/hci/hci_packets.pdl
	// https://www.lisha.ufsc.br/teaching/shi/ine5346-2003-1/work/bluetooth/hci_commands.html
	switch(OGF)
	{
		case 0x01:
			RtlStringCbCatA(buffer, bufSize, "LINK_CONTROL:");
			switch(OCF)
			{		
				case 0x0001:
					RtlStringCbCatA(buffer, bufSize, "INQUIRY"); // Command used to enter Inquiry mode where it discovers other Bluetooth devices.
					break;					
				case 0x0002:
					RtlStringCbCatA(buffer, bufSize, "INQUIRY_CANCEL"); // Command to cancel the Inquiry mode in which the Bluetooth device is in.
					break;					
				case 0x0003:
					RtlStringCbCatA(buffer, bufSize, "PERIODIC_INQUIRY_MODE"); // Command to set the device to enter Inquiry modes periodically according to the time interval set.
					break;					
				case 0x0004:
					RtlStringCbCatA(buffer, bufSize, "EXIT_PERIODIC_INQUIRY_MODE"); // Command to exit the periodic Inquiry mode
					break;					
				case 0x0005:
					RtlStringCbCatA(buffer, bufSize, "CREATE_CONNECTION"); // Command to create an ACL connection to the device specified by the BD_ADDR in the parameters.
					break;					
				case 0x0006:
					RtlStringCbCatA(buffer, bufSize, "DISCONNECT"); // Command to terminate the existing connection to a device
					break;					
				case 0x0007:
					RtlStringCbCatA(buffer, bufSize, "ADD_SCO_CONNECTION"); // Create an SCO connection defined by the connection handle parameters.
					break;					
				case 0x0008:
					RtlStringCbCatA(buffer, bufSize, "CREATE_CONNECTION_CANCEL");
					break;					
				case 0x0009:
					RtlStringCbCatA(buffer, bufSize, "ACCEPT_CONNECTION_REQUEST"); // Command to accept a new connection request
					break;					
				case 0x000A:
					RtlStringCbCatA(buffer, bufSize, "REJECT_CONNECTION_REQUEST"); // Command to reject a new connection request
					break;					
				case 0x000B:
					RtlStringCbCatA(buffer, bufSize, "LINK_KEY_REQUEST_REPLY"); // Reply command to a link key request event sent from controller to the host
					break;					
				case 0x000C:
					RtlStringCbCatA(buffer, bufSize, "LINK_KEY_REQUEST_NEGATIVE_REPLY"); // Reply command to a link key request event from the controller to the host if there is no link key associated with the connection.
					break;					
				case 0x000D:
					RtlStringCbCatA(buffer, bufSize, "PIN_CODE_REQUEST_REPLY"); // Reply command to a PIN code request event sent from a controller to the host.
					break;					
				case 0x000E:
					RtlStringCbCatA(buffer, bufSize, "PIN_CODE_REQUEST_NEGATIVE_REPLY"); // Reply command to a PIN code request event sent from the controller to the host if there is no PIN associated with the connection.
					break;					
				case 0x000F:
					RtlStringCbCatA(buffer, bufSize, "CHANGE_CONNECTION_PACKET_TYPE"); // Command to change the type of packets to be sent for an existing connection.
					break;					
				case 0x0011:
					RtlStringCbCatA(buffer, bufSize, "AUTHENTICATION_REQUESTED"); // Command to establish authentication between two devices specified by the connection handle.
					break;					
				case 0x0013:
					RtlStringCbCatA(buffer, bufSize, "SET_CONNECTION_ENCRYPTION"); // Command to enable or disable the link level encryption.
					break;					
				case 0x0015:
					RtlStringCbCatA(buffer, bufSize, "CHANGE_CONNECTION_LINK_KEY"); // Command to force the change of a link key to a new one between two connected devices.
					break;					
				case 0x0017:
					RtlStringCbCatA(buffer, bufSize, "CENTRAL_LINK_KEY"); // Command to force two devices to use the master's link key temporarily.
					break;					
				case 0x0019:
					RtlStringCbCatA(buffer, bufSize, "REMOTE_NAME_REQUEST"); // Command to determine the user friendly name of the connected device.
					break;					
				case 0x001A:
					RtlStringCbCatA(buffer, bufSize, "REMOTE_NAME_REQUEST_CANCEL");
					break;					
				case 0x001B:
					RtlStringCbCatA(buffer, bufSize, "READ_REMOTE_SUPPORTED_FEATURES"); // Command to determine the features supported by the connected device.
					break;					
				case 0x001C:
					RtlStringCbCatA(buffer, bufSize, "READ_REMOTE_EXTENDED_FEATURES");
					break;					
				case 0x001D:
					RtlStringCbCatA(buffer, bufSize, "READ_REMOTE_VERSION_INFORMATION"); // Command to determine the version information of the connected device.
					break;					
				case 0x001F:
					RtlStringCbCatA(buffer, bufSize, "READ_CLOCK_OFFSET"); // Command to read the clock offset of the remote device.
					break;										
				case 0x0020:
					RtlStringCbCatA(buffer, bufSize, "READ_LMP_HANDLE");
					break;															
				case 0x0028:
					RtlStringCbCatA(buffer, bufSize, "SETUP_SYNCHRONOUS_CONNECTION");
					break;															
				case 0x0029:
					RtlStringCbCatA(buffer, bufSize, "ACCEPT_SYNCHRONOUS_CONNECTION");
					break;															
				case 0x002A:
					RtlStringCbCatA(buffer, bufSize, "REJECT_SYNCHRONOUS_CONNECTION");
					break;															
				case 0x002B:
					RtlStringCbCatA(buffer, bufSize, "IO_CAPABILITY_REQUEST_REPLY");
					break;															
				case 0x002C:
					RtlStringCbCatA(buffer, bufSize, "USER_CONFIRMATION_REQUEST_REPLY");
					break;															
				case 0x002D:
					RtlStringCbCatA(buffer, bufSize, "USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY");
					break;															
				case 0x002E:
					RtlStringCbCatA(buffer, bufSize, "USER_PASSKEY_REQUEST_REPLY");
					break;															
				case 0x002F:
					RtlStringCbCatA(buffer, bufSize, "USER_PASSKEY_REQUEST_NEGATIVE_REPLY");
					break;															
				case 0x0030:
					RtlStringCbCatA(buffer, bufSize, "REMOTE_OOB_DATA_REQUEST_REPLY");
					break;															
				case 0x0033:
					RtlStringCbCatA(buffer, bufSize, "REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY");
					break;															
				case 0x0034:
					RtlStringCbCatA(buffer, bufSize, "IO_CAPABILITY_REQUEST_NEGATIVE_REPLY");
					break;															
				case 0x003D:
					RtlStringCbCatA(buffer, bufSize, "ENHANCED_SETUP_SYNCHRONOUS_CONNECTION");
					break;															
				case 0x003E:
					RtlStringCbCatA(buffer, bufSize, "ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION");
					break;															
				case 0x0045:
					RtlStringCbCatA(buffer, bufSize, "REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY");
					break;																				
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}
			break;				
		case 0x02:
			RtlStringCbCatA(buffer, bufSize, "LINK_POLICY:");
			switch(OCF)
			{		
				case 0x0001:
					RtlStringCbCatA(buffer, bufSize, "HOLD_MODE"); // Command to place the current or remote device into the Hold mode state.
					break;	
				case 0x0003:
					RtlStringCbCatA(buffer, bufSize, "SNIFF_MODE"); // Command to place the current or remote device into the Sniff mode state.
					break;	
				case 0x0004:
					RtlStringCbCatA(buffer, bufSize, "EXIT_SNIFF_MODE"); // Command to exit the current or remote device from the Sniff mode state.
					break;	
				case 0x0005:
					RtlStringCbCatA(buffer, bufSize, "PARK_MODE"); // Command to place the current or remote device into the Park mode state.
					break;	
				case 0x0006:
					RtlStringCbCatA(buffer, bufSize, "EXIT_PARK_MODE"); // Command to exit the current or remote device from the Park mode state.
					break;	
				case 0x0007:
					RtlStringCbCatA(buffer, bufSize, "QOS_SETUP"); // Command to setup the Quality of Service parameters of the device.
					break;	
				case 0x0009:
					RtlStringCbCatA(buffer, bufSize, "ROLE_DISCOVERY"); // Command to determine the role of the device for a particular connection.
					break;	
				case 0x000B:
					RtlStringCbCatA(buffer, bufSize, "SWITCH_ROLE"); // Command to allow the device to switch roles for a particular connection.
					break;	
				case 0x000C:
					RtlStringCbCatA(buffer, bufSize, "READ_LINK_POLICY_SETTINGS"); // Command to determine the link policy that the LM can use to establish connections.
					break;	
				case 0x000D:
					RtlStringCbCatA(buffer, bufSize, "WRITE_LINK_POLICY_SETTINGS"); // Command to set the link policy that the LM can use for a particular connection.
					break;	
				case 0x000E:
					RtlStringCbCatA(buffer, bufSize, "READ_DEFAULT_LINK_POLICY_SETTINGS");
					break;	
				case 0x000F:
					RtlStringCbCatA(buffer, bufSize, "WRITE_DEFAULT_LINK_POLICY_SETTINGS");
					break;	
				case 0x0010:
					RtlStringCbCatA(buffer, bufSize, "FLOW_SPECIFICATION");
					break;	
				case 0x0011:
					RtlStringCbCatA(buffer, bufSize, "SNIFF_SUBRATING");
					break;						
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}					
			break;							
		case 0x03:
			RtlStringCbCatA(buffer, bufSize, "CONTROLLER_AND_BASEBAND:");
			switch(OCF)
			{		
				case 0x0001:
					RtlStringCbCatA(buffer, bufSize, "SET_EVENT_MASK"); // Command to set which events are generated by the HCI for the host.
					break;	
				case 0x0003:
					RtlStringCbCatA(buffer, bufSize, "RESET"); // Command to reset the host controller, link manager and the radio module.
					break;	
				case 0x0005:
					RtlStringCbCatA(buffer, bufSize, "SET_EVENT_FILTER"); // Command used by host to set the different types of event filters that the host needs to receive.
					break;	
				case 0x0008:
					RtlStringCbCatA(buffer, bufSize, "FLUSH"); // Command used to flush all pending data packets for transmission for a particular connection handle.
					break;	
				case 0x0009:
					RtlStringCbCatA(buffer, bufSize, "READ_PIN_TYPE"); // Command used by host to determine if the link manager assumes that the host requires a variable PIN type or fixed PIN code. PIN is used during pairing.
					break;	
				case 0x000A:
					RtlStringCbCatA(buffer, bufSize, "WRITE_PIN_TYPE"); // Command used by host to write to the host controller on the PIN type supported by the host.
					break;	
				case 0x000B:
					RtlStringCbCatA(buffer, bufSize, "CREATE_NEW_UNIT_KEY"); // Command used to create a new unit key.
					break;	
				case 0x000D:
					RtlStringCbCatA(buffer, bufSize, "READ_STORED_LINK_KEY"); // Command to read the link key stored in the host controller.
					break;	
				case 0x0011:
					RtlStringCbCatA(buffer, bufSize, "WRITE_STORED_LINK_KEY"); // Command to write the link key to the host controller.
					break;	
				case 0x0012:
					RtlStringCbCatA(buffer, bufSize, "DELETE_STORED_LINK_KEY"); // Command to delete a stored link key in the host controller.
					break;	
				case 0x0013:
					RtlStringCbCatA(buffer, bufSize, "WRITE_LOCAL_NAME"); // Command to modify the user friendly name of the device.
					break;	
				case 0x0014:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_NAME"); // Command to read the user friendly name of the device.
					break;	
				case 0x0015:
					RtlStringCbCatA(buffer, bufSize, "READ_CONNECTION_ACCEPT_TIMEOUT"); // Command to determine the timeout session before the host denies and rejects a new connection request.
					break;	
				case 0x0016:
					RtlStringCbCatA(buffer, bufSize, "WRITE_CONNECTION_ACCEPT_TIMEOUT"); // Command to set the timeout session before a device can deny or reject a connection request.
					break;	
				case 0x0017:
					RtlStringCbCatA(buffer, bufSize, "READ_PAGE_TIMEOUT"); // Command to read the timeout value where a device will wait for a connection acceptance before sending a connection failure is returned.
					break;	
				case 0x0018:
					RtlStringCbCatA(buffer, bufSize, "WRITE_PAGE_TIMEOUT"); // Command to write the timeout value where a device will wait for a connection acceptance before sending a connection failure is returned.
					break;	
				case 0x0019:
					RtlStringCbCatA(buffer, bufSize, "READ_SCAN_ENABLE"); // Command to read the status of the Scan_Enable configuration.
					break;	
				case 0x001A:
					RtlStringCbCatA(buffer, bufSize, "WRITE_SCAN_ENABLE"); // Command to set the status of the Scan_Enable configuration.
					break;	
				case 0x001B:
					RtlStringCbCatA(buffer, bufSize, "READ_PAGE_SCAN_ACTIVITY"); // Command to read the value of the Page_Scan_Interval and Page_Scan_Window configurations.
					break;	
				case 0x001C:
					RtlStringCbCatA(buffer, bufSize, "WRITE_PAGE_SCAN_ACTIVITY"); // Command to write the value of the Page_Scan_Interval and Page_Scan_Window configurations.
					break;	
				case 0x001D:
					RtlStringCbCatA(buffer, bufSize, "READ_INQUIRY_SCAN_ACTIVITY"); // Command to read the value of the Inquiry_Scan_Interval and Inquiry_Scan_Window configurations.
					break;	
				case 0x001E:
					RtlStringCbCatA(buffer, bufSize, "WRITE_INQUIRY_SCAN_ACTIVITY"); // Command to set the value of the Inquiry_Scan_Interval and Inquiry_Scan_Window configurations.
					break;	
				case 0x001F:
					RtlStringCbCatA(buffer, bufSize, "READ_AUTHENTICATION_ENABLE"); // Command to read the Authentication_Enable parameter.
					break;	
				case 0x0020:
					RtlStringCbCatA(buffer, bufSize, "WRITE_AUTHENTICATION_ENABLE"); // Command to set the Authentication_Enable parameter.
					break;	
				case 0x0021:
					RtlStringCbCatA(buffer, bufSize, "READ_ENCRYPTION_MODE"); // Command to read the Encryption_Mode parameter.
					break;	
				case 0x0022:
					RtlStringCbCatA(buffer, bufSize, "WRITE_ENCRYPTION_MODE"); // Command to write the Encryption_Mode parameter.
					break;	
				case 0x0023:
					RtlStringCbCatA(buffer, bufSize, "READ_CLASS_OF_DEVICE"); // Command to read the Class_Of_Device parameter.
					break;	
				case 0x0024:
					RtlStringCbCatA(buffer, bufSize, "WRITE_CLASS_OF_DEVICE"); // Command to set the Class_Of_Device parameter.
					break;	
				case 0x0025:
					RtlStringCbCatA(buffer, bufSize, "READ_VOICE_SETTING"); // Command to read the Voice_Setting parameter. Used for voice connections.
					break;	
				case 0x0026:
					RtlStringCbCatA(buffer, bufSize, "WRITE_VOICE_SETTING"); // Command to set the Voice_Setting parameter. Used for voice connections.
					break;	
				case 0x0027:
					RtlStringCbCatA(buffer, bufSize, "READ_AUTOMATIC_FLUSH_TIMEOUT"); // Command to read the Flush_Timeout parameter. Used for ACL connections only.
					break;	
				case 0x0028:
					RtlStringCbCatA(buffer, bufSize, "WRITE_AUTOMATIC_FLUSH_TIMEOUT"); // Command to set the Flush_Timeout parameter. Used for ACL connections only.
					break;	
				case 0x0029:
					RtlStringCbCatA(buffer, bufSize, "READ_NUM_BROADCAST_RETRANSMITS"); // Command to read the number of time a broadcast message is retransmitted.
					break;	
				case 0x002A:
					RtlStringCbCatA(buffer, bufSize, "WRITE_NUM_BROADCAST_RETRANSMITS"); // Command to set the number of time a broadcast message is retransmitted.
					break;	
				case 0x002B:
					RtlStringCbCatA(buffer, bufSize, "READ_HOLD_MODE_ACTIVITY"); // Command to set the Hold_Mode activity to instruct the device to perform an activity during hold mode.
					break;	
				case 0x002C:
					RtlStringCbCatA(buffer, bufSize, "WRITE_HOLD_MODE_ACTIVITY"); // Command to set the Hold_Mode_Activity parameter.
					break;	
				case 0x002D:
					RtlStringCbCatA(buffer, bufSize, "READ_TRANSMIT_POWER_LEVEL"); // Command to read the power level required for transmission for a connection handle.
					break;	
				case 0x002E:
					RtlStringCbCatA(buffer, bufSize, "READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE"); // Command to check the current status of the flow control for the SCO connection.
					break;	
				case 0x002F:
					RtlStringCbCatA(buffer, bufSize, "WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE"); // Command to set the status of the flow control for a connection handle.
					break;	
				case 0x0031:
					RtlStringCbCatA(buffer, bufSize, "SET_CONTROLLER_TO_HOST_FLOW_CONTROL"); // Command to set the flow control from the host controller to host in on or off state.
					break;	
				case 0x0033:
					RtlStringCbCatA(buffer, bufSize, "HOST_BUFFER_SIZE"); // Command set by host to inform the host controller of the buffer size of the host for ACL and SCO connections.
					break;	
				case 0x0035:
					RtlStringCbCatA(buffer, bufSize, "HOST_NUM_COMPLETED_PACKETS"); // Command set from host to host controller when it is ready to receive more data packets.
					break;	
				case 0x0036:
					RtlStringCbCatA(buffer, bufSize, "READ_LINK_SUPERVISION_TIMEOUT"); // Command to read the timeout for monitoring link losses.
					break;	
				case 0x0037:
					RtlStringCbCatA(buffer, bufSize, "WRITE_LINK_SUPERVISION_TIMEOUT"); // Command to set the timeout for monitoring link losses.
					break;	
				case 0x0038:
					RtlStringCbCatA(buffer, bufSize, "READ_NUMBER_OF_SUPPORTED_IAC"); // Command to read the number of IACs that the device can listen on during Inquiry access.
					break;	
				case 0x0039:
					RtlStringCbCatA(buffer, bufSize, "READ_CURRENT_IAC_LAP"); // Command to read the LAP for the current IAC.
					break;	
				case 0x003A:
					RtlStringCbCatA(buffer, bufSize, "WRITE_CURRENT_IAC_LAP"); // Command to set the LAP for the current IAC.
					break;	
				case 0x003B:
					RtlStringCbCatA(buffer, bufSize, "READ_PAGE_SCAN_PERIOD_MODE"); // Command to read the timeout session of a page scan.
					break;	
				case 0x003C:
					RtlStringCbCatA(buffer, bufSize, "WRITE_PAGE_SCAN_PERIOD_MODE"); // Command to set the timeout session of a page scan.
					break;	
				case 0x003D:
					RtlStringCbCatA(buffer, bufSize, "READ_PAGE_SCAN_MODE"); // Command to read the default Page scan mode.
					break;	
				case 0x003E:
					RtlStringCbCatA(buffer, bufSize, "WRITE_PAGE_SCAN_MODE"); // Command to set the default page scan mode.
					break;	
				case 0x003F:
					RtlStringCbCatA(buffer, bufSize, "SET_AFH_HOST_CHANNEL_CLASSIFICATION"); 
					break;	
				case 0x0042:
					RtlStringCbCatA(buffer, bufSize, "READ_INQUIRY_SCAN_TYPE"); 
					break;	
				case 0x0043:
					RtlStringCbCatA(buffer, bufSize, "WRITE_INQUIRY_SCAN_TYPE"); 
					break;	
				case 0x0044:
					RtlStringCbCatA(buffer, bufSize, "READ_INQUIRY_MODE"); 
					break;	
				case 0x0045:
					RtlStringCbCatA(buffer, bufSize, "WRITE_INQUIRY_MODE"); 
					break;	
				case 0x0046:
					RtlStringCbCatA(buffer, bufSize, "READ_PAGE_SCAN_TYPE"); 
					break;	
				case 0x0047:
					RtlStringCbCatA(buffer, bufSize, "WRITE_PAGE_SCAN_TYPE"); 
					break;	
				case 0x0048:
					RtlStringCbCatA(buffer, bufSize, "READ_AFH_CHANNEL_ASSESSMENT_MODE"); 
					break;	
				case 0x0049:
					RtlStringCbCatA(buffer, bufSize, "WRITE_AFH_CHANNEL_ASSESSMENT_MODE"); 
					break;						
				case 0x0051:
					RtlStringCbCatA(buffer, bufSize, "READ_EXTENDED_INQUIRY_RESPONSE"); 
					break;						
				case 0x0052:
					RtlStringCbCatA(buffer, bufSize, "WRITE_EXTENDED_INQUIRY_RESPONSE"); 
					break;						
				case 0x0053:
					RtlStringCbCatA(buffer, bufSize, "REFRESH_ENCRYPTION_KEY"); 
					break;						
				case 0x0055:
					RtlStringCbCatA(buffer, bufSize, "READ_SIMPLE_PAIRING_MODE"); 
					break;						
				case 0x0056:
					RtlStringCbCatA(buffer, bufSize, "WRITE_SIMPLE_PAIRING_MODE"); 
					break;						
				case 0x0057:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_OOB_DATA"); 
					break;						
				case 0x0058:
					RtlStringCbCatA(buffer, bufSize, "READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL"); 
					break;						
				case 0x0059:
					RtlStringCbCatA(buffer, bufSize, "WRITE_INQUIRY_TRANSMIT_POWER_LEVEL"); 
					break;						
				case 0x005F:
					RtlStringCbCatA(buffer, bufSize, "ENHANCED_FLUSH"); 
					break;						
				case 0x0060:
					RtlStringCbCatA(buffer, bufSize, "SEND_KEYPRESS_NOTIFICATION"); 
					break;						
				case 0x006C:
					RtlStringCbCatA(buffer, bufSize, "READ_LE_HOST_SUPPORT"); 
					break;						
				case 0x006D:
					RtlStringCbCatA(buffer, bufSize, "WRITE_LE_HOST_SUPPORT"); 
					break;						
				case 0x0079:
					RtlStringCbCatA(buffer, bufSize, "READ_SECURE_CONNECTIONS_HOST_SUPPORT"); 
					break;						
				case 0x007A:
					RtlStringCbCatA(buffer, bufSize, "WRITE_SECURE_CONNECTIONS_HOST_SUPPORT"); 
					break;						
				case 0x007D:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_OOB_EXTENDED_DATA"); 
					break;						
				case 0x0082:
					RtlStringCbCatA(buffer, bufSize, "SET_ECOSYSTEM_BASE_INTERVAL"); 
					break;						
				case 0x0083:
					RtlStringCbCatA(buffer, bufSize, "CONFIGURE_DATA_PATH"); 
					break;											
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}					
			break;		
		case 0x04:
			RtlStringCbCatA(buffer, bufSize, "INFORMATIONAL_PARAMETERS:");
			switch(OCF)
			{		
				case 0x0001:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_VERSION_INFORMATION"); 
					break;	
				case 0x0002:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_SUPPORTED_COMMANDS"); 
					break;	
				case 0x0003:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_SUPPORTED_FEATURES"); 
					break;	
				case 0x0004:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_EXTENDED_FEATURES"); 
					break;	
				case 0x0005:
					RtlStringCbCatA(buffer, bufSize, "READ_BUFFER_SIZE"); 
					break;	
				case 0x0007:
					RtlStringCbCatA(buffer, bufSize, "READ_COUNTRY_CODE"); 
					break;						
				case 0x0009:
					RtlStringCbCatA(buffer, bufSize, "READ_BD_ADDR"); 
					break;						
				case 0x000A:
					RtlStringCbCatA(buffer, bufSize, "READ_DATA_BLOCK_SIZE"); 
					break;						
				case 0x000B:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_SUPPORTED_CODECS_V1"); 
					break;						
				case 0x000D:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_SUPPORTED_CODECS_V2"); 
					break;						
				case 0x000E:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES"); 
					break;						
				case 0x000F:
					RtlStringCbCatA(buffer, bufSize, "READ_LOCAL_SUPPORTED_CONTROLLER_DELAY"); 
					break;						
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}								
			break;		
		case 0x05:
			RtlStringCbCatA(buffer, bufSize, "STATUS_PARAMETERS:");
			switch(OCF)
			{		
				case 0x0001:
					RtlStringCbCatA(buffer, bufSize, "READ_FAILED_CONTACT_COUNTER"); 
					break;	
				case 0x0002:
					RtlStringCbCatA(buffer, bufSize, "RESET_FAILED_CONTACT_COUNTER"); 
					break;	
				case 0x0003:
					RtlStringCbCatA(buffer, bufSize, "READ_LINK_QUALITY"); 
					break;	
				case 0x0005:
					RtlStringCbCatA(buffer, bufSize, "READ_RSSI"); 
					break;	
				case 0x0006:
					RtlStringCbCatA(buffer, bufSize, "READ_AFH_CHANNEL_MAP"); 
					break;	
				case 0x0007:
					RtlStringCbCatA(buffer, bufSize, "READ_CLOCK"); 
					break;	
				case 0x0008:
					RtlStringCbCatA(buffer, bufSize, "READ_ENCRYPTION_KEY_SIZE"); 
					break;						
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}								
			break;		
		case 0x06:
			RtlStringCbCatA(buffer, bufSize, "TESTING:");
			switch(OCF)
			{		
				case 0x0001:
					RtlStringCbCatA(buffer, bufSize, "READ_LOOPBACK_MODE"); 
					break;	
				case 0x0002:
					RtlStringCbCatA(buffer, bufSize, "WRITE_LOOPBACK_MODE"); 
					break;	
				case 0x0003:
					RtlStringCbCatA(buffer, bufSize, "ENABLE_DEVICE_UNDER_TEST_MODE"); 
					break;	
				case 0x0004:
					RtlStringCbCatA(buffer, bufSize, "WRITE_SIMPLE_PAIRING_DEBUG_MODE"); 
					break;	
				case 0x000A:
					RtlStringCbCatA(buffer, bufSize, "WRITE_SECURE_CONNECTIONS_TEST_MODE"); 
					break;	
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}								
			break;		
		case 0x08:
			RtlStringCbCatA(buffer, bufSize, "LE_CONTROLLER:");
			switch(OCF)
			{		
				case 0x0001:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EVENT_MASK"); 
					break;	
				case 0x0002:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_BUFFER_SIZE_V1"); 
					break;	
				case 0x0003:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_LOCAL_SUPPORTED_FEATURES"); 
					break;	
				case 0x0005:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_RANDOM_ADDRESS"); 
					break;	
				case 0x0006:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_ADVERTISING_PARAMETERS"); 
					break;	
				case 0x0007:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER"); 
					break;	
				case 0x0008:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_ADVERTISING_DATA"); 
					break;	
				case 0x0009:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_SCAN_RESPONSE_DATA"); 
					break;	
				case 0x000A:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_ADVERTISING_ENABLE"); 
					break;	
				case 0x000B:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_SCAN_PARAMETERS"); 
					break;	
				case 0x000C:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_SCAN_ENABLE"); 
					break;	
				case 0x000D:
					RtlStringCbCatA(buffer, bufSize, "LE_CREATE_CONNECTION"); 
					break;	
				case 0x000E:
					RtlStringCbCatA(buffer, bufSize, "LE_CREATE_CONNECTION_CANCEL"); 
					break;	
				case 0x000F:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_CONNECT_LIST_SIZE"); 
					break;	
				case 0x0010:
					RtlStringCbCatA(buffer, bufSize, "LE_CLEAR_CONNECT_LIST"); 
					break;	
				case 0x0011:
					RtlStringCbCatA(buffer, bufSize, "LE_ADD_DEVICE_TO_CONNECT_LIST"); 
					break;	
				case 0x0012:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOVE_DEVICE_FROM_CONNECT_LIST"); 
					break;	
				case 0x0013:
					RtlStringCbCatA(buffer, bufSize, "LE_CONNECTION_UPDATE"); 
					break;	
				case 0x0014:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_HOST_CHANNEL_CLASSIFICATION"); 
					break;	
				case 0x0015:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_CHANNEL_MAP"); 
					break;	
				case 0x0016:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_REMOTE_FEATURES"); 
					break;	
				case 0x0017:
					RtlStringCbCatA(buffer, bufSize, "LE_ENCRYPT"); 
					break;	
				case 0x0018:
					RtlStringCbCatA(buffer, bufSize, "LE_RAND"); 
					break;	
				case 0x0019:
					RtlStringCbCatA(buffer, bufSize, "LE_START_ENCRYPTION"); 
					break;	
				case 0x001A:
					RtlStringCbCatA(buffer, bufSize, "LE_LONG_TERM_KEY_REQUEST_REPLY"); 
					break;	
				case 0x001B:
					RtlStringCbCatA(buffer, bufSize, "LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY"); 
					break;	
				case 0x001C:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_SUPPORTED_STATES"); 
					break;	
				case 0x001D:
					RtlStringCbCatA(buffer, bufSize, "LE_RECEIVER_TEST"); 
					break;	
				case 0x001E:
					RtlStringCbCatA(buffer, bufSize, "LE_TRANSMITTER_TEST"); 
					break;	
				case 0x001F:
					RtlStringCbCatA(buffer, bufSize, "LE_TEST_END"); 
					break;	
				case 0x0020:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY"); 
					break;	
				case 0x0021:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY"); 
					break;	
				case 0x0022:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_DATA_LENGTH"); 
					break;	
				case 0x0023:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH"); 
					break;	
				case 0x0024:
					RtlStringCbCatA(buffer, bufSize, "LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGT"); 
					break;	
				case 0x0025:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_LOCAL_P_256_PUBLIC_KEY_COMMAND"); 
					break;	
				case 0x0026:
					RtlStringCbCatA(buffer, bufSize, "LE_GENERATE_DHKEY_COMMAND_V1"); 
					break;	
				case 0x0027:
					RtlStringCbCatA(buffer, bufSize, "LE_ADD_DEVICE_TO_RESOLVING_LIST"); 
					break;	
				case 0x0028:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOVE_DEVICE_FROM_RESOLVING_LIST"); 
					break;	
				case 0x0029:
					RtlStringCbCatA(buffer, bufSize, "LE_CLEAR_RESOLVING_LIST "); 
					break;	
				case 0x002A:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_RESOLVING_LIST_SIZE "); 
					break;	
				case 0x002B:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_PEER_RESOLVABLE_ADDRESS "); 
					break;	
				case 0x002C:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_LOCAL_RESOLVABLE_ADDRESS "); 
					break;	
				case 0x002D:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_ADDRESS_RESOLUTION_ENABLE "); 
					break;	
				case 0x002E:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT"); 
					break;	
				case 0x002F:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_MAXIMUM_DATA_LENGTH"); 
					break;	
				case 0x0030:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_PHY"); 
					break;	
				case 0x0031:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_DEFAULT_PHY"); 
					break;	
				case 0x0032:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PHY"); 
					break;	
				case 0x0033:
					RtlStringCbCatA(buffer, bufSize, "LE_ENHANCED_RECEIVER_TEST"); 
					break;	
				case 0x0034:
					RtlStringCbCatA(buffer, bufSize, "LE_ENHANCED_TRANSMITTER_TEST"); 
					break;	
				case 0x0035:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EXTENDED_ADVERTISING_RANDOM_ADDRESS"); 
					break;	
				case 0x0036:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EXTENDED_ADVERTISING_PARAMETERS"); 
					break;	
				case 0x0037:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EXTENDED_ADVERTISING_DATA"); 
					break;	
				case 0x0038:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE"); 
					break;	
				case 0x0039:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EXTENDED_ADVERTISING_ENABLE"); 
					break;	
				case 0x003A:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH"); 
					break;	
				case 0x003B:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS"); 
					break;	
				case 0x003C:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOVE_ADVERTISING_SET"); 
					break;	
				case 0x003D:
					RtlStringCbCatA(buffer, bufSize, "LE_CLEAR_ADVERTISING_SETS"); 
					break;	
				case 0x003E:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PERIODIC_ADVERTISING_PARAM"); 
					break;	
				case 0x003F:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PERIODIC_ADVERTISING_DATA"); 
					break;	
				case 0x0040:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PERIODIC_ADVERTISING_ENABLE");
					break;
				case 0x0041:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EXTENDED_SCAN_PARAMETERS");
					break;
				case 0x0042:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_EXTENDED_SCAN_ENABLE");
					break;
				case 0x0043:
					RtlStringCbCatA(buffer, bufSize, "LE_EXTENDED_CREATE_CONNECTION");
					break;
				case 0x0044:
					RtlStringCbCatA(buffer, bufSize, "LE_PERIODIC_ADVERTISING_CREATE_SYNC");
					break;
				case 0x0045:
					RtlStringCbCatA(buffer, bufSize, "LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL");
					break;
				case 0x0046:
					RtlStringCbCatA(buffer, bufSize, "LE_PERIODIC_ADVERTISING_TERMINATE_SYNC");
					break;
				case 0x0047:
					RtlStringCbCatA(buffer, bufSize, "LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST");
					break;
				case 0x0048:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST");
					break;
				case 0x0049:
					RtlStringCbCatA(buffer, bufSize, "LE_CLEAR_PERIODIC_ADVERTISING_LIST");
					break;
				case 0x004A:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_PERIODIC_ADVERTISING_LIST_SIZE");
					break;
				case 0x004B:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_TRANSMIT_POWER");
					break;
				case 0x004C:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_RF_PATH_COMPENSATION_POWER");
					break;
				case 0x004D:
					RtlStringCbCatA(buffer, bufSize, "LE_WRITE_RF_PATH_COMPENSATION_POWER");
					break;
				case 0x004E:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PRIVACY_MODE");
					break;
				case 0x0059:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE");
					break;
				case 0x005A:
					RtlStringCbCatA(buffer, bufSize, "LE_PERIODIC_ADVERTISING_SYNC_TRANSFER");
					break;
				case 0x005B:
					RtlStringCbCatA(buffer, bufSize, "LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER");
					break;
				case 0x005C:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS");
					break;
				case 0x005D:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS");
					break;
				case 0x005E:
					RtlStringCbCatA(buffer, bufSize, "LE_GENERATE_DHKEY_COMMAND");
					break;
				case 0x005F:
					RtlStringCbCatA(buffer, bufSize, "LE_MODIFY_SLEEP_CLOCK_ACCURACY");
					break;
				case 0x0060:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_BUFFER_SIZE_V2");
					break;
				case 0x0061:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_ISO_TX_SYNC");
					break;
				case 0x0062:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_CIG_PARAMETERS");
					break;
				case 0x0063:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_CIG_PARAMETERS_TEST");
					break;
				case 0x0064:
					RtlStringCbCatA(buffer, bufSize, "LE_CREATE_CIS");
					break;
				case 0x0065:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOVE_CIG");
					break;
				case 0x0066:
					RtlStringCbCatA(buffer, bufSize, "LE_ACCEPT_CIS_REQUEST");
					break;
				case 0x0067:
					RtlStringCbCatA(buffer, bufSize, "LE_REJECT_CIS_REQUEST");
					break;
				case 0x0068:
					RtlStringCbCatA(buffer, bufSize, "LE_CREATE_BIG");
					break;
				case 0x006A:
					RtlStringCbCatA(buffer, bufSize, "LE_TERMINATE_BIG");
					break;
				case 0x006B:
					RtlStringCbCatA(buffer, bufSize, "LE_BIG_CREATE_SYNC");
					break;
				case 0x006C:
					RtlStringCbCatA(buffer, bufSize, "LE_BIG_TERMINATE_SYNC");
					break;
				case 0x006D:
					RtlStringCbCatA(buffer, bufSize, "LE_REQUEST_PEER_SCA");
					break;
				case 0x006E:
					RtlStringCbCatA(buffer, bufSize, "LE_SETUP_ISO_DATA_PATH");
					break;
				case 0x006F:
					RtlStringCbCatA(buffer, bufSize, "LE_REMOVE_ISO_DATA_PATH");
					break;
				case 0x0074:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_HOST_FEATURE");
					break;
				case 0x0075:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_ISO_LINK_QUALITY");
					break;
				case 0x0076:
					RtlStringCbCatA(buffer, bufSize, "LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL");
					break;
				case 0x0077:
					RtlStringCbCatA(buffer, bufSize, "LE_READ_REMOTE_TRANSMIT_POWER_LEVEL");
					break;
				case 0x0078:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PATH_LOSS_REPORTING_PARAMETERS");
					break;
				case 0x0079:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_PATH_LOSS_REPORTING_ENABLE");
					break;
				case 0x007A:
					RtlStringCbCatA(buffer, bufSize, "LE_SET_TRANSMIT_POWER_REPORTING_ENABLE");
					break;
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}								
			break;		
		case 0x3E:
			RtlStringCbCatA(buffer, bufSize, "BTH_LOGO_TESTING:");
			switch(OCF)
			{		
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}											
			break;		
		case 0x3F:
			RtlStringCbCatA(buffer, bufSize, "VENDOR_SPECIFIC:");
			switch(OCF)
			{		
				default:
					RtlStringCbCatA(buffer, bufSize, "UNKNOWN");			
			}														
			break;					
		default:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN:UNKNOWN");
	}
	RtlStringCbPrintfA(OGF_OCF_Value, 16, "(0x%02X:0x%04X) ", OGF, OCF);
	RtlStringCbCatA(buffer, bufSize, OGF_OCF_Value);

	return buffer;
}


CHAR* StatusDesc(ULONG Status, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR StatusValue[16];
	
	switch(Status)
	{
		case 0x00000000:
			RtlStringCbCatA(buffer, bufSize, "STATUS_SUCCESS");
			break;		
		case 0xC0000120:
			RtlStringCbCatA(buffer, bufSize, "STATUS_CANCELLED");
			break;
		default:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN");
	}
	RtlStringCbPrintfA(StatusValue, 16, "(0x%08X) ", Status);
	RtlStringCbCatA(buffer, bufSize, StatusValue);

	return buffer;
}

CHAR* HciPacketTypeDesc(BTHX_HCI_PACKET_TYPE type, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR packetType[16];
	
	switch(type)
	{
		case HciPacketCommand:
			RtlStringCbCatA(buffer, bufSize, "HciPacketCommand");
			break;
		case HciPacketAclData:
			RtlStringCbCatA(buffer, bufSize, "HciPacketAclData");
			break;
		case HciPacketEvent:
			RtlStringCbCatA(buffer, bufSize, "HciPacketEvent");
			break;
		default:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN");
	}
	RtlStringCbPrintfA(packetType, 16, "(0x%02X) ", type);
	RtlStringCbCatA(buffer, bufSize, packetType);

	return buffer;
}

CHAR* EventDecode(UCHAR* Data, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);

	UCHAR EventCode = Data[0];
	UCHAR PayloadLength = Data[1];
	ULONG OpCode;
	ULONG OGF;			
	ULONG OCF;
	CHAR info1[256];
	CHAR info2[256];

	switch(EventCode)
	{
		case 0x0E:
			OpCode = Data[4] << 8;// Little-endian
			OpCode += Data[3];
			OGF = (OpCode >> 10) & 0x3F;			
			OCF = OpCode & 0x3FF;
			RtlStringCbPrintfA(buffer, bufSize, "Num_HCI_Command_Packets=0x%02X Command_Opcode=0x%04X (%s) Return_Parameters=%s", Data[2],OpCode,OGF_OCF_Desc(OGF,OCF,info1,256),ErrorCodeDesc(Data[5],info2,256));
			break;
		default:
			RtlStringCbPrintfA(buffer, bufSize, "TODO");
	}
	
	return buffer;
}


CHAR* IrpMajorFunctionDesc(UCHAR MajorFunction, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR functionCode[16];
	
	switch(MajorFunction)
	{
		case 0x00:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_CREATE");
			break;
		case 0x01:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_CREATE_NAMED_PIPE");
			break;
		case 0x02:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_CLOSE");
			break;
		case 0x03:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_READ");
			break;
		case 0x04:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_WRITE");
			break;
		case 0x05:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_QUERY_INFORMATION");
			break;
		case 0x06:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_SET_INFORMATION");
			break;
		case 0x07:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_QUERY_EA");
			break;
		case 0x08:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_SET_EA");
			break;
		case 0x09:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_FLUSH_BUFFERS");
			break;
		case 0x0A:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_QUERY_VOLUME_INFORMATION");
			break;
		case 0x0B:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_SET_VOLUME_INFORMATION");
			break;
		case 0x0C:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_DIRECTORY_CONTROL");
			break;
		case 0x0D:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_FILE_SYSTEM_CONTROL");
			break;
		case 0x0E:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_DEVICE_CONTROL");
			break;
		case 0x0F:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_INTERNAL_DEVICE_CONTROL");
			break;
		case 0x10:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_SHUTDOWN");
			break;
		case 0x11:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_LOCK_CONTROL");
			break;
		case 0x12:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_CLEANUP");
			break;
		case 0x13:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_CREATE_MAILSLOT");
			break;
		case 0x14:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_QUERY_SECURITY");
			break;
		case 0x15:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_SET_SECURITY");
			break;
		case 0x16:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_POWER");
			break;
		case 0x17:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_SYSTEM_CONTROL");
			break;
		case 0x18:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_DEVICE_CHANGE");
			break;
		case 0x19:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_QUERY_QUOTA");
			break;
		case 0x1A:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_SET_QUOTA");
			break;
		case 0x1B:
			RtlStringCbCatA(buffer, bufSize, "IRP_MJ_PNP");
			break;		
		default:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN");
	}
	RtlStringCbPrintfA(functionCode, 16, "(0x%02X) ", MajorFunction);
	RtlStringCbCatA(buffer, bufSize, functionCode);

	return buffer;
}

CHAR* IoControlCodeDesc(ULONG IoControlCode, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR unknown[32];
	CHAR ioctl[16];

	switch(IoControlCode)
	{
		case 0x220003:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_GET_DEVICEOBJECT");
			break;
		case 0x220007:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_GET_KSNODETYPES");
			break;
		case 0x22000b:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_GET_CONTAINERID");
			break;
		case 0x22000f:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_REQUEST_CONNECT");
			break;
		case 0x220013:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_REQUEST_DISCONNECT");
			break;
		case 0x220017:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_GET_CONNECTION_STATUS_UPDATE");
			break;
		case 0x22001b:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_SPEAKER_SET_VOLUME");
			break;
		case 0x22001f:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_SPEAKER_GET_VOLUME_STATUS_UPDATE");
			break;
		case 0x220023:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_MIC_SET_VOLUME");
			break;
		case 0x220027:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_MIC_GET_VOLUME_STATUS_UPDATE");
			break;
		case 0x22002b:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_STREAM_OPEN");
			break;
		case 0x22002f:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_STREAM_CLOSE");
			break;
		case 0x220033:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_STREAM_GET_STATUS_UPDATE");
			break;
		case 0x22003c:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_GET_CODEC_ID");
			break;
		case 0x220193:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_GET_DESCRIPTOR");
			break;
		case 0x220197:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHHFP_DEVICE_GET_VOLUMEPROPERTYVALUES");
			break;
		case 0x410000:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_GET_LOCAL_INFO");
			break;
		case 0x410007:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_INTERNAL_BTHENUM_GET_enumInfo");
			break;
		case 0x410008:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_GET_DEVICE_INFO");
			break;
		case 0x41000c:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_DISCONNECT_DEVICE");
			break;
		case 0x4100d8:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_DISCONNECT_DEVICE_EX");
			break;
		case 0x4100e4:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_LE_ENTER_ACTIVE_SCANNING");
			break;
		case 0x410200:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SDP_CONNECT");
			break;
		case 0x410204:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SDP_DISCONNECT");
			break;
		case 0x410210:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SDP_SERVICE_ATTRIBUTE_SEARCH");
			break;
		case 0x410214:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SDP_SUBMIT_RECORD");
			break;
		case 0x410218:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SDP_REMOVE_RECORD");
			break;
		case 0x41021c:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SDP_SUBMIT_RECORD_WITH_INFO");
			break;
		case 0x410403:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHX_GET_VERSION");
			break;
		case 0x410407:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHX_SET_VERSION");
			break;
		case 0x41040b:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHX_QUERY_CAPABILITIES");
			break;
		case 0x41040f:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHX_WRITE_HCI");
			break;
		case 0x410413:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHX_READ_HCI");
			break;			
		case 0x411000:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_INQUIRY_DEVICE");
			break;
		case 0x411004:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_AUTH_RESPONSE");
			break;
		case 0x411008:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_UPDATE_SETTINGS");
			break;
		case 0x41100c:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_PERSONALIZE_DEVICE");
			break;
		case 0x411010:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_PAIR_DEVICE");
			break;
		case 0x411014:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_UNPAIR_DEVICE");
			break;
		case 0x411018:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_QUERY_UNPAIR_DEVICE");
			break;
		case 0x411020:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SCAN_ENABLE");
			break;
		case 0x411030:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_UPDATE_DEVICE");
			break;
		case 0x411038:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_GET_DEVICE_PROTOCOLS_INFO");
			break;
		case 0x41104c:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_SET_LOCAL_SERVICE_INFO");
			break;
		case 0x411058:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_GET_DEVICE_INFO_EX");
			break;
		case 0x41110c:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_UNPAIR_DEVICE_EX");
			break;
		case 0x411cc0:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_INITIALIZE_AUDIO_DEVICE");
			break;
		case 0x411cc4:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_ALLOW_INCOMING_SCO");
			break;
		case 0x411cc8:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_FORBID_INCOMING_SCO");
			break;
		case 0x411ccc:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_CONNECT_SCO");
			break;
		case 0x411cd0:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_DISCONNECT_SCO");
			break;
		case 0x411cd4:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_SET_AUDIO_CONNECTED");
			break;
		case 0x411cd8:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_SET_AUDIO_DISCONNECTED");
			break;
		case 0x411cdc:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_CHANGE_SPEAKER_VOLUME");
			break;
		case 0x411ce0:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_CHANGE_MICROPHONE_VOLUME");
			break;
		case 0x411ce4:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_GET_AUDIO_INDICATION");
			break;
		case 0x411ce8:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_SET_CODEC_ID");
			break;
		case 0x411d00:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_L2CAP_REGISTER");
			break;
		case 0x411d04:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_L2CAP_UNREGISTER");
			break;
		case 0x411d08:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_L2CAP_LISTEN");
			break;
		case 0x411d0c:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_L2CAP_CONNECT");
			break;
		case 0x411d10:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_L2CAP_ATTACH");
			break;
		case 0x411d14:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTH_WP8_L2CAP_DISPOSE");
			break;
		case 0x414010:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHLEENUM_READ_GATT_EVENT");
			break;
		case 0x414014:
			RtlStringCbCatA(buffer, bufSize, "IOCTL_BTHLEENUM_READ_QUEUE_ACTIVATE");
			break;
		default:
			RtlStringCbCatA(buffer, bufSize, "UNKNOWN");		
	}
	RtlStringCbPrintfA(ioctl, 16, "(0x%06X) ", IoControlCode);
	RtlStringCbCatA(buffer, bufSize, ioctl);

	RtlZeroMemory(unknown, 32);
	ULONG deviceType = DEVICE_TYPE_FROM_CTL_CODE(IoControlCode);
	switch(deviceType)
	{
		case 0x00000041:
			RtlStringCbCatA(buffer, bufSize, "deviceType=FILE_DEVICE_BLUETOOTH ");
			break;
		case 0x00000022:
			RtlStringCbCatA(buffer, bufSize, "deviceType=FILE_DEVICE_UNKNOWN ");
			break;
		default:
			RtlStringCbPrintfA(unknown, 32, "deviceType=0x%8X ", deviceType);
			RtlStringCbCatA(buffer, bufSize, unknown);
	}

	RtlZeroMemory(unknown, 32);
	ULONG requiredAccess = REQUIRED_ACCESS_FROM_CTL_CODE(IoControlCode);
	switch(requiredAccess)
	{
		case 0x0000:
			RtlStringCbCatA(buffer, bufSize, "requiredAccess=FILE_ANY_ACCESS ");
			break;
		case 0x0001:
			RtlStringCbCatA(buffer, bufSize, "requiredAccess=FILE_READ_ACCESS ");
			break;
		case 0x0002:
			RtlStringCbCatA(buffer, bufSize, "requiredAccess=FILE_WRITE_ACCESS ");
			break;
		default:
			RtlStringCbPrintfA(unknown, 32, "requiredAccess=0x%4X ", requiredAccess);
			RtlStringCbCatA(buffer, bufSize, unknown);
	}	

	RtlZeroMemory(unknown, 32);	
	ULONG transferType = METHOD_FROM_CTL_CODE(IoControlCode);
	switch(transferType)
	{
		case 0:
			RtlStringCbCatA(buffer, bufSize, "transferType=METHOD_BUFFERED");
			break;
		case 1:
			RtlStringCbCatA(buffer, bufSize, "transferType=METHOD_IN_DIRECT");
			break;
		case 2:
			RtlStringCbCatA(buffer, bufSize, "transferType=METHOD_OUT_DIRECT");
			break;
		case 3:
			RtlStringCbCatA(buffer, bufSize, "transferType=METHOD_NEITHER");
			break;			
		default:
			RtlStringCbPrintfA(unknown, 32, "transferType=%u", transferType);
			RtlStringCbCatA(buffer, bufSize, unknown);
	}
	
	return buffer;
}

VOID printBufferContent(PVOID buffer, size_t bufSize, CHAR* deviceName)
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
	for(; i<bufSize && i < 608; i++)
	{
		RtlStringCbPrintfA(tempString, 8, "%02X ", p[i]);
		RtlStringCbCatA(hexString, 256, tempString);

		RtlStringCbPrintfA(tempString, 8, "%c", p[i]>31 && p[i]<127 ? p[i] : '.' );
		RtlStringCbCatA(chrString, 256, tempString);

		if ((i+1)%38 == 0)
		{
			DbgPrint("Filter!%s!%s%s",deviceName, hexString, chrString);
			RtlZeroMemory(hexString, 256);
			RtlZeroMemory(chrString, 256);
			multiLine = TRUE;
		}
	}
	RtlStringCbLengthA(hexString,256,&length);
	if (length != 0)
	{
		CHAR padding[256];
		RtlZeroMemory(padding, 256);
		if (multiLine)
		{
			RtlStringCbPrintfA(padding, 256, "%*s", 3*(38-(i%38)),"");
		}

		DbgPrint("Filter!%s!%s%s%s",deviceName, hexString, padding, chrString);
	}

	if (i == 608)
	{
		DbgPrint("Filter!%s!...\n",deviceName);
	}	
}

VOID
FilterRequestCompletionRoutine(
    IN WDFREQUEST                  Request,
    IN WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    IN WDFCONTEXT                  Context
   )
{
    UNREFERENCED_PARAMETER(Target);
	
	NTSTATUS status;
	PDEVICEFILTER_CONTEXT deviceContext = Context;
	size_t OutputBufferLength;
	PIRP irp;
	UCHAR MajorFunction;
	UCHAR MinorFunction;
	CHAR info1[256];
	CHAR info2[256];
	CHAR info3[256];
	PVOID  buffer = NULL;
	size_t  bufSize = 0;
	ULONG IoControlCode;
	CHAR logPrintBufferName[256];
	PBTHX_HCI_READ_WRITE_CONTEXT HCIContext;
	BTHX_HCI_PACKET_TYPE PacketType;

	irp = WdfRequestWdmGetIrp(Request);

	MajorFunction = irp->Tail.Overlay.CurrentStackLocation->MajorFunction;
	MinorFunction = irp->Tail.Overlay.CurrentStackLocation->MinorFunction;
	
	DbgPrint("Filter!%s!Complet %s MinorFunction=0x%02X %s IoStatus.Information=0x%X\n", deviceContext->Name, IrpMajorFunctionDesc(MajorFunction, info1, 256), MinorFunction, StatusDesc(CompletionParams->IoStatus.Status, info2, 256), CompletionParams->IoStatus.Information);
	
	if (MajorFunction == IRP_MJ_DEVICE_CONTROL || MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL)
	{
		IoControlCode = irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.IoControlCode;
		OutputBufferLength = irp->Tail.Overlay.CurrentStackLocation->Parameters.DeviceIoControl.OutputBufferLength;	
		DbgPrint("Filter!%s!Complet %s (OutputBufferLength=%u or %u)\n", deviceContext->Name, IoControlCodeDesc(IoControlCode, info1, 256), OutputBufferLength, CompletionParams->IoStatus.Information);

		// Looks like this is the real OutputBufferLength
		OutputBufferLength = CompletionParams->IoStatus.Information;
		
		if (OutputBufferLength > 0)
		{
			RtlZeroMemory(logPrintBufferName, 256);
			RtlStringCbPrintfA(logPrintBufferName, 256, "%s", deviceContext->Name);
			
			status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &buffer, &bufSize );
			if (!NT_SUCCESS(status)) {
				DbgPrint("Filter!%s!WdfRequestRetrieveOutputBuffer failed: 0x%x\n", deviceContext->Name, status);
				goto exit;
			}
			
			if (IoControlCode == 0x410413) // HCI read
			{
				HCIContext = (PBTHX_HCI_READ_WRITE_CONTEXT) buffer;
				PacketType = (BTHX_HCI_PACKET_TYPE) HCIContext->Type; 
				
				
				if (PacketType == 0x04) // HciPacketEvent
				{				
					UCHAR* Data = HCIContext->Data;
					
					UCHAR EventCode = Data[0];
					UCHAR PayloadLength = Data[1];
					
					DbgPrint("Filter!%s!Complet HCI read type=%s EventCode=%s PayloadLength=0x%02X %s\n",deviceContext->Name, HciPacketTypeDesc(PacketType,info1,256), EventCodeDesc(EventCode,info2,256), PayloadLength, EventDecode(Data,info3,256));
				}
				else
				{
					DbgPrint("Filter!%s!Complet HCI read type=%s\n",deviceContext->Name, HciPacketTypeDesc(PacketType,info1,256));
			}
				
				RtlStringCbCatA(logPrintBufferName, 256, "!HCI");
			}
			else if (IoControlCode == 0x41040F) // HCI write
			{
				RtlStringCbCatA(logPrintBufferName, 256, "!HCI");
			}
			
			printBufferContent(buffer, OutputBufferLength, logPrintBufferName);
		}
	}
	
exit:
    WdfRequestComplete(Request, CompletionParams->IoStatus.Status);

    return;
}


VOID
FilterForwardRequestWithCompletionRoutine(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target,
	IN PDEVICEFILTER_CONTEXT deviceContext
    )
{
    BOOLEAN ret;
    NTSTATUS status;

    //
    // The following funciton essentially copies the content of
    // current stack location of the underlying IRP to the next one. 
    //
    WdfRequestFormatRequestUsingCurrentType(Request);

    WdfRequestSetCompletionRoutine(Request,
                                FilterRequestCompletionRoutine,
                                deviceContext);

    ret = WdfRequestSend(Request,
                         Target,
                         WDF_NO_SEND_OPTIONS);

    if (ret == FALSE) {
        status = WdfRequestGetStatus (Request);
        DbgPrint("Filter!%s!WdfRequestSend failed: 0x%x\n",deviceContext->Name, status);
        WdfRequestComplete(Request, status);
    }

    return;
}

VOID
FilterForwardRequest(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target,
	IN PDEVICEFILTER_CONTEXT deviceContext
    )
{
    WDF_REQUEST_SEND_OPTIONS options;
    BOOLEAN ret;
    NTSTATUS status;

    //
    // We are not interested in post processing the IRP so 
    // fire and forget.
    //
    WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                  WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

    ret = WdfRequestSend(Request, Target, &options);

    if (ret == FALSE) {
        status = WdfRequestGetStatus (Request);
        DbgPrint("Filter!%s!WdfRequestSend failed: 0x%x\n",deviceContext->Name, status);
        WdfRequestComplete(Request, status);
    }

    return;
}

VOID
FilterEvtIoDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
{
    NTSTATUS                        status = STATUS_SUCCESS;
    WDFDEVICE                       device;
	CHAR info1[256];
	CHAR info2[256];
	PVOID  buffer = NULL;
	size_t  bufSize = 0;
	BTHX_HCI_PACKET_TYPE PacketType;
	PBTHX_HCI_READ_WRITE_CONTEXT HCIContext;
	CHAR logPrintBufferName[256];

    //DbgPrint("Filter!Begin FilterEvtIoDeviceControl\n");

    device = WdfIoQueueGetDevice(Queue);
	PDEVICEFILTER_CONTEXT deviceContext = GetDeviceContext(device);
	
	
	// PIRP irp = WdfRequestWdmGetIrp(Request);
		
	DbgPrint("Filter!%s!Receive %s InputBufferLength=%u OutputBufferLength=%u\n",deviceContext->Name, IoControlCodeDesc(IoControlCode,info1,256), InputBufferLength, OutputBufferLength);
	
	if (InputBufferLength > 0)
	{
		RtlZeroMemory(logPrintBufferName, 256);
		RtlStringCbPrintfA(logPrintBufferName, 256, "%s", deviceContext->Name);
		
		status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &buffer, &bufSize );
		if (!NT_SUCCESS(status)) {
			DbgPrint("Filter!%s!WdfRequestRetrieveInputBuffer failed: 0x%x\n", deviceContext->Name, status);
			WdfRequestComplete(Request, status);
			goto exit;
			return;
		}
		
		if (IoControlCode == 0x410413) // HCI read
		{
			PacketType = *((BTHX_HCI_PACKET_TYPE *) buffer);
			DbgPrint("Filter!%s!Receive HCI read type=%s\n",deviceContext->Name, HciPacketTypeDesc(PacketType,info1,256));
			
			RtlStringCbCatA(logPrintBufferName, 256, "!HCI");
		}
		else if (IoControlCode == 0x41040F) // HCI write
		{
			HCIContext = (PBTHX_HCI_READ_WRITE_CONTEXT) buffer;
			PacketType = (BTHX_HCI_PACKET_TYPE) HCIContext->Type; 
			
			if (PacketType == 0x01) // HciPacketCommand
			{				
				UCHAR* Data = HCIContext->Data;
				
				ULONG OpCode = Data[1] << 8;// Little-endian
				OpCode += Data[0];

				ULONG OGF = (OpCode >> 10) & 0x3F;			
				ULONG OCF = OpCode & 0x3FF;
				
				UCHAR PayloadLength = Data[2];
				
				DbgPrint("Filter!%s!Receive HCI write type=%s OpCode=0x%04X OGF:OCF=%s PayloadLength=0x%02X\n",deviceContext->Name, HciPacketTypeDesc(PacketType,info1,256), OpCode, OGF_OCF_Desc(OGF,OCF,info2,256), PayloadLength);
			}
			else
			{
				DbgPrint("Filter!%s!Receive HCI write type=%s\n",deviceContext->Name, HciPacketTypeDesc(PacketType,info1,256));
			}
			
			RtlStringCbCatA(logPrintBufferName, 256, "!HCI");
		}

		printBufferContent(buffer, bufSize, logPrintBufferName);
	}
	
	//FilterForwardRequest(Request, WdfDeviceGetIoTarget(device), deviceContext);
	FilterForwardRequestWithCompletionRoutine(Request, WdfDeviceGetIoTarget(device), deviceContext);

exit:
	//DbgPrint("Filter!%s!End FilterEvtIoDeviceControl\n",deviceContext->Name);

    return;
}


VOID
FilterEvtIoInternalDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
{
    NTSTATUS                        status = STATUS_SUCCESS;
    WDFDEVICE                       device;

    //DbgPrint("Filter!Begin FilterEvtIoInternalDeviceControl\n");

    device = WdfIoQueueGetDevice(Queue);
	PDEVICEFILTER_CONTEXT deviceContext = GetDeviceContext(device);
	
	
	PIRP irp = WdfRequestWdmGetIrp(Request);
		
	CHAR info[256];
	DbgPrint("Filter!%s!Receive Internal %s InputBufferLength=%u OutputBufferLength=%u\n",deviceContext->Name, IoControlCodeDesc(IoControlCode,info,256), InputBufferLength, OutputBufferLength);

	PVOID  buffer = NULL;
	size_t  bufSize = 0;
	if (InputBufferLength > 0)
	{
		status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &buffer, &bufSize );
		if (!NT_SUCCESS(status)) {
			DbgPrint("Filter!%s!WdfRequestRetrieveInputBuffer failed: 0x%x\n", deviceContext->Name, status);
			WdfRequestComplete(Request, status);
			goto exit;
			return;
		}
		printBufferContent(buffer, bufSize, deviceContext->Name);
	}
	
    

	FilterForwardRequestWithCompletionRoutine(Request, WdfDeviceGetIoTarget(device), deviceContext);

exit:
	//DbgPrint("Filter!%s!End FilterEvtIoInternalDeviceControl\n",deviceContext->Name);

    return;
}


VOID
FilterEvtIoDefault(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request
    )
{
    NTSTATUS                        status = STATUS_SUCCESS;
    WDFDEVICE                       device;

    //DbgPrint("Filter!Begin FilterEvtIoDefault\n");

    device = WdfIoQueueGetDevice(Queue);
	PDEVICEFILTER_CONTEXT deviceContext = GetDeviceContext(device);
	
	
	PIRP irp = WdfRequestWdmGetIrp(Request);
		
	DbgPrint("Filter!%s!Receive Default\n",deviceContext->Name);


	FilterForwardRequestWithCompletionRoutine(Request, WdfDeviceGetIoTarget(device), deviceContext);

	//DbgPrint("Filter!%s!End FilterEvtIoDefault\n",deviceContext->Name);

    return;
}

VOID
FilterEvtIoRead(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
	size_t Length
    )
{
    NTSTATUS                        status = STATUS_SUCCESS;
    WDFDEVICE                       device;

    //DbgPrint("Filter!Begin FilterEvtIoRead\n");

    device = WdfIoQueueGetDevice(Queue);
	PDEVICEFILTER_CONTEXT deviceContext = GetDeviceContext(device);
	
	
	PIRP irp = WdfRequestWdmGetIrp(Request);
		
	DbgPrint("Filter!%s!Receive Read Length=%u\n",deviceContext->Name, Length);


	FilterForwardRequestWithCompletionRoutine(Request, WdfDeviceGetIoTarget(device), deviceContext);

	//DbgPrint("Filter!%s!End FilterEvtIoRead\n",deviceContext->Name);

    return;
}

VOID
FilterEvtIoWrite(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
	size_t Length
    )
{
    NTSTATUS                        status = STATUS_SUCCESS;
    WDFDEVICE                       device;

    //DbgPrint("Filter!Begin FilterEvtIoWrite\n");

    device = WdfIoQueueGetDevice(Queue);
	PDEVICEFILTER_CONTEXT deviceContext = GetDeviceContext(device);
	
	
	PIRP irp = WdfRequestWdmGetIrp(Request);
		
	DbgPrint("Filter!%s!Receive Write Length=%u\n",deviceContext->Name, Length);


	FilterForwardRequestWithCompletionRoutine(Request, WdfDeviceGetIoTarget(device), deviceContext);

	//DbgPrint("Filter!%s!End FilterEvtIoWrite\n",deviceContext->Name);

    return;
}


NTSTATUS EvtDriverDeviceAdd(WDFDRIVER  Driver, PWDFDEVICE_INIT  DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);
	NTSTATUS                        status;
    WDFDEVICE                       device;    
    WDF_OBJECT_ATTRIBUTES           deviceAttributes;
	WDF_IO_QUEUE_CONFIG     		ioQueueConfig;
    
	DbgPrint("Filter!Begin EvtDriverDeviceAdd\n");

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inherting all the device flags & characterstics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

    //
    // Set device attributes
    //
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICEFILTER_CONTEXT);
 
	//
    // Create a framework device object.  This call will in turn create
    // a WDM deviceobject, attach to the lower stack and set the
    // appropriate flags and attributes.
    //
    status = WdfDeviceCreate(
        &DeviceInit,
        &deviceAttributes,
        &device
        );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Filter!WdfDeviceCreate failed with Status code %d\n", status);
        goto exit;
    }
	
	PDRIVER_OBJECT pWdmDriver = WdfDriverWdmGetDriverObject(Driver);
	PDEVICE_OBJECT pWdmPDO = WdfDeviceWdmGetPhysicalDevice(device);
	PDEVICE_OBJECT pWdmFDO = WdfDeviceWdmGetDeviceObject(device);
	PDEVICE_OBJECT pWdmLowerDO = WdfDeviceWdmGetAttachedDevice(device);
	
	DbgPrint("Filter!Driver 0x%p, FDO 0x%p, PDO 0x%p, Lower 0x%p\n", pWdmDriver, pWdmFDO, pWdmPDO, pWdmLowerDO);
	
	DbgPrint("Filter!FDO Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmFDO->Type, pWdmFDO->Size, pWdmFDO->DriverObject, pWdmFDO->NextDevice, pWdmFDO->AttachedDevice);
	DbgPrint("Filter!PDO Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmPDO->Type, pWdmPDO->Size, pWdmPDO->DriverObject, pWdmPDO->NextDevice, pWdmPDO->AttachedDevice);
	DbgPrint("Filter!PDO2 Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmPDO->NextDevice->Type, pWdmPDO->NextDevice->Size, pWdmPDO->NextDevice->DriverObject, pWdmPDO->NextDevice->NextDevice, pWdmPDO->NextDevice->AttachedDevice);
	DbgPrint("Filter!LowerDO Type=%d (3=Device), Size=%d, Driver=0x%p, NextDevice=0x%p, AttachedDevice=0x%p\n",pWdmLowerDO->Type, pWdmLowerDO->Size, pWdmLowerDO->DriverObject, pWdmLowerDO->NextDevice, pWdmLowerDO->AttachedDevice);
	
	PDRIVER_OBJECT pWdmDriver2 = pWdmFDO->DriverObject;
	DbgPrint("Filter!FDO Driver Type=%d (4=Driver), Device=0x%p, DriverName=%wZ, HardwareDatabase=%wZ\n",pWdmDriver2->Type, pWdmDriver2->DeviceObject, &(pWdmDriver2->DriverName), pWdmDriver2->HardwareDatabase);
	
	pWdmDriver2 = pWdmPDO->DriverObject;
	DbgPrint("Filter!PDO Driver Type=%d (4=Driver), Device=0x%p, DriverName=%wZ, HardwareDatabase=%wZ\n",pWdmDriver2->Type, pWdmDriver2->DeviceObject, &(pWdmDriver2->DriverName), pWdmDriver2->HardwareDatabase);

	pWdmDriver2 = pWdmLowerDO->DriverObject;
	DbgPrint("Filter!LowerDO Driver Type=%d (4=Driver), Device=0x%p, DriverName=%wZ, HardwareDatabase=%wZ\n",pWdmDriver2->Type, pWdmDriver2->DeviceObject, &(pWdmDriver2->DriverName), pWdmDriver2->HardwareDatabase);
	
				
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);	
	//WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);	
	
	//ioQueueConfig.EvtIoDefault = FilterEvtIoDefault;
	//ioQueueConfig.EvtIoRead = FilterEvtIoRead;
	//ioQueueConfig.EvtIoWrite = FilterEvtIoWrite;
	ioQueueConfig.EvtIoDeviceControl = FilterEvtIoDeviceControl;
	//ioQueueConfig.EvtIoInternalDeviceControl = FilterEvtIoInternalDeviceControl;
	
	status = WdfIoQueueCreate(device,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            WDF_NO_HANDLE // pointer to default queue
                            );
    if (!NT_SUCCESS(status)) {
        DbgPrint("Filter!WdfIoQueueCreate failed 0x%x\n", status);
        goto exit;
    }   
	
	PDEVICEFILTER_CONTEXT deviceContext = GetDeviceContext(device);
	
	deviceContext->Device = device;
	
	CHAR fullDriverName[32] = {0};
	RtlStringCbPrintfA(fullDriverName, 32-1, "%wZ", &(pWdmLowerDO->DriverObject->DriverName));
	CHAR *shortDriverName = fullDriverName;
	if (RtlCompareMemory(fullDriverName, "\\Driver\\", 8) == 8)
	{
		shortDriverName = fullDriverName + 8;
	}
	CHAR buffer[32];
	RtlZeroMemory(buffer, 32);
	RtlStringCbPrintfA(buffer, 32-1, "%p-%s", pWdmLowerDO->DriverObject->DeviceObject, shortDriverName);
	RtlCopyMemory(deviceContext->Name, buffer, 32);
			
exit:    
	DbgPrint("Filter!End EvtDriverDeviceAdd\n");
    return status;
}

void EvtCleanupCallback(WDFOBJECT DriverObject) 
{
    UNREFERENCED_PARAMETER(DriverObject);
	
	DbgPrint("Filter!Begin EvtCleanupCallback\n");
	DbgPrint("Filter!End EvtCleanupCallback\n");
}

// DriverEntry
NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING  RegistryPath)
{
	DbgPrint("Filter!Begin DriverEntry\n");
	
    NTSTATUS status;
    WDFDRIVER driver;
    WDF_OBJECT_ATTRIBUTES attributes;
        
    WDF_DRIVER_CONFIG DriverConfig;
    WDF_DRIVER_CONFIG_INIT(
                           &DriverConfig,
                           EvtDriverDeviceAdd
                           );

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = EvtCleanupCallback;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &DriverConfig,
        &driver
        );

	DbgPrint("Filter!Driver registryPath= %S\n", RegistryPath->Buffer);

	DbgPrint("Filter!End DriverEntry\n");
    return status;
}