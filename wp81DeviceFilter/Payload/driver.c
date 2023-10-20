// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} bootlog Yes
// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} testsigning yes
//
// set PATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\x86_arm;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin;%PATH%
//

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

} DEVICEFILTER_CONTEXT, *PDEVICEFILTER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICEFILTER_CONTEXT, GetDeviceContext);


VOID
FilterRequestCompletionRoutine(
    IN WDFREQUEST                  Request,
    IN WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    IN WDFCONTEXT                  Context
   )
{
    UNREFERENCED_PARAMETER(Target);
    UNREFERENCED_PARAMETER(Context);
	
	DbgPrint("Filter!Completion Request Size=%u Type=0x%x IoStatus.Status=0x%x IoStatus.Information=0x%x\n", CompletionParams->Size, CompletionParams->Type, CompletionParams->IoStatus.Status, CompletionParams->IoStatus.Information);

    WdfRequestComplete(Request, CompletionParams->IoStatus.Status);

    return;
}


VOID
FilterForwardRequestWithCompletionRoutine(
    IN WDFREQUEST Request,
    IN WDFIOTARGET Target
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
                                WDF_NO_CONTEXT);

    ret = WdfRequestSend(Request,
                         Target,
                         WDF_NO_SEND_OPTIONS);

    if (ret == FALSE) {
        status = WdfRequestGetStatus (Request);
        DbgPrint("Filter!WdfRequestSend failed: 0x%x\n", status);
        WdfRequestComplete(Request, status);
    }

    return;
}

CHAR* IoControlCodeInfo(ULONG IoControlCode, CHAR* buffer, size_t bufSize)
{
	RtlZeroMemory(buffer, bufSize);
	CHAR unknown[32];
	CHAR ioctl[16];

	RtlStringCbCatA(buffer, bufSize, "IoControlCode=");
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
	RtlStringCbPrintfA(ioctl, 16, "(0x%6X) ", IoControlCode);
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

    //DbgPrint("Filter!Begin FilterEvtIoDeviceControl\n");

    device = WdfIoQueueGetDevice(Queue);
	
	PIRP irp = WdfRequestWdmGetIrp(Request);
		
	CHAR info[256];
	DbgPrint("Filter!%s InputBufferLength=%u OutputBufferLength=%u IRP: Type=0x%x Size=%u\n",IoControlCodeInfo(IoControlCode,info,256), InputBufferLength, OutputBufferLength, irp->Type, irp->Size);

	PVOID  buffer;
	size_t  bufSize;
	status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &buffer, &bufSize );
	
	CHAR hexString[256];
	CHAR chrString[256];
	CHAR tempString[8];
	RtlZeroMemory(hexString, 256);
	RtlZeroMemory(chrString, 256);
	RtlZeroMemory(tempString, 8);
	unsigned char *p = (unsigned char*)buffer;
	unsigned int i = 0;
	BOOLEAN multiLine = FALSE;
	for(; i<bufSize; i++)
	{
		RtlStringCbPrintfA(tempString, 8, "%02X ", p[i]);
		RtlStringCbCatA(hexString, 256, tempString);

		RtlStringCbPrintfA(tempString, 8, "%c", p[i]>31 && p[i]<127 ? p[i] : '.' );
		RtlStringCbCatA(chrString, 256, tempString);

		if ((i+1)%38 == 0)
		{
			DbgPrint("Filter!%s%s",hexString,chrString);
			RtlZeroMemory(hexString, 256);
			RtlZeroMemory(chrString, 256);
			multiLine = TRUE;
		}
	}
	if ((i+1)%38 != 0)
	{
		CHAR padding[256];
		RtlZeroMemory(padding, 256);
		if (multiLine)
		{
			RtlStringCbPrintfA(padding, 256, "%*s", 3*(38-(i%38)),"");
		}
		
		DbgPrint("Filter!%s%s%s",hexString,padding,chrString);
	}

    switch (IoControlCode) {

    //
    // Put your cases for handling IOCTLs here
    //
    }
    
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
		goto exit;
        return;
    }

	FilterForwardRequestWithCompletionRoutine(Request, WdfDeviceGetIoTarget(device));

exit:
	//DbgPrint("Filter!End FilterEvtIoDeviceControl\n");

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
	
	ioQueueConfig.EvtIoDeviceControl = FilterEvtIoDeviceControl;

	status = WdfIoQueueCreate(device,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            WDF_NO_HANDLE // pointer to default queue
                            );
    if (!NT_SUCCESS(status)) {
        DbgPrint("Filter!WdfIoQueueCreate failed 0x%x\n", status);
        goto exit;
    }   
			
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