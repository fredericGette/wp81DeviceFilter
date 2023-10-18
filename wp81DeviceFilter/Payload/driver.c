// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} bootlog Yes
// bcdedit /store f:\EFIESP\efi\Microsoft\Boot\BCD /set {default} testsigning yes
//
// set PATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\x86_arm;C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin;%PATH%
//

#include <ntifs.h>
#include <wdf.h>

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
	
	DbgPrint("Filter!Completion Request Type=0x%x\n", CompletionParams->Type);

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

	DbgPrint("Filter!IoControlCode=0x%x InputBufferLength=%d OutputBufferLength=%d IRP: Type=%d Size=%d\n",IoControlCode, InputBufferLength, OutputBufferLength, irp->Type, irp->Size);

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