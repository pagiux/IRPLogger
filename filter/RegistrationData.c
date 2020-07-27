#include "IRPLoggerKernel.h"
#include "IRPLoggerUtils.h"
//  Registration information for FLTMGR.

#ifdef ALLOC_DATA_PRAGMA
    #pragma data_seg("INIT")
    #pragma const_seg("INIT")
#endif

CONST FLT_OPERATION_REGISTRATION callbacks[] = {
/*
    { IRP_MJ_CREATE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_CLOSE,
      0,
	  pre_operation_callback,
	  post_operation_callback },
*/
    { IRP_MJ_READ,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_WRITE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

	{ IRP_MJ_DIRECTORY_CONTROL,
	  0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_SET_INFORMATION,
      0,
	  pre_operation_callback,
	  post_operation_callback },

/*
	{ IRP_MJ_CREATE_NAMED_PIPE,
	  0,
	  pre_operation_callback,
	  post_operation_callback },

	{ IRP_MJ_QUERY_INFORMATION,
	  0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_QUERY_EA,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_SET_EA,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_DEVICE_CONTROL,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_SHUTDOWN,
      0,
	  pre_operation_callback,
      NULL },                           //post operation callback not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_CLEANUP,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_QUERY_SECURITY,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_SET_SECURITY,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_QUERY_QUOTA,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_SET_QUOTA,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_PNP,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_NOTIFY_STREAM_FILE_OBJECT,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_MDL_READ,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_VOLUME_MOUNT,
      0,
	  pre_operation_callback,
	  post_operation_callback },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
	  pre_operation_callback,
	  post_operation_callback },
*/
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION contexts[] = {

#if IRPLOGGER_VISTA
    {
		FLT_TRANSACTION_CONTEXT,
		0,
		delete_txf_context,
		sizeof(IRPLOGGER_TRANSACTION_CONTEXT),
		'IRPL'
	},

#endif 
    { FLT_CONTEXT_END }
};

//  This defines what we want to filter with FltMgr
CONST FLT_REGISTRATION filter_registration = {

    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version   
#if IRPLOGGER_WIN8 
    FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,   //  Flags
#else
    0,                                      //  Flags
#endif

    contexts,                               //  Context
    callbacks,                              //  Operation callbacks

	filter_unload,                        //  FilterUnload

    NULL,                                   //  InstanceSetup
	query_teardown,                       //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete

    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
#if IRPLOGGER_VISTA
    ,
	ktm_notification_callback              //  KTM notification callback
#endif 
};

#ifdef ALLOC_DATA_PRAGMA
    #pragma data_seg()
    #pragma const_seg()
#endif

