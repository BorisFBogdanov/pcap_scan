/* header file */

#define TCAP_BEGIN    (0x62)
#define TCAP_CONTINUE (0x65)
#define TCAP_END      (0x64)

#define TCAP_OTID      (0x48)
#define TCAP_DTID      (0x49)
#define TCAP_DIALOGUE  (0x6B)
#define TCAP_COMPONENT (0x6C)
#define TCAP_ABORT     (0x4A)

#define CAP_IDP 		 0
#define CAP_Connect 		20
#define CAP_Contunue 		31
#define CAP_ApplyChargeReport 	36
#define CAP_CallInfoReport 	44
#define CAP_CallInfoRequest 	45
#define CAP_ReqRepBSCMEvent 	23
#define CAP_ApplyCharging 	35

#define CAP_I_CalledPN   0x82
#define CAP_I_CallingPN  0x83
#define CAP_C_CalledPN   0x04
#define CAP_I_IMSI     0x9F32

#define MAP_updateLocation 		2
#define MAP_cancelLocation 		3
#define MAP_provideRoamingNumber 	4
#define MAP_noteSubscriberDataModified 	5
#define MAP_resumeCallHandling		6
#define MAP_insertSubscriberData 	7
#define MAP_deleteSubscriberData 	8
#define MAP_registerSS 		        10
#define MAP_eraseSS 			11
#define MAP_activateSS 			12
#define MAP_deactivateSS 		13
#define MAP_interrogateSS 		14
#define MAP_authenticationFailureReport 15
#define MAP_registerPassword 		17
#define MAP_getPassword 		18
#define MAP_releaseResources 		20
#define MAP_mt_ForwardSM_VGCS 		21
#define MAP_sendRoutingInfo 		22
#define MAP_updateGprsLocation 		23
#define MAP_sendRoutingInfoForGprs 	24
#define MAP_failureReport 		25
#define MAP_noteMsPresentForGprs 	26
#define MAP_sendEndSignal 		29
#define MAP_processAccessSignalling 	33
#define MAP_forwardAccessSignalling 	34
#define MAP_reset 			37
#define MAP_forwardCheckSS_Indication 	38
#define MAP_checkIMEI 			43
#define MAP_mt_ForwardSM 		44
#define MAP_sendRoutingInfoForSM 	45
#define MAP_mo_ForwardSM 		46
#define MAP_reportSM_DeliveryStatus 	47
#define MAP_activateTraceMode       	50
#define MAP_deactivateTraceMode     	51
#define MAP_sendIdentification 		55
#define MAP_sendAuthenticationInfo 	56
#define MAP_restoreData 		57
#define MAP_sendIMSI 			58
#define MAP_processUnstructuredSS_Request 59
#define MAP_unstructuredSS_Request 	60
#define MAP_unstructuredSS_Notify  	61
#define MAP_anyTimeSubscriptionInterrogation 62
#define MAP_informServiceCentre 	63
#define MAP_alertServiceCentre  	64
#define MAP_anyTimeModification 	65
#define MAP_readyForSM          	66
#define MAP_purgeMS             	67
#define MAP_prepareHandover     	68
#define MAP_prepareSubsequentHandover 	69
#define MAP_provideSubscriberInfo     	70
#define MAP_anyTimeInterrogation      	71
#define MAP_setReportingState 		73      
#define MAP_statusReport 		74
#define MAP_remoteUserFree 		75
#define MAP_provideSubscriberLocation 	83
#define MAP_noteMM_Event 		89

#define IP_TCP    6
#define IP_UDP   17
#define IP_SCTP 132

#define SSN_CAP	146

#define DIAM_AVP_SessionID		263
#define DIAM_AVP_SubscriptionID		443
#define DIAM_AVP_SubscriptionID_Type	450
#define DIAM_AVP_SubscriptionID_Data	444
#define DIAM_AVP_Service_Information	873
#define DIAM_AVP_IMS_Information	876
#define DIAM_AVP_Calling_Party		831
#define DIAM_AVP_Called_Party		832

#define DIAM_END_USER_IMSI	1
#define DIAM_END_USER_MSISDN	0

/* end of file */
