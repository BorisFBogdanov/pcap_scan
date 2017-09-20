/* header file */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* TCP/IP */ 

#define IP_TCP    6
#define IP_UDP   17
#define IP_SCTP 132

#define SSN_CAP	146


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* TCAP definitions */
/* Q.773 199706 */

/* table 8 Q.773 */
#define TCAP_UNIDIRECTIONAL	(0x61)
#define TCAP_BEGIN   		(0x62)
#define TCAP_END      		(0x64)
#define TCAP_CONTINUE 		(0x65)
#define TCAP_ABORT 		(0x67)

/* table 10 Q.773 */
#define TCAP_OTID      (0x48)
#define TCAP_DTID      (0x49)

/* table 11 Q.773 */
#define TCAP_P_ABORT     (0x4A)
/* table 13 Q.773 */
#define TCAP_DIALOGUE  (0x6B)
/* table 14 Q.773 */
#define TCAP_COMPONENT (0x6C)

/* table 19 Q.773 */
#define TCAP_INVOKE	(0xA1)
#define TCAP_RRLAST	(0xA2)
#define TCAP_RERROR	(0xA3)
#define TCAP_REJECT	(0xA4)
#define TCAP_RETRES	(0xA7)

/* table 20 Q.773 */
#define TCAP_InvokeID	(0x02)
#define TCAP_LinkedID	(0x80)

/* table 21 Q.773 */
#define TCAP_NULL_TAG	(0x05)

/* table 22 Q.773 */
#define TCAP_OpCode	(0x02)
#define TCAP_OpCode_G	(0x06)

/* table 22 Q.773 */
#define TCAP_Sequence_Tag	(0x30)
#define TCAP_Set_Tag		(0x31)


#define TCAP_DLG_AARQ   (0x60)
#define TCAP_DLG_AARE   (0x61)
#define TCAP_DLG_ABRT   (0x65)
#define TCAP_DLG_AUDT	(0x60)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* CAMEL definitions */
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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* MAP definitions */
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

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* DIAMETER definitions */

#define DIAM_AVP_SessionID		263
#define DIAM_AVP_SubscriptionID		443
#define DIAM_AVP_SubscriptionID_Type	450
#define DIAM_AVP_SubscriptionID_Data	444
#define DIAM_AVP_Service_Information	873
#define DIAM_AVP_IMS_Information	876
#define DIAM_AVP_Calling_Party		831
#define DIAM_AVP_Called_Party		832
#define DIAM_AVP_SMS_INFO		2000
#define DIAM_AVP_SMS_Originator_INFO	2027
#define DIAM_AVP_SMS_Recipient_INFO	2026
#define DIAM_AVP_SMS_Recipient_Address	1201
#define DIAM_AVP_SMS_Address_Type	899
#define DIAM_AVP_SMS_Address_Data	897
#define DIAM_SMS_USER_MSISDN		1

#define DIAM_END_USER_IMSI	1
#define DIAM_END_USER_MSISDN	0

#define DIAM_3GPP_Application_S6ad	16777251
#define DIAM_3GPP_Application_S13	16777252
#define DIAM_Vendor_3GPP		10415

// Diameter commands
#define DIAM_Watch_Dog			280

#define DIAM_CREDIT_CONTROL		272

#define DIAM_3GPP_UPDATE_LOCATION	316
#define DIAM_3GPP_CANCEL_LOCATION	317
#define DIAM_3GPP_AUTH_INFO		318
#define DIAM_3GPP_INSERT_DATA		319
#define DIAM_3GPP_DELETE_DATA		320
#define DIAM_3GPP_PURGE_UE 		321
#define DIAM_3GPP_RESET 		322
#define DIAM_3GPP_NOTIFY 		323
#define DIAM_3GPP_IMEI_CHECK 		324

#define DIAM_AVP_USER_ID		1444
#define DIAM_AVP_USER_NAME		1
#define DIAM_AVP_Subscription_Data	1400
#define DIAM_AVP_MSISDN			701

// SMPP commands
#define SMPP_GENERIC		(0x000)
#define SMPP_SUBMIT_SM		(0x004)
#define SMPP_DELIVER_SM		(0x005)
#define SMPP_ENQ_LINK		(0x015)
#define SMPP_ALERT		(0x102)
#define SMPP_DATA_SM 		(0x103)

#define SMPP_TON_Unk		0
#define SMPP_TON_Int		1
#define SMPP_TON_Nat		2
#define SMPP_TON_Net		3
#define SMPP_TON_Sub		4
#define SMPP_TON_Alf		5
#define SMPP_TON_Abr		6

#define SMPP_NPI_Unk		0
#define SMPP_NPI_164		1
#define SMPP_NPI_121		3
#define SMPP_NPI_F64		4
#define SMPP_NPI_212		6
#define SMPP_NPI_Nat		8
#define SMPP_NPI_Pvt		9
#define SMPP_NPI_ERM		10
#define SMPP_NPI_IP		14
#define SMPP_NPI_WAP		18





/* end of file */
