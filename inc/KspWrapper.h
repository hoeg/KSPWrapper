// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.


#ifndef __KSP_WRAPPER_H__
#define __KSP_WRAPPER_H__

#define KSPWRAPPER_INTERFACE_VERSION BCRYPT_MAKE_INTERFACE_VERSION(1,0)
#define KSPWRAPPER_VERSION 0x00010000                        
#define KSPWRAPPER_SUPPORT_SECURITY_DESCRIPTOR   0x00000001
#define KSPWRAPPER_PROVIDER_NAME           L"Key Storage Provider Wrapper"
#define KSPWRAPPER_PROVIDER_MAGIC          0x53504C50      // SPLP
#define KSPWRAPPER_KEY_MAGIC               0x53504C4b      // SPLK
#define KSPWRAPPER_KEY_FILE_VERSION        1               // version of the key file
#define KSPWRAPPER_RSA_ALGID               1               // Algorithm ID RSA
#define KSPWRAPPER_DEFAULT_KEY_LENGTH      1024            // default key length
#define KSPWRAPPER_RSA_MIN_LENGTH          512             // minimal key length
#define KSPWRAPPER_RSA_MAX_LENGTH          16384           // maximal key length
#define KSPWRAPPER_RSA_INCREMENT           64              // increment of key length
#define KSPWRAPPER_KEYFOLDER_NAME          L"\\AppData\\Roaming\\Microsoft\\Crypto\\KSPWRAPPER\\"  //key storage directory
//property ID
#define KSPWRAPPER_IMPL_TYPE_PROPERTY      1
#define KSPWRAPPER_MAX_NAME_LEN_PROPERTY   2
#define KSPWRAPPER_NAME_PROPERTY           3
#define KSPWRAPPER_VERSION_PROPERTY        4
#define KSPWRAPPER_SECURITY_DESCR_SUPPORT_PROPERTY     5
#define KSPWRAPPER_ALGORITHM_PROPERTY      6
#define KSPWRAPPER_BLOCK_LENGTH_PROPERTY   7
#define KSPWRAPPER_EXPORT_POLICY_PROPERTY  8
#define KSPWRAPPER_KEY_USAGE_PROPERTY      9
#define KSPWRAPPER_KEY_TYPE_PROPERTY       10
#define KSPWRAPPER_LENGTH_PROPERTY         11
#define KSPWRAPPER_LENGTHS_PROPERTY        12
#define KSPWRAPPER_SECURITY_DESCR_PROPERTY 13
#define KSPWRAPPER_ALGORITHM_GROUP_PROPERTY 14
#define KSPWRAPPER_USE_CONTEXT_PROPERTY    15
#define KSPWRAPPER_UNIQUE_NAME_PROPERTY    16
#define KSPWRAPPER_UI_POLICY_PROPERTY      17
#define KSPWRAPPER_WINDOW_HANDLE_PROPERTY  18
//const
#define MAXUSHORT   0xffff
#define MAX_NUM_PROPERTIES  100


//error handling
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_INTERNAL_ERROR           ((NTSTATUS)0xC00000E5L)
#define STATUS_INVALID_SIGNATURE        ((NTSTATUS)0xC000A000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif

//provider handle
typedef __struct_bcount(sizeof(KSPWRAPPER_PROVIDER)) struct _KSPWRAPPER_PROVIDER
{
    DWORD               cbLength;   //length of the whole data struct
    DWORD               dwMagic;    //type of the provider
    DWORD               dwFlags;    //reserved flags
    LPWSTR              pszName;    //name of the KSP
    BCRYPT_ALG_HANDLE   hRsaAlgorithm;    //bcrypt rsa algorithm handle
    LPWSTR              pszContext;       //context
}KSPWRAPPER_PROVIDER;

//property struct stored in the key file
typedef __struct_bcount(sizeof(KSPWRAPPER_NAMED_PROPERTY) +cbPropertyName+cbPropertyData) struct _KSPWRAPPER_NAMED_PROPERTY
{
    DWORD cbLength;         //length of the whole data blob
    DWORD cbPropertyName;   //length of the property name
    DWORD cbPropertyData;   //length of the property data
    BOOL  fBuildin;         //Whether it is a build-in property or not
    // property name
    // property data
} KSPWRAPPER_NAMED_PROPERTY;

//property struct in the key handle
typedef __struct_bcount(sizeof(KSPWRAPPER_PROPERTY) + cbPropertyData) struct _KSPWRAPPER_PROPERTY
{
    DWORD               cbLength;         //length of the whole data blob
    BOOL                fPersisted;       //is this a persisted property
    WCHAR               szName[NCRYPT_MAX_PROPERTY_NAME + 1];   //name of the property
    DWORD               cbPropertyData;                         //property data
    LIST_ENTRY          ListEntry;                              //ListEntry node
    BOOL                fBuildin;         //whether it is a build-in property or not
    // property data
} KSPWRAPPER_PROPERTY;

//key file header stored in the key file
typedef __struct_bcount(sizeof(KSPWRAPPER_KEYFILE_HEADER)+cbProperties+cbPrivateKey) struct _KSPWRAPPER_KEYFILE_HEADER
{
    DWORD cbLength;         //length of the whole data blob
    DWORD dwVersion;        //the version of the key
    DWORD dwAlgorithm;      //Algorithm ID

    DWORD cbProperties;     //length of the properties
    DWORD cbPrivateKey;     //length of the private key
    DWORD cbName;           //length of the key name

    //properties data
    //private key
    //name of the key
} KSPWRAPPER_KEYFILE_HEADER;

//key handle
typedef __struct_bcount(sizeof(KSPWRAPPER_KEY)+cbKeyFile+cbPrivateKey+cbSecurityDescr) struct _KSPWRAPPER_KEY
{
    DWORD               cbLength;           //length of the whole data blob
    DWORD               dwMagic;            //type of the key
    LPWSTR              pszKeyName;         //name of the key (key file)
    LPWSTR              pszKeyFilePath;     //path of the key file
    LPWSTR              pszKeyBlobType;     //BCRYPT_RSAPRIVATE_BLOB or BCRYPT_RSAFULLPRIVATE_BLOB
    DWORD               dwAlgID;            //Algorithm ID
    DWORD               dwKeyBitLength;     //length of the key
    DWORD               dwExportPolicy;     //export policy
    DWORD               dwKeyUsagePolicy;   //key usage policy
    BOOL                fFinished;          //Whether the key is finalized

    //key file header
    __field_bcount(cbKeyFile) PBYTE               pbKeyFile;
    DWORD               cbKeyFile;

    //encrypted private key blob
    __field_bcount(cbPrivateKey) PBYTE               pbPrivateKey;
    DWORD               cbPrivateKey;

    // handle to cryptography providers needed to perform operations with
    // the key.
    BCRYPT_ALG_HANDLE   hProvider;

    // handle to key objects.
    BCRYPT_KEY_HANDLE   hPublicKey;
    BCRYPT_KEY_HANDLE   hPrivateKey;

    // security descriptor to be set on the private key file.
    DWORD               dwSecurityFlags;
    __field_bcount(cbSecurityDescr) PBYTE               pbSecurityDescr;
    DWORD               cbSecurityDescr;

    //context
    LPWSTR              pszContext;

    // list of properties.
    LIST_ENTRY          PropertyList;

    // multi-read/single write lock can be added here to support synchronization for multi-threading
} KSPWRAPPER_KEY;

//enum state used in enum keys and enum providers
typedef struct _KSPWRAPPER_ENUM_STATE
{
    DWORD  dwIndex;
    HANDLE hFind;
    LPWSTR pszPath;
} KSPWRAPPER_ENUM_STATE;

//list of buffer allocated for enum keys / enum providers
typedef struct _KSPWRAPPER_MEMORY_BUFFER
{
    PVOID pvBuffer;
    LIST_ENTRY List;
} KSPWRAPPER_MEMORY_BUFFER;

//this algorithm handle can be shared by all key handles
static BCRYPT_ALG_HANDLE g_hRSAProvider;

NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD dwFlags);


SECURITY_STATUS
WINAPI
KSPWRAPPEROpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider);

SECURITY_STATUS
WINAPI
KSPWRAPPEROpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS
WINAPI
KSPWRAPPERFreeBuffer(
    __deref PVOID   pvInput);

SECURITY_STATUS
WINAPI
KSPWRAPPEREncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
KSPWRAPPERIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
KSPWRAPPEREnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations, // this is the crypto operations that are to be enumerated
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPEREnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID  *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR  pszOperation,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
KSPWRAPPERDeriveKey(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in_opt    NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags);

SECURITY_STATUS
WINAPI
KSPWRAPPERFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret);

SECURITY_STATUS
WINAPI
CreateNewKeyObject(
    __in_opt LPCWSTR pszKeyName,
    __deref_out KSPWRAPPER_KEY **ppKey);

SECURITY_STATUS
WINAPI
DeleteKeyObject(
     __inout KSPWRAPPER_KEY *pKey);

DWORD
ProtectPrivateKey(
    __in KSPWRAPPER_KEY *pKey,
    __deref_out PBYTE *ppbEncPrivateKey,
    __out DWORD *pcbEncPrivateKey);

HRESULT
GetSampleKeyStorageArea(
    __deref_out LPWSTR *ppwszKeyFilePath);

SECURITY_STATUS
ValidateKeyFileExistence(
    __in KSPWRAPPER_KEY* pKey);

SECURITY_STATUS
RemoveKeyFromStore(
    __in KSPWRAPPER_KEY *pKey);

SECURITY_STATUS
ReadKeyNameFromFile(
    __in LPWSTR  pszKeyStorageArea,
    __in LPWSTR  pszFileName,
    __deref_out NCryptKeyName **ppKeyName);

SECURITY_STATUS
ReadKeyFile(
    __inout KSPWRAPPER_KEY *pKey);

SECURITY_STATUS
WriteKeyToStore(
    __inout KSPWRAPPER_KEY *pKey
    );

SECURITY_STATUS
ParseKeyFile(
    __inout KSPWRAPPER_KEY *pKey);

SECURITY_STATUS
GetSecurityOnKeyFile(
    __in    KSPWRAPPER_KEY *pKey,
    __in    DWORD   dwSecurityFlags,
    __deref_out_bcount(*pcbSecurityDescr) PSECURITY_DESCRIPTOR *ppSecurityDescr,
    __out   DWORD * pcbSecurityDescr);

SECURITY_STATUS
KSPWRAPPERImportPKCS7Blob(
    __in    KSPWRAPPER_PROVIDER *pProvider,
    __in    KSPWRAPPER_KEY **ppKey,
    __in_opt NCryptBufferDesc *pParameterList,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags);

SECURITY_STATUS
KSPWRAPPERExportPKCS7Blob(
    __in     KSPWRAPPER_KEY *pKey,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult);

SECURITY_STATUS
KSPWRAPPERImportPKCS8Blob (
    __in NCRYPT_PROV_HANDLE hProv,
    __deref_out KSPWRAPPER_KEY** ppKey,
    __in_opt NCryptBufferDesc const* pImportParamList,
    __in_bcount (cbIn) BYTE const* pbIn,
    __in DWORD cbIn,
    __in DWORD dwFlags);

SECURITY_STATUS
KSPWRAPPERExportPKCS8Blob (
    __in KSPWRAPPER_KEY const* pKey,
    __in_opt NCryptBufferDesc const* pExportParamList,
    __out_bcount_part_opt (cbOut, *pcbResult) BYTE* pbOut,
    __in DWORD cbOut,
    __out DWORD* pcbResult);

SECURITY_STATUS
ReadKeyNameFromParams(
    __in_opt NCryptBufferDesc const* pParamList,
    __out LPWSTR* pszKeyName);

BOOL
IsPkcs8KeyExportable(
    __in KSPWRAPPER_KEY const* pKey,
    __in_opt NCryptBufferDesc const* pExportParamList);

SECURITY_STATUS
NormalizeNteStatus(
    __in NTSTATUS NtStatus);

KSPWRAPPER_PROVIDER *
KSPWRAPPERValidateProvHandle(
    __in    NCRYPT_PROV_HANDLE hProvider);

KSPWRAPPER_KEY *
KSPWRAPPERValidateKeyHandle(
    __in    NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS
CreateNewProperty(
    __in_opt                LPCWSTR pszProperty,
    __in_bcount(cbProperty) PBYTE   pbProperty,
    __in                    DWORD   cbProperty,
    __in                    DWORD   dwFlags,
    __deref_out             KSPWRAPPER_PROPERTY    **ppProperty);

SECURITY_STATUS
SetBuildinKeyProperty(
    __inout     KSPWRAPPER_KEY  *pKey,
    __in        LPCWSTR pszProperty,
    __in_bcount(cbInput)    PBYTE pbInput,
    __in                    DWORD   cbInput,
    __inout    DWORD*   dwFlags);

SECURITY_STATUS
ProtectAndSetPrivateKey(
    __in LPCWSTR pszBlobType,
    __in PBYTE  pbKeyBlob,
    __in DWORD  cbKeyBlob,
    __inout KSPWRAPPER_KEY* pKey);

SECURITY_STATUS
AllocAndGetRsaPrivateKeyBlob(
    __inout KSPWRAPPER_KEY *pKey,
    __in    LPCWSTR pszExportBlobType,
    __deref_out_bcount(cbCngKeyBlob) PBYTE *pbCngKeyBlob,
    __out DWORD *cbCngKeyBlob);

HRESULT
ImportRsaKeyPair(
    __inout KSPWRAPPER_KEY *pKey);

SECURITY_STATUS
FinalizeKey(
    __inout KSPWRAPPER_KEY *pKey);

KSPWRAPPER_MEMORY_BUFFER *
RemoveMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer);

KSPWRAPPER_MEMORY_BUFFER *
LookupMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer);

SECURITY_STATUS
LookupExistingKeyProperty(
    __in    KSPWRAPPER_KEY *pKey,
    __in    LPCWSTR pszProperty,
    __out   KSPWRAPPER_PROPERTY **ppProperty);

SECURITY_STATUS
CreateNewProperty(
    __in_opt                LPCWSTR pszProperty,
    __in_bcount(cbProperty) PBYTE   pbProperty,
    __in                    DWORD   cbProperty,
    __in                    DWORD   dwFlags,
    __deref_out             KSPWRAPPER_PROPERTY    **ppProperty);

SECURITY_STATUS
FindFirstKeyFile(
    __out PVOID *ppEnumState,
    __deref_out NCryptKeyName **ppKeyName);

SECURITY_STATUS
FindNextKeyFile(
    __inout PVOID pEnumState,
    __deref_out NCryptKeyName **ppKeyName);

//macro for list operation
#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink)}

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

#endif //__SAMPLE_KSP_H__
