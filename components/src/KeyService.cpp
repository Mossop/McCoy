/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is McCoy.
 *
 * The Initial Developer of the Original Code is
 * the Mozilla Foundation <http://www.mozilla.org/>.
 * Portions created by the Initial Developer are Copyright (C) 2007
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Dave Townsend <dtownsend@oxymoronical.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "stdio.h"
#include "KeyService.h"
#include "KeyPair.h"
#include "KeyUtils.h"
#include "nsCOMPtr.h"
#include "nsCOMArray.h"
#include "nsArrayEnumerator.h"
#include "nsStringAPI.h"
#include "nss.h"
#include "keyhi.h"
#include "cryptohi.h"
#include "cert.h"
#include "nssb64.h"
#include "secdert.h"
#include "nsITokenPasswordDialogs.h"
#include "nsAppDirectoryServiceDefs.h"
#include "nsDirectoryServiceUtils.h"

static const unsigned char P[] = { 0, 
       0x98, 0xef, 0x3a, 0xae, 0x70, 0x98, 0x9b, 0x44, 
       0xdb, 0x35, 0x86, 0xc1, 0xb6, 0xc2, 0x47, 0x7c, 
       0xb4, 0xff, 0x99, 0xe8, 0xae, 0x44, 0xf2, 0xeb, 
       0xc3, 0xbe, 0x23, 0x0f, 0x65, 0xd0, 0x4c, 0x04, 
       0x82, 0x90, 0xa7, 0x9d, 0x4a, 0xc8, 0x93, 0x7f, 
       0x41, 0xdf, 0xf8, 0x80, 0x6b, 0x0b, 0x68, 0x7f, 
       0xaf, 0xe4, 0xa8, 0xb5, 0xb2, 0x99, 0xc3, 0x69, 
       0xfb, 0x3f, 0xe7, 0x1b, 0xd0, 0x0f, 0xa9, 0x7a, 
       0x4a, 0x04, 0xbf, 0x50, 0x9e, 0x22, 0x33, 0xb8, 
       0x89, 0x53, 0x24, 0x10, 0xf9, 0x68, 0x77, 0xad, 
       0xaf, 0x10, 0x68, 0xb8, 0xd3, 0x68, 0x5d, 0xa3, 
       0xc3, 0xeb, 0x72, 0x3b, 0xa0, 0x0b, 0x73, 0x65, 
       0xc5, 0xd1, 0xfa, 0x8c, 0xc0, 0x7d, 0xaa, 0x52, 
       0x29, 0x34, 0x44, 0x01, 0xbf, 0x12, 0x25, 0xfe, 
       0x18, 0x0a, 0xc8, 0x3f, 0xc1, 0x60, 0x48, 0xdb, 
       0xad, 0x93, 0xb6, 0x61, 0x67, 0xd7, 0xa8, 0x2d };
static const unsigned char Q[] = { 0,
       0xb5, 0xb0, 0x84, 0x8b, 0x44, 0x29, 0xf6, 0x33, 
       0x59, 0xa1, 0x3c, 0xbe, 0xd2, 0x7f, 0x35, 0xa1, 
       0x76, 0x27, 0x03, 0x81                         };
static const unsigned char G[] = { 
       0x04, 0x0e, 0x83, 0x69, 0xf1, 0xcd, 0x7d, 0xe5, 
       0x0c, 0x78, 0x93, 0xd6, 0x49, 0x6f, 0x00, 0x04, 
       0x4e, 0x0e, 0x6c, 0x37, 0xaa, 0x38, 0x22, 0x47, 
       0xd2, 0x58, 0xec, 0x83, 0x12, 0x95, 0xf9, 0x9c, 
       0xf1, 0xf4, 0x27, 0xff, 0xd7, 0x99, 0x57, 0x35, 
       0xc6, 0x64, 0x4c, 0xc0, 0x47, 0x12, 0x31, 0x50, 
       0x82, 0x3c, 0x2a, 0x07, 0x03, 0x01, 0xef, 0x30, 
       0x09, 0x89, 0x82, 0x41, 0x76, 0x71, 0xda, 0x9e, 
       0x57, 0x8b, 0x76, 0x38, 0x37, 0x5f, 0xa5, 0xcd, 
       0x32, 0x84, 0x45, 0x8d, 0x4c, 0x17, 0x54, 0x2b, 
       0x5d, 0xc2, 0x6b, 0xba, 0x3e, 0xa0, 0x7b, 0x95, 
       0xd7, 0x00, 0x42, 0xf7, 0x08, 0xb8, 0x83, 0x87, 
       0x60, 0xe1, 0xe5, 0xf4, 0x1a, 0x54, 0xc2, 0x20, 
       0xda, 0x38, 0x3a, 0xd1, 0xb6, 0x10, 0xf4, 0xcb, 
       0x35, 0xda, 0x97, 0x92, 0x87, 0xd6, 0xa5, 0x37, 
       0x62, 0xb4, 0x93, 0x4a, 0x15, 0x21, 0xa5, 0x10 };

/*  h:
 *      4a:76:30:89:eb:e1:81:7c:99:0b:39:7f:95:4a:65:72:
 *      c6:b4:05:92:48:6c:3c:b2:7e:e7:39:f3:92:7d:c1:3f:
 *      bf:e1:fd:b3:4a:46:3e:ce:29:80:e3:d6:f4:59:c6:92:
 *      16:2b:0e:d7:d6:bb:ef:94:36:31:c2:66:46:c5:4a:77:
 *      aa:95:84:ef:99:7e:e3:9c:d9:a0:32:42:09:b6:4e:d0:
 *      b3:c8:5e:06:df:a1:ac:4d:2d:f9:08:c2:cb:4b:a4:42:
 *      db:8a:5b:de:25:6e:2b:5b:ca:00:75:2c:57:00:18:aa:
 *      68:59:a1:94:03:07:94:78:38:bc:f8:7c:1e:1c:a3:2e
 *  SEED:
 *      b5:44:66:c9:0f:f1:ca:1c:95:45:ce:90:74:89:14:f2:
 *      13:3e:23:5a:b0:6a:bf:86:ad:cb:a0:7d:ce:3b:c8:16:
 *      7f:2d:a2:1a:cb:33:7d:c1:e7:d7:07:aa:1b:a2:d7:89:
 *      f5:a4:db:f7:8b:50:00:cd:b4:7d:25:81:3f:f8:a8:dd:
 *      6c:46:e5:77:b5:60:7e:75:79:b8:99:57:c1:c4:f3:f7:
 *      17:ca:43:00:b8:33:b6:06:8f:4d:91:ed:23:a5:66:1b:
 *      ef:14:d7:bc:21:2b:82:d8:ab:fa:fd:a7:c3:4d:bf:52:
 *      af:8e:57:59:61:1a:4e:65:c6:90:d6:a6:ff:0b:15:b1
 *  g:       1024
 *  counter: 1003
 */

static const SECKEYPQGParams default_pqg_params = {
    NULL,
    { (SECItemType)0, (unsigned char *)P, sizeof(P) },
    { (SECItemType)0, (unsigned char *)Q, sizeof(Q) },
    { (SECItemType)0, (unsigned char *)G, sizeof(G) }
};

NS_IMPL_ISUPPORTS1(KeyService, nsIKeyService)

nsresult
KeyService::Init()
{
    // Bring up psm
    nsCOMPtr<nsISupports> nss = do_GetService("@mozilla.org/psm;1");
    SECStatus sv;
    mSlot = PK11_GetInternalKeySlot();
    
    if (PK11_NeedUserInit(mSlot)) {
        NS_ConvertUTF8toUTF16 tokenName(PK11_GetTokenName(mSlot));
        
        nsCOMPtr<nsITokenPasswordDialogs> dialogs;
        dialogs = do_GetService(NS_TOKENPASSWORDSDIALOG_CONTRACTID);
        if (!dialogs)
            return NS_ERROR_FAILURE;
        
        PRBool cancelled;
        nsresult rv = dialogs->SetPassword(nsnull, tokenName.get(), &cancelled);
        NS_ENSURE_SUCCESS(rv, rv);
        
        if (cancelled)
            return NS_ERROR_FAILURE;
    }
    
    if (PK11_NeedLogin(mSlot)) {
        sv = PK11_Authenticate(mSlot, PR_TRUE, NULL);
        if (sv != SECSuccess)
            return NS_ERROR_FAILURE;
    }
    
    return NS_OK;
}

KeyService::~KeyService()
{
    PK11_FreeSlot(mSlot);
}

/* void changePassword (); */
NS_IMETHODIMP
KeyService::ChangePassword()
{
    NS_ConvertUTF8toUTF16 tokenName(PK11_GetTokenName(mSlot));
    
    nsCOMPtr<nsITokenPasswordDialogs> dialogs;
    dialogs = do_GetService(NS_TOKENPASSWORDSDIALOG_CONTRACTID);
    if (!dialogs)
        return NS_ERROR_FAILURE;
    
    PRBool cancelled;
    return dialogs->SetPassword(nsnull, tokenName.get(), &cancelled);
}

/* nsISimpleEnumerator enumerateKeys (); */
NS_IMETHODIMP
KeyService::EnumerateKeys(nsISimpleEnumerator **_retval)
{
    SECKEYPrivateKeyList *list;
    SECKEYPrivateKeyListNode *node;

    nsCOMArray<nsIKeyPair> keys;
    
    // Retrieve all the private keys
    list = PK11_ListPrivKeysInSlot(mSlot, NULL, NULL);
    if (!list)
        return NS_NewArrayEnumerator(_retval, keys);
    
    // Walk the list
    for (node = PRIVKEY_LIST_HEAD(list); !PRIVKEY_LIST_END(node,list);
         node = PRIVKEY_LIST_NEXT(node)) {
        KeyPair *key = new KeyPair(node->key);
        keys.AppendObject(key);
    }
    
    SECKEY_DestroyPrivateKeyList(list);

    return NS_NewArrayEnumerator(_retval, keys);
}

/* nsIKeyPair createKeyPair(in PRUint32 aKeyType); */
NS_IMETHODIMP
KeyService::CreateKeyPair(PRUint32 aKeyType, nsIKeyPair **_retval)
{
    PK11RSAGenParams rsaparams;
    CK_MECHANISM_TYPE mechanism;
    void *params;

    // Initialize parameters based on key type
    switch (aKeyType) {
    case nsIKeyPair::KEYTYPE_RSA:
        rsaparams.keySizeInBits = 1024;
        rsaparams.pe = 0x010001;
        mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        params = &rsaparams;
        break;
    case nsIKeyPair::KEYTYPE_DSA:
        // Right now DSA can't be handled correctly
        return NS_ERROR_INVALID_ARG;
        mechanism = CKM_DSA_KEY_PAIR_GEN;
        params = (void *)&default_pqg_params;
        break;
    default:
        return NS_ERROR_INVALID_ARG;
    }
    
    // Create the key
    SECKEYPublicKey *pubKey;
    SECKEYPrivateKey *privKey;
    privKey = PK11_GenerateKeyPair(mSlot, mechanism, params, &pubKey, PR_TRUE, PR_TRUE, NULL);
    if (!privKey)
        return NS_ERROR_FAILURE;
    SECKEY_DestroyPublicKey(pubKey);

    // Pass on to a KeyPair
    KeyPair *key = new KeyPair(privKey);
    SECKEY_DestroyPrivateKey(privKey);
    if (!key)
        return NS_ERROR_OUT_OF_MEMORY;
    NS_ADDREF(*_retval = key);

    return NS_OK;
}
