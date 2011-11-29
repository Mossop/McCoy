/*
# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is McCoy.
#
# The Initial Developer of the Original Code is
# the Mozilla Foundation <http://www.mozilla.org/>.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Dave Townsend <dtownsend@oxymoronical.com>
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
*/

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/FileUtils.jsm");

const nsslib = ctypes.open(FileUtils.getFile("GreD", [ctypes.libraryName("nss3")]).path);

const SECSuccess = 0;
const SECFailure = -1;
const CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0000;
const CKM_INVALID_MECHANISM = 0xffffffff;
const CKA_DECRYPT = 0x105;
const DER_DEFAULT_CHUNKSIZE = 2048;

const KU_DATA_ENCIPHERMENT = 0x10;
const KU_DIGITAL_SIGNATURE = 0x80;

const SEC_ASN1_OCTET_STRING = 0x04;
const SEC_ASN1_OBJECT_ID = 0x06;
const SEC_ASN1_SEQUENCE = 0x10;
const SEC_ASN1_OPTIONAL = 0x00100;
const SEC_ASN1_ANY = 0x00400;
const SEC_ASN1_INLINE = 0x00800;
const SEC_ASN1_XTRN = 0;

const siUTF8String = 14;

function offsetof(aStruct, aMember) {
  function ptrValue(aPtr)
    ctypes.cast(aPtr, ctypes.uintptr_t).value.toString();

  let instance = aStruct();
  let memberptr = ptrValue(instance.addressOfField(aMember));
  let chararray = ctypes.cast(instance, ctypes.char.array(aStruct.size));
  let offset = 0;
  while (memberptr != ptrValue(chararray.addressOfElement(offset)))
    ++offset;
  return offset;
}

let nss_t = {};
let tmpl = {};
nss_t.PRBool = ctypes.int;
nss_t.SECStatus = ctypes.int;
nss_t.PK11SlotInfo = ctypes.void_t;
nss_t.PLArenaPool = ctypes.void_t;
nss_t.PRArenaPool = ctypes.void_t;
nss_t.KeyType = ctypes.int;
nss_t.CK_MECHANISM_TYPE = ctypes.unsigned_long;
nss_t.CK_ATTRIBUTE_TYPE = ctypes.unsigned_long;
nss_t.SECItemType = ctypes.int;

nss_t.SECKEYPrivateKey = ctypes.void_t;
nss_t.SECKEYPublicKey = ctypes.void_t;
nss_t.PK11SymKey = ctypes.void_t;
nss_t.PK11Context = ctypes.void_t;

nss_t.PRCList = ctypes.StructType("PRCList");
nss_t.PRCList.define([
  { next: nss_t.PRCList.ptr },
  { pref: nss_t.PRCList.ptr }
]);

nss_t.SECKEYPrivateKeyListNode = ctypes.StructType("SECKEYPrivateKeyListNode", [
  { links: nss_t.PRCList },
  { key: nss_t.SECKEYPrivateKey.ptr }
]);

nss_t.SECKEYPrivateKeyList = ctypes.StructType("SECKEYPrivateKeyList", [
  { list: nss_t.PRCList },
  { arena: nss_t.PLArenaPool.ptr }
]);

nss_t.PK11RSAGenParams = ctypes.StructType("PK11RSAGenParams", [
  { keySizeInBits: ctypes.int },
  { pe: ctypes.unsigned_long }
]);

nss_t.SECItem = ctypes.StructType("SecItem", [
  { type: this.nss_t.SECItemType },
  { data: ctypes.unsigned_char.ptr },
  { len : ctypes.int }
]);

nss_t.SECAlgorithmID = ctypes.StructType("SECAlgorithmID", [
  { algorithm: nss_t.SECItem },
  { parameters: nss_t.SECItem }
]);

nss_t.SECKEYEncryptedPrivateKeyInfo = ctypes.StructType("SECKEYEncryptedPrivateKeyInfo", [
  { arena: nss_t.PLArenaPool.ptr },
  { algorithm: nss_t.SECAlgorithmID },
  { encryptedData: nss_t.SECItem }
]);

nss_t.CK_MECHANISM = ctypes.StructType("CK_MECHANISM", [
  { mechanism: nss_t.CK_MECHANISM_TYPE },
  { pParameter: ctypes.voidptr_t },
  { ulParameterLen: ctypes.unsigned_long }
]);

nss_t.SEC_ASN1Template = ctypes.StructType("SEC_ASN1Template", [
  { kind: ctypes.unsigned_long },
  { offset: ctypes.unsigned_long },
  { sub: ctypes.voidptr_t },
  { size: ctypes.unsigned_int }
]);

nss_t.SEC_ASN1TemplateArray = nss_t.SEC_ASN1Template.array();

function declareTemplate(aName, aArgs) {
  let template = new nss_t.SEC_ASN1TemplateArray(aArgs.length + 1);

  aArgs.forEach(function(aPart, aIndex) {
    ["kind", "offset", "sub", "size"].forEach(function(aField) {
      if (aField in aPart)
        template[aIndex][aField] = aPart[aField];
    });
  });
  template[aArgs.length].kind = 0;

  tmpl[aName] = template;
}

declareTemplate("SECOID_AlgorithmIDTemplate", [
  { kind: SEC_ASN1_SEQUENCE, size: nss_t.SECAlgorithmID.size },
  { kind: SEC_ASN1_OBJECT_ID, offset: offsetof(nss_t.SECAlgorithmID, "algorithm") },
  { kind: SEC_ASN1_OPTIONAL | SEC_ASN1_ANY, offset: offsetof(nss_t.SECAlgorithmID, "parameters") }
]);

declareTemplate("SECKEY_EncryptedPrivateKeyInfoTemplate", [
  { kind: SEC_ASN1_SEQUENCE, size: nss_t.SECKEYEncryptedPrivateKeyInfo.size },
  { kind: SEC_ASN1_INLINE | SEC_ASN1_XTRN, offset: offsetof(nss_t.SECKEYEncryptedPrivateKeyInfo, "algorithm"), sub: tmpl.SECOID_AlgorithmIDTemplate },
  { kind: SEC_ASN1_OCTET_STRING, offset: offsetof(nss_t.SECKEYEncryptedPrivateKeyInfo, "encryptedData") }
]);

nss_t.PK11PasswordFunc = ctypes.FunctionType(ctypes.default_abi, ctypes.char.ptr, [nss_t.PK11SlotInfo.ptr, nss_t.PRBool, ctypes.voidptr_t]);

function declare(aName, aReturn) {
  let args = Array.slice(arguments, 1);
  args.unshift(ctypes.default_abi);
  args.unshift(aName);

  try {
    this[aName] = nsslib.declare.apply(nsslib, args);
  }
  catch (e) {
    Components.utils.reportError("Failed to declare function " + aName, e);
    throw e;
  }
}

declare("PK11_SetPasswordFunc",
        ctypes.void_t, nss_t.PK11PasswordFunc.ptr);
declare("PK11_CheckUserPassword",
        nss_t.SECStatus, nss_t.PK11SlotInfo.ptr, ctypes.char.ptr);
declare("PK11_GetInternalKeySlot",
        nss_t.PK11SlotInfo.ptr);
declare("PK11_NeedUserInit",
        nss_t.PRBool, nss_t.PK11SlotInfo.ptr);
declare("PK11_InitPin",
        nss_t.SECStatus, nss_t.PK11SlotInfo.ptr, ctypes.char.ptr, ctypes.char.ptr);
declare("PK11_ChangePW",
        nss_t.SECStatus, nss_t.PK11SlotInfo.ptr, ctypes.char.ptr, ctypes.char.ptr);
declare("PK11_NeedLogin",
        nss_t.PRBool, nss_t.PK11SlotInfo.ptr);
declare("PK11_Authenticate",
        nss_t.SECStatus, nss_t.PK11SlotInfo.ptr, nss_t.PRBool, ctypes.voidptr_t);
declare("PK11_Logout",
        nss_t.SECStatus, nss_t.PK11SlotInfo.ptr);
declare("PK11_ListPrivKeysInSlot",
        nss_t.SECKEYPrivateKeyList.ptr, nss_t.PK11SlotInfo.ptr, ctypes.char.ptr, ctypes.voidptr_t);
declare("SECKEY_DestroyPrivateKeyList",
        ctypes.void_t, nss_t.SECKEYPrivateKeyList.ptr);
declare("SECKEY_CopyPrivateKey",
        nss_t.SECKEYPrivateKey.ptr, nss_t.SECKEYPrivateKey.ptr);
declare("PK11_GetPrivateKeyNickname",
        ctypes.char.ptr, nss_t.SECKEYPrivateKey.ptr);
declare("PK11_SetPrivateKeyNickname",
        nss_t.SECStatus, nss_t.SECKEYPrivateKey.ptr, ctypes.char.ptr);
declare("PK11_DeleteTokenPrivateKey",
        nss_t.SECStatus, nss_t.SECKEYPrivateKey.ptr, nss_t.PRBool);
declare("PK11_GenerateKeyPair",
        nss_t.SECKEYPrivateKey.ptr, nss_t.PK11SlotInfo.ptr, nss_t.CK_MECHANISM_TYPE, 
        ctypes.voidptr_t, nss_t.SECKEYPublicKey.ptr.ptr, nss_t.PRBool, 
        nss_t.PRBool, ctypes.voidptr_t);
declare("SECKEY_GetPrivateKeyType",
        nss_t.KeyType, nss_t.SECKEYPrivateKey.ptr);
declare("SECKEY_DestroyPublicKey",
        ctypes.void_t, nss_t.SECKEYPublicKey.ptr);
declare("SECKEY_DestroyPrivateKey",
        ctypes.void_t, nss_t.SECKEYPrivateKey.ptr);
declare("PORT_Alloc",
        ctypes.voidptr_t, ctypes.size_t);
declare("PORT_NewArena",
        nss_t.PRArenaPool.ptr, ctypes.unsigned_long);
declare("PORT_FreeArena",
        ctypes.void_t, nss_t.PRArenaPool.ptr, nss_t.PRBool);
declare("PORT_ArenaZAlloc",
        ctypes.voidptr_t, nss_t.PRArenaPool.ptr, ctypes.size_t);
function PORT_ArenaZNew(aArena, aType) {
  return ctypes.cast(PORT_ArenaZAlloc(aArena, aType.size), aType.ptr);
}
declare("PORT_Strdup",
        ctypes.char.ptr, ctypes.char.ptr);
declare("PORT_Free",
        ctypes.void_t, ctypes.voidptr_t);
declare("NSSBase64_DecodeBuffer",
        nss_t.SECItem.ptr, nss_t.PRArenaPool.ptr, nss_t.SECItem.ptr, ctypes.char.ptr, ctypes.unsigned_int);
declare("SEC_ASN1DecodeItem",
        nss_t.SECStatus, nss_t.PRArenaPool.ptr, ctypes.voidptr_t, nss_t.SEC_ASN1Template.ptr, nss_t.SECItem.ptr);
declare("PK11_GetPBECryptoMechanism",
        nss_t.CK_MECHANISM_TYPE, nss_t.SECAlgorithmID.ptr, nss_t.SECItem.ptr.ptr, nss_t.SECItem.ptr);
declare("PK11_GetPadMechanism",
        nss_t.CK_MECHANISM_TYPE, nss_t.CK_MECHANISM_TYPE);
declare("PK11_PBEKeyGen",
        nss_t.PK11SymKey.ptr, nss_t.PK11SlotInfo.ptr, nss_t.SECAlgorithmID.ptr, nss_t.SECItem.ptr, nss_t.PRBool, ctypes.voidptr_t);
declare("SECITEM_AllocItem",
        nss_t.SECItem.ptr, nss_t.PLArenaPool.ptr, nss_t.SECItem.ptr, ctypes.unsigned_int);
declare("SECITEM_FreeItem",
        ctypes.void_t, nss_t.SECItem.ptr, nss_t.PRBool);
declare("PK11_FreeSymKey",
        ctypes.void_t, nss_t.PK11SymKey.ptr);
declare("PK11_CreateContextBySymKey",
        nss_t.PK11Context.ptr, nss_t.CK_MECHANISM_TYPE, nss_t.CK_ATTRIBUTE_TYPE, nss_t.PK11SymKey.ptr, nss_t.SECItem.ptr);
declare("PK11_DestroyContext",
        ctypes.void_t, nss_t.PK11Context.ptr, nss_t.PRBool);
declare("PK11_CipherOp",
        nss_t.SECStatus, nss_t.PK11Context.ptr, ctypes.unsigned_char.ptr, ctypes.int.ptr, ctypes.int, ctypes.unsigned_char.ptr, ctypes.int);
declare("PK11_ImportDERPrivateKeyInfoAndReturnKey",
        nss_t.SECStatus, nss_t.PK11SlotInfo.ptr, nss_t.SECItem.ptr, nss_t.SECItem.ptr, nss_t.SECItem.ptr, nss_t.PRBool, nss_t.PRBool, ctypes.unsigned_int, nss_t.SECKEYPrivateKey.ptr.ptr, ctypes.voidptr_t);
declare("SECKEY_ConvertToPublicKey",
        nss_t.SECKEYPublicKey.ptr, nss_t.SECKEYPrivateKey.ptr);
declare("SECKEY_EncodeDERSubjectPublicKeyInfo",
        nss_t.SECItem.ptr, nss_t.SECKEYPublicKey.ptr);
declare("SECKEY_DestroyPublicKey",
        ctypes.void_t, nss_t.SECKEYPublicKey.ptr);
declare("NSSBase64_EncodeItem",
        ctypes.char.ptr, nss_t.PRArenaPool.ptr, ctypes.char.ptr, ctypes.unsigned_int, nss_t.SECItem.ptr);

function SECCheck(aResult) {
  if (aResult != SECSuccess)
    throw Cr.NS_ERROR_FAILURE;
}

function iteratePrivKeys(aPrivKeyListPtr) {
  try {
    let list = aPrivKeyListPtr.contents.list.address();
    let nodePtr = aPrivKeyListPtr.contents.list.next;
    while (nodePtr.toString() != list.toString()) {
      let node = ctypes.cast(nodePtr, nss_t.SECKEYPrivateKeyListNode.ptr);
      yield node.contents.key;
      nodePtr = node.contents.links.next;
    }
  }
  finally {
    SECKEY_DestroyPrivateKeyList(aPrivKeyListPtr);
  }
}

function KeyPair(aPrivKeyPtr) {
  this.privKeyPtr = SECKEY_CopyPrivateKey(aPrivKeyPtr);
}

KeyPair.prototype = {
  privKeyPtr: null,

  getPublicKey: function() {
    let key = SECKEY_ConvertToPublicKey(this.privKeyPtr);
    if (key.isNull())
      throw Cr.NS_ERROR_FAILURE;
    return key;
  },

  get name() {
    if (!this.privKeyPtr)
      throw Cr.NS_ERROR_NOT_INITIALIZED;

    let namePtr = PK11_GetPrivateKeyNickname(this.privKeyPtr);
    let name = namePtr.readString();
    PORT_Free(namePtr);

    return name;
  },

  set name(aName) {
    if (!this.privKeyPtr)
      throw Cr.NS_ERROR_NOT_INITIALIZED;

    SECCheck(PK11_SetPrivateKeyNickname(this.privKeyPtr, aName));
  },

  get type() {
    if (!this.privKeyPtr)
      throw Cr.NS_ERROR_NOT_INITIALIZED;

    return SECKEY_GetPrivateKeyType(this.privKeyPtr);
  },

  exportPublicKey: function() {
    if (!this.privKeyPtr)
      throw Cr.NS_ERROR_NOT_INITIALIZED;

    let publicKey = this.getPublicKey();

    // DER Encode the public key
    let item = SECKEY_EncodeDERSubjectPublicKeyInfo(publicKey);
    SECKEY_DestroyPublicKey(publicKey);

    if (item.isNull())
      throw Cr.NS_ERROR_FAILURE;

    let data = NSSBase64_EncodeItem(null, null, 0, item);
    SECITEM_FreeItem(item, true);

    if (data.isNull())
      throw Cr.NS_ERROR_FAILURE;

    let result = data.readString().replace(/\s/g, "");
    PORT_Free(data);

    return result;
  },

  exportPrivateKey: function(aPassword) {
    if (!this.privKeyPtr)
      throw Cr.NS_ERROR_NOT_INITIALIZED;
    throw Cr.NS_ERROR_NOT_IMPLEMENTED;
  },

  signData: function(aData, aHashType) {
    if (!this.privKeyPtr)
      throw Cr.NS_ERROR_NOT_INITIALIZED;
    throw Cr.NS_ERROR_NOT_IMPLEMENTED;
  },

  verifyData: function(aData, aSignature) {
    if (!this.privKeyPtr)
      throw Cr.NS_ERROR_NOT_INITIALIZED;
    throw Cr.NS_ERROR_NOT_IMPLEMENTED;
  },

  delete: function() {
    SECCheck(PK11_DeleteTokenPrivateKey(this.privKeyPtr, false));
    this.privKeyPtr = null;
  },

  QueryInterface: XPCOMUtils.generateQI([Ci.nsIKeyPair])
};

function KeyService() {
  // Bring up psm
  let nss = Cc["@mozilla.org/psm;1"].getService();

  PK11_SetPasswordFunc(nss_t.PK11PasswordFunc.ptr(this.getPassword, this));

  let slot = PK11_GetInternalKeySlot();
  if (!slot.isNull())
    this.slot = slot;
}

KeyService.prototype = {
  slot: null,
  prompter: null,
  passAttempts: null,

  getPassword: function(aSlot, aRetry, aCtx) {
    if (aRetry)
      this.passAttempts++;
    else
      this.passAttempts = 1;

    // Called by nss when one of the operations needs to log in to the slot
    if (!this.prompter) {
      this.prompter = Cc["@toolkit.mozilla.org/passwordprompt;1"].
                      getService(Ci.nsIPasswordPrompt);
    }

    let password = this.prompter.getPassword(this.passAttempts);
    if (!password)
      return null;

    return PORT_Strdup(password);
  },

  ensureSlotInitialised: function() {
    if (PK11_NeedUserInit(this.slot)) {
      if (!this.prompter) {
        this.prompter = Cc["@toolkit.mozilla.org/passwordprompt;1"].
                        getService(Ci.nsIPasswordPrompt);
      }

      let password = this.prompter.createPassword();
      if (!password)
        throw Cr.NS_ERROR_FAILURE;

      SECCheck(PK11_InitPin(this.slot, "", password));
    }
  },

  login: function() {
    this.ensureSlotInitialised();

    if (PK11_NeedLogin(this.slot))
      SECCheck(PK11_Authenticate(this.slot, true, null));
  },

  logout: function() {
    SECCheck(PK11_Logout(this.slot));
  },

  changePassword: function(aOldPassword, aNewPassword) {
    SECCheck(PK11_ChangePW(this.slot, aOldPassword, aNewPassword));
  },

  setPasswordPrompt: function(aPrompt) {
    this.prompter = aPrompt;
  },

  enumerateKeys: function() {
    var keys = [];

    if (!PK11_NeedUserInit(this.slot)) {
      this.login();

      let list = PK11_ListPrivKeysInSlot(this.slot, null, null);
      if (!list.isNull()) {
        for (let keyPtr in iteratePrivKeys(list))
          keys.push(new KeyPair(keyPtr));
      }
    }

    return {
      pos: 0,

      hasMoreElements: function() {
        return this.pos < keys.length;
      },

      getNext: function() {
        return keys[this.pos++];
      }
    };
  },

  createKeyPair: function(aKeyType) {
    var rsaparams, mechanism, params;

    // Initialize parameters based on key type
    switch (aKeyType) {
    case Ci.nsIKeyPair.KEYTYPE_RSA:
        rsaparams = new nss_t.PK11RSAGenParams(); // WHAT?
        rsaparams.keySizeInBits = 1024;
        rsaparams.pe = 0x010001;
        mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        params = rsaparams.address();
        break;
    case Ci.nsIKeyPair.KEYTYPE_DSA:
        // Right now DSA can't be handled correctly
        return NS_ERROR_INVALID_ARG;
        break;
    default:
        return NS_ERROR_INVALID_ARG;
    }

    this.login();

    // Create the key
    let pubKeyPtr = new nss_t.SECKEYPublicKey.ptr();
    let privKeyPtr = PK11_GenerateKeyPair(this.slot, mechanism, params,
                                          pubKeyPtr.address(), true, true, null);
    if (privKeyPtr.isNull())
      throw Cr.NS_ERROR_FAILURE;
    SECKEY_DestroyPublicKey(pubKeyPtr);

    // Pass on to a KeyPair
    let key = new KeyPair(privKeyPtr);
    SECKEY_DestroyPrivateKey(privKeyPtr);

    return key;
  },

  importPrivateKey: function(aData, aPassword, aTemporary) {
    // First find the PEM data in the string and make sure it is the right type
    let start = aData.indexOf("-----BEGIN ");
    if (start < 0)
      throw Cr.NS_ERROR_ILLEGAL_VALUE;
    start += 11;

    let end = aData.indexOf("-----", start);
    if (end < 0)
      throw Cr.NS_ERROR_ILLEGAL_VALUE;

    let type = aData.substring(start, end);
    if (type != "ENCRYPTED PRIVATE KEY")
      throw Cr.NS_ERROR_ILLEGAL_VALUE;

    start = end + 5;
    end = aData.indexOf("-----END", start);
    if (end < 0)
      throw Cr.NS_ERROR_ILLEGAL_VALUE;

    let pem = aData.substring(start, end);
    let arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

    try {
      // Decode it
      let rawdata = NSSBase64_DecodeBuffer(arena, null, pem, pem.length);
      if (rawdata.isNull())
        throw Cr.NS_ERROR_FAILURE;

      let epki = PORT_ArenaZNew(arena, nss_t.SECKEYEncryptedPrivateKeyInfo);
      if (epki.isNull())
        throw Cr.NS_ERROR_FAILURE;

      SECCheck(SEC_ASN1DecodeItem(arena, epki, tmpl.SECKEY_EncryptedPrivateKeyInfoTemplate,
                                  rawdata));

      let password = ctypes.char.array()(aPassword);

      let pwitem = new nss_t.SECItem();
      pwitem.type = siUTF8String;
      pwitem.data = ctypes.cast(password.addressOfElement(0), ctypes.unsigned_char.ptr);
      pwitem.len = aPassword.length;

      // Decrypt the key into derPKI
      let cryptoParam = new nss_t.SECItem.ptr();
      let cryptoMechType = PK11_GetPBECryptoMechanism(epki.contents.algorithm.address(), cryptoParam.address(), pwitem.address());
      if (cryptoMechType == CKM_INVALID_MECHANISM)
        throw Cr.NS_ERROR_FAILURE;

      let derPKI = null;

      try {
        let cryptoMech = new nss_t.CK_MECHANISM();
        cryptoMech.mechanism = PK11_GetPadMechanism(cryptoMechType);
        cryptoMech.pParameter = !cryptoParam.isNull() ? cryptoParam.contents.data : null;
        cryptoMech.ulParameterLen = !cryptoParam.isNull() ? cryptoParam.contents.len : 0;

        let symKey = PK11_PBEKeyGen(this.slot, epki.contents.algorithm.address(), pwitem.address(), false, null);
        if (symKey.isNull())
          throw Cr.NS_ERROR_FAILURE;

        try {
          let ctx = PK11_CreateContextBySymKey(cryptoMechType, CKA_DECRYPT, symKey, cryptoParam);
          if (ctx.isNull())
            throw Cr.NS_ERROR_FAILURE;

          try {
            derPKI = SECITEM_AllocItem(arena, null, epki.contents.encryptedData.len);

            SECCheck(PK11_CipherOp(ctx, derPKI.contents.data, derPKI.contents.addressOfField("len"),
                                   derPKI.contents.len, epki.contents.encryptedData.data, epki.contents.encryptedData.len));
          }
          finally {
            PK11_DestroyContext(ctx, true);
          }
        }
        finally {
          PK11_FreeSymKey(symKey);
        }
      }
      finally {
        SECITEM_FreeItem(cryptoParam, true);
      }

      let privKeyPtr = new nss_t.SECKEYPrivateKey.ptr();
      // XXX fails if the key already exists due to bug 436417
      SECCheck(PK11_ImportDERPrivateKeyInfoAndReturnKey(this.slot, derPKI, null, null,
                                                       !aTemporary, false,
                                                       KU_DATA_ENCIPHERMENT | KU_DIGITAL_SIGNATURE,
                                                       privKeyPtr.address(), null));
      let key = new KeyPair(privKeyPtr);
      SECKEY_DestroyPrivateKey(privKeyPtr);
      return key;
    }
    finally {
      PORT_FreeArena(arena, false);
    }
  },

  classID: Components.ID("{d38c73d6-b388-45d9-a980-640c665d7b21}"),
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIKeyService])
};

const NSGetFactory = XPCOMUtils.generateNSGetFactory([KeyService]);
