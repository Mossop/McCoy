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

const XULNS = "http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul";
const Cc = Components.classes;
const Ci = Components.interfaces;

var gKS = null;
var gList = null;
var gStrings = null;

function EM_NS(prop)
{
  return gRDF.GetResource(PREFIX_NS_EM + prop);
}

var mainController = {
  supportsCommand: function(cmd)
  {
    switch (cmd) {
      case "cmd_changepassword":
      case "cmd_createkey":
      case "cmd_renamekey":
      case "cmd_deletekey":
      case "cmd_copypublic":
        return true;
    }
    return false;
  },
  
  isCommandEnabled: function(cmd)
  {
    switch (cmd) {
      case "cmd_changepassword":
      case "cmd_createkey":
        return true;
      case "cmd_renamekey":
      case "cmd_deletekey":
      case "cmd_copypublic":
        return gList.selectedIndex>=0;
    }
    return false;
  },
  
  doCommand: function(cmd)
  {
    if (this.isCommandEnabled(cmd)) {
      switch (cmd) {
        case "cmd_changepassword":
          gKS.changePassword();
          break;
        case "cmd_createkey":
          var promptSvc = Cc["@mozilla.org/embedcomp/prompt-service;1"].
                          getService(Ci.nsIPromptService);
          var name = { value: "" };
          var title = gStrings.getString("createkey.title");
          var text = gStrings.getString("createkey.text");
          if (promptSvc.prompt(window, title, text, name, null, {})) {
            if (name.value) {
              var key = gKS.createKeyPair(Ci.nsIKeyPair.KEYTYPE_RSA);
              key.name = name.value;
              var item = createItem(key);
              insertItem(item);
              gList.selectedItem = item;
            }
            else {
              alert(gStrings.getString("createkey.noname"));
            }
          }
          break;
        case "cmd_renamekey":
          var promptSvc = Cc["@mozilla.org/embedcomp/prompt-service;1"].
                          getService(Ci.nsIPromptService);
          var name = { value: gList.selectedItem.key.name };
          var title = gStrings.getString("renamekey.title");
          var text = gStrings.getString("renamekey.text");
          if (promptSvc.prompt(window, title, text, name, null, {})) {
            var item = gList.selectedItem;
            item.key.name=name.value;
            item.setAttribute("label", name.value);
            insertItem(item);
            gList.selectedItem = item;
          }
          break;
        case "cmd_deletekey":
          var promptSvc = Cc["@mozilla.org/embedcomp/prompt-service;1"].
                          getService(Ci.nsIPromptService);
          var title = gStrings.getString("deletekey.title");
          var text = gStrings.getString("deletekey.text");
          if (promptSvc.confirm(window, title, text)) {
            gList.selectedItem.key.delete();
            gList.removeChild(gList.selectedItem);
          }
          break;
        case "cmd_copypublic":
          var clipboard = Cc["@mozilla.org/widget/clipboardhelper;1"].
                          getService(Ci.nsIClipboardHelper);
          clipboard.copyString(gList.selectedItem.key.exportPublicKey());
          break;
      }
    }
  },
  
  /**
   * Updates all of the commands in the commandset
   */
  onCommandUpdate: function()
  {
    var commands = document.getElementById("mainCommands")
                           .getElementsByTagName("command");
    for (var i = 0; i < commands.length; i++)
      goSetCommandEnabled(commands[i].id, this.isCommandEnabled(commands[i].id));
  },
  
  onEvent: function(evt) { }
}

/**
 * Creates a richlistboxitem for the key.
 * @param key an nsIKeyPair
 * @returns a richlistitem element
 */
function createItem(key)
{
  var item = document.createElementNS(XULNS, "richlistitem");
  item.setAttribute("label", key.name);
  switch (key.type)
  {
    case Ci.nsIKeyPair.KEYTYPE_RSA:
      item.setAttribute("type", "RSA");
      break;
    case Ci.nsIKeyPair.KEYTYPE_DSA:
      item.setAttribute("type", "DSA");
      break;
  }
  item.setAttribute("context", "menu-keycontext");
  item.key = key;
  return item;
}

/**
 * Inserts a key richlistitem into the list in the appropriate place
 * @param item the richlistitem to be inserted
 */
function insertItem(item)
{
  var name = item.key.name.toLowerCase();
  var items = gList.children;

  for (var i = 0; i < items.length; i++) {
    // Might be moving an item, skip over ourself
    if (items[i] == item)
      continue;
    
    // This matches the insertion point
    if (items[i].key.name.toLowerCase() > name) {
      gList.insertBefore(item, items[i]);
      return;
    }
  }
  // Nothing later found, put at the end
  gList.appendChild(item);
}

/**
 * Refreshes the list of keys in the listbox.
 */
function readKeys()
{
  // Clear out any exiting list
  while (gList.lastChild)
    gList.removeChild(gList.lastChild);

  var keyObjects = {};
  var keyNames = [];
  
  // Update the key hashes
  var keys = gKS.enumerateKeys();
  while (keys.hasMoreElements()) {
    var key = keys.getNext().QueryInterface(Ci.nsIKeyPair);
    var name = key.name.toLowerCase();
    keyObjects[name] = key;
    keyNames.push(name);
  }
  keyNames.sort();
  
  // Generate the list
  for (var i = 0; i < keyNames.length; i++) {
    key = keyObjects[keyNames[i]];
    var item = createItem(key);
    gList.appendChild(item);
  }
}

/**
 * Initialise the window
 */
function startup()
{
  try {
    gKS = Cc["@toolkit.mozilla.org/keyservice;1"].
          getService(Ci.nsIKeyService);
  }
  catch (e) {
    // Chances are the user cancelled the password dialog
  }
  
  gList = document.getElementById("keylist");
  gStrings = document.getElementById("strings");
  
  window.controllers.appendController(mainController);
  mainController.onCommandUpdate();

  // Build the initial key list
  readKeys();
}
