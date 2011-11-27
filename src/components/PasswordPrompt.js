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
# Portions created by the Initial Developer are Copyright (C) 2008
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

function PasswordPrompt() {
}

PasswordPrompt.prototype = {
  createPassword: function() {
    var params = Cc["@mozilla.org/embedcomp/dialogparam;1"].
                 createInstance(Ci.nsIDialogParamBlock);
    params.SetInt(0, 0);
    params.SetNumberStrings(1);
    var ww = Cc["@mozilla.org/embedcomp/window-watcher;1"].
             getService(Ci.nsIWindowWatcher);
    ww.openWindow(null, "chrome://mccoy/content/changepw.xul", "",
                  "chrome,centerscreen,modal,dialog,titlebar", params);
    if (params.GetInt(0) == 1)
      return params.GetString(0);
    return null;
  },

  getPassword: function(attempt) {
    var sbs = Cc["@mozilla.org/intl/stringbundle;1"].
              getService(Ci.nsIStringBundleService);
    var strings = sbs.createBundle("chrome://mccoy/locale/passwords.properties");
    var ww = Cc["@mozilla.org/embedcomp/window-watcher;1"].
             getService(Ci.nsIWindowWatcher);
    var prompt = ww.getNewPrompter(null);
    var pass = { value: "" };
    if (prompt.promptPassword(strings.GetStringFromName("getpassword.title"),
                              strings.GetStringFromName("getpassword.description"),
                              pass, null, {}))
      return pass.value;
    return null;
  },

  classDescription: "McCoy Password Prompt Service",
  contractID: "@toolkit.mozilla.org/passwordprompt;1",
  classID: Components.ID("{06958b62-9c20-4878-b6af-3ebbf460ccd7}"),
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIPasswordPrompt])
};

function NSGetModule(compMgr, fileSpec)
  XPCOMUtils.generateModule([PasswordPrompt]);
