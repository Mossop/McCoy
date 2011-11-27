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
 * Portions created by the Initial Developer are Copyright (C) 2008
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

const Cc = Components.classes;
const Ci = Components.interfaces;

var isChange = true;
var params;
var strings;

function startup()
{
  strings = document.getElementById("strings");
  if (window.arguments.length == 1 &&
      window.arguments[0] instanceof Ci.nsIDialogParamBlock) {
    params = window.arguments[0];
    isChange = false;
  }

  window.title = strings.getString(isChange ? "changepassword.title" : "setpassword.title");
  document.getElementById("oldpassrow").hidden = !isChange;
  document.getElementById("changepw-desc").hidden = !isChange;
  document.getElementById("setpw-desc").hidden = isChange;
  document.documentElement.getButton("cancel").hidden = !isChange;
}

function accept() {
  var pass = document.getElementById("newpass1").value;

  if (isChange) {
    var ks = Cc["@toolkit.mozilla.org/keyservice;1"].
             getService(Ci.nsIKeyService);
    try {
      ks.changePassword(document.getElementById("oldpass").value, pass);
      return true;
    }
    catch (e) {
      alert(strings.getString("wrongpassword"));
      return false;
    }
  }
  else {
    params.SetInt(0, 1);
    params.SetString(0, pass);
  }
}

function checkPasswords() {
  var button = document.documentElement.getButton("accept");

  button.disabled = document.getElementById("newpass1").value !=
                    document.getElementById("newpass2").value;
}

function setPasswordStrength()
{
  // Here is how we weigh the quality of the password
  // number of characters
  // numbers
  // non-alpha-numeric chars
  // upper and lower case characters

  var pw = document.getElementById('newpass1').value;

  //length of the password
  var pwlength = pw.length;
  if (pwlength > 5)
    pwlength = 5;

  //use of numbers in the password
  var numnumeric = pw.replace (/[0-9]/g, "");
  var numeric = pw.length - numnumeric.length;
  if (numeric > 3)
    numeric = 3;

  //use of symbols in the password
  var symbols = pw.replace (/\W/g, "");
  var numsymbols = pw.length - symbols.length;
  if (numsymbols > 3)
    numsymbols = 3;

  //use of uppercase in the password
  var numupper = pw.replace (/[A-Z]/g, "");
  var upper = pw.length - numupper.length;
  if (upper > 3)
    upper = 3;


  var pwstrength=((pwlength * 10) - 20) + (numeric * 10) +
                 (numsymbols * 15) + (upper * 10);

  // make sure we're give a value between 0 and 100
  if (pwstrength < 0)
    pwstrength = 0;
  
  if (pwstrength > 100)
    pwstrength = 100;

  var mymeter = document.getElementById('pwmeter');
  mymeter.setAttribute("value",pwstrength);

  return;
}
