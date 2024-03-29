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

Components.utils.import("resource:///modules/Manifests.jsm");

var gManifest = null;
var gPublicKey = null;

function getString(key) {
  return document.getElementById("strings").getString(key);
}

function selectAddon() {
  document.getElementById("addon").disabled = false;
  document.getElementById("key").disabled = true;
  addonChosen();
}

function selectKey() {
  document.getElementById("key").disabled = false;
  document.getElementById("addon").disabled = true;
  keyChosen();
}

function addonChosen() {
  var file = document.getElementById("addon").file;
  if (file && file.exists()) {
    try {
      var manifest = InstallManifestFactory.loadFromFile(file);
      gPublicKey = manifest.updateKey;
      if (gPublicKey) {
        document.getElementById("file").disabled = false;
        fileChosen();
        return;
      }
      else {
        alert(getString("verifysign.missingupdatekey"));
      }
    }
    catch (e) {
      Components.utils.reportError("Error loading install manifest: " + e);
      alert(getString("verifysign.invalidaddonrdf"));
    }
  }
  gPublicKey = null;
  document.getElementById("file").disabled = true;
  document.getElementById("check").disabled = true;
}

function keyChosen() {
  if (document.getElementById("key").key) {
    gPublicKey = document.getElementById("key").key.exportPublicKey();
    document.getElementById("file").disabled = false;
    fileChosen();
  }
  else {
    gPublicKey = null;
    document.getElementById("file").disabled = true;
    document.getElementById("check").disabled = true;
  }
}

function fileChosen() {
  var file = document.getElementById("file").file;
  if (file && file.exists()) {
    try {
      gManifest = UpdateManifestFactory.loadFromFile(file);
      var manifests = gManifest.getAllManifests();
      for (var i = 0; i < manifests.length; i++) {
        if (!manifests[i].signature) {
          alert(getString("verifysign.unsigned"));
          document.getElementById("check").disabled = true;
          return;
        }
      }
      document.getElementById("check").disabled = false;
      return;
    }
    catch (e) {
      Components.utils.reportError("Error loading update manifest: " + e);
      alert(getString("verifysign.invalidupdaterdf"));
    }
  }
  document.getElementById("check").disabled = true;
}

function check() {
  var manifests = gManifest.getAllManifests();
  for (var i = 0; i < manifests.length; i++) {
    if (!manifests[i].verifyData(gPublicKey)) {
      document.getElementById("panes").selectedIndex = 2;
      return;
    }
  }
  document.getElementById("panes").selectedIndex = 1;
}
