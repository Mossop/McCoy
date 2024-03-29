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

function getString(key) {
  return document.getElementById("strings").getString(key);
}

function getMainString(key) {
  return document.getElementById("mainStrings").getString(key);
}

function fileChosen() {
  var file = document.getElementById("file").file;
  if (file && file.exists()) {
    try {
      gManifest = UpdateManifestFactory.loadFromFile(file);
      document.getElementById("key").disabled = false;
      keyChosen();
      return;
    }
    catch (e) {
      Components.utils.reportError("Error loading update manifest: " + e);
      alert(getString("sign.invalidrdf"));
    }
  }
  document.getElementById("key").disabled = true;
  document.getElementById("save").disabled = false;
}

function keyChosen() {
  if (document.getElementById("key").key)
    document.getElementById("save").disabled = false;
}

function save() {
  var file = document.getElementById("file").file;

  var fp = Cc["@mozilla.org/filepicker;1"].
           createInstance(Ci.nsIFilePicker);
  fp.init(window, getString("sign.save.title"), Ci.nsIFilePicker.modeSave);

  fp.appendFilter(getMainString("filepicker.type.rdf"), "*.rdf");
  fp.appendFilters(Ci.nsIFilePicker.filterAll);
  fp.filterIndex = 0;
  if (file) {
    fp.displayDirectory = file.parent;
    fp.defaultString = file.leafName;
  }

  if (fp.show() != Ci.nsIFilePicker.returnCancel) {
    var key = document.getElementById("key").key;
    var manifests = gManifest.getAllManifests();
    for (var i = 0; i < manifests.length; i++)
      manifests[i].signData(key);
    gManifest.saveToFile(fp.file);
    document.getElementById("panes").selectedIndex = 1;
  }
}
