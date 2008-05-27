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

const HELP_URL          = "http://developer.mozilla.org/en/docs/McCoy";
const INTRO_URL         = "chrome://mccoy/content/intro.xul";

// If a window with the type exists just focus it otherwise open a new window
function openWindowForType(type, uri, features) {
  var topWindow = Cc['@mozilla.org/appshell/window-mediator;1'].
                  getService(Ci.nsIWindowMediator).
                  getMostRecentWindow(type);

  if (topWindow)
    topWindow.focus();
  else if (features)
    window.open(uri, "_blank", features);
  else
    window.open(uri, "_blank", "chrome,extrachrome,menubar,resizable,scrollbars,status,toolbar");
}

function openKeyManager() {
  var ks = Cc["@toolkit.mozilla.org/keyservice;1"].
           getService(Ci.nsIKeyService);
  try {
    ks.login();
    openWindowForType("McCoy:KeyManager", "chrome://mccoy/content/keymanager.xul");
  }
  catch (e) {
    // Login throws if the user cancelled the log in
  }
}

function openAddons() {
  openWindowForType("Extension:Manager",
                    "chrome://mozapps/content/extensions/extensions.xul");
}

function openErrorConsole() {
  openWindowForType("global:console", "chrome://global/content/console.xul");
}

function openDOMInspector() {
  window.openDialog("chrome://inspector/content/", "_blank",
                    "chrome,all,dialog=no", document);
}

function openAbout() {
  openWindowForType("McCoy:About", "chrome://mccoy/content/about.xul",
                    "chrome,dialog,centerscreen");
}

function openHelp() {
  openURL(HELP_URL);
}

/**
 * Checks whether navigating away from the currently displayed task is
 * allowed.
 */
function canChangeTask() {
  return true;
}

function changeTask(id) {
  var display = document.getElementById("taskDisplay");
  var task = document.getElementById(id);
  if (display.getAttribute("src") == task.getAttribute("href"))
    return;

  if (!canChangeTask())
    return;

  var selector = document.getElementById("paneSelector");
  var lists = document.getElementById("taskLists");
  lists.selectedPanel = task.parentNode;
  selector.selectedIndex = lists.selectedIndex;
  task.parentNode.selectedItem = task;
  display.setAttribute("src", task.getAttribute("href"));
}

function paneSelected(event) {
  if (event.target.localName != "radio")
    return;

  var selector = document.getElementById("paneSelector");
  var lists = document.getElementById("taskLists");
  var newIndex = selector.selectedIndex;
  if (lists.selectedIndex == newIndex)
    return;

  if (canChangeTask()) {
    lists.selectedIndex = newIndex;
    lists.selectedPanel.selectedIndex = -1;
    document.getElementById("taskDisplay").setAttribute("src", INTRO_URL);
  }
  else {
    selector.selectedIndex = lists.selectedIndex;
  }
}

function taskSelected(event) {
  if (event.target.localName != "radio")
    return;

  var display = document.getElementById("taskDisplay");
  if (display.getAttribute("src") == event.target.getAttribute("href"))
    return;

  if (canChangeTask()) {
    display.setAttribute("src", event.target.getAttribute("href"));
  }
  else {
    // XXX revert the change
  }
}

/**
 * Initialise the window
 */
function startup() {
  document.getElementById("taskLists").selectedPanel.selectedIndex = -1;
}
