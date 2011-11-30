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
Components.utils.import("resource://gre/modules/FileUtils.jsm");
Components.utils.import("resource://gre/modules/Services.jsm");

/**
 * Convert a string containing binary values to hex.
 */
function binaryToHex(input) {
  var result = "";
  for (var i = 0; i < input.length; ++i) {
    var hex = input.charCodeAt(i).toString(16);
    if (hex.length == 1)
      hex = "0" + hex;
    result += hex;
  }
  return result;
}

function PasswordPrompt(password) {
  this.password = password;
}

PasswordPrompt.prototype = {
  password: null,

  createPassword: function() {
    return null;
  },

  getPassword: function(attempt) {
    if (attempt > 1)
      return null;
    return this.password;
  },

  QueryInterface: XPCOMUtils.generateQI([Ci.nsIPasswordPrompt])
};

function display(aText) {
  if (Services.appinfo.OS == "WINNT") {
    Services.prompt.alert(null, "McCoy", aText);
  }
  else {
    dump(aText);
  }
}

var File = Components.Constructor("@mozilla.org/file/local;1", Ci.nsILocalFile, "initWithPath");

/**
 * Attempts to get the absolute nsIFile for a passed in path
 */
function resolveFile(aPath) {
  if (Services.appinfo.OS == "WINNT") {
    aPath = aPath.replace("/", "\\", "g");
    if (aPath[1] == ":")
      return new File(aPath);
    if (aPath[0] == "\\")
      return null; // TODO
    aPath = aPath.replace("\\", "/", "g");
  }
  else {
    if (aPath[0] == "/")
      return new File(aPath);
  }

  return FileUtil.getDir("CurWorkD", aPath.split("/"));
}

/**
 * Consumes the -n, -k and -pass command line arguments in order to return
 * an nsIKeyPair. Returns null if no key was found.
 */
function getKeyFromCommandLine(commandLine) {
  var name = commandLine.handleFlagWithParam("n", false);
  if (!name)
    name = commandLine.handleFlagWithParam("name", false);
  var file = commandLine.handleFlagWithParam("k", false);
  if (!file)
    file = commandLine.handleFlagWithParam("key", false);
  var pass = commandLine.handleFlagWithParam("pass", false);
  if (file && name) {
    display("You cannot give both -n and -k on the command line\n");
    throw Cr.NS_ERROR_INVALID_ARG;
  }
  if (!file && !name)
    return null;

  var ks = Cc["@toolkit.mozilla.org/keyservice;1"].
           getService(Ci.nsIKeyService);
  if (file) {
    file = resolveFile(file);
    if (!file.exists()) {
      display("File " + file.path + " not found.\n");
      throw Cr.NS_ERROR_INVALID_ARG;
    }
    var istream = Cc["@mozilla.org/network/file-input-stream;1"].
                  createInstance(Ci.nsIFileInputStream);
    istream.init(file, 0x01, 0444, 0);
    istream.QueryInterface(Ci.nsILineInputStream);
    var data = "";
    var line = {};
    do {
      var hasmore = istream.readLine(line);
      data += line.value + "\n";
    } while (hasmore);
    istream.close();
    return ks.importPrivateKey(data, pass, true);
  }
  else {
    ks.setPasswordPrompt(new PasswordPrompt(pass));
    var keys = ks.enumerateKeys();
    ks.setPasswordPrompt(null);
    while (keys.hasMoreElements()) {
      var key = keys.getNext().QueryInterface(Ci.nsIKeyPair);
      if (key.name == name)
        return key;
    }
  }

  return null;
}

function TaskHandler() {
}

TaskHandler.prototype = {
  tasks: {
    "install-key": {
      summary: "Add an update key to an install manifest",
      help: "Usage: mccoy install-key [-n <name> | -k <file>] [options] <install rdf>\n\n" +
            "  -n -name <name>       The name of the key to add to the manifest.\n" +
            "  -k -key <file>        A PEM encoded private key to add to the manifest.\n" +
            "  -pass <password>      The password to access keys or to decrypt a key file\n" +
            "                        given by -k.\n" +
            "  -o -out <file>        select output file, otherwise overwrite the input file\n",
      handle: function(commandLine) {
        var key = getKeyFromCommandLine(commandLine);
        if (!key) {
          display("You must use either -n or -k arguments to choose a key to add.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        var outfile = commandLine.handleFlagWithParam("o", false);
        if (!outfile)
          outfile = commandLine.handleFlagWithParam("out", false);

        if (commandLine.length != 1) {
          display("You must give a single install rdf file to add the key to.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        var file = resolveFile(commandLine.getArgument(0));
        if (!file.exists()) {
          display("File " + file.path + " not found.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        if (outfile) {
          outfile = resolveFile(outfile);
        }
        else {
          outfile = file;
        }

        Components.utils.import("resource:///modules/Manifests.jsm");

        var install = InstallManifestFactory.loadFromFile(file);
        install.updateKey = key.exportPublicKey();
        install.saveToFile(outfile);
      }
    },
    "sign-update": {
      summary: "Sign an update manifest",
      help: "Usage: mccoy sign-update [-n <name> | -k <file>] [options] <update rdf>\n\n" +
            "  -n -name <name>       The name of the key to use for signing.\n" +
            "  -k -key <file>        A PEM encoded private key to use for signing.\n" +
            "  -pass <password>      The password to access keys or to decrypt a key file\n" +
            "                        given by -k.\n" +
            "  -id <id>              Only sign the updates for the extension with the\n" +
            "                        given id, otherwise will sign updates for all\n" +
            "                        extensions in the file.\n" +
            "  -o -out <file>        select output file, otherwise overwrite the input file\n",
      handle: function(commandLine) {
        var key = getKeyFromCommandLine(commandLine);
        if (!key) {
          display("You must use either -n or -k arguments to choose a key to sign with.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        var id = commandLine.handleFlagWithParam("id", false);
        var outfile = commandLine.handleFlagWithParam("o", false);
        if (!outfile)
          outfile = commandLine.handleFlagWithParam("out", false);

        if (commandLine.length != 1) {
          display("You must give a single update rdf file to sign.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        var file = resolveFile(commandLine.getArgument(0));
        if (!file.exists()) {
          display("File " + file.path + " not found.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        if (outfile) {
          outfile = resolveFile(outfile);
        }
        else {
          outfile = file;
        }

        Components.utils.import("resource:///modules/Manifests.jsm");

        var update = UpdateManifestFactory.loadFromFile(file);
        if (id) {
          var manifest = update.getManifestForID(id);
          if (!manifest) {
            display("Update manifest does not contain information about add-on " + id + ".\n");
            throw Cr.NS_ERROR_INVALID_ARG;
          }
          manifest.signData(key);
        }
        else {
          manifests = update.getAllManifests();
          for (var i = 0; i < manifests.length; i++)
            manifests[i].signData(key);
        }

        update.saveToFile(outfile);
      }
    },
    "hash": {
      summary: "Output a cryptographic hash for a file",
      help: "Usage: mccoy hash [options] <file>\n\n" +
            "  -a -alg <alg>         Hash using the given algorithm. The default is\n" +
            "                        sha512.\n",
      handle: function(commandLine) {
        var alg = commandLine.handleFlagWithParam("a", false);
        if (!alg)
          alg = commandLine.handleFlagWithParam("alg", false);
        if (!alg)
          alg = "sha512";
        if (commandLine.length != 1) {
          display("You must give a file to hash.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        var file = resolveFile(commandLine.getArgument(0));
        if (!file.exists()) {
          display("File " + file.path + " not found.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }
        if (!file.isFile()) {
          display(file.path + " is not a file.\n");
          throw Cr.NS_ERROR_INVALID_ARG;
        }

        var hasher = Cc["@mozilla.org/security/hash;1"].
                     createInstance(Ci.nsICryptoHash);
        hasher.initWithString(alg);
        var fis = Cc["@mozilla.org/network/file-input-stream;1"].
                  createInstance(Ci.nsIFileInputStream);
        fis.init(file, -1, -1, false);
        hasher.updateFromStream(fis, -1);
        dump(alg.toLowerCase() + ":" + binaryToHex(hasher.finish(false)) + "\n");
        fis.close();
      }
    }
  },

  handle: function(commandLine) {
    var task = null;

    // OSX may pass this (as does the test) so ignore it.
    commandLine.handleFlag("foreground", false);

    var help = commandLine.handleFlag("taskhelp", false);
    if (commandLine.length > 0) {
      var command = commandLine.getArgument(0);
      if (command in this.tasks) {
        task = this.tasks[command];
        commandLine.removeArguments(0, 0);
      }
    }

    if (help) {
      commandLine.preventDefault = true;
      if (task) {
        display(task.help);
      }
      else {
        let helptext = "Usage: mccoy <task> [options]\n" +
                       "       mccoy -taskhelp <task>\n\n" +
                       "Available tasks:\n\n";
        for (var task in this.tasks) {
          helptext += "  " + task;
          var pos = task.length + 2;
          while (pos < 24) {
            helptext += " ";
            pos++;
          }
          helptext += this.tasks[task].summary + "\n";
        }
        display(helptext);
      }
    }
    else if (task) {
      commandLine.preventDefault = true;
      try {
        task.handle(commandLine);
      }
      catch (e) {
        if (e == Cr.NS_ERROR_INVALID_ARG)
          // thrown by js code
          display(task.help);
        else if (e.result == Cr.NS_ERROR_INVALID_ARG)
          // thrown by xpcom (handleFlagWithParam)
          display("Invalid arguments\n" + task.help);
        else
          // unknown error
          display("Error performing task: " + e + "\n");
      }
    }
  },

  // XULRunner app command line handlers can't output help :(
  helpInfo: "",

  classID: Components.ID("{fa2e87fa-d48d-4ff1-9b55-e9c9fb824710}"),
  QueryInterface: XPCOMUtils.generateQI([Ci.nsICommandLineHandler])
};

const NSGetFactory = XPCOMUtils.generateNSGetFactory([TaskHandler]);
