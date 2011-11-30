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

Components.utils.import("resource:///modules/UpdateDataSerializer.jsm");
Components.utils.import("resource:///modules/RDFDataSource.jsm");

const PREFIX_NS_EM                    = "http://www.mozilla.org/2004/em-rdf#";
const PREFIX_ITEM_URI                 = "urn:mozilla:item:";
const PREFIX_EXTENSION                = "urn:mozilla:extension:";
const PREFIX_THEME                    = "urn:mozilla:theme:";
const RDFURI_INSTALL_MANIFEST_ROOT    = "urn:mozilla:install-manifest";
const RDFURI_ITEM_ROOT                = "urn:mozilla:item:root";

var EXPORTED_SYMBOLS = ["InstallManifestFactory", "UpdateManifestFactory"];

var gRDF = Cc["@mozilla.org/rdf/rdf-service;1"].
           getService(Ci.nsIRDFService);
var gIDTest = /^(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}|[a-z0-9-\._]*\@[a-z0-9-\._]+)$/i;

function EM_R(property) {
  return PREFIX_NS_EM + property;
}

/**
 * This represents the full install manifest for an add-on.
 */
function RDFInstallManifest(datasource) {
  this._datasource = datasource;
  this._manifest = this._datasource.getResource(RDFURI_INSTALL_MANIFEST_ROOT);
}

RDFInstallManifest.prototype = {
  get id() {
    return this._getStringProperty("id");
  },

  get version() {
    return this._getStringProperty("version");
  },

  get updateKey() {
    return this._getStringProperty("updateKey");
  },

  set updateKey(val) {
    this._setStringProperty("updateKey", val);
  },

  _datasource: null,

  _getStringProperty: function(property) {
    var prop = this._manifest.getProperty(EM_R(property));
    return prop ? prop.getValue() : null;
  },

  _setStringProperty: function(property, value) {
    this._manifest.setProperty(EM_R(property), new RDFLiteral(value));
  },

  saveToFile: function(file) {
    this._datasource.saveToFile(file);
  }
};

/**
 * This represents the part of the update manifest that is relevant for a single add-on
 */
function AddonUpdateManifest(id, datasource, resource) {
  this._id = id;
  this._resource = resource;
  this._datasource = datasource;
}

AddonUpdateManifest.prototype = {
  _id: null,
  _resource: null,
  _datasource: null,
  
  get id() {
    return this._id;
  },

  get signature() {
    var prop = this._resource.getProperty(EM_R("signature"));
    return prop ? prop.getValue() : null;
  },

  set signature(val) {
    this._resource.setProperty(EM_R("signature"), new RDFLiteral(val));
  },

  verifyData: function(publicKey) {
    var ioService = Cc["@mozilla.org/network/io-service;1"].
                    getService(Ci.nsIIOService);
    var uri = ioService.newURI(this._datasource.uri, null, null);
    var rdfParser = Cc["@mozilla.org/rdf/xml-parser;1"].
                    createInstance(Ci.nsIRDFXMLParser)
    var ds = Cc["@mozilla.org/rdf/datasource;1?name=in-memory-datasource"].
             createInstance(Ci.nsIRDFDataSource);
    rdfParser.parseString(ds, uri, this._datasource.saveToString());

    var serializer = new UpdateDataSerializer();
    var data = serializer.serializeResource(ds, gRDF.GetResource(this._resource.getURI()));
    var verifier = Cc["@mozilla.org/security/datasignatureverifier;1"].
                   getService(Ci.nsIDataSignatureVerifier);
    return verifier.verifyData(data, this.signature, publicKey);
  },

  signData: function(key) {
    var ioService = Cc["@mozilla.org/network/io-service;1"].
                    getService(Ci.nsIIOService);
    var uri = ioService.newURI(this._datasource.uri, null, null);
    var rdfParser = Cc["@mozilla.org/rdf/xml-parser;1"].
                    createInstance(Ci.nsIRDFXMLParser)
    var ds = Cc["@mozilla.org/rdf/datasource;1?name=in-memory-datasource"].
             createInstance(Ci.nsIRDFDataSource);
    rdfParser.parseString(ds, uri, this._datasource.saveToString());

    var serializer = new UpdateDataSerializer();
    var data = serializer.serializeResource(ds, gRDF.GetResource(this._resource.getURI()));
    this.signature = key.signData(data, Ci.nsIKeyPair.HASHTYPE_SHA512);
  }
};

/**
 * This represents the full update manifest for one or more add-ons.
 */
function RDFUpdateManifest(datasource) {
  this._addonManifests = {};
  this._datasource = datasource;

  var resources = this._datasource.getAllResources();
  for (var i = 0; i < resources.length; i++) {
    var resource = resources[i];

    // No updates arc makes this not a possible update resource
    if (!resource.hasProperty(EM_R("updates")))
      continue;

    var uri = resource.getURI();
    if (uri.substring(0, PREFIX_EXTENSION.length) == PREFIX_EXTENSION)
      this._addAddonUpdateManifest(uri.substring(PREFIX_EXTENSION.length), resource);
    else if (uri.substring(0, PREFIX_ITEM_URI.length) == PREFIX_ITEM_URI)
      this._addAddonUpdateManifest(uri.substring(PREFIX_ITEM_URI.length), resource);
    else if (uri.substring(0, PREFIX_THEME.length) == PREFIX_THEME)
      this._addAddonUpdateManifest(uri.substring(PREFIX_THEME.length), resource);
  }
}

RDFUpdateManifest.prototype = {
  _datasource: null,
  _addonManifests: null,

  getAllManifests: function() {
    var manifests = [];
    for each (var manifest in this._addonManifests)
      manifests.push(manifest);
    return manifests;
  },

  getManifestForID: function(id) {
    if (id in this._addonManifests)
      return this._addonManifests[id];
    return null;
  },

  _addAddonUpdateManifest: function(id, resource) {
    // If the ID is invalid then just ignore this entry
    if (!gIDTest.test(id))
      return;
    this._addonManifests[id] = new AddonUpdateManifest(id, this._datasource, resource);
  },

  saveToFile: function(file) {
    this._datasource.saveToFile(file);
  }
};

/**
 * These are simple factories allowing for the creation or loading of the
 * manifests. In the future this can easily be extended for different format
 * manifests.
 */

var InstallManifestFactory = {
  loadFromRDFFile: function(file) {
    if (!file.exists())
      throw "file does not exist";

    var datasource = RDFDataSourceFactory.loadFromFile(file);
    var manifest = datasource.getResource(RDFURI_INSTALL_MANIFEST_ROOT);
    var predicates = manifest.getPredicates();
    if (predicates.length == 0)
      throw "install manifest appears to be malformed";

    return new RDFInstallManifest(datasource);
  },

  loadFromFile: function(file) {
    // Currently only rdf format manifests exist
    return this.loadFromRDFFile(file);
  },

  loadFromURL: function(url, callback) {
    throw "Not yet implemented";
  }
};

var UpdateManifestFactory = {
  loadFromRDFFile: function(file) {
    if (!file.exists())
      throw "file does not exist";

    return new RDFUpdateManifest(RDFDataSourceFactory.loadFromFile(file));
  },

  loadFromFile: function(file) {
    // Currently only rdf format manifests exist
    return this.loadFromRDFFile(file);
  },

  loadFromURL: function(url, callback) {
    throw "Not yet implemented";
  }
};
