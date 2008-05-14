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

const PREFIX_NS_EM                    = "http://www.mozilla.org/2004/em-rdf#";
const PREFIX_ITEM_URI                 = "urn:mozilla:item:";
const PREFIX_EXTENSION                = "urn:mozilla:extension:";
const PREFIX_THEME                    = "urn:mozilla:theme:";
const RDFURI_INSTALL_MANIFEST_ROOT    = "urn:mozilla:install-manifest";
const RDFURI_ITEM_ROOT                = "urn:mozilla:item:root";

var EXPORTED_SYMBOLS = ["InstallManifestFactory", "UpdateManifestFactory"];

var gRDF = Cc["@mozilla.org/rdf/rdf-service;1"].
           getService(Ci.nsIRDFService);
var gUtils = Cc["@mozilla.org/rdf/container-utils;1"].
             getService(Ci.nsIRDFContainerUtils);
var gInstallManifestRoot = gRDF.GetResource(RDFURI_INSTALL_MANIFEST_ROOT);
var gIDTest = /^(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}|[a-z0-9-\._]*\@[a-z0-9-\._]+)$/i;

function EM_NS(property) {
  return PREFIX_NS_EM + property;
}

function EM_R(property) {
  return gRDF.GetResource(EM_NS(property));
}

function EM_L(literal) {
  return gRDF.GetLiteral(literal);
}

function EM_I(integer) {
  return gRDF.GetIntLiteral(integer);
}

function getURIFromFile(file) {
  var ioServ = Cc["@mozilla.org/network/io-service;1"].
               getService(Ci.nsIIOService);
  return ioServ.newFileURI(file);
}

/**
 * Extract the string value from a RDF Literal or Resource
 * @param   literalOrResource
 *          RDF String Literal or Resource
 * @returns String value of the literal or resource, or undefined if the object
 *          supplied is not a RDF string literal or resource.
 */
function stringData(literalOrResource) {
  if (literalOrResource instanceof Ci.nsIRDFLiteral)
    return literalOrResource.Value;
  if (literalOrResource instanceof Ci.nsIRDFResource)
    return literalOrResource.Value;
  return undefined;
}

/**
 * Extract the integer value of a RDF Literal
 * @param   literal
 *          nsIRDFInt literal
 * @return  integer value of the literal
 */
function intData(literal) {
  if (literal instanceof Ci.nsIRDFInt)
    return literal.Value;
  return undefined;
}

/**
 * Removes any assertions for the given source and property.
 */
function removeProperty(ds, source, property) {
  var target = ds.GetTarget(source, property, true);
  while (target) {
    ds.Unassert(source, property, target, true);
    target = ds.GetTarget(source, property, true);
  }
}

/**
 * This loads an rdf file into an in-memory rdf datasource. The resultant
 * datasource can be safely modified without it automatically overwriting
 * the contents of the file
 */
function loadDataSource(file) {
  var uri = getURIFromFile(file);
  var fis = Cc["@mozilla.org/network/file-input-stream;1"].
            createInstance(Ci.nsIFileInputStream);
  fis.init(file, -1, -1, false);
  var bis = Cc["@mozilla.org/network/buffered-input-stream;1"].
            createInstance(Ci.nsIBufferedInputStream);
  bis.init(fis, 4096);
  
  var rdfParser = Cc["@mozilla.org/rdf/xml-parser;1"].
                  createInstance(Ci.nsIRDFXMLParser)
  var ds = Cc["@mozilla.org/rdf/datasource;1?name=in-memory-datasource"].
           createInstance(Ci.nsIRDFDataSource);
  var listener = rdfParser.parseAsync(ds, uri);
  var channel = Cc["@mozilla.org/network/input-stream-channel;1"].
                createInstance(Ci.nsIInputStreamChannel);
  channel.setURI(uri);
  channel.contentStream = bis;
  channel.QueryInterface(Ci.nsIChannel);
  channel.contentType = "text/xml";

  listener.onStartRequest(channel, null);
  try {
    var pos = 0;
    var count = bis.available();
    while (count > 0) {
      listener.onDataAvailable(channel, null, bis, pos, count);
      pos += count;
      count = bis.available();
    }
    listener.onStopRequest(channel, null, Components.results.NS_OK);
    bis.close();
    fis.close();

    return ds;
  }
  catch (e) {
    listener.onStopRequest(channel, null, e.result);
    bis.close();
    fis.close();
    throw e;
  }
}

/**
 * This serializes a datasource to a file with a few customizations.
 */
function saveDataSource(datasource, file) {
  var serializer = Cc["@mozilla.org/rdf/xml-serializer;1"].
                   createInstance(Ci.nsIRDFXMLSerializer).
                   QueryInterface(Ci.nsIRDFXMLSource);

  var out = Cc["@mozilla.org/network/file-output-stream;1"].
            createInstance(Ci.nsIFileOutputStream);
  out.init(file, -1, -1, false);

  var atomService = Cc["@mozilla.org/atom-service;1"].
                    getService(Ci.nsIAtomService);
  serializer.init(datasource);
  serializer.addNameSpace(atomService.getAtom("em"), PREFIX_NS_EM);
  serializer.Serialize(out);
  out.close();
}

/**
 * This represents the full install manifest for an add-on.
 */
function RDFInstallManifest(datasource) {
  this._datasource = datasource;
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
    return stringData(this._datasource.GetTarget(gInstallManifestRoot, EM_R(property), true));
  },

  _setStringProperty: function(property, value) {
    removeProperty(this._datasource, gInstallManifestRoot, EM_R(property));
    this._datasource.Assert(gInstallManifestRoot, EM_R(property), EM_L(value), true);
  },

  saveToFile: function(file) {
    saveDataSource(this._datasource, file);
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
    return stringData(this._datasource.GetTarget(this._resource, EM_R("signature"), true));
  },

  set signature(val) {
    removeProperty(this._datasource, this._resource, EM_R("signature"));
    this._datasource.Assert(this._resource, EM_R("signature"), EM_L(val), true);
  },

  verifyData: function(publicKey) {
    var serializer = new UpdateDataSerializer();
    var data = serializer.serializeResource(this._datasource, this._resource);
    var verifier = Cc["@mozilla.org/security/datasignatureverifier;1"].
                   getService(Ci.nsIDataSignatureVerifier);
    return verifier.verifyData(data, this.signature, publicKey);
  },

  signData: function(key) {
    var serializer = new UpdateDataSerializer();
    var data = serializer.serializeResource(this._datasource, this._resource);
    this.signature = key.signData(data, Ci.nsIKeyPair.HASHTYPE_SHA512);
  }
};

/**
 * This represents the full update manifest for one or more add-ons.
 */
function RDFUpdateManifest(datasource) {
  this._addonManifests = {};
  this._datasource = datasource;

  var resources = this._datasource.GetAllResources();
  while (resources.hasMoreElements()) {
    var resource = resources.getNext().QueryInterface(Ci.nsIRDFResource);

    // No updates arc makes this not a possible update resource
    if (!this._datasource.hasArcOut(resource, EM_R("updates")))
      continue;

    var uri = resource.ValueUTF8;
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
    saveDataSource(this._datasource, file);
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

    var datasource = loadDataSource(file);

    var arcs = datasource.ArcLabelsOut(gInstallManifestRoot);
    if (!arcs.hasMoreElements())
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

    return new RDFUpdateManifest(loadDataSource(file));
  },

  loadFromFile: function(file) {
    // Currently only rdf format manifests exist
    return this.loadFromRDFFile(file);
  },

  loadFromURL: function(url, callback) {
    throw "Not yet implemented";
  }
};
