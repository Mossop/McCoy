/**
 * Logs an info message to the error console
 */
function LOG(str) {
  var consoleService = Components.classes["@mozilla.org/consoleservice;1"]
                                 .getService(Components.interfaces.nsIConsoleService);
  consoleService.logStringMessage(str);
}

/**
 * Logs an error message to the error console
 */
function ERROR(str) {
  Components.utils.reportError(str);
}

function getURIFromFile(file) {
  var ioServ = Cc["@mozilla.org/network/io-service;1"].
               getService(Ci.nsIIOService);
  return ioServ.newFileURI(file);
}

/**
 * Loads an rdf datasource from a file avoiding the rdf service's caching.
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
 * Gets an nsIFile handle for a file used during tests. Takes the path the file
 * was copied to.
 */
function getTestFile(path) {
  var ios = Components.classes["@mozilla.org/network/io-service;1"]
                      .getService(Components.interfaces.nsIIOService);
  var chromeURI = ios.newURI("chrome://mochikit/content/" + path,
                             null, null);
  var resolvedURI = Components.classes["@mozilla.org/chrome/chrome-registry;1"]
                              .getService(Components.interfaces.nsIChromeRegistry)
                              .convertChromeURL(chromeURI);
  var fileHandler = Components.classes["@mozilla.org/network/protocol;1?name=file"]
                              .getService(Components.interfaces.nsIFileProtocolHandler);
  return fileHandler.getFileFromURLSpec(resolvedURI.spec);
}

/**
 * Gets a temporary file to use for testing.
 */
function getTempFile() {
  var dirService = Components.classes["@mozilla.org/file/directory_service;1"]
                             .getService(Components.interfaces.nsIProperties);
  var file = dirService.get("TmpD", Components.interfaces.nsILocalFile);
  file.append("tempfile.rdf");
  file.createUnique(Components.interfaces.nsIFile.NORMAL_FILE_TYPE, 0664);
  return file;
}

/**
 * This is a helper method used to compare that a resource in one datasource
 * has the same outgoing assertions as a matching resource in a second
 * datasource.
 * In the event that an anonymous resource is encountered this method becomes
 * recursive and may be called with two anonymous resources that potentially
 * represent the same resource but have differing uri's.
 */
function compareResource(rdf, testDS, testRes, refDS, refRes) {
  LOG("Comparing graphs " + testRes.ValueUTF8 + " to " + refRes.ValueUTF8);
  var properties = [];

  var propEnum = refDS.ArcLabelsOut(refRes);
  while (propEnum.hasMoreElements())
    properties.push(propEnum.getNext().QueryInterface(Components.interfaces.nsIRDFResource));

  var propcount = 0;
  propEnum = testDS.ArcLabelsOut(testRes);
  while (propEnum.hasMoreElements()) {
    var prop = propEnum.getNext().QueryInterface(Components.interfaces.nsIRDFResource);
    if (properties.indexOf(prop) < 0) {
      ERROR("Property " + prop.ValueUTF8 + " does not exist in reference graph");
      return false;
    }
    propcount++;
  }

  if (propcount != properties.length) {
    ERROR("Property mismatch");
    return false;
  }

  for (var i = 0; i < properties.length; i++) {
    var anons = [];
    var targets = [];

    var targetEnum = testDS.GetTargets(testRes, properties[i], true);
    while (targetEnum.hasMoreElements()) {
      var target = targetEnum.getNext().QueryInterface(Components.interfaces.nsIRDFNode);
      if ((target instanceof Components.interfaces.nsIRDFResource) &&
          (rdf.IsAnonymousResource(target)))
        anons.push(target);
      else
        targets.push(target);
    }

    targetEnum = refDS.GetTargets(refRes, properties[i], true);
    while (targetEnum.hasMoreElements()) {
      target = targetEnum.getNext().QueryInterface(Components.interfaces.nsIRDFNode);
      if ((target instanceof Components.interfaces.nsIRDFResource) &&
          (rdf.IsAnonymousResource(target))) {
        // Here we must test every anonymous resource in the other graph as a 
        // potential match
        var found = false;
        LOG("Searching for an anonymous match for " + target.ValueUTF8 + " for property " + properties[i].ValueUTF8);
        for (var j = 0; j < anons.length; j++) {
          if (compareResource(rdf, testDS, anons[j], refDS, target)) {
            anons.splice(j, 1);
            LOG("Found a match");
            found = true;
            break;
          }
        }
        if (!found) {
          ERROR("No anonymous match found.");
          return false;
        }
      }
      else {
        var pos = targets.indexOf(target);
        if (pos < 0) {
          ERROR("No matching target for property " + properties[i].ValueUTF8);
          return false;
        }
        targets.splice(pos, 1);
      }
    }

    if (anons.length > 0) {
      ERROR("Too many anonymous targets for property " + properties[i].ValueUTF8);
      return false;
    }

    if (targets.length > 0) {
      ERROR("Too many targets for property " + properties[i].ValueUTF8);
      return false;
    }
  }

  return true;
}

/**
 * This compares two RDF graphs to ensure that they contain equivalent
 * information without needing the serialisation to be identical. It is used
 * to identify that a series of operations produces the expected graph.
 *
 * This currently places requirements on the rdf under test. Any anonymous
 * resources must be referenced exactly once. In practice this should be the
 * case for all install and update manifests unless data has not been properly
 * cleaned up.
 */
function compareRDF(testFile, refFile) {
  LOG("Comparing " + testFile.path + " to " + refFile.path);
  if (!testFile.exists())  throw "test file should exist";
  if (!refFile.exists()) throw "reference file should exist";

  var rdf = Components.classes["@mozilla.org/rdf/rdf-service;1"]
                      .getService(Components.interfaces.nsIRDFService);

  var testDS = loadDataSource(testFile);
  var refDS = loadDataSource(refFile);

  var resources = [];
  var anoncount = 0;
  var rescount = 0;

  // Populate resources with all non-anonymous resources, count the anonymouse ones
  var resEnum = testDS.GetAllResources();
  while (resEnum.hasMoreElements()) {
    var res = resEnum.getNext().QueryInterface(Components.interfaces.nsIRDFResource);
    if (rdf.IsAnonymousResource(res)) {
      var arcs = testDS.ArcLabelsIn(res);
      if (!arcs.hasMoreElements())
        throw "Anonymous resource " + res.ValueUTF8 + " is disconnected";
      arcs.getNext();
      if (arcs.hasMoreElements())
        throw "Anonymous resource " + res.ValueUTF8 + " has more than one reference";
      anoncount++;
    }
    else {
      resources.push(res);
    }
  }

  // Check the same resources and the same number of non-anonymouse resources exist
  resEnum = refDS.GetAllResources();
  while (resEnum.hasMoreElements()) {
    res = resEnum.getNext().QueryInterface(Components.interfaces.nsIRDFResource);
    if (rdf.IsAnonymousResource(res)) {
      arcs = refDS.ArcLabelsIn(res);
      if (!arcs.hasMoreElements())
        throw "Anonymous resource " + res.ValueUTF8 + " is disconnected";
      arcs.getNext();
      if (arcs.hasMoreElements())
        throw "Anonymous resource " + res.ValueUTF8 + " has more than one reference";
      anoncount--;
    }
    else {
      if (resources.indexOf(res) < 0) {
        ERROR("Test does not have " + res.ValueUTF8 + " resource");
        return false;
      }
      rescount++;
    }
  }

  if (rescount != resources.length) {
    ERROR("Mismatched number of resources");
    return false;
  }
  if (anoncount != 0) {
    ERROR("Mismatched number of anonymous resources");
    return false;
  }

  LOG("Entering graphs");

  for (var i = 0; i < resources.length; i++) {
    if (!compareResource(rdf, testDS, resources[i], refDS, resources[i])) {
      ERROR("Resource " + resources[i].ValueUTF8 + " failed comparison");
      return false;
    }
  }

  return true;
}
