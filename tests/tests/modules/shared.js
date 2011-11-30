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
  var chromeURI = ios.newURI("chrome://mochitests/content/" + path,
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

/*
 * Compares the two sets of triples. The arrays blanksA and blanksB are used to
 * map blank nodes in triplesA to those in triplesB to attempt to make a match.
 *
 * Returns true if these triples matched.
 */
function compareAdjustedTriples(blanksA, blanksB, triplesA, triplesB) {
  for (var subjectA in triplesA) {
    var pos = blanksA.indexOf(subjectA);
    var subjectB = (pos < 0) ? subjectA : blanksB[pos];

    if (!(subjectB in triplesB))
      return false;

    // Clone the triple list so we can modify it
    var testTriples = triplesB[subjectB].slice(0);

    if (triplesA[subjectA].length != testTriples.length)
      return false;

    for (var i = 0; i < triplesA[subjectA].length; i++) {
      var predicate = triplesA[subjectA][i].predicate;
      var object = triplesA[subjectA][i].object

      pos = blanksA.indexOf(object);
      if (pos >= 0)
        object = blanksB[pos];

      // See if this triple now matches one in the test set
      var found = false;
      for (var j = 0; j < testTriples.length; j++) {
        if ((predicate == testTriples[j].predicate) &&
            (object == testTriples[j].object)) {
          testTriples.splice(j, 1);
          found = true;
          break;
        }
      }
      if (!found)
        return false;
    }
  }
  // Every single triple matched
  return true;
}

function untripleHex(aChars)
{
  return String.fromCharCode("0x" + aChars.join(""));
}

function untripleString(aString)
{
  if (!aString)
    return aString;

  var chars = aString.split("");

  for (var i = 0; i < chars.length; ++i) {
    if (chars[i] != "\\")
      continue;

    var numSplice = 1;

    switch (chars[i + 1]) {
    case "t":
      chars[i] = "\t";
      break;

    case "n":
      chars[i] = "\n";
      break;

    case "r":
      chars[i] = "\r";
      break;

    case '"':
      chars[i] = '"';
      break;

    case "\\":
      break;

    case "u":
      chars[i] = untripleHex(chars.slice(i + 2, i + 6));
      numSplice = 5;
      break;

    case "U":
      chars[i] = untripleHex(chars.slice(i + 2, i + 10));
      numSplice = 9;
      break;

    default:
      throw Error("Malformed escape letter in N-triples: '" + chars[i + 1] + "'.");
    }
    chars.splice(i + 1, numSplice);
  }

  return chars.join("");
}

function tripleHex(aCode, aLength)
{
  var hex = aCode.toString(16).toUpperCase();
  while (hex.length < aLength) {
    hex = "0" + hex;
  }
  return hex;
}

function tripleString(aString)
{
  var rv = "";

  var len = aString.length;

  for (var i = 0; i < len; ++i) {
    var code = aString.charCodeAt(i);
    var val;

    switch (code) {
    case 0x9:
      val = "\\t";
      break;

    case 0xA:
      val = "\\n";
      break;

    case 0xD:
      val = "\\r";
      break;

    case 0x22:
      val = "\\\"";
      break;

    case 0x5C:
      val = "\\\\";
      break;

    default:
      if (code >= 0x20 && code <= 0x7E) {
        val = String.fromCharCode(code);
      }
      else if (code <= 0xFFFF) {
        val = "\\u" + tripleHex(code, 4);
      }
      else {
        val = "\U" + tripleHex(code, 8);
      }
    }

    rv += val;
  }

  return rv;
}

/*
 * Recursive generator. Returns every possible permutation of the input array.
 */
function permutations(blanks) {
  if (blanks.length == 0) {
    yield [];
    return;
  }

  for (var i = 0; i < blanks.length; i++) {
    var newBlanks = blanks.slice(0);
    newBlanks.splice(i, 1);
    for (var permutation in permutations(newBlanks)) {
      permutation.unshift(blanks[i]);
      yield permutation;
    }
  }
}

/*
 * Serialises an N-Triple structure to a string.
 */
function serializeNTriples(ntriples) {
  var result = "";
  for (var subject in ntriples) {
    for (var i = 0; i < ntriples[subject].length; i++) {
      result += subject + " " +
                ntriples[subject][i].predicate + " " +
                ntriples[subject][i].object + ".\n";
    }
  }
  return result;
}

/*
 * Splits a line from an N-Triple line into the 3 parts. Throws an exception
 * if the line seems invalid. Returns null if the line is empty or a comment.
 */
function splitTriple(str) {
  // Trim any whitespace
  str = str.replace(/^\s+|\s+$/g, "");
  // Ignore blank lines and comments
  if ((str.length == 0) || (str.charAt(0) == "#"))
    return null;

  // Subjects and predicates cannot contain whitespace, which is handy
  var matches = str.match(/^(<\S+>|_:\S+)\s+(<\S+>)\s+(<\S+>|_:\S+|".*?"(?:\^\^<\S+>)?)\s*\.$/);
  if (!matches)
    throw "Illegal triple \"" + str + "\"";

  return [matches[1], matches[2], matches[3]];
}

/*
 * Tests if a string from a triple represents a blank node.
 */
function isBlankNode(str) {
  if (str.length < 3)
    return false;
  return (str.substring(0, 2) == "_:");
}

/*
 * Compares two sets of N-Triples for equivalence. Uses brute force to test
 * every possible combination of matches for blank nodes.
 *
 * aTriplesA and aTriplesB are N-Triple structures
 */
function compareNTriples(aTriplesA, aTriplesB) {
  function getSubjects(triples) {
    var subjects = [];
    var blanks = [];
    for (var subject in triples) {
      subjects.push(subject);
      if (isBlankNode(subject) && (blanks.indexOf(subject) < 0))
        blanks.push(subject);
      for (var i = 0; i < triples[subject].length; i++) {
        if (isBlankNode(triples[subject][i].object) &&
            (blanks.indexOf(triples[subject][i].object) < 0))
          blanks.push(triples[subject][i].object);
      }
    }
    return [subjects, blanks];
  }

  // Collect a list of subjects and blank nodes from each set of triples
  var [subjectsA, blanksA] = getSubjects(aTriplesA);
  var [subjectsB, blanksB] = getSubjects(aTriplesB);

  if (subjectsA.length != subjectsB.length)
    return false;

  if (blanksA.length != blanksB.length)
    return false;

  for (var permutation in permutations(blanksB)) {
    if (compareAdjustedTriples(blanksA, permutation, aTriplesA, aTriplesB))
      return true;
  }
  return false;
}

/*
 * Returns an appropriate N-Triple string for the given nsIRDFNode.
 */
function getXPCOMNTripleStr(node) {
  var rdf = Components.classes["@mozilla.org/rdf/rdf-service;1"]
                      .getService(Components.interfaces.nsIRDFService);

  if (node instanceof Components.interfaces.nsIRDFResource) {
    if (rdf.IsAnonymousResource(node))
      return "_:" + node.ValueUTF8.substring(4); // Technically not a valid N-Triple name, but safe for us to use
    return "<" + tripleString(node.ValueUTF8) + ">";
  }
  else if (node instanceof Components.interfaces.nsIRDFInt) {
    return "\"" + tripleString(node.Value) + "\"^^<http://home.netscape.com/NC-rdf#Integer>";
  }
  else if (node instanceof Components.interfaces.nsIRDFDate) {
    return "\"" + tripleString(node.Value) + "\"^^<http://home.netscape.com/NC-rdf#Date>";
  }
  else if (node instanceof Components.interfaces.nsIRDFLiteral) {
    return "\"" + tripleString(node.Value) + "\"";
  }
  throw "Unknown type " + node;
}

/*
 * Returns an N-Triples structure for an nsIRDFDataSource
 */
function getNTriplesForXPCOMDataSource(ds) {
  var triples = {};
  var sourceEnum = ds.GetAllResources();
  while (sourceEnum.hasMoreElements()) {
    var source = sourceEnum.getNext().QueryInterface(Components.interfaces.nsIRDFResource);
    var subject = getXPCOMNTripleStr(source);

    var arcEnum = ds.ArcLabelsOut(source);
    while (arcEnum.hasMoreElements()) {
      var arc = arcEnum.getNext().QueryInterface(Components.interfaces.nsIRDFResource);
      var predicate = "<" + tripleString(arc.ValueUTF8) + ">";
      var targetEnum = ds.GetTargets(source, arc, true);
      while (targetEnum.hasMoreElements()) {
        var target = targetEnum.getNext();
        if (!(subject in triples))
          triples[subject] = [];
        triples[subject].push({predicate: predicate, object: getXPCOMNTripleStr(target)});
      }
    }
  }
  return triples;
}

/*
 * Returns an appropriate N-Triple string for an RDFNode
 */
function getNTripleStr(object, unnamedNodes) {
  if (object instanceof RDFBlankNode) {
    var id = object.getNodeID();
    if (!id) {
      if (unnamedNodes.indexOf(object) < 0) {
        unnamedNodes.push(object);
      }
      id = "NTripleNode" + unnamedNodes.indexOf(object);
    }
    return "_:" + id;
  }
  else if (object instanceof RDFResource) {
    return "<" + tripleString(object.getURI()) + ">";
  }
  else if (object instanceof RDFDateLiteral) {
    return "\"" + object.getValue().getTime() + "\"^^<http://home.netscape.com/NC-rdf#Date>";
  }
  else if (object instanceof RDFIntLiteral) {
    return "\"" + object.getValue() + "\"^^<http://home.netscape.com/NC-rdf#Integer>";
  }
  else if (object instanceof RDFLiteral) {
    return "\"" + tripleString(object.getValue()) + "\"";
  }
  throw "Unknown object " + object;
}

/*
 * Returns an N-Triples structure for an RDFDataSource
 */
function getNTriplesForDataSource(ds) {
  var triples = {};
  var unnamed = [];
  var subjects = ds.getAllSubjects();
  for (var i = 0; i < subjects.length; i++) {
    var subject = getNTripleStr(subjects[i], unnamed);
    var predicates = subjects[i].getPredicates();
    for (var j = 0; j < predicates.length; j++) {
      var objects = subjects[i].getObjects(predicates[j]);
      for (var k = 0; k < objects.length; k++) {
        if (!(subject in triples))
          triples[subject] = [];
        triples[subject].push({ predicate: "<" + tripleString(predicates[j]) + ">",
                                object: getNTripleStr(objects[k], unnamed) });
      }
    }
  }

  return triples;
}

/*
 * Loads a file into an N-Triple structure.
 */
function loadNTriples(file) {
  var stream = Cc["@mozilla.org/network/file-input-stream;1"].
               createInstance(Ci.nsIFileInputStream);
  stream.init(file, -1, 0, 0);
  stream.QueryInterface(Ci.nsILineInputStream);

  var line = {};
  var triples = {};

  do {
    var more = stream.readLine(line);
    var triple = splitTriple(line.value);
    if (!triple)
      continue;

    if (!(triple[0] in triples))
      triples[triple[0]] = [];
    triples[triple[0]].push({ predicate: triple[1], object: triple[2] });
  } while (more);

  stream.close();
  return triples;
}

/**
 * This compares two RDF graphs to ensure that they contain equivalent
 * information without needing the serialisation to be identical. It is used
 * to identify that a series of operations produces the expected graph.
 */
function compareRDF(testFile, refFile) {
  LOG("Comparing " + testFile.path + " to " + refFile.path);
  if (!testFile.exists())  throw "test file should exist";
  if (!refFile.exists()) throw "reference file should exist";

  return compareNTriples(getNTriplesForXPCOMDataSource(loadDataSource(testFile)),
                         getNTriplesForXPCOMDataSource(loadDataSource(refFile)));
}

/**
 * Performs a line by line comparison of the two files.
 */
function compareFile(testFile, refFile) {
  if (!testFile.exists())  throw "test file should exist";
  if (!refFile.exists()) throw "reference file should exist";

  var testStream = Cc["@mozilla.org/network/file-input-stream;1"].
                   createInstance(Ci.nsIFileInputStream);
  testStream.init(testFile, -1, 0, 0);
  testStream.QueryInterface(Ci.nsILineInputStream);

  var refStream = Cc["@mozilla.org/network/file-input-stream;1"].
                  createInstance(Ci.nsIFileInputStream);
  refStream.init(refFile, -1, 0, 0);
  refStream.QueryInterface(Ci.nsILineInputStream);

  var testLine = {};
  var refLine = {};
  var pos = 0;
  var testMore = false;
  var refMore = false;

  do {
    testMore = testStream.readLine(testLine);
    refMore = refStream.readLine(refLine);
    pos++;
    is(testLine.value, refLine.value, "File compare failed at line " + pos);
  } while (testMore && refMore);

  ok(!testMore, "Test file contained too many lines");
  ok(!refMore, "Test file contained too many lines");

  testStream.close();
  refStream.close();
}
