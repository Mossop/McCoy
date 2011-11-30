#
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
# Mozilla Foundation.
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

"""
Tests McCoy's command line handler.
"""

import sys
import shutil
import os
import filecmp
import difflib
from tempfile import mkdtemp
from runner import AppEnvironment

def difffile(got, expected):
  fe = open(expected)
  try:
    expectedLines = fe.readlines()
    fg = open(got)
    try:
      gotLines = fg.readlines()
      diff = difflib.unified_diff(expectedLines, gotLines, expected, got)
      return [l for l in diff]
    finally:
      fg.close()
  finally:
    fe.close()

# The password for the keystore in the test profile
PASSWORD = "McC0y1e$1pa$$w0rd"

basedir = sys.argv[1]

environment = AppEnvironment(basedir)

datadir = os.path.join(basedir, "tests", "test_taskhandler")

tempdir = environment.temp

# Copy in the test key store
shutil.copy(os.path.join(datadir, "cert8.db"), environment.profile)
shutil.copy(os.path.join(datadir, "key3.db"), environment.profile)

output = os.path.join(tempdir, "test.rdf")

install = os.path.join(datadir, "install1.rdf")

# Add the key already in the profile to the manifest
args = [ "install-key", "-n", "test1", "-pass", PASSWORD, "-o", output, install ]
environment.launchApp(args)
if os.path.exists(output):
  diff = difffile(output, os.path.join(datadir, "install1_test1.rdf"))
  if len(diff) == 0:
    print "PASS: Adding test1 key to update1.rdf gave correct output"
  else:
    print "FAIL: Adding test1 key to update1.rdf gave incorrect output"
  os.remove(output)
else:
  print "FAIL: Adding key did not output a result"

# Add a key from a file to the manifest
args = [ "install-key", "-k", os.path.join(datadir, "test4.pem"), "-pass", "keytest4", "-o", output, install ]
environment.launchApp(args)
if os.path.exists(output):
  diff = difffile(output, os.path.join(datadir, "install1_test4.rdf"))
  if len(diff) == 0:
    print "PASS: Adding test4.pem to update1.rdf gave correct output"
  else:
    print "FAIL: Adding test4.pem to update1.rdf gave incorrect output"
  os.remove(output)
else:
  print "FAIL: Adding key did not output a result"

update = os.path.join(datadir, "update1.rdf")

# Sign the update with a key already in the profile
args = [ "sign-update", "-n", "test1", "-pass", PASSWORD, "-o", output, update ]
environment.launchApp(args)
if os.path.exists(output):
  diff = difffile(output, os.path.join(datadir, "update1_test1.rdf"))
  if len(diff) == 0:
    print "PASS: Signing update1.rdf with test1 key gave correct output"
  else:
    print "FAIL: Signing update1.rdf with test1 key gave incorrect output"
  os.remove(output)
else:
  print "FAIL: Signing did not output a result"

# Sign the update with a key already in the profile, just a selected id
args = [ "sign-update", "-n", "test2", "-pass", PASSWORD, "-id", "test2@tests.mccoy.mozilla.org", "-o", output, update ]
environment.launchApp(args)
if os.path.exists(output):
  diff = difffile(output, os.path.join(datadir, "update1_test2.rdf"))
  if len(diff) == 0:
    print "PASS: Signing update1.rdf with test2 key gave correct output"
  else:
    print "FAIL: Signing update1.rdf with test2 key gave incorrect output"
  os.remove(output)
else:
  print "FAIL: Signing did not output a result"

# Sign the update with a key provided in a file
args = [ "sign-update", "-k", os.path.join(datadir, "test4.pem"), "-pass", "keytest4", "-o", output, update ]
environment.launchApp(args)
if os.path.exists(output):
  diff = difffile(output, os.path.join(datadir, "update1_test4.rdf"))
  if len(diff) == 0:
    print "PASS: Signing update1.rdf with test4.pem gave correct output"
  else:
    print "FAIL: Signing update1.rdf with test4.pem gave incorrect output"
    sys.stdout.writelines(diff)
  os.remove(output)
else:
  print "FAIL: Signing did not output a result"
