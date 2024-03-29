pref("toolkit.defaultChromeURI", "chrome://mccoy/content");
pref("toolkit.defaultChromeFeatures", "chrome,resizable,centerscreen,dialog=no");
pref("toolkit.singletonWindowType", "McCoy:Main");
pref("network.protocol-handler.expose-all", false);
pref("network.protocol-handler.warn-external-default", false);

//The minimum delay in seconds for the timer to fire.
//default=2 minutes
pref("app.update.timerMinimumDelay", 60);
//Check if an update check needs to be run once a minute
pref("app.update.timer", 60000);

pref("app.update.enabled", true);
// Automatically download updates
pref("app.update.auto", true);
// Prompt if installed extensions are incompatible with the update
pref("app.update.mode", 1);
pref("app.update.url", "https://www.fractalbrew.com/aus/3/%PRODUCT%/%VERSION%/%BUILD_ID%/%BUILD_TARGET%/%LOCALE%/%CHANNEL%/%OS_VERSION%/%DISTRIBUTION%/%DISTRIBUTION_VERSION%/update.xml");
pref("app.update.url.manual", "http://developer.mozilla.org/en/docs/McCoy");
pref("app.update.url.details", "http://developer.mozilla.org/en/docs/McCoy");
// Check once a day
pref("app.update.interval", 86400);
//Show the Update Checking/Ready UI when the user was idle for x seconds
pref("app.update.idletime", 60);
// The post install UI appears to be broken
pref("app.update.showInstalledUI", false);

// Enable automatic extension updates
pref("extensions.update.enabled", true);
pref("extensions.update.interval", 86400);
pref("extensions.update.autoUpdateDefault", true);
pref("extensions.getAddons.cache.enabled", false);

pref("javascript.options.showInConsole", true);
pref("javascript.options.strict", true);
pref("browser.dom.window.dump.enabled", true);
