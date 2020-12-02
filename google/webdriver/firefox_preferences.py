preferences = {
    # [1] Disable the Firefox disk, memory and offline cache
    "browser.cache.disk.enable": False,
    "browser.cache.memory.enable": False,
    "browser.cache.offline.enable": False,
    "network.http.use-cache": False,
    # [2] Block the browser-generated requests
    # Disable Mozilla Safebrowsing
    "browser.safebrowsing.enabled": False,
    "browser.safebrowsing.downloads.enabled": False,
    "browser.safebrowsing.downloads.remote.enabled": False,
    "browser.safebrowsing.maleware.enabled": False,
    # Disable automatic updates
    "app.update.enabled": False,
    # Do not get information about add-ons
    "extensions.getAddons.cache.enabled": False,
    # Disable all the content blocking features
    "browser.contentblocking.enabled": False,
    # Do not update the list of blocked contents
    "extensions.blocklist.enabled": False,
    # Disable geographic targeting
    "browser.search.geoSpecificDefaults": False,
    "browser.search.geoSpecificDefaults.url": "",
    "browser.search.geoip.url": "",
    "privacy.trackingprotection.enabled": False,
    "browser.safebrowsing.provider.mozilla.updateURL": "",
    # Do not load the Mozilla snippets
    "browser.newtabpage.activity-stream.feeds.snippets": False,
    "browser.newtabpage.activity-stream.disableSnippets": True,
    # Block calls to 'push.services.mozilla.com'
    "dom.push.serverURL": "",
    "dom.push.connection.enabled": False,
    "javascript.enabled": True,
    "useAutomationExtension": False
}
