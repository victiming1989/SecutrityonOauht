const patterns = ["*://get_cookies/*"];

// Intercept the request
function intercept(request) {
    console.log("intercepted: " + request.url);
    browser.cookies.getAll({}).then((cookies) => {
        console.log(cookies);
        let response = "data:text/plain," + encodeURIComponent(JSON.stringify(cookies));
        return {redirectUrl: response};
    });
}

// Event triggered when a request is about to be made
browser.webRequest.onBeforeRequest.addListener(intercept, {urls: patterns}, ["blocking"]);