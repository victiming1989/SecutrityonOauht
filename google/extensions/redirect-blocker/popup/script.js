
// Update the icon of the extension
function updateIcon(){
    return browser.browserAction.setIcon({path: enabled ?
        {16: "../icons/lock.svg", 32: "../icons/lock.svg"} :
        {16: "../icons/lock-open.svg", 32: "../icons/lock-open.svg"}
    });
}

let port = browser.runtime.connect({name: "popup-port"});
let enabled = JSON.parse(localStorage.getItem("enabled"));
document.getElementById(enabled ? "enable" : "disable").classList.add("d-none");

// Enable or disable the blocker with a click
document.addEventListener("click", (e) => {
    if (e.target.classList.contains("toggle")){

        // Edit the button shown in the popup
        e.target.classList.add("d-none");
        document.getElementById(enabled ? "enable" : "disable").classList.remove("d-none");

        enabled = !enabled;
        updateIcon();
        port.postMessage({enabled: enabled});
        localStorage.setItem("enabled", JSON.stringify(enabled));
    }
});
