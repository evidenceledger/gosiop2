// @ts-check

// This is the starting point for the application
// This module starts executing as soon as parsing of the HTML has finished
// We will bootstrap the app and start the loading process for all components

// The CSS module
import './css/w3.css'

// Logging support
import { log } from "./log";

// For rendering the HTML in the pages
import { render, html } from 'uhtml';

// Translation support
import './i18n/tr.js'

// Prepare for lazy-loading the pages
// @ts-ignore
const pageModules = import.meta.glob('./pages/*.js')

// *****************************************************
// This is a micro-router with just-enough functionality
//
// Implements gotoPage(pageName, pageData) and goHome()
// *****************************************************

// The default home page where to start and when refreshing the app is set
// in the HTML page importing us in the window.homePage variable.
// @ts-ignore
var homePage = window.homePage
if (!homePage) {
    throw "No homePage was set."
}

// The name of the page when we try to go to a nonexistent page
var name404 = "Page404"

// This will hold all pages in a ("pageName", pageClass) structure
var pages = new Map()

// Register a new page name, associated to a class instance
function route(pageName, classInstance) {
    // Populate the map
    pages.set(pageName, classInstance)
}

// Set the default home page for the application
function setHomePage(page) {
    homePage = page
}

async function goHome() {

    if (homePage != undefined) {
        await gotoPage(homePage);
    }

}

// gotoPage transitions to the target page passing pageData object
// It is up to the page to define the structure of pageData
async function gotoPage(pageName, pageData) {
    console.log("Inside gotoPage:", pageName)

    // If pageName is not a registered page, go to the 404 error page
    // passing the target page as pageData
    var pageFunction = pageModules[`./pages/${pageName}.js`]
    if (!pageFunction) {
        log.error("Target page does not exist: ", pageName);
        pageData = pageName
        pageName = name404
        // Make sure that the page is loaded
        await pageModules[`./pages/${pageName}.js`]()
    }

    // Load the page. This is a no-op if the module is already loaded.
    await pageModules[`./pages/${pageName}.js`]()

    // Create a new browser history state, to support the back button in the browser.
    window.history.pushState(
        { pageName: pageName, pageData: pageData },
        `${pageName}`
    );

    // Process the page transition
    await processPageEntered(pageName, pageData, false);
}

// Handle page transition
async function processPageEntered(pageName, pageData, historyData) {

    // Hide the Splash Screen
    let elem = document.getElementById("SplashScreen")
    if (elem) {
        elem.style.display = "none"
    }    

    // Hide all pages of the application. Later we unhide the one we are entering
    // We also tell all other pages to exit, so they can perform any cleanup
    try {
        // @ts-ignore
        for (let [name, classInstance] of pages) {
            // Hide the page
            classInstance.domElem.style.display = "none"
            // Call the page exit() method for all except the target page, so it can perform any cleanup 
            if ((name !== pageName) && classInstance.exit) {
                await classInstance.exit()
            }
        }
    } catch (error) {
        log.error("Trying to call exit", error);
        return;
    }

    let targetPage = pages.get(pageName)

    // If the target page is not a registered page, go to the Page404 page,
    // passing the target page as pageData
    if (targetPage === undefined) {
        pageData = pageName
        targetPage = pages.get(name404)
    }

    // Reset scroll position to make sure the page is at the top
    window.scrollTo(0, 0);

    // Invoke the page enter() function to enter the page
    // This will allow the page to create dynamic content
    try {
        if (targetPage.enter) {
            await targetPage.enter(pageData, historyData);
        } else {
            // Static pages do not have to implement the enter() method.
            // Dynamic pages control their visibility as they need.
            // For static pages we make sure the target page is visible.
            targetPage.style.display = "block"
        }

    } catch (error) {
        log.error("Calling enter()", error);
        return;
    }

}

// Listen for PopStateEvent (navigator Back or Forward buttons are clicked)
window.addEventListener("popstate", async function (event) {
    // Set defaults
    var pageName = homePage;
    var pageData = undefined;

    // Get current state data if not null
    var state = event.state;
    if (state != null) {
        pageName = state.pageName;
        pageData = state.pageData;
    }

    // Process the page transition
    await processPageEntered(pageName, pageData, true);
});


// Get the version of the application and store in database

/**
 * 
 * @returns undefined
 */
async function getAndUpdateVersion() {
    // @ts-ignore
    let version = import.meta.env.VITE_APP_VERSION

    // Store the version in global Window object and in local storage
    // @ts-ignore
    window.appVersion = version
    window.localStorage.setItem("VERSION", version)
    console.log("Version:", version)

    return;
}


// When this event is fired the DOM is fully loaded and safe to manipulate
// @ts-ignore
window.addEventListener('DOMContentLoaded', async (event) => {
    console.log("DOMContentLoaded")

    // Get the version of the application asynchronously
    getAndUpdateVersion()

    // Go to the home page
    await goHome()

    // Load the pages of the application in parallel
    for (const path in pageModules) {
        pageModules[path]()
    }

});


var INSTALL_SERVICE_WORKER = true

// This function is called on first load and when a refresh is triggered in any page
// When called the DOM is fully loaded and safe to manipulate
// @ts-ignore
window.addEventListener('load', async (event) => {
    console.log("load")

    // Install Service Worker only when in Production
    // @ts-ignore
    if (import.meta.env.DEV) {
        console.log("In development")
        INSTALL_SERVICE_WORKER = false
    } else {
        console.log("In production")
    }

    // Install service worker for off-line support
    if (INSTALL_SERVICE_WORKER && ("serviceWorker" in navigator)) {
        const { Workbox } = await import('workbox-window');

        const wb = new Workbox("./sw.js");

        wb.addEventListener("message", (event) => {
            if (event.data.type === "CACHE_UPDATED") {
                const { updatedURL } = event.data.payload;

                console.log(`A newer version of ${updatedURL} is available!`);
            }
        });

        wb.addEventListener("activated", async (event) => {
            // `event.isUpdate` will be true if another version of the service
            // worker was controlling the page when this version was registered.
            if (event.isUpdate) {
                console.log("Service worker has been updated.", event);
                await performAppUpgrade(true)
            } else {
                console.log("Service worker has been installed for the first time.", event);
                await performAppUpgrade(false)
            }
        });

        // @ts-ignore
        wb.addEventListener("waiting", (event) => {
            console.log(
                `A new service worker has installed, but it can't activate` +
                `until all tabs running the current version have fully unloaded.`
            );
        });

        // Register the service worker after event listeners have been added.
        wb.register();

        //    const swVersion = await wb.messageSW({ type: "GET_VERSION" });
        //    console.log("Service Worker version:", swVersion);

    }

});


// This is called when a new version of the Service Worker has been activated.
// This means that a new version of the application has been installed
async function performAppUpgrade(isUpdate) {
    console.log("Performing Upgrade");

    // Notify the user and ask to refresh the application
    gotoPage("SWNotify", { isUpdate: isUpdate })

}

// *****************************************************
// HeaderBar definition
// *****************************************************

// @ts-ignore
function toggleMenu() {
    let x = document.getElementById("dropMenu")
    if (x) {
        x.classList.toggle("hidden")
    }
}
function hideMenu() {
    let x = document.getElementById("dropMenu")
    if (x) {
        x.classList.add("hidden")
    }
}
// @ts-ignore
function resetAndGoHome(e) {
    hideMenu()
    // @ts-ignore
    if (window.MHR.goHome) {
        goHome()
    }
}
function T(e) {
    // @ts-ignore
    if (window.T) {
        // @ts-ignore
        return(window.T(e))
    }
    return (e)
}

// @ts-ignore
function newresetAndGoHome(e) {
    HeaderBar()
    // @ts-ignore
    if (window.MHR.goHome) {
        goHome()
    }
}


function HeaderBar(menu = false) {
    let header = document.querySelector('header')

    var subMenu = html``
    var flag = !menu

    if (menu) {
        subMenu = html`
        <div id="mainmenu" class="w3-bar-block w3-card">
            ${window.
            // @ts-ignore
            menuItems.map(
                ({page, params, text}) => html`<a href="#" class="w3-bar-item w3-button" onclick=${()=>gotoPage(page, params)}>${text}</a>`
            )}
        </div>
        `;
    }

    var fullHB = html`
    <div class="w3-content">

        <div class="w3-bar w3-card w3-large">
            <a class="w3-bar-item w3-btn" onclick=${() => resetAndGoHome()}>
                <img style="height:1.5em; margin-bottom:5px" src="/evidencesmall.png" alt="EvidenceLedger logo">
            </a>
            <div class="w3-bar-item">Privacy Wallet</div>
            <a class="w3-bar-item w3-btn w3-right" onclick=${() => HeaderBar(flag)}>☰</a>
        </div>

        ${subMenu}
    
    </div>
    `;
    
    // @ts-ignore
    render(header, fullHB)

    return;

}

// *****************************************************
// AbstractPage is the superclass of all pages in the application
// *****************************************************

class AbstractPage {
    html;           // The uhtml html function, for subclasses
    domElem;        // The DOM Element that holds the page
    pageName;       // The name of the page for routing

    constructor(id) {
        if (!id) { throw "A page name is needed"}

        // Set the html tag function so subclasses do not have to import uhtml
        this.html = html

        // Create a <div> tag to contain the page
        this.domElem = document.createElement('div')

        // Set the id and name of the page for routing
        this.pageName = id
        this.domElem.id = this.pageName

        // Register the page in the router
        route(this.pageName, this)

        // The page starts hidden
        this.domElem.style.display = "none"

        // Insert into the DOM inside the <main> element
        var mainElem = document.querySelector('main')
        if (mainElem) {
            mainElem.appendChild(this.domElem)
        }

        console.log("Page constructor:", id)

    }

    render(theHtml) {
        // This is called by subclasses to render its contents
        // Show the page
        this.domElem.style.display = "block"
        // Redraw the header just in case the menu was active
        HeaderBar()
        // Render the html of the page into the DOM element of this page
        render(this.domElem, theHtml)
    }
}

function register(pageName, classDefinition) {
    let instance = new classDefinition(pageName)
}


// This module exports the `mhr` object into the global namespace, where we wil add
// the relevant functions that we want globally available to other modules.
// This way they do not have to import us (and avoid circular references in some cases) and
// we do not pollute the global namespace with our functions and variables
// @ts-ignore
window.MHR = {
    route: route,
    goHome: goHome,
    gotoPage: gotoPage,
    AbstractPage: AbstractPage,
    register: register,
}
