// *******************************************************
// Translation support. This module adds to the
// global scope a translation function T()
// *******************************************************

// Use "ca" as default language unless set explicitly by the
// user in the application.
var preferredLanguage = "ca"

// Check if the user had set explicitly the language
let l = localStorage.getItem("preferredLanguage")
if (l) {preferredLanguage = l}

// Set preferred language in global scope, for easy module access
window.preferredLanguage = preferredLanguage

import {translations} from "./translations.js"

// This function is used in runtime to get translated text
function T(key) {
    // Texts in the application are written in English
    // If language is "en" we do not need to search
    if ((window.preferredLanguage === "en") && (key.charAt(0) != "$")) { return key }

    // Check if the entry text has some translation, otherwise return unmodified
    let entry = translations[key]
    if (entry === undefined) { return key }

    // Check if we have the text translated to the current language
    let translated = entry[window.preferredLanguage]
    if (translated === undefined) { return key }
    return translated
}
// Set the function in the global scope
window.T = T
