import { html } from 'uhtml'
import { log } from '../log'

window.MHR.register("MicroWallet", class MicroWallet extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    async enter() {
        let html = this.html

        // We can receive QRs via the URL or scanning with the camera

        // If URL specifies a QR then
        //     check it and store in local storage
        //     clean the URL and reload the app
        // If URL is clean (initially or after reloading)
        //     retrieve the QR from local storage and display it

        // Check if we received a certificate via the URL
        // The URL should be: https://host:port/?eudcc=QRCodeInBase64Encoding
        // The QRCodeInBase64Encoding is the long string representing each QR code
        let params = new URLSearchParams(document.location.search.substring(1));
        let eudcc = params.get("eudcc");
    
        // QR code found in URL. Process and display it
        if (eudcc !== null) {
            // Decode from Base64url
            eudcc = atob(eudcc)
            console.log("EUDCC received:", eudcc)

            // Ask the user to accept the certificate
            await window.MHR.gotoPage("AskUserToStoreQR", eudcc)
            return;
        
        }
    
        // Check if we have a certificate in local storage
        let qrContent = window.localStorage.getItem("MYEUDCC")
        if (qrContent !== null) {
            // Display the certificate
            await window.MHR.gotoPage("DisplayMyHcert", qrContent)
            return;        
        }

        // We do not have a QR in the local storage
        this.render(html`
            <div id="hcertFailed" class="w3-panel bkg-fail">
                <h2>${T("There is no certificate.")}</h2>
            </div>
       `)
        return
    }
})
