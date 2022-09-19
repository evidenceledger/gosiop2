import { html } from 'uhtml'
import { log } from '../log'
import { CWT } from "../components/cwt"
import { verifyHcert } from '../components/verifications'

window.MHR.register("AskUserToStoreQR", class AskUserToStoreQR extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    async enter(qrcode) {
        let html = this.html

        let verification = await this.verifyQRCertificate(qrcode)

        if (verification.result == "ERROR") {
            this.render(html`
            <div class="container center">
                <div id="hcertFailed" class="w3-panel bkg-error ptb-16">
                    <h3>Failed!</h3>
                    <p>${verification.message}.</p>
                </div>

                <div class="ptb-16">
        
                    <btn-primary @click=${()=>window.location.replace(location.origin)}>${T("Cancel")}</btn-primary>
        
                </div>
            </div>
                `
            )
            return;
        }

        this.QRCertificate = qrcode

        let theHtml = html`
        <div class="container">
            <div class="w3-card-4 w3-center" style="margin-top:100px;">
        
                <header class="w3-container color-primary" style="padding:10px">
                    <h1>${T("You received a new EU COVID certificate!")}</h1>
                </header>
        
                <div class="w3-container ptb-16">
                    <p>${T("You can save it in this device for easy access later.")}</p>
                    <p>${T("Please click Save to save the certificate.")}</p>
                </div>
        
                <div class="ptb-16">
        
                    <btn-primary @click=${()=>this.saveQRCertificate()}>${T("Save")}</btn-primary>
        
                </div>
        
            </div>
        </div>
        `

        this.render(theHtml)
    }

    async verifyQRCertificate(qrContent) {

        let hcert = undefined
    
        // Decode QR credential verifying it at the same time
        // At this moment we perform only technical verifications
        try {
            hcert = await CWT.decodeHC1QR(qrContent, true);
        } catch (error) {
            // An exception means there was a problem with decoding
            log.error("Error verifying credential", error)
            return {
                result: "ERROR",
                message: T("Signature validation failed. The certificate is not valid.")
            }
        }
    
        let technical_verification = hcert[3]
        if (technical_verification == false) {
            log.error("Error verifying credential")
            return {
                result: "ERROR",
                message: T("Signature validation failed. The certificate is not valid.")
            }
        }
    
        // If technical verification was OK, apply additional verifications
        console.log("Additional verifications")
        let business_verification = verifyHcert(hcert)
        console.log(business_verification)
        if (business_verification != true) {
            return {
                result: "ERROR",
                message: T(business_verification)
            }
        }
    
        // We passed all verifications, but should return a WARNING for certificates
        // with public keys in the PREPRODUCTION list
    
        // Build the verification structure
        let verification = {
            result: "OK",
            hcert: hcert,
            message: T("The certificate is valid.")
        }
    
        if (technical_verification === "PRE") {
            verification.result = "WARNING"
            verification.message = T("$warningmsg")
        }
    
        return verification
    
    }
    


    saveQRCertificate() {

        // Store it in local storage
        window.localStorage.setItem("MYEUDCC", this.QRCertificate)
    
        // Reload the application with a clean URL
        window.location.replace(document.location.origin)
    
    }
    
})
