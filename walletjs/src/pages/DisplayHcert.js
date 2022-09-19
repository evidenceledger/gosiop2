import { html } from 'uhtml'
import { log } from '../log'
import { CWT } from "../components/cwt"
import { verifyHcert } from '../components/verifications'

// The images for result of verifications
import ok_image from "../img/ok.png"
import error_image from "../img/error.png"
import warning_image from "../img/warning.png"

var testQR = "HC1:NCFOXN%TSMAHN-H%WKPL9/BP:BCP6M-AH0VC1ROT$SD PO%I$TQ3.P:.IO6T+6NNO4*J8OX4W$C2VLWLIVO5ON1: B.T1RTOF:P ZPEX9Z0QTU1B+HON1MU9%*JJR3Z+INTICZUKSR*LA/CJ6IAXPMHQ1*P1TU19UEOQ1OH6CN5ILGBUHSHA.W2YJ2/E2VZ1W6A8C9IEP2SAC/9B95ZE9Q$95:UENEUW66469366JDO$9KZ56DE/.QC$Q3J62:6LZ6O59++9-G9+E93ZMV70- CC8C90JK.A+ C/8DXEDKG0CGJ5AL5:4/60O3P:XRUVI/E2$4JY/K0:S6QNROF GVV378.GTGV /KH-KVLV5KN+*431TF68UXD-I69NTCW4HKLT*QGTA W7G 7N31BUUSS1SC5X%06W0H*OVIUH$AA2A PK7+O8ZEBPJT8IDBSQ7O574J98%.BWUN*7K:JVR%DAQOU/CZ$9N$LN0G$X8G+MJNRFNB4CRDMA 203F2.3"

var debugging = true

window.MHR.register("DisplayHcert", class DisplayHcert extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    async enter(qrContent) {
        let hcert
        let verified = false
        let thehtml = ""

        if (debugging) {
            qrContent = testQR
        }

        // Decode credential verifying it at the same time
        try {
            hcert = await CWT.decodeHC1QR(qrContent, true);
            verified = hcert[3]
        } catch (error) {
            log.error("Error verifying credential", error)
            this.render(this.renderGeneralError(error))
            return;
        }

        // Build the verification structure
        let verification = {
            result: "OK",
            message: T("The certificate is valid.")
        }

        if (verified === false) {
            verification.result = "ERROR"
            verification.message = T("Signature validation failed. The certificate is not valid.")
        } else if (verified === "PRE") {
            verification.result = "WARNING"
            verification.message = T("$warningmsg")
        }

        // If basic verification was OK, apply additional verifications
        console.log(verification)
        if ((verified === true) || (verified === "PRE")) {
            console.log("Additional verifications")
            verified = verifyHcert(hcert)
            console.log(verified)
            if (verified != true) {
                verification.result = "ERROR",
                verification.message = T(verified)
            }
        }

        console.log(verification)

        try {
            // Render the credential
            thehtml = this.renderDetail(hcert, verification);
        } catch (error) {
            log.error("Error rendering credential", error)
            this.render(this.renderGeneralError(error))
            return;
        }

        let fullPage = html`
        <div class="w3-center">
            ${thehtml}
            <btn-primary @click=${()=> window.MHR.gotoPage("ScanQrPage")}>${T("Verify another")}</btn-primary>
        </div>
        `
        this.render(fullPage)

    }

    renderGeneralError(error) {
        return this.html`
            <div id="hcertFailed" class="w3-panel bg-fail">
                <h3>Failed!</h3>
                <p>The credential has an invalid format.</p>
            </div>
            `
    }

    renderDetail(cred, verification) {
        // The credential
        let payload = cred[1];

        // Parameters in case of correct validation
        let title = "Validated"
        let image = ok_image
        let color = "color-success"

        // Modify the parameters if WARNING or ERROR
        if (verification.result === "WARNING") {
            title = "Warning"
            image = warning_image
            color = "color-warning"
        } else if (verification.result === "ERROR") {
            title = "Not Validated"
            image = error_image
            color = "color-error"
        }

        let thehtml = this.html`

        <div class=${`py-3 mb-3 shadow-lg ${color}`}>
            <div class="flex justify-center">
                <img class="mr-2" src=${image}  alt="" />
                <h3 class="my-auto text-xl font-bold ml-2">${T(title)}</h3>                
            </div>
            <p class="text-lg">${verification.message}</p>
        </div>

        <div class="mb-5">
            <div class="subsection">
                <div class="etiqueta">${T("Surname and forename")}</div>
                <div class="text-xl font-semibold">${payload.fullName}</div>
            </div>
            <div class="subsection">
                <div class="etiqueta">${T("Date of birth")}</div>
                <div class="text-xl font-semibold">${payload.dateOfBirth}</div>
            </div>
        </div>
           
        `;


        return thehtml;
    }

})
