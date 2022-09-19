import {log} from '../log'
import { BrowserQRCodeReader } from '@zxing/browser';
import { AbstractPage, register } from '../components/AbstractPage'
import { getPreferredVideoDevice, getPlatformOS } from '../components/camerainfo'

// This is to facilitate debugging of certificates
var testQRdata = "HC1:NCFOXNYT7"

var testQR = {
    text: testQRdata
}

// Set the QR raw data above and enable debugging setting this flag to true
var debugging = false

const QR_UNKNOWN = 0
const QR_URL = 1
const QR_MULTI = 2
const QR_HC1 = 3

register("ScanQrPage", class ScanQrPage extends AbstractPage {
    codeReader;     // Instance of QR Code Reader reused across invocations
    controls;
    videoElem;      // DOMElement where the video is displayed, reused across invocations
    selectedCameraId;   // The last used camera ID

    constructor(id) {
        super(id);

        // Initialize the QR library
        this.codeReader = new BrowserQRCodeReader()
        this.controls = undefined

        // Create the 'video' element and attach the event handler
        this.videoElem = document.createElement("video")
        this.videoElem.style.display = "none"
        this.videoElem.oncanplay = this.canPlay

    }

    async enter(displayPage) {
        let html = this.html

        if (!displayPage) {
            displayPage = "DisplayHcert"
        }

        // If debugging, just try to decode the test QR
        if (debugging) {
            await this.processQRpiece(testQR, displayPage)
            return
        }

        // Use the camera explicitly configured by the user
        var selectedCameraId = localStorage.getItem("selectedCamera")
        console.log("User selected camera:", selectedCameraId)

        // If nothing configured, try to use last one used, if any
        if (!selectedCameraId) {
            selectedCameraId = this.selectedCameraId
            console.log("Last used camera:", selectedCameraId)
        }
 
        // If we are in Android and this is the first time, try to select the most appropriate camera
        // This will request permission from the user
        if (!selectedCameraId && ("Android" == getPlatformOS())) {
            console.log("We are in Andoid and this is the first time")
            let allVideoDevices;
            try {
                allVideoDevices = await getPreferredVideoDevice()
                console.log("Video devices in Android:", allVideoDevices)
            } catch (error) {
                log.error("Error requesting camera access", error)
            }
            if (allVideoDevices && allVideoDevices.defaultPreferredCamera) {
                selectedCameraId = allVideoDevices.defaultPreferredCamera.deviceId
                console.log("Selected camera in Android:", selectedCameraId)
            }

            if (!selectedCameraId) {
                console.log("In Android and no selected camera")
                this.render(this.messageNoCameraPermissions())
                return;
            }
    
        }

        // Record the currently selected camera
        this.selectedCameraId = selectedCameraId
        console.log("Remembering camera used:", selectedCameraId)

        let theHtml = html`${this.videoElem}`;

        // Prepare the screen, waiting for the video
        this.render(theHtml)

        let constraints;
        if (!selectedCameraId) {
            console.log("Constraints without camera")
            constraints = {
                audio: false,
                video: {
                    width: { ideal: 1080, max: 1920 },
                    facingMode: "environment"
                }
            }
        } else {
            console.log("Constraints with deviceID:", selectedCameraId)
            constraints = {
                audio: false,
                video: {
                    width: { ideal: 1080, max: 1920 },
                    deviceId: selectedCameraId
                }
            }
        }

        // Call the QR decoder using the video element just created
        // If cameraQR is undefined, the decoder will choose the appropriate camera
        try {

            this.controls = await this.codeReader.decodeFromConstraints(constraints, this.videoElem, (result, err, controls) => {
                if (result) {
                    // Successful decode
                    console.log("RESULT", result)
    
                    // Only decode Health Certificates
                    let qrType = this.detectQRtype(result)
                    console.log("QRTYPE", qrType)
    
                    if (qrType === QR_HC1) {
                        // Stop scanning
                        controls.stop()
                        // And process the scanned QR code
                        this.processQRpiece(result, displayPage)
                    }
    
                }
            })

        } catch (error) {
            console.log("No permissions from user")
            theHtml = this.messageNoCameraPermissions()
            this.render(theHtml)
            return;

        }

    }

    canPlay(e){
        // The video stream is ready, show the 'video' element
        e.target.style.display = "block"
    }
    
    async exit() {
        // Reset the decoder just in case the camera was still working
        if (this.controls) {
            this.controls.stop()
        }
        this.videoElem.style.display = "none"
    }

    async processQRpiece(readerResult, displayPage) {
        let qrData = readerResult.text
    
        let qrType = this.detectQRtype(readerResult)
        console.log("QRTYPE", qrType)
        if (qrType !== QR_HC1) {
            return false;
        }
    
        // Display data of a normal QR
        if (qrType === QR_UNKNOWN || qrType === QR_URL) {
            window.MHR.gotoPage("DisplayNormalQR", qrData)
            return true;
        }
    
        // Handle HCERT data
        if (qrType === QR_HC1) {
            console.log("Going to ", displayPage)
            window.MHR.gotoPage(displayPage, qrData)
            return true;
        }
    
    }
    
    detectQRtype(readerResult) {
        // Try to detect the type of data received
        let qrData = readerResult.text
      
        console.log("detectQRtype:", qrData);
        if (!qrData.startsWith) {
            log.error("detectQRtype: data is not string")
        }
      
        if (qrData.startsWith("https")) {
          // We require secure connections
          // Normal QR: we receive a URL where the real data is located
          return QR_URL;
        } else if (qrData.startsWith("multi|w3cvc|")) {
          // A multi-piece JWT
          return QR_MULTI;
        } else if (qrData.startsWith("HC1:")) {
          return QR_HC1;
        } else {
            return QR_UNKNOWN
        }
    }
    
    messageNoCameraPermissions() {
        let html = this.html

        let theHtml = html`
        <div class="container">
            <div class="w3-card-4 center" style="margin-top:100px;">
        
                <header class="container color-primary" style="padding:10px">
                    <h1>${T("No camera access")}</h1>
                </header>
        
                <div class="container ptb-16">
                    <p>${T("You need to allow camera access to be able to scan a QR.")}</p>
                    <p>${T("Please click Accept to refresh the page.")}</p>
                </div>
        
                <div class="ptb-16">
        
                    <btn-primary @click=${()=>window.location.reload()}>${T("Accept")}</btn-primary>
        
                </div>
        
            </div>
        </div>
        `
        return theHtml

    }

})
