import { html } from 'uhtml'

window.MHR.register("DisplayNormalQR", class DisplayNormalQR extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    enter(qrData) {
        let html = this.html

        let isURL = false
        if (qrData.startsWith("https://") || qrData.startsWith("http://")) {
            isURL = true
        }

        let theHtml = html`
        <div class="container" style="margin-top:50px;">
            <h2 class="mb-16 center">Received QR</h2>
            <p class="w3-large" style="word-break: break-all;">${qrData}</p>
        
            <div class="w3-bar ptb-16 w3-center" style="max-width:70%;margin:50px auto;">

                <a href="javascript:void(0)" @click=${()=> window.history.back()} class="btn left color-secondary hover-color-secondary
                    w3-large w3-round-xlarge">Back</a>
    
                ${isURL
                ? html`<a href="${qrData}" class="btn right color-secondary hover-color-secondary
                    w3-large w3-round-xlarge">Go to site</a>`
                : html``
                }
                
            </div>
        </div>
        `

        this.render(theHtml)
    }
})
