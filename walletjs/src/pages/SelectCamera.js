import { html } from 'uhtml'
import { getPreferredVideoDevice } from '../components/camerainfo'

window.MHR.register("SelectCamera", class SelectCamera extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    async enter() {
        let html = this.html

        try {
            var preferredVideoDevices = await getPreferredVideoDevice()
            if (preferredVideoDevices.videoDevices.length == 0) {
                this.render(html`<p>No camera available</p>`)
                return;
            }
    
            var videoDevices = preferredVideoDevices.videoDevices
    
        } catch (error) {
            this.render(html`<p>No camera available</p>`)
            return;
    }

        let theHtml = html`
<section class="w3-container">
    <h2>Select a camera</h2>
    <div class="w3-bar-block w3-card">
        ${videoDevices.map((camera) =>
        html`
        <a class="w3-bar-item w3-btn w3-border" @click=${()=>this.setCamera(camera.deviceId)} href="javascript:void(0)">
            <p class="w3-medium">${camera.label}</p>
        </a>`        
        )}
    </div>
</section>`
        this.render(theHtml)
    }

    async setCamera(l) {
        window.selectedCamera = l
        localStorage.setItem("selectedCamera", l)
        window.history.back()
    }

})
