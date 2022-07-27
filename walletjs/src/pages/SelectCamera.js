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
        <h2 class="text-center text-lg font-semibold my-3">Select a camera</h2>

        <ul>
        ${videoDevices.map((camera) =>

            html`
            <li class="mx-4 my-2 shadow-md">
                <a @click=${()=>this.setCamera(camera.deviceId)} href="javascript:void(0)">
                    <div class="flex p-3">
                    <p class="text-lg font-medium">${camera.label}</p>
                    </div>
                </a>
            </li>`
            
            )}
        </ul>

        `
        this.render(theHtml)
    }

    async setCamera(l) {
        console.log("Selecting camera", l)
        window.selectedCamera = l
        localStorage.setItem("selectedCamera", l)
        window.history.back()
    }

})
