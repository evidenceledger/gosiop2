import { log } from '../log'
import { html } from 'uhtml'
// import * as db from "../components/db"
// import * as jwt from "../components/jwt"

function Card(content) {
    return html`
<div class="w3-col">
    <div class="w3-margin-bottom w3-card-4 w3-round-large">

        <div class="w3-cell-row">

            <div class="w3-cell w3-container w3-primary w3-round-top-left" style="width:70%">
                <div>Logo</div>
            </div>

            <div class="w3-cell w3-container">

                <div class="w3-cell-row">
                    <div class="w3-cell w3-tiny w3-monospace w3-text-grey">
                        <div class="w3-tiny w3-monospace w3-text-grey">FLIGHT</div>
                        <div class="w3-small w3-monospace">IB3205</div>
                    </div>
                    <div class="w3-cell w3-tiny w3-monospace w3-text-grey">
                        <div class="w3-tiny w3-monospace w3-text-grey">DATE</div>
                        <div class="w3-small w3-monospace">28JUN</div>
                    </div>
                </div>

            </div>

        </div>


        <div class="w3-cell-row">
            <div class="w3-cell w3-center" style="width:40%">
                <div class="w3-xlarge">SOURCE</div>
            </div>
            <div class="w3-cell w3-center" style="width:10%">
                <div>Logo</div>
            </div>
            <div class="w3-cell w3-center" style="width:40%">
                <div>DEST</div>
            </div>
        </div>

        <div class="w3-cell-row">
            <div class="w3-container w3-large">${content.encoded}</div>
        </div>


        <div class="w3-cell-row">
            <div class="w3-container w3-large">&#128712;</div>
        </div>


    </div>
</div>`
}



window.MHR.register("IntroPage", class IntroPage extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)

    }

    async enter() {

        var cards = await getCredentialList()

        let theHtml = html`
        <div class="w3-content w3-margin-top">
        
            <div class="w3-row-padding ">

                ${cards.map(
                    (content) => Card(content)
                )}               
            
            </div>
            
            <div class="w3-center">
                <button class="w3-btn w3-primary" onclick='${() => window.MHR.gotoPage("ScanQrPage")}'>
                    ${T("The start")}
                </button>
            </div>
        </div>
        `;

        this.render(theHtml)

    }

})



async function getCredentialList(backEndpoint) {
    backEndpoint = "http://127.0.0.1:8080/api/allcredentials"

    try {
        let response = await fetch(backEndpoint)
        var cards = await response.json()
    } catch (error) {
        log.error(error)
        throw "ERROR getting the cards"
    }

    return cards

}
