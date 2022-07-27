import { html } from 'uhtml'
import { log } from '../log'

function shortDate(timestamp) {
    let date = new Date(timestamp)
//    return `${date.getFullYear()}-${date.getMonth()+1}-${date.getDate()+1}`
    return `${date.toISOString()}`
}

window.MHR.register("LogsPage", class LogsPage extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    enter() {
        let html = this.html

        let items = []
        for (let i = 0; i < log.num_items(); i++) {
            items.push(log.item(i))
        }

        let theHtml = html`
        <div class="container">
            <h2 class="mb-16 wball">${T("Displaying the technical logs")}</h2>

            <ul>
                ${items.map(
                ({timestamp, desc}, i) => html`<li class="bb-1 wball">${shortDate(timestamp)}-${desc}</li>`
                )}
            </ul>

        </div>`;

        this.render(theHtml)
    }
})
