import { html } from 'uhtml'

window.MHR.register("Page404", class Page404 extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    enter(pageData) {

        let theHtml = html`
        <div class="w3-container">
            <h2>The requested page does not exist: ${pageData}</h2>
        </div>
        `

        this.render(theHtml)
    }
})
