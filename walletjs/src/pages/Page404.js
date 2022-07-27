import { html } from 'uhtml'

window.MHR.register("Page404", class Page404 extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    enter(pageData) {
        let html = this.html

        let theHtml = html`
        <div class="w3-container">
            <h1>The requested page does not exist!: ${pageData}</h1>
        </div>
        `

        this.render(theHtml)
    }
})
