import { html } from 'uhtml'

window.MHR.register("SWNotify", class SWNotify extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    enter(pageData) {
        let html = this.html

        let msg
        if (pageData && pageData.isUpdate) {
            msg = T("Application updated")
        } else {
            msg = T("Application available")
        }

        let theHtml = html`
        <div class="max-w-sm mx-auto px-6">
            <div class=" rounded text-center overflow-hidden shadow-lg mx-auto" style="margin-top:100px;">
        
                <header class="color-primary" style="padding:10px">
                    <h1 class="text-lg">${msg}</h1>
                </header>
        
                <div class="py-6">
                    <p>${T("There is a new version of the application and it has already been updated.")}</p>
                    <p>${T("Please click Accept to refresh the page.")}</p>
                </div>
                
                <div class="mb-4">
                <button class="btn-primary" onclick=${()=>window.location.reload()}>${T("Accept")}</button>        
                </div>

            </div>
        </div>
        `

        this.render(theHtml)
    }
})
