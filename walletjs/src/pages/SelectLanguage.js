import { html } from 'uhtml';

import ukflag from '../i18n/flags/uk.png'
import esflag from '../i18n/flags/es.png'
import caflag from '../i18n/flags/ca.png'
import frflag from '../i18n/flags/fr.png'
import deflag from '../i18n/flags/de.png'
import itflag from '../i18n/flags/it.png'

window.MHR.register("SelectLanguage", class SelectLanguage extends window.MHR.AbstractPage {

    constructor(id) {
        super(id)
    }

    enter() {

        let theHtml = html`
<section class="w3-container">

    <h2>Select a language</h2>

    <div class="w3-bar-block w3-card">
        <a class="w3-bar-item w3-btn w3-border" @click=${()=>this.selectLang("en")} href="javascript:void(0)">
            <img src=${ukflag} style="width:70px;height:45px">
            <span class="w3-margin-left">English</span>
        </a>
        <a class="w3-bar-item w3-btn w3-border" @click=${()=>this.selectLang("ca")} href="javascript:void(0)">
            <img src=${caflag} style="width:70px;height:45px">
            <span class="w3-margin-left">Català</span>
        </a>
        <a class="w3-bar-item w3-btn w3-border" @click=${()=>this.selectLang("es")} href="javascript:void(0)">
            <img src=${esflag} style="width:70px;height:45px">
            <span class="w3-margin-left">Español</span>
        </a>
        <a class="w3-bar-item w3-btn w3-border" @click=${()=>this.selectLang("fr")} href="javascript:void(0)">
            <img src=${frflag} style="width:70px;height:45px">
            <span class="w3-margin-left">Français</span>
        </a>
        <a class="w3-bar-item w3-btn w3-border" @click=${()=>this.selectLang("de")} href="javascript:void(0)">
            <img src=${deflag} style="width:70px;height:45px">
            <span class="w3-margin-left">Deutsch</span>
        </a>
        <a class="w3-bar-item w3-btn w3-border" @click=${()=>this.selectLang("it")} href="javascript:void(0)">
            <img src=${itflag} style="width:70px;height:45px">
            <span class="w3-margin-left">Italiano</span>
        </a>
    </div>
</section>
`
        this.render(theHtml)
    }

    async selectLang(l) {
        console.log("Selecting language", l)
        window.preferredLanguage = l
        localStorage.setItem("preferredLanguage", l)
        window.MHR.goHome()
    }
})

