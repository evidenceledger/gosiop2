import { html } from 'uhtml';

import ukflag from '../i18n/flags/uk.png'
import esflag from '../i18n/flags/es.png'
import caflag from '../i18n/flags/ca.png'
import frflag from '../i18n/flags/fr.png'
import deflag from '../i18n/flags/de.png'
import itflag from '../i18n/flags/it.png'

export default class SelectLanguage extends window.MHR.AbstractPage {

    constructor(id) {
        super("SelectLanguage")
    }

    enter() {
        console.log("Select language")

        let theHtml = html`
    <h2 class="text-center text-lg font-semibold my-3">Select a language</h2>

    <ul>

        <li class="mx-4 my-2 shadow-md"> 
            <a @click=${()=>this.selectLang("en")} href="javascript:void(0)">
                <div class="flex p-2">
                    <img class="mr-4" src=${ukflag} style="width:70px;height:45px">
                    <span class="my-auto font-medium">English</span>
                </div>
            </a>
        </li>

        <li class="mx-4 my-2 shadow-md"> 
            <a @click=${()=>this.selectLang("ca")} href="javascript:void(0)">
                <div class="flex p-2">
                    <img class="mr-4" src=${caflag} style="width:70px;height:45px">
                    <span class="my-auto font-medium">Català</span>
                </div>
            </a>
        </li>

        <li class="mx-4 my-2 shadow-md">
            <a @click=${()=>this.selectLang("es")} href="javascript:void(0)">
                <div class="flex p-2">
                    <img class="mr-4" src=${esflag} style="width:70px;height:45px">
                    <span class="my-auto font-medium">Español</span>
                </div>
            </a>
        </li>

        <li class="mx-4 my-2 shadow-md">
            <a @click=${()=>this.selectLang("fr")} href="javascript:void(0)">
                <div class="flex p-2">
                    <img class="mr-4" src=${frflag} style="width:70px;height:45px">
                    <span class="my-auto font-medium">Français</span>
                </div>
            </a>
        </li>

        <li class="mx-4 my-2 shadow-md">
            <a @click=${()=>this.selectLang("de")} href="javascript:void(0)">
                <div class="flex p-2">
                    <img class="mr-4" src=${deflag} style="width:70px;height:45px">
                    <span class="my-auto font-medium">Deutsch</span>
                </div>
            </a>
        </li>

        <li class="mx-4 my-2 shadow-md">
            <a @click=${()=>this.selectLang("it")} href="javascript:void(0)">
                <div class="flex p-2">
                    <img class="mr-4" src=${itflag} style="width:70px;height:45px">
                    <span class="my-auto font-medium">Italiano</span>
                </div>
            </a>
        </li>

    </ul>
`
        this.render(theHtml)
    }

    async selectLang(l) {
        console.log("Selecting language", l)
        window.preferredLanguage = l
        localStorage.setItem("preferredLanguage", l)
        window.MHR.goHome()
    }
}

let page = new SelectLanguage()