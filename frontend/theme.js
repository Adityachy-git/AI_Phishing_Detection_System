// ==============================
// Theme Manager
// ==============================

function toggleTheme(){

    const body = document.body;

    const darkMode =
        document.getElementById("themeToggle").checked;

    if(darkMode){

        body.classList.add("light-mode");

        localStorage.setItem("theme","light");

    }

    else{

        body.classList.remove("light-mode");

        localStorage.setItem("theme","dark");

    }

}

window.addEventListener("DOMContentLoaded",()=>{

    const savedTheme =
        localStorage.getItem("theme");

    const toggle =
        document.getElementById("themeToggle");

    if(savedTheme==="light"){

        document.body.classList.add("light-mode");

        if(toggle){

            toggle.checked=true;

        }

    }

});