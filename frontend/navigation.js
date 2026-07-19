// =====================================
// Sidebar Navigation
// =====================================

function showPage(page, element) {

    // Hide all pages
    document.getElementById("dashboardPage").style.display = "none";
    document.getElementById("historyPage").style.display = "none";
    document.getElementById("reportsPage").style.display = "none";
    document.getElementById("settingsPage").style.display = "none";

    // Remove active class
    document.querySelectorAll(".menu-item")
        .forEach(item => item.classList.remove("active"));

    // Show selected page
    switch(page){

        case "dashboard":
            document.getElementById("dashboardPage").style.display = "block";
            break;

        case "history":
            document.getElementById("historyPage").style.display = "block";

            if(typeof loadHistory === "function"){
                loadHistory();
            }

            break;

        case "reports":
            document.getElementById("reportsPage").style.display = "block";
            break;

        case "settings":
            document.getElementById("settingsPage").style.display = "block";
            break;

    }

    element.classList.add("active");

}
// =====================================
// Initial Page
// =====================================

window.addEventListener("DOMContentLoaded", () => {

    const firstMenu = document.querySelector(".menu-item");

    showPage("dashboard", firstMenu);

});