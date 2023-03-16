// selecting dom element
const textInput = document.querySelector("#mytext");
const textOutput = document.querySelector("#decryptedText");
const btn = document.querySelector("#submit");

// adding event listener to button
btn.addEventListener("click", fetchHandler);

// selecting loading div
const loader = document.querySelector("#loading");

// showing loading
function displayLoading() {
    loader.classList.add("display");
    // to stop loading after some time
    setTimeout(() => {
        loader.classList.remove("display");
    }, 5000);
}

// hiding loading
function hideLoading() {
    loader.classList.remove("display");
}

// dummy url
var url = "https://lessonfourapi.tanaypratap.repl.co/translate/yoda.json"

function fetchHandler(event) {
    displayLoading()
//    var input = textInput.value;
//    var finalURL = buildURL(input);
//
//    fetch(finalURL)
//        .then(response => response.json())
//        .then(json => {
//            hideLoading()
//            textOutput.innerText = json.contents.translated;
//        })
}
// creating url format
// we need
// https://lessonfourapi.tanaypratap.repl.co/translate/yoda.json?text="your input"

function buildURL(inputData) {
    return `${url}?text=${inputData}`;
}