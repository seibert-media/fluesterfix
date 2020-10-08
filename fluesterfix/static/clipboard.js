function copy() {
    var copyText = document.querySelector("#copytarget");
    copyText.select();
    document.execCommand("copy");
}
